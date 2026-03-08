// ============================================================================
// SCAN SCHEDULER
// Cron-based scheduling with recurrence and dependencies
// ============================================================================

import { EventEmitter } from 'events'

// ============================================================================
// TYPES
// ============================================================================

export interface ScheduledScan {
  id: string
  name: string
  type: 'full' | 'incremental' | 'targeted'
  schedule: ScanSchedule
  targets: ScanTargetDefinition
  status: 'enabled' | 'disabled' | 'running'
  lastRun?: number
  nextRun?: number
  lastResult?: ScanResultSummary
  config: ScanConfig
  notifications: NotificationConfig
  metadata: Record<string, any>
  createdAt: number
  updatedAt: number
}

export interface ScanSchedule {
  type: 'once' | 'cron' | 'interval'
  cron?: string           // Cron expression for type='cron'
  interval?: number       // Interval in ms for type='interval'
  startAt?: number        // Specific start time
  endAt?: number          // Expiration time
  timezone?: string       // Timezone for cron
  skipIfRunning?: boolean // Skip if previous run still in progress
  retryOnFailure?: boolean
  maxRetries?: number
}

export interface ScanTargetDefinition {
  type: 'all' | 'zones' | 'tags' | 'list' | 'query'
  zones?: string[]
  tags?: string[]
  hosts?: string[]
  query?: string
  excludeHosts?: string[]
  dynamic?: boolean  // Re-evaluate targets before each run
}

export interface ScanConfig {
  timeout: number
  maxConcurrent: number
  priority: 'critical' | 'high' | 'medium' | 'low'
  rateLimit?: number
  saveResults: boolean
  retentionDays: number
  generateReport: boolean
  reportFormats?: ('pdf' | 'html' | 'json')[]
}

export interface NotificationConfig {
  onComplete: boolean
  onFailure: boolean
  onCriticalFindings: boolean
  channels: NotificationChannel[]
}

export interface NotificationChannel {
  type: 'email' | 'slack' | 'webhook' | 'pagerduty'
  config: Record<string, any>
}

export interface ScanResultSummary {
  scanId: string
  scheduledScanId: string
  startTime: number
  endTime: number
  duration: number
  status: 'success' | 'partial' | 'failed'
  targetsTotal: number
  targetsScanned: number
  targetsFailed: number
  findings: {
    critical: number
    high: number
    medium: number
    low: number
  }
}

export interface SchedulerStats {
  totalScans: number
  enabledScans: number
  runningScans: number
  completedToday: number
  failedToday: number
  nextScheduled: number | null
}

// ============================================================================
// CRON PARSER (Simplified)
// ============================================================================

class CronParser {
  /**
   * Parse cron expression and get next run time
   */
  static getNextRun(cronExpr: string, from: number = Date.now()): number {
    const parts = cronExpr.trim().split(/\s+/)
    
    if (parts.length !== 5) {
      throw new Error(`Invalid cron expression: ${cronExpr}`)
    }
    
    const [minute, hour, dayOfMonth, month, dayOfWeek] = parts.map(this.parsePart)
    
    // Start from the next minute
    const start = new Date(from)
    start.setSeconds(0)
    start.setMilliseconds(0)
    start.setMinutes(start.getMinutes() + 1)
    
    // Find next matching time (max 366 days ahead)
    for (let i = 0; i < 525600; i++) {  // Max iterations (minutes in a year)
      const date = new Date(start.getTime() + i * 60000)
      
      if (this.matches(date, minute, hour, dayOfMonth, month, dayOfWeek)) {
        return date.getTime()
      }
    }
    
    throw new Error('No matching time found within a year')
  }

  private static parsePart(part: string): number[] {
    if (part === '*') {
      return []  // Match all
    }
    
    const values: number[] = []
    
    for (const segment of part.split(',')) {
      if (segment.includes('/')) {
        const [range, step] = segment.split('/')
        const stepNum = parseInt(step, 10)
        const rangeValues = this.parseRange(range)
        
        for (let i = 0; i < rangeValues.length; i += stepNum) {
          values.push(rangeValues[i])
        }
      } else {
        values.push(...this.parseRange(segment))
      }
    }
    
    return [...new Set(values)].sort((a, b) => a - b)
  }

  private static parseRange(range: string): number[] {
    if (range === '*') {
      return []
    }
    
    if (range.includes('-')) {
      const [start, end] = range.split('-').map(n => parseInt(n, 10))
      const values: number[] = []
      for (let i = start; i <= end; i++) {
        values.push(i)
      }
      return values
    }
    
    return [parseInt(range, 10)]
  }

  private static matches(
    date: Date,
    minute: number[],
    hour: number[],
    dayOfMonth: number[],
    month: number[],
    dayOfWeek: number[]
  ): boolean {
    if (minute.length > 0 && !minute.includes(date.getMinutes())) return false
    if (hour.length > 0 && !hour.includes(date.getHours())) return false
    if (dayOfMonth.length > 0 && !dayOfMonth.includes(date.getDate())) return false
    if (month.length > 0 && !month.includes(date.getMonth() + 1)) return false
    if (dayOfWeek.length > 0 && !dayOfWeek.includes(date.getDay())) return false
    
    return true
  }
}

// ============================================================================
// SCHEDULE STORE
// ============================================================================

class ScheduleStore {
  private scans: Map<string, ScheduledScan> = new Map()

  save(scan: ScheduledScan): void {
    this.scans.set(scan.id, { ...scan })
  }

  get(id: string): ScheduledScan | undefined {
    return this.scans.get(id)
  }

  delete(id: string): boolean {
    return this.scans.delete(id)
  }

  getAll(): ScheduledScan[] {
    return Array.from(this.scans.values())
  }

  getEnabled(): ScheduledScan[] {
    return this.getAll().filter(s => s.status === 'enabled')
  }

  getByNextRun(): ScheduledScan[] {
    return this.getEnabled()
      .filter(s => s.nextRun)
      .sort((a, b) => (a.nextRun || Infinity) - (b.nextRun || Infinity))
  }
}

// ============================================================================
// SCAN SCHEDULER
// ============================================================================

export class ScanScheduler extends EventEmitter {
  private store: ScheduleStore
  private timers: Map<string, NodeJS.Timeout> = new Map()
  private runningScans: Set<string> = new Set()
  private checkInterval?: NodeJS.Timeout
  private isRunning: boolean = false

  constructor() {
    super()
    this.store = new ScheduleStore()
  }

  /**
   * Start the scheduler
   */
  start(): void {
    if (this.isRunning) return
    
    this.isRunning = true
    
    // Schedule all enabled scans
    for (const scan of this.store.getEnabled()) {
      this.scheduleScan(scan)
    }
    
    // Start periodic check (every minute)
    this.checkInterval = setInterval(() => {
      this.checkPendingScans()
    }, 60000)
    
    this.emit('started')
  }

  /**
   * Stop the scheduler
   */
  stop(): void {
    this.isRunning = false
    
    if (this.checkInterval) {
      clearInterval(this.checkInterval)
      this.checkInterval = undefined
    }
    
    // Clear all timers
    for (const [id, timer] of this.timers) {
      clearTimeout(timer)
    }
    this.timers.clear()
    
    this.emit('stopped')
  }

  /**
   * Create a new scheduled scan
   */
  createScan(
    name: string,
    type: ScheduledScan['type'],
    schedule: ScanSchedule,
    targets: ScanTargetDefinition,
    config: ScanConfig,
    notifications: NotificationConfig = { onComplete: true, onFailure: true, onCriticalFindings: true, channels: [] }
  ): ScheduledScan {
    const now = Date.now()
    
    const scan: ScheduledScan = {
      id: `scan-${now}-${Math.random().toString(36).slice(2, 8)}`,
      name,
      type,
      schedule,
      targets,
      status: 'enabled',
      config,
      notifications,
      metadata: {},
      createdAt: now,
      updatedAt: now,
    }
    
    // Calculate next run time
    scan.nextRun = this.calculateNextRun(scan)
    
    this.store.save(scan)
    
    if (this.isRunning && scan.status === 'enabled') {
      this.scheduleScan(scan)
    }
    
    this.emit('scanCreated', scan)
    return scan
  }

  /**
   * Update a scheduled scan
   */
  updateScan(id: string, updates: Partial<ScheduledScan>): ScheduledScan | undefined {
    const scan = this.store.get(id)
    if (!scan) return undefined
    
    // Cancel existing timer
    this.cancelScanTimer(id)
    
    // Apply updates
    Object.assign(scan, updates, { updatedAt: Date.now() })
    
    // Recalculate next run
    if (updates.schedule) {
      scan.nextRun = this.calculateNextRun(scan)
    }
    
    this.store.save(scan)
    
    // Reschedule if enabled
    if (this.isRunning && scan.status === 'enabled') {
      this.scheduleScan(scan)
    }
    
    this.emit('scanUpdated', scan)
    return scan
  }

  /**
   * Delete a scheduled scan
   */
  deleteScan(id: string): boolean {
    this.cancelScanTimer(id)
    const result = this.store.delete(id)
    
    if (result) {
      this.emit('scanDeleted', id)
    }
    
    return result
  }

  /**
   * Enable a scheduled scan
   */
  enableScan(id: string): boolean {
    const scan = this.store.get(id)
    if (!scan) return false
    
    scan.status = 'enabled'
    scan.nextRun = this.calculateNextRun(scan)
    this.store.save(scan)
    
    if (this.isRunning) {
      this.scheduleScan(scan)
    }
    
    this.emit('scanEnabled', scan)
    return true
  }

  /**
   * Disable a scheduled scan
   */
  disableScan(id: string): boolean {
    const scan = this.store.get(id)
    if (!scan) return false
    
    scan.status = 'disabled'
    this.store.save(scan)
    
    this.cancelScanTimer(id)
    
    this.emit('scanDisabled', scan)
    return true
  }

  /**
   * Trigger a scan immediately
   */
  triggerScan(id: string): boolean {
    const scan = this.store.get(id)
    if (!scan) return false
    
    if (scan.schedule.skipIfRunning && this.runningScans.has(id)) {
      return false
    }
    
    this.executeScan(scan)
    return true
  }

  /**
   * Get a scheduled scan
   */
  getScan(id: string): ScheduledScan | undefined {
    return this.store.get(id)
  }

  /**
   * Get all scheduled scans
   */
  getAllScans(): ScheduledScan[] {
    return this.store.getAll()
  }

  /**
   * Get scheduler statistics
   */
  getStats(): SchedulerStats {
    const scans = this.store.getAll()
    const now = Date.now()
    const todayStart = new Date(now).setHours(0, 0, 0, 0)
    
    const nextScheduled = this.store.getByNextRun()[0]?.nextRun || null
    
    return {
      totalScans: scans.length,
      enabledScans: scans.filter(s => s.status === 'enabled').length,
      runningScans: this.runningScans.size,
      completedToday: scans.filter(s => 
        s.lastRun && s.lastRun >= todayStart && s.lastResult?.status === 'success'
      ).length,
      failedToday: scans.filter(s => 
        s.lastRun && s.lastRun >= todayStart && s.lastResult?.status === 'failed'
      ).length,
      nextScheduled,
    }
  }

  // Private methods

  private scheduleScan(scan: ScheduledScan): void {
    if (!scan.nextRun) return
    
    const delay = scan.nextRun - Date.now()
    
    if (delay <= 0) {
      // Time has passed, execute now
      this.executeScan(scan)
      return
    }
    
    const timer = setTimeout(() => {
      this.executeScan(scan)
    }, delay)
    
    this.timers.set(scan.id, timer)
  }

  private cancelScanTimer(id: string): void {
    const timer = this.timers.get(id)
    if (timer) {
      clearTimeout(timer)
      this.timers.delete(id)
    }
  }

  private async executeScan(scan: ScheduledScan): Promise<void> {
    // Check if should skip
    if (scan.schedule.skipIfRunning && this.runningScans.has(scan.id)) {
      this.emit('scanSkipped', scan, 'Already running')
      this.rescheduleScan(scan)
      return
    }
    
    // Mark as running
    scan.status = 'running'
    this.runningScans.add(scan.id)
    this.store.save(scan)
    
    this.emit('scanStarted', scan)
    
    try {
      // Execute the scan (would integrate with actual scanner)
      const result = await this.runScan(scan)
      
      scan.lastRun = Date.now()
      scan.lastResult = result
      
      // Send notifications
      if (scan.notifications.onComplete) {
        this.sendNotification(scan, result, 'complete')
      }
      
      if (result.findings.critical > 0 && scan.notifications.onCriticalFindings) {
        this.sendNotification(scan, result, 'critical')
      }
      
      this.emit('scanCompleted', scan, result)
    } catch (error) {
      const result: ScanResultSummary = {
        scanId: `run-${Date.now()}`,
        scheduledScanId: scan.id,
        startTime: Date.now(),
        endTime: Date.now(),
        duration: 0,
        status: 'failed',
        targetsTotal: 0,
        targetsScanned: 0,
        targetsFailed: 0,
        findings: { critical: 0, high: 0, medium: 0, low: 0 },
      }
      
      scan.lastRun = Date.now()
      scan.lastResult = result
      
      if (scan.notifications.onFailure) {
        this.sendNotification(scan, result, 'failed')
      }
      
      this.emit('scanFailed', scan, error)
    } finally {
      scan.status = 'enabled'
      this.runningScans.delete(scan.id)
      
      // Reschedule
      this.rescheduleScan(scan)
    }
  }

  private rescheduleScan(scan: ScheduledScan): void {
    // Calculate next run
    scan.nextRun = this.calculateNextRun(scan)
    this.store.save(scan)
    
    // Schedule
    if (this.isRunning && scan.status === 'enabled') {
      this.scheduleScan(scan)
    }
  }

  private calculateNextRun(scan: ScheduledScan): number | undefined {
    const { schedule } = scan
    const now = Date.now()
    
    // Check if expired
    if (schedule.endAt && now >= schedule.endAt) {
      return undefined
    }
    
    // Calculate based on type
    let nextRun: number | undefined
    
    switch (schedule.type) {
      case 'once':
        nextRun = schedule.startAt
        break
        
      case 'interval':
        nextRun = schedule.startAt || (now + (schedule.interval || 0))
        break
        
      case 'cron':
        nextRun = CronParser.getNextRun(schedule.cron || '* * * * *', now)
        break
    }
    
    // Check bounds
    if (nextRun && schedule.startAt && nextRun < schedule.startAt) {
      nextRun = schedule.startAt
    }
    
    if (nextRun && schedule.endAt && nextRun >= schedule.endAt) {
      nextRun = undefined
    }
    
    return nextRun
  }

  private async runScan(scan: ScheduledScan): Promise<ScanResultSummary> {
    // This would integrate with the actual scanner
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          scanId: `run-${Date.now()}`,
          scheduledScanId: scan.id,
          startTime: Date.now() - 60000,
          endTime: Date.now(),
          duration: 60000,
          status: 'success',
          targetsTotal: 100,
          targetsScanned: 100,
          targetsFailed: 0,
          findings: { critical: 2, high: 5, medium: 15, low: 30 },
        })
      }, 1000)
    })
  }

  private checkPendingScans(): void {
    const now = Date.now()
    
    for (const scan of this.store.getEnabled()) {
      if (scan.nextRun && scan.nextRun <= now && !this.runningScans.has(scan.id)) {
        this.executeScan(scan)
      }
    }
  }

  private sendNotification(scan: ScheduledScan, result: ScanResultSummary, type: string): void {
    for (const channel of scan.notifications.channels) {
      this.emit('notification', {
        scan,
        result,
        type,
        channel,
      })
    }
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export { CronParser, ScheduleStore }
