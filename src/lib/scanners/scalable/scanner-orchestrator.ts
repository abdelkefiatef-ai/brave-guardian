// ============================================================================
// SCANNER ORCHESTRATOR
// Manages parallel scanning with connection pooling and rate limiting
// Handles 10,000+ assets efficiently
// ============================================================================

import { EventEmitter } from 'events'

// ============================================================================
// TYPES
// ============================================================================

export interface ScanJob {
  id: string
  targets: ScanTarget[]
  priority: 'critical' | 'high' | 'medium' | 'low'
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  progress: number
  startTime?: number
  endTime?: number
  results: ScanResult[]
  errors: string[]
  metadata: Record<string, any>
}

export interface ScanTarget {
  id: string
  host: string
  port?: number
  username: string
  auth: {
    type: 'password' | 'key' | 'agent'
    password?: string
    keyPath?: string
  }
  zone?: 'dmz' | 'internal' | 'restricted' | 'cloud'
  criticality?: number
  metadata?: Record<string, any>
}

export interface ScanResult {
  target: ScanTarget
  success: boolean
  data: Record<string, string>
  misconfigurations: DetectedMisconfiguration[]
  errors: string[]
  duration: number
  timestamp: number
  cached: boolean
}

export interface DetectedMisconfiguration {
  id: string
  title: string
  description: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  evidence: string
  remediation: string
  references: string[]
}

export interface OrchestratorConfig {
  maxConcurrent: number
  batchSize: number
  timeout: number
  retryAttempts: number
  retryDelay: number
  rateLimit: {
    maxRequestsPerSecond: number
    burstLimit: number
  }
  connectionPool: {
    maxSize: number
    idleTimeout: number
  }
  caching: {
    enabled: boolean
    ttl: number
    maxSize: number
  }
  callbacks: {
    onProgress?: (jobId: string, progress: number) => void
    onComplete?: (jobId: string, results: ScanResult[]) => void
    onError?: (jobId: string, error: string) => void
    onTargetComplete?: (jobId: string, target: ScanTarget, result: ScanResult) => void
  }
}

// ============================================================================
// CONNECTION POOL
// ============================================================================

interface PooledConnection {
  id: string
  host: string
  port: number
  inUse: boolean
  lastUsed: number
  createdAt: number
  errorCount: number
}

class ConnectionPoolManager {
  private pools: Map<string, PooledConnection[]> = new Map()
  private config: OrchestratorConfig['connectionPool']

  constructor(config: OrchestratorConfig['connectionPool']) {
    this.config = config
  }

  async acquire(target: ScanTarget): Promise<PooledConnection | null> {
    const poolKey = `${target.host}:${target.port || 22}`
    const pool = this.pools.get(poolKey) || []

    // Find idle connection
    const idle = pool.find(c => !c.inUse)
    if (idle) {
      idle.inUse = true
      idle.lastUsed = Date.now()
      return idle
    }

    // Create new connection if under limit
    if (pool.length < this.config.maxSize) {
      const conn: PooledConnection = {
        id: `${poolKey}-${Date.now()}`,
        host: target.host,
        port: target.port || 22,
        inUse: true,
        lastUsed: Date.now(),
        createdAt: Date.now(),
        errorCount: 0,
      }
      pool.push(conn)
      this.pools.set(poolKey, pool)
      return conn
    }

    // Wait for connection to become available
    return null
  }

  release(connection: PooledConnection): void {
    connection.inUse = false
  }

  markError(connection: PooledConnection): void {
    connection.errorCount++
    if (connection.errorCount >= 3) {
      // Remove connection with too many errors
      const poolKey = `${connection.host}:${connection.port}`
      const pool = this.pools.get(poolKey) || []
      const idx = pool.findIndex(c => c.id === connection.id)
      if (idx >= 0) {
        pool.splice(idx, 1)
        this.pools.set(poolKey, pool)
      }
    }
  }

  cleanup(): void {
    const now = Date.now()
    for (const [key, pool] of this.pools) {
      const filtered = pool.filter(c => 
        !c.inUse && (now - c.lastUsed) < this.config.idleTimeout
      )
      if (filtered.length === 0) {
        this.pools.delete(key)
      } else {
        this.pools.set(key, filtered)
      }
    }
  }

  getStats(): { totalConnections: number; activeConnections: number; idleConnections: number } {
    let total = 0
    let active = 0
    
    for (const pool of this.pools.values()) {
      total += pool.length
      active += pool.filter(c => c.inUse).length
    }
    
    return {
      totalConnections: total,
      activeConnections: active,
      idleConnections: total - active,
    }
  }
}

// ============================================================================
// RATE LIMITER
// ============================================================================

class RateLimiter {
  private tokens: number
  private lastRefill: number
  private config: OrchestratorConfig['rateLimit']

  constructor(config: OrchestratorConfig['rateLimit']) {
    this.config = config
    this.tokens = config.burstLimit
    this.lastRefill = Date.now()
  }

  async waitForToken(): Promise<void> {
    this.refill()
    
    if (this.tokens >= 1) {
      this.tokens--
      return
    }

    // Wait for token
    const waitTime = 1000 / this.config.maxRequestsPerSecond
    await new Promise(resolve => setTimeout(resolve, waitTime))
    return this.waitForToken()
  }

  private refill(): void {
    const now = Date.now()
    const elapsed = (now - this.lastRefill) / 1000
    const refillAmount = elapsed * this.config.maxRequestsPerSecond
    
    this.tokens = Math.min(
      this.config.burstLimit,
      this.tokens + refillAmount
    )
    this.lastRefill = now
  }
}

// ============================================================================
// RESULT CACHE
// ============================================================================

interface CacheEntry {
  result: ScanResult
  timestamp: number
  hash: string
}

class ResultCache {
  private cache: Map<string, CacheEntry> = new Map()
  private config: OrchestratorConfig['caching']

  constructor(config: OrchestratorConfig['caching']) {
    this.config = config
  }

  get(target: ScanTarget): ScanResult | null {
    if (!this.config.enabled) return null
    
    const key = this.getKey(target)
    const entry = this.cache.get(key)
    
    if (!entry) return null
    if (Date.now() - entry.timestamp > this.config.ttl) {
      this.cache.delete(key)
      return null
    }
    
    return { ...entry.result, cached: true }
  }

  set(target: ScanTarget, result: ScanResult): void {
    if (!this.config.enabled) return
    
    // Evict if at capacity
    if (this.cache.size >= this.config.maxSize) {
      const oldestKey = this.cache.keys().next().value
      if (oldestKey) {
        this.cache.delete(oldestKey)
      }
    }
    
    const key = this.getKey(target)
    this.cache.set(key, {
      result: { ...result, cached: false },
      timestamp: Date.now(),
      hash: this.hashResult(result),
    })
  }

  private getKey(target: ScanTarget): string {
    return `${target.host}:${target.port || 22}`
  }

  private hashResult(result: ScanResult): string {
    return JSON.stringify(result.data).slice(0, 64)
  }

  clear(): void {
    this.cache.clear()
  }

  getStats(): { size: number; hitRate: number } {
    return {
      size: this.cache.size,
      hitRate: 0, // Would need tracking
    }
  }
}

// ============================================================================
// PARALLEL SCANNER
// ============================================================================

class ParallelScanner {
  private config: OrchestratorConfig
  private connectionPool: ConnectionPoolManager
  private rateLimiter: RateLimiter
  private cache: ResultCache
  private eventEmitter: EventEmitter

  constructor(config: OrchestratorConfig) {
    this.config = config
    this.connectionPool = new ConnectionPoolManager(config.connectionPool)
    this.rateLimiter = new RateLimiter(config.rateLimit)
    this.cache = new ResultCache(config.caching)
    this.eventEmitter = new EventEmitter()
  }

  /**
   * Scan multiple targets in parallel with controlled concurrency
   */
  async scanTargets(
    targets: ScanTarget[],
    onProgress?: (completed: number, total: number) => void
  ): Promise<ScanResult[]> {
    const results: ScanResult[] = new Array(targets.length)
    let completed = 0
    
    // Create worker queues
    const queue = targets.map((target, index) => ({ target, index }))
    const activeWorkers: Promise<void>[] = []
    
    const processNext = async (): Promise<void> => {
      while (queue.length > 0) {
        const item = queue.shift()
        if (!item) break
        
        // Rate limit
        await this.rateLimiter.waitForToken()
        
        // Scan target
        const result = await this.scanSingleTarget(item.target)
        results[item.index] = result
        
        completed++
        onProgress?.(completed, targets.length)
      }
    }
    
    // Start workers
    for (let i = 0; i < this.config.maxConcurrent; i++) {
      activeWorkers.push(processNext())
    }
    
    await Promise.all(activeWorkers)
    
    // Cleanup idle connections
    this.connectionPool.cleanup()
    
    return results
  }

  /**
   * Scan a single target
   */
  private async scanSingleTarget(target: ScanTarget): Promise<ScanResult> {
    const startTime = Date.now()
    
    // Check cache first
    const cached = this.cache.get(target)
    if (cached) {
      return cached
    }
    
    // Get connection
    const connection = await this.connectionPool.acquire(target)
    
    try {
      // Execute scan with retries
      let lastError: Error | null = null
      
      for (let attempt = 0; attempt < this.config.retryAttempts; attempt++) {
        try {
          const data = await this.executeScan(target)
          const result: ScanResult = {
            target,
            success: true,
            data,
            misconfigurations: this.detectMisconfigurations(data),
            errors: [],
            duration: Date.now() - startTime,
            timestamp: Date.now(),
            cached: false,
          }
          
          // Cache result
          this.cache.set(target, result)
          
          return result
        } catch (error) {
          lastError = error as Error
          if (attempt < this.config.retryAttempts - 1) {
            await this.sleep(this.config.retryDelay * (attempt + 1))
          }
        }
      }
      
      // All retries failed
      if (connection) {
        this.connectionPool.markError(connection)
      }
      
      return {
        target,
        success: false,
        data: {},
        misconfigurations: [],
        errors: [lastError?.message || 'Unknown error'],
        duration: Date.now() - startTime,
        timestamp: Date.now(),
        cached: false,
      }
    } finally {
      if (connection) {
        this.connectionPool.release(connection)
      }
    }
  }

  /**
   * Execute actual scan (would integrate with actual scanner)
   */
  private async executeScan(target: ScanTarget): Promise<Record<string, string>> {
    // This would integrate with the OptimizedScanner or HighPerformanceScanner
    // For now, return placeholder
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          hostname: target.host,
          os: 'Linux',
          // ... other scan data
        })
      }, 100 + Math.random() * 500) // Simulate scan time
    })
  }

  /**
   * Detect misconfigurations from scan data
   */
  private detectMisconfigurations(data: Record<string, string>): DetectedMisconfiguration[] {
    const misconfigs: DetectedMisconfiguration[] = []
    
    // Example detection rules
    if (data.sshd_config?.includes('PermitRootLogin yes')) {
      misconfigs.push({
        id: 'M001',
        title: 'SSH Root Login Enabled',
        description: 'SSH permits direct root login',
        category: 'authentication',
        severity: 'high',
        evidence: 'PermitRootLogin yes found in sshd_config',
        remediation: 'Set PermitRootLogin no or prohibit-password',
        references: ['CIS-5.2.8', 'MITRE-T1021.004'],
      })
    }
    
    if (data.firewall_ufw?.includes('inactive')) {
      misconfigs.push({
        id: 'M019',
        title: 'Host Firewall Disabled',
        description: 'UFW firewall is not active',
        category: 'network',
        severity: 'medium',
        evidence: 'UFW status shows inactive',
        remediation: 'Enable UFW and configure rules',
        references: ['CIS-3.5.1'],
      })
    }
    
    return misconfigs
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }

  getStats(): {
    connections: { totalConnections: number; activeConnections: number; idleConnections: number }
    cache: { size: number; hitRate: number }
  } {
    return {
      connections: this.connectionPool.getStats(),
      cache: this.cache.getStats(),
    }
  }
}

// ============================================================================
// SCANNER ORCHESTRATOR
// ============================================================================

export class ScannerOrchestrator extends EventEmitter {
  private config: OrchestratorConfig
  private scanner: ParallelScanner
  private jobs: Map<string, ScanJob> = new Map()
  private isRunning: boolean = false

  constructor(config: Partial<OrchestratorConfig> = {}) {
    super()
    
    this.config = {
      maxConcurrent: config.maxConcurrent || 25,
      batchSize: config.batchSize || 100,
      timeout: config.timeout || 30000,
      retryAttempts: config.retryAttempts || 2,
      retryDelay: config.retryDelay || 1000,
      rateLimit: config.rateLimit || {
        maxRequestsPerSecond: 50,
        burstLimit: 100,
      },
      connectionPool: config.connectionPool || {
        maxSize: 50,
        idleTimeout: 300000,
      },
      caching: config.caching || {
        enabled: true,
        ttl: 3600000,
        maxSize: 10000,
      },
      callbacks: config.callbacks || {},
    }
    
    this.scanner = new ParallelScanner(this.config)
  }

  /**
   * Create and queue a new scan job
   */
  createJob(targets: ScanTarget[], priority: ScanJob['priority'] = 'medium', metadata: Record<string, any> = {}): string {
    const jobId = `job-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    
    const job: ScanJob = {
      id: jobId,
      targets,
      priority,
      status: 'pending',
      progress: 0,
      results: [],
      errors: [],
      metadata,
    }
    
    this.jobs.set(jobId, job)
    return jobId
  }

  /**
   * Start executing a job
   */
  async startJob(jobId: string): Promise<ScanResult[]> {
    const job = this.jobs.get(jobId)
    if (!job) {
      throw new Error(`Job ${jobId} not found`)
    }
    
    if (job.status === 'running') {
      throw new Error(`Job ${jobId} is already running`)
    }
    
    job.status = 'running'
    job.startTime = Date.now()
    this.emit('jobStarted', job)
    
    try {
      // Sort by priority
      const sortedTargets = this.sortTargetsByPriority(job.targets)
      
      // Scan in batches
      const results = await this.scanner.scanTargets(
        sortedTargets,
        (completed, total) => {
          job.progress = (completed / total) * 100
          this.config.callbacks.onProgress?.(jobId, job.progress)
          this.emit('progress', jobId, job.progress)
        }
      )
      
      job.results = results
      job.status = 'completed'
      job.endTime = Date.now()
      
      this.config.callbacks.onComplete?.(jobId, results)
      this.emit('jobCompleted', job)
      
      return results
    } catch (error) {
      job.status = 'failed'
      job.errors.push((error as Error).message)
      job.endTime = Date.now()
      
      this.config.callbacks.onError?.(jobId, (error as Error).message)
      this.emit('jobFailed', job, error)
      
      throw error
    }
  }

  /**
   * Cancel a running job
   */
  cancelJob(jobId: string): boolean {
    const job = this.jobs.get(jobId)
    if (!job || job.status !== 'running') {
      return false
    }
    
    job.status = 'cancelled'
    job.endTime = Date.now()
    this.emit('jobCancelled', job)
    
    return true
  }

  /**
   * Get job status
   */
  getJob(jobId: string): ScanJob | undefined {
    return this.jobs.get(jobId)
  }

  /**
   * Get all jobs
   */
  getAllJobs(): ScanJob[] {
    return Array.from(this.jobs.values())
  }

  /**
   * Get orchestrator statistics
   */
  getStats(): {
    jobs: { total: number; running: number; completed: number; failed: number }
    scanner: ReturnType<ParallelScanner['getStats']>
  } {
    const jobs = Array.from(this.jobs.values())
    
    return {
      jobs: {
        total: jobs.length,
        running: jobs.filter(j => j.status === 'running').length,
        completed: jobs.filter(j => j.status === 'completed').length,
        failed: jobs.filter(j => j.status === 'failed').length,
      },
      scanner: this.scanner.getStats(),
    }
  }

  /**
   * Sort targets by priority (critical first, then internet-facing, then by criticality)
   */
  private sortTargetsByPriority(targets: ScanTarget[]): ScanTarget[] {
    return [...targets].sort((a, b) => {
      // Internet-facing first
      const zonePriority: Record<string, number> = {
        dmz: 0,
        internal: 1,
        restricted: 2,
        cloud: 3,
      }
      
      const aZone = zonePriority[a.zone || 'internal'] ?? 1
      const bZone = zonePriority[b.zone || 'internal'] ?? 1
      
      if (aZone !== bZone) return aZone - bZone
      
      // Then by criticality (higher first)
      return (b.criticality || 0) - (a.criticality || 0)
    })
  }

  /**
   * Cleanup resources
   */
  cleanup(): void {
    this.jobs.clear()
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export { ConnectionPoolManager, RateLimiter, ResultCache, ParallelScanner }
