// ============================================================================
// JOB STATE MANAGER
// Persistent state management with SQLite
// Supports job recovery, history, and analytics
// ============================================================================

import { promises as fs } from 'fs'
import path from 'path'

// ============================================================================
// TYPES
// ============================================================================

export interface JobState {
  id: string
  type: 'scan' | 'discovery' | 'analysis'
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  priority: 'critical' | 'high' | 'medium' | 'low'
  targets: JobTarget[]
  results: JobResult[]
  progress: number
  startTime?: number
  endTime?: number
  duration?: number
  error?: string
  metadata: Record<string, any>
  createdBy: string
  createdAt: number
  updatedAt: number
}

export interface JobTarget {
  id: string
  host: string
  port: number
  zone?: string
  criticality?: number
  status: 'pending' | 'scanning' | 'completed' | 'failed'
  result?: JobResult
}

export interface JobResult {
  targetId: string
  host: string
  success: boolean
  misconfigurations: MisconfigurationFinding[]
  data: Record<string, string>
  errors: string[]
  duration: number
  timestamp: number
}

export interface MisconfigurationFinding {
  id: string
  title: string
  description: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  evidence: string
  remediation: string
}

export interface JobFilter {
  status?: string[]
  type?: string[]
  priority?: string[]
  createdBy?: string
  startDate?: number
  endDate?: number
  limit?: number
  offset?: number
}

export interface JobStats {
  total: number
  pending: number
  running: number
  completed: number
  failed: number
  cancelled: number
  avgDuration: number
  totalFindings: number
  criticalFindings: number
}

// ============================================================================
// IN-MEMORY STORAGE (Development Mode)
// ============================================================================

class MemoryStorage {
  private jobs: Map<string, JobState> = new Map()
  private history: JobState[] = []
  private maxSize: number

  constructor(maxSize: number = 1000) {
    this.maxSize = maxSize
  }

  async save(job: JobState): Promise<void> {
    this.jobs.set(job.id, { ...job })
  }

  async get(id: string): Promise<JobState | undefined> {
    return this.jobs.get(id)
  }

  async delete(id: string): Promise<boolean> {
    return this.jobs.delete(id)
  }

  async list(filter: JobFilter): Promise<JobState[]> {
    let results = Array.from(this.jobs.values())
    
    if (filter.status?.length) {
      results = results.filter(j => filter.status!.includes(j.status))
    }
    if (filter.type?.length) {
      results = results.filter(j => filter.type!.includes(j.type))
    }
    if (filter.priority?.length) {
      results = results.filter(j => filter.priority!.includes(j.priority))
    }
    if (filter.createdBy) {
      results = results.filter(j => j.createdBy === filter.createdBy)
    }
    if (filter.startDate) {
      results = results.filter(j => j.createdAt >= filter.startDate!)
    }
    if (filter.endDate) {
      results = results.filter(j => j.createdAt <= filter.endDate!)
    }
    
    // Sort by creation time (newest first)
    results.sort((a, b) => b.createdAt - a.createdAt)
    
    if (filter.offset) {
      results = results.slice(filter.offset)
    }
    if (filter.limit) {
      results = results.slice(0, filter.limit)
    }
    
    return results
  }

  async archive(job: JobState): Promise<void> {
    this.history.push({ ...job })
    this.jobs.delete(job.id)
    
    // Trim history if needed
    if (this.history.length > this.maxSize) {
      this.history = this.history.slice(-this.maxSize)
    }
  }

  async getStats(): Promise<JobStats> {
    const jobs = Array.from(this.jobs.values())
    const completed = jobs.filter(j => j.status === 'completed')
    
    return {
      total: jobs.length,
      pending: jobs.filter(j => j.status === 'pending').length,
      running: jobs.filter(j => j.status === 'running').length,
      completed: completed.length,
      failed: jobs.filter(j => j.status === 'failed').length,
      cancelled: jobs.filter(j => j.status === 'cancelled').length,
      avgDuration: completed.length > 0
        ? completed.reduce((s, j) => s + (j.duration || 0), 0) / completed.length
        : 0,
      totalFindings: completed.reduce(
        (s, j) => s + j.results.reduce(
          (s2, r) => s2 + r.misconfigurations.length, 0
        ), 0
      ),
      criticalFindings: completed.reduce(
        (s, j) => s + j.results.reduce(
          (s2, r) => s2 + r.misconfigurations.filter(m => m.severity === 'critical').length, 0
        ), 0
      ),
    }
  }

  async clear(): Promise<void> {
    this.jobs.clear()
    this.history = []
  }
}

// ============================================================================
// FILE-BASED STORAGE (Production Mode)
// ============================================================================

class FileStorage {
  private dataDir: string
  private jobsFile: string
  private historyFile: string
  private cache: Map<string, JobState> = new Map()
  private initialized: boolean = false

  constructor(dataDir: string) {
    this.dataDir = dataDir
    this.jobsFile = path.join(dataDir, 'jobs.json')
    this.historyFile = path.join(dataDir, 'history.json')
  }

  private async init(): Promise<void> {
    if (this.initialized) return
    
    try {
      await fs.mkdir(this.dataDir, { recursive: true })
      
      // Load existing jobs
      try {
        const data = await fs.readFile(this.jobsFile, 'utf-8')
        const jobs: JobState[] = JSON.parse(data)
        for (const job of jobs) {
          this.cache.set(job.id, job)
        }
      } catch {
        // File doesn't exist, that's OK
      }
      
      this.initialized = true
    } catch (error) {
      console.error('Failed to initialize storage:', error)
      throw error
    }
  }

  private async persist(): Promise<void> {
    const jobs = Array.from(this.cache.values())
    await fs.writeFile(this.jobsFile, JSON.stringify(jobs, null, 2))
  }

  async save(job: JobState): Promise<void> {
    await this.init()
    this.cache.set(job.id, { ...job })
    await this.persist()
  }

  async get(id: string): Promise<JobState | undefined> {
    await this.init()
    return this.cache.get(id)
  }

  async delete(id: string): Promise<boolean> {
    await this.init()
    const result = this.cache.delete(id)
    if (result) {
      await this.persist()
    }
    return result
  }

  async list(filter: JobFilter): Promise<JobState[]> {
    await this.init()
    let results = Array.from(this.cache.values())
    
    if (filter.status?.length) {
      results = results.filter(j => filter.status!.includes(j.status))
    }
    if (filter.type?.length) {
      results = results.filter(j => filter.type!.includes(j.type))
    }
    if (filter.priority?.length) {
      results = results.filter(j => filter.priority!.includes(j.priority))
    }
    if (filter.createdBy) {
      results = results.filter(j => j.createdBy === filter.createdBy)
    }
    if (filter.startDate) {
      results = results.filter(j => j.createdAt >= filter.startDate!)
    }
    if (filter.endDate) {
      results = results.filter(j => j.createdAt <= filter.endDate!)
    }
    
    results.sort((a, b) => b.createdAt - a.createdAt)
    
    if (filter.offset) {
      results = results.slice(filter.offset)
    }
    if (filter.limit) {
      results = results.slice(0, filter.limit)
    }
    
    return results
  }

  async archive(job: JobState): Promise<void> {
    await this.init()
    
    // Append to history file
    try {
      let history: JobState[] = []
      try {
        const data = await fs.readFile(this.historyFile, 'utf-8')
        history = JSON.parse(data)
      } catch {}
      
      history.push({ ...job })
      await fs.writeFile(this.historyFile, JSON.stringify(history, null, 2))
    } catch (error) {
      console.error('Failed to archive job:', error)
    }
    
    // Remove from active jobs
    this.cache.delete(job.id)
    await this.persist()
  }

  async getStats(): Promise<JobStats> {
    await this.init()
    const jobs = Array.from(this.cache.values())
    const completed = jobs.filter(j => j.status === 'completed')
    
    return {
      total: jobs.length,
      pending: jobs.filter(j => j.status === 'pending').length,
      running: jobs.filter(j => j.status === 'running').length,
      completed: completed.length,
      failed: jobs.filter(j => j.status === 'failed').length,
      cancelled: jobs.filter(j => j.status === 'cancelled').length,
      avgDuration: completed.length > 0
        ? completed.reduce((s, j) => s + (j.duration || 0), 0) / completed.length
        : 0,
      totalFindings: completed.reduce(
        (s, j) => s + j.results.reduce(
          (s2, r) => s2 + r.misconfigurations.length, 0
        ), 0
      ),
      criticalFindings: completed.reduce(
        (s, j) => s + j.results.reduce(
          (s2, r) => s2 + r.misconfigurations.filter(m => m.severity === 'critical').length, 0
        ), 0
      ),
    }
  }

  async clear(): Promise<void> {
    await this.init()
    this.cache.clear()
    await this.persist()
  }
}

// ============================================================================
// JOB STATE MANAGER
// ============================================================================

export class JobStateManager {
  private storage: MemoryStorage | FileStorage
  private dataDir?: string

  constructor(options: { dataDir?: string; inMemory?: boolean } = {}) {
    if (options.inMemory || !options.dataDir) {
      this.storage = new MemoryStorage()
    } else {
      this.dataDir = options.dataDir
      this.storage = new FileStorage(options.dataDir)
    }
  }

  /**
   * Create a new job
   */
  async createJob(
    type: JobState['type'],
    targets: JobTarget[],
    options: {
      priority?: JobState['priority']
      createdBy?: string
      metadata?: Record<string, any>
    } = {}
  ): Promise<JobState> {
    const job: JobState = {
      id: `job-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      type,
      status: 'pending',
      priority: options.priority || 'medium',
      targets,
      results: [],
      progress: 0,
      metadata: options.metadata || {},
      createdBy: options.createdBy || 'system',
      createdAt: Date.now(),
      updatedAt: Date.now(),
    }
    
    await this.storage.save(job)
    return job
  }

  /**
   * Get a job by ID
   */
  async getJob(id: string): Promise<JobState | undefined> {
    return this.storage.get(id)
  }

  /**
   * Update job status
   */
  async updateStatus(id: string, status: JobState['status']): Promise<void> {
    const job = await this.storage.get(id)
    if (!job) throw new Error(`Job ${id} not found`)
    
    job.status = status
    job.updatedAt = Date.now()
    
    if (status === 'running' && !job.startTime) {
      job.startTime = Date.now()
    }
    
    if (['completed', 'failed', 'cancelled'].includes(status)) {
      job.endTime = Date.now()
      if (job.startTime) {
        job.duration = job.endTime - job.startTime
      }
    }
    
    await this.storage.save(job)
  }

  /**
   * Update job progress
   */
  async updateProgress(id: string, progress: number): Promise<void> {
    const job = await this.storage.get(id)
    if (!job) throw new Error(`Job ${id} not found`)
    
    job.progress = Math.min(100, Math.max(0, progress))
    job.updatedAt = Date.now()
    await this.storage.save(job)
  }

  /**
   * Add a result to a job
   */
  async addResult(id: string, result: JobResult): Promise<void> {
    const job = await this.storage.get(id)
    if (!job) throw new Error(`Job ${id} not found`)
    
    // Update target status
    const target = job.targets.find(t => t.id === result.targetId)
    if (target) {
      target.status = result.success ? 'completed' : 'failed'
      target.result = result
    }
    
    job.results.push(result)
    job.updatedAt = Date.now()
    
    // Update progress
    job.progress = (job.results.length / job.targets.length) * 100
    
    await this.storage.save(job)
  }

  /**
   * Mark job as failed
   */
  async failJob(id: string, error: string): Promise<void> {
    const job = await this.storage.get(id)
    if (!job) throw new Error(`Job ${id} not found`)
    
    job.status = 'failed'
    job.error = error
    job.endTime = Date.now()
    if (job.startTime) {
      job.duration = job.endTime - job.startTime
    }
    job.updatedAt = Date.now()
    
    await this.storage.save(job)
  }

  /**
   * Cancel a job
   */
  async cancelJob(id: string): Promise<void> {
    const job = await this.storage.get(id)
    if (!job) throw new Error(`Job ${id} not found`)
    
    if (job.status === 'running') {
      job.status = 'cancelled'
      job.endTime = Date.now()
      if (job.startTime) {
        job.duration = job.endTime - job.startTime
      }
      job.updatedAt = Date.now()
      await this.storage.save(job)
    }
  }

  /**
   * Archive a completed job
   */
  async archiveJob(id: string): Promise<void> {
    const job = await this.storage.get(id)
    if (!job) throw new Error(`Job ${id} not found`)
    
    if (!['completed', 'failed', 'cancelled'].includes(job.status)) {
      throw new Error(`Cannot archive job with status ${job.status}`)
    }
    
    await this.storage.archive(job)
  }

  /**
   * List jobs with filtering
   */
  async listJobs(filter: JobFilter = {}): Promise<JobState[]> {
    return this.storage.list(filter)
  }

  /**
   * Get job statistics
   */
  async getStats(): Promise<JobStats> {
    return this.storage.getStats()
  }

  /**
   * Delete a job
   */
  async deleteJob(id: string): Promise<boolean> {
    return this.storage.delete(id)
  }

  /**
   * Clear all jobs
   */
  async clear(): Promise<void> {
    return this.storage.clear()
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export { MemoryStorage, FileStorage }
