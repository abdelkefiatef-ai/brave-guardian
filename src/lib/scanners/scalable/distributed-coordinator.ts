// ============================================================================
// DISTRIBUTED COORDINATOR
// Coordinates scanning across multiple worker nodes
// Supports horizontal scaling for 10,000+ assets
// ============================================================================

import { EventEmitter } from 'events'

// ============================================================================
// TYPES
// ============================================================================

export interface WorkerNode {
  id: string
  url: string
  status: 'idle' | 'busy' | 'offline' | 'error'
  capacity: number        // Max concurrent scans
  currentLoad: number     // Current active scans
  lastHeartbeat: number
  metadata: {
    region?: string
    zone?: string
    version?: string
    tags?: string[]
  }
  stats: WorkerStats
}

export interface WorkerStats {
  totalScans: number
  successfulScans: number
  failedScans: number
  avgScanTime: number
  uptime: number
}

export interface ScanChunk {
  id: string
  jobId: string
  targets: ScanTarget[]
  workerId?: string
  status: 'pending' | 'assigned' | 'completed' | 'failed'
  startTime?: number
  endTime?: number
  results?: ScanResult[]
  error?: string
}

export interface ScanTarget {
  id: string
  host: string
  port?: number
  username: string
  auth: { type: string; password?: string; keyPath?: string }
  zone?: string
  criticality?: number
}

export interface ScanResult {
  target: ScanTarget
  success: boolean
  data: Record<string, string>
  errors: string[]
  duration: number
}

export interface CoordinatorConfig {
  heartbeatInterval: number     // ms
  heartbeatTimeout: number      // ms
  chunkSize: number             // targets per chunk
  maxChunksPerWorker: number    // max chunks assigned to one worker
  rebalanceInterval: number     // ms
  retryFailedChunks: boolean
  maxRetries: number
}

// ============================================================================
// WORKER REGISTRY
// ============================================================================

class WorkerRegistry {
  private workers: Map<string, WorkerNode> = new Map()
  private config: CoordinatorConfig

  constructor(config: CoordinatorConfig) {
    this.config = config
  }

  /**
   * Register a new worker
   */
  register(worker: Omit<WorkerNode, 'status' | 'currentLoad' | 'lastHeartbeat' | 'stats'>): WorkerNode {
    const fullWorker: WorkerNode = {
      ...worker,
      status: 'idle',
      currentLoad: 0,
      lastHeartbeat: Date.now(),
      stats: {
        totalScans: 0,
        successfulScans: 0,
        failedScans: 0,
        avgScanTime: 0,
        uptime: Date.now(),
      },
    }
    
    this.workers.set(worker.id, fullWorker)
    return fullWorker
  }

  /**
   * Unregister a worker
   */
  unregister(workerId: string): boolean {
    return this.workers.delete(workerId)
  }

  /**
   * Update worker heartbeat
   */
  heartbeat(workerId: string): boolean {
    const worker = this.workers.get(workerId)
    if (!worker) return false
    
    worker.lastHeartbeat = Date.now()
    if (worker.status === 'offline') {
      worker.status = 'idle'
    }
    return true
  }

  /**
   * Get available workers
   */
  getAvailableWorkers(): WorkerNode[] {
    return Array.from(this.workers.values()).filter(w => 
      w.status !== 'offline' &&
      w.status !== 'error' &&
      w.currentLoad < w.capacity
    )
  }

  /**
   * Get all workers
   */
  getAllWorkers(): WorkerNode[] {
    return Array.from(this.workers.values())
  }

  /**
   * Get worker by ID
   */
  getWorker(workerId: string): WorkerNode | undefined {
    return this.workers.get(workerId)
  }

  /**
   * Update worker status
   */
  updateStatus(workerId: string, status: WorkerNode['status']): void {
    const worker = this.workers.get(workerId)
    if (worker) {
      worker.status = status
    }
  }

  /**
   * Update worker load
   */
  updateLoad(workerId: string, delta: number): void {
    const worker = this.workers.get(workerId)
    if (worker) {
      worker.currentLoad = Math.max(0, worker.currentLoad + delta)
      worker.status = worker.currentLoad >= worker.capacity ? 'busy' : 'idle'
    }
  }

  /**
   * Check for stale workers (missed heartbeats)
   */
  checkStaleWorkers(): string[] {
    const now = Date.now()
    const staleWorkerIds: string[] = []
    
    for (const [id, worker] of this.workers) {
      if (now - worker.lastHeartbeat > this.config.heartbeatTimeout) {
        worker.status = 'offline'
        staleWorkerIds.push(id)
      }
    }
    
    return staleWorkerIds
  }
}

// ============================================================================
// CHUNK MANAGER
// ============================================================================

class ChunkManager {
  private chunks: Map<string, ScanChunk> = new Map()
  private chunksByJob: Map<string, Set<string>> = new Map()
  private config: CoordinatorConfig

  constructor(config: CoordinatorConfig) {
    this.config = config
  }

  /**
   * Create chunks from targets
   */
  createChunks(jobId: string, targets: ScanTarget[]): ScanChunk[] {
    const chunks: ScanChunk[] = []
    const chunksForJob = new Set<string>()
    
    for (let i = 0; i < targets.length; i += this.config.chunkSize) {
      const chunkTargets = targets.slice(i, i + this.config.chunkSize)
      const chunk: ScanChunk = {
        id: `chunk-${jobId}-${i / this.config.chunkSize}`,
        jobId,
        targets: chunkTargets,
        status: 'pending',
      }
      
      chunks.push(chunk)
      this.chunks.set(chunk.id, chunk)
      chunksForJob.add(chunk.id)
    }
    
    this.chunksByJob.set(jobId, chunksForJob)
    return chunks
  }

  /**
   * Get pending chunks
   */
  getPendingChunks(): ScanChunk[] {
    return Array.from(this.chunks.values()).filter(c => c.status === 'pending')
  }

  /**
   * Get chunks for a job
   */
  getChunksForJob(jobId: string): ScanChunk[] {
    const chunkIds = this.chunksByJob.get(jobId)
    if (!chunkIds) return []
    
    return Array.from(chunkIds)
      .map(id => this.chunks.get(id)!)
      .filter(Boolean)
  }

  /**
   * Assign chunk to worker
   */
  assignChunk(chunkId: string, workerId: string): boolean {
    const chunk = this.chunks.get(chunkId)
    if (!chunk || chunk.status !== 'pending') return false
    
    chunk.workerId = workerId
    chunk.status = 'assigned'
    chunk.startTime = Date.now()
    return true
  }

  /**
   * Mark chunk as completed
   */
  completeChunk(chunkId: string, results: ScanResult[]): boolean {
    const chunk = this.chunks.get(chunkId)
    if (!chunk) return false
    
    chunk.status = 'completed'
    chunk.endTime = Date.now()
    chunk.results = results
    return true
  }

  /**
   * Mark chunk as failed
   */
  failChunk(chunkId: string, error: string): boolean {
    const chunk = this.chunks.get(chunkId)
    if (!chunk) return false
    
    chunk.status = 'failed'
    chunk.endTime = Date.now()
    chunk.error = error
    return true
  }

  /**
   * Reset failed chunks for retry
   */
  resetFailedChunks(): ScanChunk[] {
    const reset: ScanChunk[] = []
    
    for (const chunk of this.chunks.values()) {
      if (chunk.status === 'failed') {
        chunk.status = 'pending'
        chunk.workerId = undefined
        chunk.error = undefined
        reset.push(chunk)
      }
    }
    
    return reset
  }

  /**
   * Clear chunks for a job
   */
  clearJob(jobId: string): void {
    const chunkIds = this.chunksByJob.get(jobId)
    if (chunkIds) {
      for (const id of chunkIds) {
        this.chunks.delete(id)
      }
      this.chunksByJob.delete(jobId)
    }
  }

  /**
   * Get chunk statistics
   */
  getStats(): { total: number; pending: number; assigned: number; completed: number; failed: number } {
    let total = 0, pending = 0, assigned = 0, completed = 0, failed = 0
    
    for (const chunk of this.chunks.values()) {
      total++
      switch (chunk.status) {
        case 'pending': pending++; break
        case 'assigned': assigned++; break
        case 'completed': completed++; break
        case 'failed': failed++; break
      }
    }
    
    return { total, pending, assigned, completed, failed }
  }
}

// ============================================================================
// LOAD BALANCER
// ============================================================================

class LoadBalancer {
  private registry: WorkerRegistry
  private chunkManager: ChunkManager
  private config: CoordinatorConfig

  constructor(registry: WorkerRegistry, chunkManager: ChunkManager, config: CoordinatorConfig) {
    this.registry = registry
    this.chunkManager = chunkManager
    this.config = config
  }

  /**
   * Assign pending chunks to available workers
   */
  balance(): Map<string, string[]> {
    const assignments = new Map<string, string[]>()
    const pendingChunks = this.chunkManager.getPendingChunks()
    const availableWorkers = this.registry.getAvailableWorkers()
    
    if (pendingChunks.length === 0 || availableWorkers.length === 0) {
      return assignments
    }
    
    // Sort workers by load (ascending)
    availableWorkers.sort((a, b) => 
      (a.currentLoad / a.capacity) - (b.currentLoad / b.capacity)
    )
    
    // Sort chunks by priority (could be based on target criticality)
    
    for (const chunk of pendingChunks) {
      // Find worker with lowest load
      let assigned = false
      for (const worker of availableWorkers) {
        const workerAssignments = assignments.get(worker.id) || []
        
        // Check if worker has capacity for more chunks
        if (worker.currentLoad + workerAssignments.length < worker.capacity * this.config.maxChunksPerWorker) {
          this.chunkManager.assignChunk(chunk.id, worker.id)
          this.registry.updateLoad(worker.id, 1)
          
          workerAssignments.push(chunk.id)
          assignments.set(worker.id, workerAssignments)
          assigned = true
          break
        }
      }
      
      if (!assigned) {
        // All workers at capacity
        break
      }
    }
    
    return assignments
  }

  /**
   * Rebalance chunks from failed workers
   */
  rebalance(failedWorkerIds: string[]): void {
    for (const workerId of failedWorkerIds) {
      const worker = this.registry.getWorker(workerId)
      if (!worker) continue
      
      // Find chunks assigned to this worker
      for (const chunk of this.chunkManager.getChunksForJob('')) {
        if (chunk.workerId === workerId && chunk.status === 'assigned') {
          // Reset chunk to pending for reassignment
          chunk.status = 'pending'
          chunk.workerId = undefined
        }
      }
      
      // Reset worker load
      worker.currentLoad = 0
    }
  }
}

// ============================================================================
// DISTRIBUTED COORDINATOR
// ============================================================================

export class DistributedCoordinator extends EventEmitter {
  private config: CoordinatorConfig
  private registry: WorkerRegistry
  private chunkManager: ChunkManager
  private loadBalancer: LoadBalancer
  private heartbeatTimer?: NodeJS.Timeout
  private balanceTimer?: NodeJS.Timeout

  constructor(config: Partial<CoordinatorConfig> = {}) {
    super()
    
    this.config = {
      heartbeatInterval: config.heartbeatInterval || 5000,
      heartbeatTimeout: config.heartbeatTimeout || 30000,
      chunkSize: config.chunkSize || 50,
      maxChunksPerWorker: config.maxChunksPerWorker || 2,
      rebalanceInterval: config.rebalanceInterval || 10000,
      retryFailedChunks: config.retryFailedChunks ?? true,
      maxRetries: config.maxRetries || 3,
    }
    
    this.registry = new WorkerRegistry(this.config)
    this.chunkManager = new ChunkManager(this.config)
    this.loadBalancer = new LoadBalancer(this.registry, this.chunkManager, this.config)
  }

  /**
   * Start the coordinator
   */
  start(): void {
    // Start heartbeat checker
    this.heartbeatTimer = setInterval(() => {
      const staleWorkers = this.registry.checkStaleWorkers()
      if (staleWorkers.length > 0) {
        this.loadBalancer.rebalance(staleWorkers)
        this.emit('workersOffline', staleWorkers)
      }
    }, this.config.heartbeatInterval)
    
    // Start load balancer
    this.balanceTimer = setInterval(() => {
      const assignments = this.loadBalancer.balance()
      if (assignments.size > 0) {
        this.emit('assignments', assignments)
      }
    }, this.config.rebalanceInterval)
  }

  /**
   * Stop the coordinator
   */
  stop(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer)
      this.heartbeatTimer = undefined
    }
    if (this.balanceTimer) {
      clearInterval(this.balanceTimer)
      this.balanceTimer = undefined
    }
  }

  /**
   * Register a worker
   */
  registerWorker(worker: Omit<WorkerNode, 'status' | 'currentLoad' | 'lastHeartbeat' | 'stats'>): WorkerNode {
    const registered = this.registry.register(worker)
    this.emit('workerRegistered', registered)
    return registered
  }

  /**
   * Unregister a worker
   */
  unregisterWorker(workerId: string): boolean {
    const result = this.registry.unregister(workerId)
    if (result) {
      this.emit('workerUnregistered', workerId)
    }
    return result
  }

  /**
   * Update worker heartbeat
   */
  workerHeartbeat(workerId: string): boolean {
    return this.registry.heartbeat(workerId)
  }

  /**
   * Create a scan job
   */
  createJob(jobId: string, targets: ScanTarget[]): ScanChunk[] {
    const chunks = this.chunkManager.createChunks(jobId, targets)
    this.emit('jobCreated', jobId, chunks.length)
    
    // Trigger immediate balancing
    const assignments = this.loadBalancer.balance()
    if (assignments.size > 0) {
      this.emit('assignments', assignments)
    }
    
    return chunks
  }

  /**
   * Report chunk completion from worker
   */
  reportChunkComplete(workerId: string, chunkId: string, results: ScanResult[]): boolean {
    const chunk = this.chunkManager.getChunksForJob('').find(c => c.id === chunkId)
    if (!chunk || chunk.workerId !== workerId) return false
    
    this.chunkManager.completeChunk(chunkId, results)
    this.registry.updateLoad(workerId, -1)
    
    // Update worker stats
    const worker = this.registry.getWorker(workerId)
    if (worker) {
      worker.stats.totalScans += results.length
      worker.stats.successfulScans += results.filter(r => r.success).length
    }
    
    this.emit('chunkComplete', chunkId, results)
    
    // Check if job is complete
    const jobChunks = this.chunkManager.getChunksForJob(chunk.jobId)
    if (jobChunks.every(c => c.status === 'completed')) {
      this.emit('jobComplete', chunk.jobId)
    }
    
    return true
  }

  /**
   * Report chunk failure from worker
   */
  reportChunkFailed(workerId: string, chunkId: string, error: string): boolean {
    const chunk = this.chunkManager.getChunksForJob('').find(c => c.id === chunkId)
    if (!chunk || chunk.workerId !== workerId) return false
    
    this.chunkManager.failChunk(chunkId, error)
    this.registry.updateLoad(workerId, -1)
    
    // Update worker stats
    const worker = this.registry.getWorker(workerId)
    if (worker) {
      worker.stats.failedScans += chunk.targets.length
    }
    
    this.emit('chunkFailed', chunkId, error)
    
    // Retry if configured
    if (this.config.retryFailedChunks) {
      this.chunkManager.resetFailedChunks()
      this.loadBalancer.balance()
    }
    
    return true
  }

  /**
   * Get coordinator statistics
   */
  getStats(): {
    workers: { total: number; available: number; busy: number; offline: number }
    chunks: { total: number; pending: number; assigned: number; completed: number; failed: number }
  } {
    const workers = this.registry.getAllWorkers()
    
    return {
      workers: {
        total: workers.length,
        available: workers.filter(w => w.status === 'idle').length,
        busy: workers.filter(w => w.status === 'busy').length,
        offline: workers.filter(w => w.status === 'offline' || w.status === 'error').length,
      },
      chunks: this.chunkManager.getStats(),
    }
  }

  /**
   * Get all workers
   */
  getWorkers(): WorkerNode[] {
    return this.registry.getAllWorkers()
  }

  /**
   * Get chunks for a job
   */
  getJobChunks(jobId: string): ScanChunk[] {
    return this.chunkManager.getChunksForJob(jobId)
  }

  /**
   * Clear a job
   */
  clearJob(jobId: string): void {
    this.chunkManager.clearJob(jobId)
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export { WorkerRegistry, ChunkManager, LoadBalancer }
