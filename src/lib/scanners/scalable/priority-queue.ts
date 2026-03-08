// ============================================================================
// PRIORITY QUEUE
// Priority-based task scheduling with business impact scoring
// ============================================================================

// ============================================================================
// TYPES
// ============================================================================

export interface PriorityTask {
  id: string
  type: 'scan' | 'discovery' | 'analysis'
  priority: number           // Calculated priority score
  basePriority: 'critical' | 'high' | 'medium' | 'low'
  target: TaskTarget
  metadata: Record<string, any>
  createdAt: number
  scheduledAt?: number
  startedAt?: number
  completedAt?: number
  retries: number
  maxRetries: number
}

export interface TaskTarget {
  id: string
  host: string
  port: number
  zone?: 'dmz' | 'internal' | 'restricted' | 'cloud'
  criticality?: number       // 1-5
  internetFacing?: boolean
  businessUnit?: string
  annualRevenueExposure?: number
  dataSensitivity?: 'public' | 'internal' | 'confidential' | 'restricted'
  complianceRequirements?: string[]
}

export interface PriorityFactors {
  zoneWeight: Record<string, number>
  criticalityWeight: number
  internetFacingWeight: number
  revenueExposureWeight: number
  dataSensitivityWeight: Record<string, number>
  complianceWeight: number
  ageWeight: number
}

export interface QueueStats {
  size: number
  critical: number
  high: number
  medium: number
  low: number
  avgWaitTime: number
  processed: number
  throughput: number  // tasks per second
}

// ============================================================================
// PRIORITY CALCULATOR
// ============================================================================

class PriorityCalculator {
  private factors: PriorityFactors

  constructor(factors?: Partial<PriorityFactors>) {
    this.factors = {
      zoneWeight: factors?.zoneWeight || {
        dmz: 100,
        internal: 50,
        restricted: 75,
        cloud: 60,
      },
      criticalityWeight: factors?.criticalityWeight || 20,
      internetFacingWeight: factors?.internetFacingWeight || 40,
      revenueExposureWeight: factors?.revenueExposureWeight || 0.00001,
      dataSensitivityWeight: factors?.dataSensitivityWeight || {
        public: 0,
        internal: 10,
        confidential: 30,
        restricted: 50,
      },
      complianceWeight: factors?.complianceWeight || 15,
      ageWeight: factors?.ageWeight || 0.1,  // Points per second of age
    }
  }

  /**
   * Calculate priority score for a target
   */
  calculate(target: TaskTarget, basePriority: PriorityTask['basePriority'], createdAt: number): number {
    let score = 0

    // Base priority (critical=1000, high=750, medium=500, low=250)
    const baseScores = { critical: 1000, high: 750, medium: 500, low: 250 }
    score += baseScores[basePriority]

    // Zone weight
    if (target.zone) {
      score += this.factors.zoneWeight[target.zone] || 0
    }

    // Criticality (1-5 scale)
    if (target.criticality) {
      score += target.criticality * this.factors.criticalityWeight
    }

    // Internet-facing
    if (target.internetFacing) {
      score += this.factors.internetFacingWeight
    }

    // Revenue exposure (logarithmic scale)
    if (target.annualRevenueExposure) {
      score += Math.log10(target.annualRevenueExposure) * this.factors.revenueExposureWeight
    }

    // Data sensitivity
    if (target.dataSensitivity) {
      score += this.factors.dataSensitivityWeight[target.dataSensitivity] || 0
    }

    // Compliance requirements
    if (target.complianceRequirements?.length) {
      score += target.complianceRequirements.length * this.factors.complianceWeight
    }

    // Age factor (older tasks get higher priority)
    const ageSeconds = (Date.now() - createdAt) / 1000
    score += ageSeconds * this.factors.ageWeight

    return Math.round(score)
  }

  /**
   * Update priority factors
   */
  updateFactors(factors: Partial<PriorityFactors>): void {
    this.factors = { ...this.factors, ...factors }
  }
}

// ============================================================================
// PRIORITY QUEUE IMPLEMENTATION
// ============================================================================

export class PriorityQueue {
  private heap: PriorityTask[] = []
  private taskMap: Map<string, number> = new Map()  // task ID -> heap index
  private calculator: PriorityCalculator
  private processed: number = 0
  private waitTimes: number[] = []

  constructor(factors?: Partial<PriorityFactors>) {
    this.calculator = new PriorityCalculator(factors)
  }

  /**
   * Add a task to the queue
   */
  enqueue(
    type: PriorityTask['type'],
    target: TaskTarget,
    basePriority: PriorityTask['basePriority'] = 'medium',
    metadata: Record<string, any> = {}
  ): PriorityTask {
    const now = Date.now()
    
    const task: PriorityTask = {
      id: `task-${now}-${Math.random().toString(36).slice(2, 8)}`,
      type,
      priority: 0,  // Will be calculated
      basePriority,
      target,
      metadata,
      createdAt: now,
      retries: 0,
      maxRetries: 3,
    }
    
    // Calculate priority
    task.priority = this.calculator.calculate(target, basePriority, task.createdAt)
    
    // Add to heap
    this.heap.push(task)
    const index = this.heap.length - 1
    this.taskMap.set(task.id, index)
    
    // Bubble up
    this.bubbleUp(index)
    
    return task
  }

  /**
   * Remove and return the highest priority task
   */
  dequeue(): PriorityTask | undefined {
    if (this.heap.length === 0) return undefined
    
    const top = this.heap[0]
    this.taskMap.delete(top.id)
    
    // Track wait time
    if (top.scheduledAt) {
      this.waitTimes.push(Date.now() - top.scheduledAt)
      if (this.waitTimes.length > 1000) {
        this.waitTimes.shift()
      }
    }
    
    // Move last to top and bubble down
    const last = this.heap.pop()
    if (this.heap.length > 0 && last) {
      this.heap[0] = last
      this.taskMap.set(last.id, 0)
      this.bubbleDown(0)
    }
    
    this.processed++
    return top
  }

  /**
   * Peek at the highest priority task without removing
   */
  peek(): PriorityTask | undefined {
    return this.heap[0]
  }

  /**
   * Get a task by ID
   */
  get(id: string): PriorityTask | undefined {
    const index = this.taskMap.get(id)
    if (index === undefined) return undefined
    return this.heap[index]
  }

  /**
   * Update task priority
   */
  updatePriority(id: string, newPriority: PriorityTask['basePriority']): boolean {
    const index = this.taskMap.get(id)
    if (index === undefined) return false
    
    const task = this.heap[index]
    const oldPriority = task.priority
    task.basePriority = newPriority
    task.priority = this.calculator.calculate(task.target, newPriority, task.createdAt)
    
    // Rebalance heap
    if (task.priority > oldPriority) {
      this.bubbleUp(index)
    } else {
      this.bubbleDown(index)
    }
    
    return true
  }

  /**
   * Remove a task by ID
   */
  remove(id: string): boolean {
    const index = this.taskMap.get(id)
    if (index === undefined) return false
    
    // Set priority to max to bubble to top
    this.heap[index].priority = Infinity
    this.bubbleUp(index)
    
    // Remove from top
    this.dequeue()
    return true
  }

  /**
   * Get queue size
   */
  size(): number {
    return this.heap.length
  }

  /**
   * Check if queue is empty
   */
  isEmpty(): boolean {
    return this.heap.length === 0
  }

  /**
   * Get all tasks sorted by priority
   */
  getAll(): PriorityTask[] {
    return [...this.heap].sort((a, b) => b.priority - a.priority)
  }

  /**
   * Get tasks by base priority
   */
  getByPriority(priority: PriorityTask['basePriority']): PriorityTask[] {
    return this.heap.filter(t => t.basePriority === priority)
  }

  /**
   * Get queue statistics
   */
  getStats(): QueueStats {
    const now = Date.now()
    
    return {
      size: this.heap.length,
      critical: this.heap.filter(t => t.basePriority === 'critical').length,
      high: this.heap.filter(t => t.basePriority === 'high').length,
      medium: this.heap.filter(t => t.basePriority === 'medium').length,
      low: this.heap.filter(t => t.basePriority === 'low').length,
      avgWaitTime: this.waitTimes.length > 0
        ? this.waitTimes.reduce((a, b) => a + b, 0) / this.waitTimes.length
        : 0,
      processed: this.processed,
      throughput: this.processed > 0 && this.waitTimes.length > 0
        ? 1000 / (this.waitTimes.reduce((a, b) => a + b, 0) / this.waitTimes.length)
        : 0,
    }
  }

  /**
   * Clear the queue
   */
  clear(): void {
    this.heap = []
    this.taskMap.clear()
  }

  /**
   * Re-prioritize all tasks (recalculate priorities)
   */
  reprioritize(): void {
    for (const task of this.heap) {
      task.priority = this.calculator.calculate(
        task.target,
        task.basePriority,
        task.createdAt
      )
    }
    
    // Rebuild heap
    this.buildHeap()
  }

  // Private methods for heap operations

  private bubbleUp(index: number): void {
    while (index > 0) {
      const parentIndex = Math.floor((index - 1) / 2)
      
      if (this.heap[index].priority <= this.heap[parentIndex].priority) {
        break
      }
      
      // Swap
      this.swap(index, parentIndex)
      index = parentIndex
    }
  }

  private bubbleDown(index: number): void {
    const length = this.heap.length
    
    while (true) {
      const leftChild = 2 * index + 1
      const rightChild = 2 * index + 2
      let largest = index
      
      if (leftChild < length && this.heap[leftChild].priority > this.heap[largest].priority) {
        largest = leftChild
      }
      
      if (rightChild < length && this.heap[rightChild].priority > this.heap[largest].priority) {
        largest = rightChild
      }
      
      if (largest === index) break
      
      this.swap(index, largest)
      index = largest
    }
  }

  private swap(i: number, j: number): void {
    [this.heap[i], this.heap[j]] = [this.heap[j], this.heap[i]]
    this.taskMap.set(this.heap[i].id, i)
    this.taskMap.set(this.heap[j].id, j)
  }

  private buildHeap(): void {
    for (let i = Math.floor(this.heap.length / 2) - 1; i >= 0; i--) {
      this.bubbleDown(i)
    }
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export { PriorityCalculator }
