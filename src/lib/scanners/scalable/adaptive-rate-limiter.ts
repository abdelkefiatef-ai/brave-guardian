// ============================================================================
// ADAPTIVE RATE LIMITER
// AIMD (Additive Increase / Multiplicative Decrease) algorithm
// Dynamically adjusts rate based on errors and timeouts
// ============================================================================

// ============================================================================
// TYPES
// ============================================================================

export interface RateLimiterConfig {
  minRate: number           // Minimum requests per second
  maxRate: number           // Maximum requests per second
  initialRate: number       // Starting rate
  increaseFactor: number    // Additive increase amount
  decreaseFactor: number    // Multiplicative decrease factor (0-1)
  windowSize: number        // Time window in ms for measuring
  errorThreshold: number    // Error rate that triggers decrease
  timeoutThreshold: number  // Timeout rate that triggers decrease
  recoveryTime: number      // Time in ms before attempting recovery
}

export interface RateLimiterStats {
  currentRate: number
  successfulRequests: number
  failedRequests: number
  timedOutRequests: number
  totalRequests: number
  errorRate: number
  timeoutRate: number
  windowStart: number
  lastAdjustment: number
  adjustmentHistory: AdjustmentRecord[]
}

export interface AdjustmentRecord {
  timestamp: number
  previousRate: number
  newRate: number
  reason: string
  trigger: 'error' | 'timeout' | 'recovery' | 'manual'
}

// ============================================================================
// SLIDING WINDOW COUNTER
// ============================================================================

class SlidingWindowCounter {
  private windows: Map<number, { success: number; error: number; timeout: number }> = new Map()
  private windowSize: number
  private maxWindows: number

  constructor(windowSize: number, maxWindows: number = 10) {
    this.windowSize = windowSize
    this.maxWindows = maxWindows
  }

  record(type: 'success' | 'error' | 'timeout'): void {
    const windowKey = Math.floor(Date.now() / this.windowSize)
    
    if (!this.windows.has(windowKey)) {
      this.windows.set(windowKey, { success: 0, error: 0, timeout: 0 })
    }
    
    const window = this.windows.get(windowKey)!
    window[type]++
    
    // Cleanup old windows
    this.cleanup()
  }

  getStats(windowCount: number = 5): { success: number; error: number; timeout: number; total: number } {
    const now = Date.now()
    const currentWindow = Math.floor(now / this.windowSize)
    
    let success = 0, error = 0, timeout = 0
    
    for (let i = 0; i < windowCount; i++) {
      const window = this.windows.get(currentWindow - i)
      if (window) {
        success += window.success
        error += window.error
        timeout += window.timeout
      }
    }
    
    return { success, error, timeout, total: success + error + timeout }
  }

  private cleanup(): void {
    const now = Date.now()
    const oldestWindow = Math.floor(now / this.windowSize) - this.maxWindows
    
    for (const key of this.windows.keys()) {
      if (key < oldestWindow) {
        this.windows.delete(key)
      }
    }
  }

  reset(): void {
    this.windows.clear()
  }
}

// ============================================================================
// TOKEN BUCKET
// ============================================================================

class TokenBucket {
  private tokens: number
  private lastRefill: number
  private rate: number
  private maxTokens: number

  constructor(rate: number, maxTokens?: number) {
    this.rate = rate
    this.maxTokens = maxTokens || rate
    this.tokens = this.maxTokens
    this.lastRefill = Date.now()
  }

  setRate(newRate: number): void {
    this.rate = newRate
    this.maxTokens = Math.max(this.maxTokens, newRate)
  }

  getRate(): number {
    return this.rate
  }

  waitForToken(): Promise<void> {
    this.refill()
    
    if (this.tokens >= 1) {
      this.tokens--
      return Promise.resolve()
    }
    
    // Calculate wait time
    const waitMs = (1 - this.tokens) * (1000 / this.rate)
    
    return new Promise(resolve => {
      setTimeout(() => {
        this.refill()
        this.tokens--
        resolve()
      }, waitMs)
    })
  }

  tryAcquire(): boolean {
    this.refill()
    
    if (this.tokens >= 1) {
      this.tokens--
      return true
    }
    
    return false
  }

  private refill(): void {
    const now = Date.now()
    const elapsed = (now - this.lastRefill) / 1000
    const refillAmount = elapsed * this.rate
    
    this.tokens = Math.min(this.maxTokens, this.tokens + refillAmount)
    this.lastRefill = now
  }
}

// ============================================================================
// ADAPTIVE RATE LIMITER
// ============================================================================

export class AdaptiveRateLimiter {
  private config: RateLimiterConfig
  private currentRate: number
  private tokenBucket: TokenBucket
  private counter: SlidingWindowCounter
  private lastAdjustment: number
  private lastErrorTime: number
  private adjustmentHistory: AdjustmentRecord[] = []
  private paused: boolean = false
  private pausedUntil: number = 0

  constructor(config: Partial<RateLimiterConfig> = {}) {
    this.config = {
      minRate: config.minRate || 1,
      maxRate: config.maxRate || 100,
      initialRate: config.initialRate || 20,
      increaseFactor: config.increaseFactor || 2,
      decreaseFactor: config.decreaseFactor || 0.5,
      windowSize: config.windowSize || 1000,
      errorThreshold: config.errorThreshold || 0.1,  // 10% errors
      timeoutThreshold: config.timeoutThreshold || 0.05,  // 5% timeouts
      recoveryTime: config.recoveryTime || 5000,
    }
    
    this.currentRate = this.config.initialRate
    this.tokenBucket = new TokenBucket(this.currentRate, this.currentRate * 2)
    this.counter = new SlidingWindowCounter(this.config.windowSize)
    this.lastAdjustment = Date.now()
    this.lastErrorTime = 0
  }

  /**
   * Wait for permission to make a request
   */
  async acquire(): Promise<void> {
    // Check if paused
    if (this.paused) {
      while (Date.now() < this.pausedUntil) {
        await this.sleep(100)
      }
      this.paused = false
    }
    
    // Wait for token
    await this.tokenBucket.waitForToken()
  }

  /**
   * Try to acquire without waiting
   */
  tryAcquire(): boolean {
    if (this.paused && Date.now() < this.pausedUntil) {
      return false
    }
    
    this.paused = false
    return this.tokenBucket.tryAcquire()
  }

  /**
   * Report a successful request
   */
  reportSuccess(): void {
    this.counter.record('success')
    this.checkAdjustment()
  }

  /**
   * Report a failed request
   */
  reportError(): void {
    this.counter.record('error')
    this.lastErrorTime = Date.now()
    this.checkAdjustment()
  }

  /**
   * Report a timed out request
   */
  reportTimeout(): void {
    this.counter.record('timeout')
    this.lastErrorTime = Date.now()
    this.checkAdjustment()
  }

  /**
   * Get current rate
   */
  getCurrentRate(): number {
    return this.currentRate
  }

  /**
   * Manually set rate
   */
  setRate(rate: number, reason: string = 'manual'): void {
    const previousRate = this.currentRate
    this.currentRate = Math.max(this.config.minRate, Math.min(this.config.maxRate, rate))
    this.tokenBucket.setRate(this.currentRate)
    
    this.recordAdjustment(previousRate, this.currentRate, reason, 'manual')
    this.lastAdjustment = Date.now()
  }

  /**
   * Pause the rate limiter
   */
  pause(durationMs: number): void {
    this.paused = true
    this.pausedUntil = Date.now() + durationMs
  }

  /**
   * Reset the rate limiter
   */
  reset(): void {
    this.currentRate = this.config.initialRate
    this.tokenBucket = new TokenBucket(this.currentRate, this.currentRate * 2)
    this.counter.reset()
    this.lastAdjustment = Date.now()
    this.lastErrorTime = 0
    this.paused = false
  }

  /**
   * Get statistics
   */
  getStats(): RateLimiterStats {
    const windowStats = this.counter.getStats()
    
    return {
      currentRate: this.currentRate,
      successfulRequests: windowStats.success,
      failedRequests: windowStats.error,
      timedOutRequests: windowStats.timeout,
      totalRequests: windowStats.total,
      errorRate: windowStats.total > 0 ? windowStats.error / windowStats.total : 0,
      timeoutRate: windowStats.total > 0 ? windowStats.timeout / windowStats.total : 0,
      windowStart: Date.now() - this.config.windowSize * 5,
      lastAdjustment: this.lastAdjustment,
      adjustmentHistory: this.adjustmentHistory.slice(-20),
    }
  }

  /**
   * Check if rate adjustment is needed
   */
  private checkAdjustment(): void {
    const now = Date.now()
    const windowStats = this.counter.getStats()
    
    if (windowStats.total < 10) return  // Need more data
    
    const errorRate = windowStats.error / windowStats.total
    const timeoutRate = windowStats.timeout / windowStats.total
    
    // Check if we need to decrease rate
    if (errorRate > this.config.errorThreshold || timeoutRate > this.config.timeoutThreshold) {
      this.decreaseRate(errorRate > this.config.errorThreshold ? 'error' : 'timeout')
      return
    }
    
    // Check if we can increase rate (recovery)
    if (now - this.lastErrorTime > this.config.recoveryTime &&
        now - this.lastAdjustment > this.config.recoveryTime) {
      this.increaseRate()
    }
  }

  /**
   * Decrease rate (multiplicative decrease)
   */
  private decreaseRate(trigger: 'error' | 'timeout'): void {
    const previousRate = this.currentRate
    this.currentRate = Math.max(
      this.config.minRate,
      Math.floor(this.currentRate * this.config.decreaseFactor)
    )
    
    if (this.currentRate !== previousRate) {
      this.tokenBucket.setRate(this.currentRate)
      this.recordAdjustment(
        previousRate,
        this.currentRate,
        `Rate decreased due to high ${trigger} rate`,
        trigger
      )
    }
    
    this.lastAdjustment = Date.now()
  }

  /**
   * Increase rate (additive increase)
   */
  private increaseRate(): void {
    const previousRate = this.currentRate
    this.currentRate = Math.min(
      this.config.maxRate,
      this.currentRate + this.config.increaseFactor
    )
    
    if (this.currentRate !== previousRate) {
      this.tokenBucket.setRate(this.currentRate)
      this.recordAdjustment(
        previousRate,
        this.currentRate,
        'Rate increased during recovery',
        'recovery'
      )
    }
    
    this.lastAdjustment = Date.now()
  }

  /**
   * Record an adjustment
   */
  private recordAdjustment(
    previousRate: number,
    newRate: number,
    reason: string,
    trigger: AdjustmentRecord['trigger']
  ): void {
    this.adjustmentHistory.push({
      timestamp: Date.now(),
      previousRate,
      newRate,
      reason,
      trigger,
    })
    
    // Keep only recent history
    if (this.adjustmentHistory.length > 100) {
      this.adjustmentHistory.shift()
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export { SlidingWindowCounter, TokenBucket }
