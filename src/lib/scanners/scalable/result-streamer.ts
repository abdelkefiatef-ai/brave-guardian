// ============================================================================
// RESULT STREAMER
// Streams scan results in real-time with aggregation and analysis
// Supports WebSocket and SSE for live updates
// ============================================================================

import { EventEmitter } from 'events'
import { Readable } from 'stream'

// ============================================================================
// TYPES
// ============================================================================

export interface StreamedResult {
  type: 'target_start' | 'target_complete' | 'target_error' | 'job_complete'
  timestamp: number
  jobId: string
  target?: StreamTarget
  result?: StreamResult
  error?: string
  stats?: StreamStats
}

export interface StreamTarget {
  id: string
  host: string
  port: number
  zone: string
  criticality: number
}

export interface StreamResult {
  success: boolean
  misconfigurations: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  duration: number
  cached: boolean
}

export interface StreamStats {
  totalTargets: number
  completedTargets: number
  failedTargets: number
  avgDuration: number
  totalMisconfigurations: number
  criticalFindings: number
  highFindings: number
  estimatedTimeRemaining: number
}

export interface AggregatedResult {
  jobId: string
  startTime: number
  endTime?: number
  status: 'running' | 'completed' | 'failed'
  stats: StreamStats
  resultsByZone: Record<string, ZoneStats>
  resultsByCategory: Record<string, CategoryStats>
  topMisconfigurations: TopMisconfiguration[]
  criticalPaths: CriticalPath[]
}

export interface ZoneStats {
  total: number
  scanned: number
  misconfigurations: number
  avgCriticality: number
}

export interface CategoryStats {
  count: number
  severity: Record<string, number>
}

export interface TopMisconfiguration {
  id: string
  title: string
  count: number
  severity: string
  affectedAssets: number
}

export interface CriticalPath {
  id: string
  entryAsset: string
  targetAsset: string
  probability: number
  misconfigCount: number
}

// ============================================================================
// RESULT AGGREGATOR
// ============================================================================

export class ResultAggregator {
  private results: Map<string, StreamedResult[]> = new Map()
  private aggregations: Map<string, AggregatedResult> = new Map()

  /**
   * Add a streamed result
   */
  addResult(result: StreamedResult): void {
    const jobId = result.jobId
    if (!this.results.has(jobId)) {
      this.results.set(jobId, [])
    }
    this.results.get(jobId)!.push(result)
    
    // Update aggregation
    this.updateAggregation(jobId)
  }

  /**
   * Get aggregated result for a job
   */
  getAggregation(jobId: string): AggregatedResult | undefined {
    return this.aggregations.get(jobId)
  }

  /**
   * Get all results for a job
   */
  getResults(jobId: string): StreamedResult[] {
    return this.results.get(jobId) || []
  }

  /**
   * Clear job data
   */
  clearJob(jobId: string): void {
    this.results.delete(jobId)
    this.aggregations.delete(jobId)
  }

  /**
   * Update aggregation for a job
   */
  private updateAggregation(jobId: string): void {
    const results = this.results.get(jobId) || []
    
    const completedResults = results.filter(r => r.type === 'target_complete')
    const errorResults = results.filter(r => r.type === 'target_error')
    const jobComplete = results.find(r => r.type === 'job_complete')
    
    // Calculate stats
    const stats: StreamStats = {
      totalTargets: 0,
      completedTargets: completedResults.length,
      failedTargets: errorResults.length,
      avgDuration: 0,
      totalMisconfigurations: 0,
      criticalFindings: 0,
      highFindings: 0,
      estimatedTimeRemaining: 0,
    }
    
    // Calculate averages and totals
    if (completedResults.length > 0) {
      const durations = completedResults
        .map(r => r.result?.duration || 0)
        .filter(d => d > 0)
      
      stats.avgDuration = durations.length > 0
        ? durations.reduce((a, b) => a + b, 0) / durations.length
        : 0
      
      for (const r of completedResults) {
        if (r.result) {
          stats.totalMisconfigurations += r.result.misconfigurations
          stats.criticalFindings += r.result.criticalCount
          stats.highFindings += r.result.highCount
        }
      }
    }
    
    // Group by zone
    const resultsByZone: Record<string, ZoneStats> = {}
    for (const r of completedResults) {
      if (!r.target) continue
      const zone = r.target.zone || 'unknown'
      
      if (!resultsByZone[zone]) {
        resultsByZone[zone] = { total: 0, scanned: 0, misconfigurations: 0, avgCriticality: 0 }
      }
      
      resultsByZone[zone].scanned++
      resultsByZone[zone].misconfigurations += r.result?.misconfigurations || 0
      resultsByZone[zone].avgCriticality += r.target.criticality || 0
    }
    
    // Calculate averages for zones
    for (const zone of Object.keys(resultsByZone)) {
      if (resultsByZone[zone].scanned > 0) {
        resultsByZone[zone].avgCriticality /= resultsByZone[zone].scanned
      }
    }
    
    // Group by category (would need actual category data)
    const resultsByCategory: Record<string, CategoryStats> = {}
    
    // Top misconfigurations (would need actual data)
    const topMisconfigurations: TopMisconfiguration[] = []
    
    // Critical paths (would need path analysis)
    const criticalPaths: CriticalPath[] = []
    
    const aggregation: AggregatedResult = {
      jobId,
      startTime: results[0]?.timestamp || Date.now(),
      endTime: jobComplete?.timestamp,
      status: jobComplete ? 'completed' : 'running',
      stats,
      resultsByZone,
      resultsByCategory,
      topMisconfigurations,
      criticalPaths,
    }
    
    this.aggregations.set(jobId, aggregation)
  }
}

// ============================================================================
// RESULT STREAMER
// ============================================================================

export class ResultStreamer extends EventEmitter {
  private aggregator: ResultAggregator
  private activeJobs: Set<string> = new Set()
  private bufferSize: number

  constructor(bufferSize: number = 1000) {
    super()
    this.aggregator = new ResultAggregator()
    this.bufferSize = bufferSize
  }

  /**
   * Start streaming for a job
   */
  startJob(jobId: string): void {
    this.activeJobs.add(jobId)
    this.emit('jobStarted', jobId)
    
    this.stream({
      type: 'target_start',
      timestamp: Date.now(),
      jobId,
    })
  }

  /**
   * Stream target start event
   */
  streamTargetStart(jobId: string, target: StreamTarget): void {
    this.stream({
      type: 'target_start',
      timestamp: Date.now(),
      jobId,
      target,
    })
  }

  /**
   * Stream target complete event
   */
  streamTargetComplete(jobId: string, target: StreamTarget, result: StreamResult): void {
    this.stream({
      type: 'target_complete',
      timestamp: Date.now(),
      jobId,
      target,
      result,
    })
  }

  /**
   * Stream target error event
   */
  streamTargetError(jobId: string, target: StreamTarget, error: string): void {
    this.stream({
      type: 'target_error',
      timestamp: Date.now(),
      jobId,
      target,
      error,
    })
  }

  /**
   * Stream job complete event
   */
  streamJobComplete(jobId: string, stats: StreamStats): void {
    this.stream({
      type: 'job_complete',
      timestamp: Date.now(),
      jobId,
      stats,
    })
    
    this.activeJobs.delete(jobId)
    this.emit('jobCompleted', jobId, stats)
  }

  /**
   * Get aggregated results
   */
  getAggregation(jobId: string): AggregatedResult | undefined {
    return this.aggregator.getAggregation(jobId)
  }

  /**
   * Get all results for a job
   */
  getResults(jobId: string): StreamedResult[] {
    return this.aggregator.getResults(jobId)
  }

  /**
   * Get active jobs
   */
  getActiveJobs(): string[] {
    return Array.from(this.activeJobs)
  }

  /**
   * Clear job data
   */
  clearJob(jobId: string): void {
    this.aggregator.clearJob(jobId)
    this.activeJobs.delete(jobId)
  }

  /**
   * Stream a result
   */
  private stream(result: StreamedResult): void {
    // Add to aggregator
    this.aggregator.addResult(result)
    
    // Emit to listeners
    this.emit('result', result)
    
    // Also emit specific event types
    this.emit(result.type, result)
  }

  /**
   * Create a readable stream for SSE
   */
  createSSEStream(jobId: string): NodeJS.ReadableStream {
    
    let buffer: StreamedResult[] = []
    
    const stream = new Readable({
      read() {
        // Push buffered results
        for (const result of buffer) {
          if (result.jobId === jobId) {
            this.push(`data: ${JSON.stringify(result)}\n\n`)
          }
        }
        buffer = []
      }
    })
    
    const handler = (result: StreamedResult) => {
      if (result.jobId === jobId) {
        if (stream.push(`data: ${JSON.stringify(result)}\n\n`)) {
          // Stream is still open
        } else {
          // Buffer for later
          buffer.push(result)
        }
      }
    }
    
    this.on('result', handler)
    
    // Cleanup on job complete
    this.once('jobCompleted', (completedJobId: string) => {
      if (completedJobId === jobId) {
        this.off('result', handler)
        stream.push(null) // End stream
      }
    })
    
    return stream
  }
}

// ============================================================================
// WEBSOCKET STREAMER
// ============================================================================

export interface WebSocketLike {
  send(data: string): void
  close(): void
  readyState: number
}

export class WebSocketStreamer {
  private connections: Map<string, Set<WebSocketLike>> = new Map()
  private streamer: ResultStreamer

  constructor(streamer: ResultStreamer) {
    this.streamer = streamer
    
    // Forward results to WebSocket connections
    this.streamer.on('result', (result: StreamedResult) => {
      this.broadcast(result.jobId, result)
    })
  }

  /**
   * Add a WebSocket connection for a job
   */
  addConnection(jobId: string, ws: WebSocketLike): void {
    if (!this.connections.has(jobId)) {
      this.connections.set(jobId, new Set())
    }
    this.connections.get(jobId)!.add(ws)
  }

  /**
   * Remove a WebSocket connection
   */
  removeConnection(jobId: string, ws: WebSocketLike): void {
    const connections = this.connections.get(jobId)
    if (connections) {
      connections.delete(ws)
      if (connections.size === 0) {
        this.connections.delete(jobId)
      }
    }
  }

  /**
   * Broadcast result to all connections for a job
   */
  private broadcast(jobId: string, result: StreamedResult): void {
    const connections = this.connections.get(jobId)
    if (!connections) return
    
    const data = JSON.stringify(result)
    
    for (const ws of connections) {
      try {
        if (ws.readyState === 1) { // WebSocket.OPEN
          ws.send(data)
        }
      } catch (error) {
        // Connection may be closed
        this.removeConnection(jobId, ws)
      }
    }
  }

  /**
   * Close all connections for a job
   */
  closeJob(jobId: string): void {
    const connections = this.connections.get(jobId)
    if (connections) {
      for (const ws of connections) {
        try {
          ws.close()
        } catch {}
      }
      this.connections.delete(jobId)
    }
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export { ResultAggregator }
