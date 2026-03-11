// ============================================================================
// BRAVE GUARDIAN — SCANNER MODULES INDEX  v4.0
// ============================================================================

// ── Core Scanners ─────────────────────────────────────────────────────────────

export { OptimizedScanner } from './optimized-scanner'
export type { ScanTarget as OptimizedScanTarget, BatchedResult, ScanConfig as OptimizedScanConfig } from './optimized-scanner'

export { HighPerformanceScanner } from './high-perf-scanner'
export type { ScanTarget, ScanResult as HighPerfScanResult, HighPerfConfig } from './high-perf-scanner'

// ── Zone Detection ────────────────────────────────────────────────────────────

export { ZoneDetector, ZoneReachability } from './zone-detection'
export type { NetworkZone, ZoneDetectionResult, ZoneEvidence, ZoneRule } from './zone-detection'

// ── False Positive Reduction ──────────────────────────────────────────────────

export { FalsePositiveAnalyzer, calculateFPStats } from './fp-reduction'
export type { FalsePositiveRisk, ValidationContext, ValidatedDetection, FalsePositiveStats } from './fp-reduction'

// ── Scalable Architecture ─────────────────────────────────────────────────────

export { ScannerOrchestrator } from './scalable/scanner-orchestrator'
export type {
  ScanJob,
  ScanTarget as OrchestratorScanTarget,
  ScanResult as OrchestratorScanResult,
  DetectedMisconfiguration,
  OrchestratorConfig,
} from './scalable/scanner-orchestrator'

export { DistributedCoordinator } from './scalable/distributed-coordinator'
export type { CoordinatorConfig } from './scalable/distributed-coordinator'

export { JobStateManager } from './scalable/job-state-manager'
export type { JobState, JobFilter, JobStats } from './scalable/job-state-manager'

export { PriorityQueue } from './scalable/priority-queue'
export type { PriorityTask, QueueStats } from './scalable/priority-queue'

export { AdaptiveRateLimiter } from './scalable/adaptive-rate-limiter'
export type { RateLimiterConfig, RateLimiterStats } from './scalable/adaptive-rate-limiter'

// ── Enhanced Attack Engine (GNN + Bayesian + MCTS) ───────────────────────────

export {
  GNNEmbeddingEngine,
  BayesianProbabilityEngine,
  MCTSPathDiscoveryEngine,
  EnhancedAttackGraphEngine,
} from './enhanced-attack-engine'

export type {
  EnhancedAsset,
  Misconfiguration,
  EvidenceBundle,
  EvidenceSource,
  BayesianEdge,
  MCTSNode,
  RealisticAttackPath,
  PathNode,
  EnhancedAnalysisResult,
  EntryPoint,
  CriticalAsset,
  RiskMetrics,
} from './enhanced-attack-engine'

// ── Version ───────────────────────────────────────────────────────────────────

export const VERSION = '4.0.0'
export const FEATURES = {
  GNN_EMBEDDINGS: true,
  BAYESIAN_INFERENCE: true,
  MCTS_PATH_DISCOVERY: true,
  LLM_VALIDATION: true,
  SIMILARITY_CACHE: true,
  NEIGHBOUR_SCORE_CACHE: true,
  ZONE_DETECTION: true,
}
