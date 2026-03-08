// ============================================================================
// BRAVE GUARDIAN - UNIFIED SCANNER MODULES INDEX
// ============================================================================
// 
// This exports all scanner and analysis modules:
// 
// LAYER 1: Core Scanners
// - OptimizedScanner: Batched SSH commands
// - HighPerformanceScanner: Connection pooling, host discovery
// 
// LAYER 2: Scalable Architecture
// - ScannerOrchestrator: Parallel scanning manager
// - DistributedCoordinator: Multi-node coordination
// - ResultStreamer: WebSocket/SSE streaming
// - JobStateManager: Persistent job state
// - PriorityQueue: Business impact ordering
// - AdaptiveRateLimiter: AIMD rate control
// - ScanScheduler: Cron-based scheduling
// 
// LAYER 3: Analysis Modules
// - ZoneDetector: DMZ/Internal/Restricted classification
// - NetworkTopologyCollector: Identity & access collection
// - FalsePositiveReducer: FP reduction (5-10% rate)
// 
// LAYER 4: Enhanced Attack Engine (NEW)
// - GNNEmbeddingEngine: Graph Neural Network embeddings
// - BayesianProbabilityEngine: Multi-source evidence fusion
// - MCTSPathDiscoveryEngine: Monte Carlo Tree Search paths
// - EnhancedAttackGraphEngine: Complete hybrid engine
// 
// LAYER 5: LLM Realism Engine (NEW)
// - LLMAttackAnalyzer: Entry/exit/path validation
// - IntegratedRealismEngine: Complete LLM validation
// 
// LAYER 6: Complete Hybrid Engine (NEW)
// - CompleteHybridEngine: Full GNN+Bayesian+MCTS+LLM integration
// 
// LAYER 7: Multi-Source Data Fusion (NEW)
// - APIDiscoverySource: CMDB, Cloud, Virtualization, AD APIs
// - PassiveNetFlowSource: Real-time network topology
// - ActiveScanSource: Targeted vulnerability scanning
// - SidescanSource: Validated attack paths
// - EvidenceFusionEngine: Dempster-Shafer evidence combination
// - MultiSourceFusionOrchestrator: Complete fusion pipeline
// 
// LAYER 8: Fused Attack Engine (NEW)
// - FusedAttackEngine: Complete multi-source + attack path pipeline
// 
// ============================================================================

// ============================================================================
// CORE SCANNERS
// ============================================================================

export { OptimizedScanner } from './optimized-scanner'
export type { 
  OptimizedScannerConfig, 
  BatchResult, 
  HostInfo 
} from './optimized-scanner'

export { HighPerformanceScanner } from './high-perf-scanner'
export type { 
  HighPerfConfig, 
  ScanTarget, 
  ScanResult as HighPerfScanResult 
} from './high-perf-scanner'

// ============================================================================
// ZONE DETECTION
// ============================================================================

export { ZoneDetector, ZoneRegistry, CIDRMatcher, ZoneReachability } from './zone-detection'
export type { 
  NetworkZone, 
  ZoneDetectionResult, 
  ZoneEvidence, 
  ZoneRule 
} from './zone-detection'

// ============================================================================
// NETWORK TOPOLOGY
// ============================================================================

export { NetworkTopologyCollector } from './network-topology-collector'
export type { 
  TopologyConfig, 
  IdentityInfo, 
  AccessPattern, 
  TrustRelationship 
} from './network-topology-collector'

// ============================================================================
// FALSE POSITIVE REDUCTION
// ============================================================================

export { FalsePositiveReducer } from './fp-reduction'
export type { 
  FPReductionConfig, 
  ValidationResult, 
  ContextCheck 
} from './fp-reduction'

// ============================================================================
// SCALABLE ARCHITECTURE
// ============================================================================

export { ScannerOrchestrator, ConnectionPoolManager, RateLimiter, ResultCache, ParallelScanner } from './scalable/scanner-orchestrator'
export type { 
  ScanJob, 
  ScanTarget as OrchestratorScanTarget, 
  ScanResult as OrchestratorScanResult,
  DetectedMisconfiguration,
  OrchestratorConfig 
} from './scalable/scanner-orchestrator'

export { DistributedCoordinator } from './scalable/distributed-coordinator'
export type { 
  CoordinatorConfig, 
  NodeInfo, 
  WorkAssignment 
} from './scalable/distributed-coordinator'

export { ResultStreamer } from './scalable/result-streamer'
export type { 
  StreamConfig, 
  StreamEvent 
} from './scalable/result-streamer'

export { JobStateManager } from './scalable/job-state-manager'
export type { 
  JobStateConfig, 
  PersistedJobState 
} from './scalable/job-state-manager'

export { PriorityQueue } from './scalable/priority-queue'
export type { 
  PriorityConfig, 
  PrioritizedItem 
} from './scalable/priority-queue'

export { AdaptiveRateLimiter } from './scalable/adaptive-rate-limiter'
export type { 
  RateLimiterConfig, 
  RateLimitState 
} from './scalable/adaptive-rate-limiter'

export { ScanScheduler } from './scalable/scan-scheduler'
export type { 
  ScheduleConfig, 
  ScheduledJob 
} from './scalable/scan-scheduler'

// ============================================================================
// ENHANCED ATTACK ENGINE (GNN + BAYESIAN + MCTS)
// ============================================================================

export { GNNEmbeddingEngine } from './enhanced-attack-engine'
export { BayesianProbabilityEngine } from './enhanced-attack-engine'
export { MCTSPathDiscoveryEngine } from './enhanced-attack-engine'
export { EnhancedAttackGraphEngine } from './enhanced-attack-engine'
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
  RiskMetrics
} from './enhanced-attack-engine'

// ============================================================================
// LLM REALISM ENGINE
// ============================================================================

export { LLMAttackAnalyzer } from './llm-realism-engine'
export { IntegratedRealismEngine } from './llm-realism-engine'
export type {
  LLMAssessment,
  EntryPointAssessment,
  ExitPointAssessment,
  PathRealismAssessment,
  AttackerProfile
} from './llm-realism-engine'

// ============================================================================
// COMPLETE HYBRID ENGINE (GNN + BAYESIAN + MCTS + LLM)
// ============================================================================

export { CompleteHybridEngine } from './complete-hybrid-engine'
export type {
  CompleteAnalysisResult,
  ValidatedAttackPath
} from './complete-hybrid-engine'

// ============================================================================
// MULTI-SOURCE DATA FUSION ENGINE
// ============================================================================

export { APIDiscoverySource } from './multi-source-fusion-engine'
export { PassiveNetFlowSource } from './multi-source-fusion-engine'
export { ActiveScanSource } from './multi-source-fusion-engine'
export { SidescanSource } from './multi-source-fusion-engine'
export { EvidenceFusionEngine } from './multi-source-fusion-engine'
export { MultiSourceFusionOrchestrator } from './multi-source-fusion-engine'
export type {
  DataSourceType,
  DataSourceConfig,
  FusionConfig,
  DiscoveredAsset,
  DiscoveredService,
  DiscoveredVulnerability,
  DiscoveredEdge,
  EdgeType,
  EdgeEvidence,
  AssetType,
  FusionResult,
  FusedAsset,
  FusedEdge
} from './multi-source-fusion-engine'

// ============================================================================
// FUSED ATTACK ENGINE (Multi-Source + Attack Path)
// ============================================================================

export { FusedAttackEngine } from './fused-attack-engine'
export type {
  FusedAnalysisConfig,
  FusedAnalysisResult,
  AttackerProfileConfig,
  RiskMetrics,
  AttackVector,
  Mitigation
} from './fused-attack-engine'

// ============================================================================
// ENHANCED ATTACK ENGINE (ALTERNATIVE)
// ============================================================================

export { EnhancedAttackEngine } from './enhanced-attack-engine'
export type { AttackConfig, AttackResult } from './enhanced-attack-engine'

// ============================================================================
// COMPLETE HYBRID ENGINE (ALTERNATIVE)
// ============================================================================

export { CompleteHybridEngine as FullHybridEngine } from './complete-hybrid-engine'

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Create a complete analysis engine with all features enabled
 */
export function createCompleteEngine(): CompleteHybridEngine {
  return new CompleteHybridEngine()
}

/**
 * Create an enhanced attack graph engine (GNN + Bayesian + MCTS only)
 */
export function createEnhancedEngine(): EnhancedAttackGraphEngine {
  return new EnhancedAttackGraphEngine()
}

/**
 * Create a scanner orchestrator with default configuration
 */
export function createScannerOrchestrator(
  config?: Partial<import('./scalable/scanner-orchestrator').OrchestratorConfig>
): ScannerOrchestrator {
  return new ScannerOrchestrator(config)
}

/**
 * Create a zone detector with default zones and rules
 */
export function createZoneDetector(): ZoneDetector {
  return new ZoneDetector()
}

// ============================================================================
// VERSION INFO
// ============================================================================

export const VERSION = '3.0.0'
export const FEATURES = {
  GNN_EMBEDDINGS: true,
  BAYESIAN_INFERENCE: true,
  MCTS_PATH_DISCOVERY: true,
  LLM_VALIDATION: true,
  SCALABLE_ARCHITECTURE: true,
  ZONE_DETECTION: true,
  FP_REDUCTION: true,
  MULTI_SOURCE_FUSION: true,
  API_DISCOVERY: true,
  PASSIVE_NETFLOW: true,
  ACTIVE_SCAN: true,
  SIDESCAN: true,
  DEMPSTER_SHAFER_FUSION: true
}
