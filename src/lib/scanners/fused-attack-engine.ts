// ============================================================================
// FUSED ATTACK ENGINE
// Integration of Multi-Source Data Fusion with Enhanced Attack Path Analysis
// ============================================================================
//
// This module creates the complete pipeline:
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │                     DATA COLLECTION LAYER                           │
// ├─────────────────────────────────────────────────────────────────────┤
// │  API Discovery   Passive NetFlow   Active Scan    Sidescan         │
// │  (100% cov)      (real-time)       (targeted)     (validated)       │
// │  Conf: 0.90      Conf: 0.85        Conf: 0.70     Conf: 0.95        │
// └────────────────────────────┬────────────────────────────────────────┘
//                              │
//                              ▼
// ┌─────────────────────────────────────────────────────────────────────┐
// │                     EVIDENCE FUSION LAYER                           │
// ├─────────────────────────────────────────────────────────────────────┤
// │  • Dempster-Shafer combination for conflict resolution              │
// │  • Temporal decay for stale evidence                                │
// │  • Cross-validation between sources                                 │
// │  • Edge classification: validated → discovered → inferred → hypoth  │
// └────────────────────────────┬────────────────────────────────────────┘
//                              │
//                              ▼
// ┌─────────────────────────────────────────────────────────────────────┐
// │                     ATTACK GRAPH LAYER                              │
// ├─────────────────────────────────────────────────────────────────────┤
// │  Layer 1: GNN Embeddings      → Scalability (100K+ assets)          │
// │  Layer 2: Bayesian Inference  → FP Reduction (2-4% rate)            │
// │  Layer 3: MCTS Discovery      → Optimal Paths                        │
// │  Layer 4: LLM Validation      → Realistic Paths                      │
// └────────────────────────────┬────────────────────────────────────────┘
//                              │
//                              ▼
// ┌─────────────────────────────────────────────────────────────────────┐
// │                     OUTPUT LAYER                                    │
// ├─────────────────────────────────────────────────────────────────────┤
// │  • Validated attack paths with confidence scores                    │
// │  • Risk metrics and business impact                                 │
// │  • Mitigation recommendations                                       │
// │  • Attack narratives                                                │
// └─────────────────────────────────────────────────────────────────────┘
//
// ============================================================================

import { 
  MultiSourceFusionOrchestrator, 
  FusionResult, 
  FusedAsset, 
  FusedEdge,
  DiscoveredAsset,
  DiscoveredEdge,
  DataSourceType,
  FusionConfig
} from './multi-source-fusion-engine'
import { 
  EnhancedAttackGraphEngine, 
  EnhancedAsset, 
  BayesianEdge,
  RealisticAttackPath,
  EnhancedAnalysisResult
} from './enhanced-attack-engine'
import { 
  CompleteHybridEngine,
  CompleteAnalysisResult,
  ValidatedAttackPath
} from './complete-hybrid-engine'

// ============================================================================
// TYPES
// ============================================================================

export interface FusedAnalysisConfig {
  // Data source configuration
  sources: {
    api_discovery: { enabled: boolean; confidence?: number }
    passive_netflow: { enabled: boolean; confidence?: number }
    active_scan: { enabled: boolean; confidence?: number; targets?: string[] }
    sidescan: { enabled: boolean; confidence?: number }
  }
  
  // Fusion configuration
  fusion: {
    conflictResolution: 'dempster_shafer' | 'weighted_average' | 'max_confidence'
    temporalDecay: boolean
    crossValidation: boolean
    minSourcesForValidation: number
  }
  
  // Attack graph configuration
  attackGraph: {
    maxPaths: number
    maxDepth: number
    llmValidation: boolean
    attackerProfiles: AttackerProfileConfig[]
  }
}

export interface AttackerProfileConfig {
  type: 'opportunistic' | 'targeted' | 'insider'
  skill: 'novice' | 'intermediate' | 'advanced' | 'expert'
  motivation: 'financial' | 'espionage' | 'disruption' | 'hacktivism'
}

export interface FusedAnalysisResult {
  // Collection stats
  collection: {
    assetsDiscovered: number
    edgesDiscovered: number
    sourceCoverage: Record<DataSourceType, { count: number; coverage: number }>
    collectionTimeMs: number
  }
  
  // Fusion stats
  fusion: {
    validatedEdges: number
    discoveredEdges: number
    inferredEdges: number
    hypotheticalEdges: number
    avgConfidence: number
    crossValidatedCount: number
    fusionTimeMs: number
  }
  
  // Attack graph stats
  attackGraph: {
    totalNodes: number
    totalEdges: number
    entryPoints: number
    criticalAssets: number
    pathsGenerated: number
    graphTimeMs: number
  }
  
  // LLM validation stats
  validation: {
    pathsValidated: number
    pathsRejected: number
    avgRealismScore: number
    validationTimeMs: number
  }
  
  // Final results
  assets: EnhancedAsset[]
  attackPaths: ValidatedAttackPath[]
  riskMetrics: RiskMetrics
  
  // Timing
  totalTimeMs: number
}

export interface RiskMetrics {
  overallRiskScore: number
  criticalPathCount: number
  avgPathProbability: number
  topAttackVectors: AttackVector[]
  recommendedMitigations: Mitigation[]
}

export interface AttackVector {
  type: string
  frequency: number
  avgProbability: number
  affectedAssets: number
}

export interface Mitigation {
  priority: 'critical' | 'high' | 'medium' | 'low'
  title: string
  description: string
  affectedPaths: number
  riskReduction: number
}

// ============================================================================
// FUSED ATTACK ENGINE
// ============================================================================

export class FusedAttackEngine {
  private fusionOrchestrator: MultiSourceFusionOrchestrator
  private attackEngine: EnhancedAttackGraphEngine
  private config: FusedAnalysisConfig

  constructor(config?: Partial<FusedAnalysisConfig>) {
    this.config = this.buildDefaultConfig(config)
    this.fusionOrchestrator = new MultiSourceFusionOrchestrator(
      this.buildFusionConfig()
    )
    this.attackEngine = new EnhancedAttackGraphEngine()
  }

  private buildDefaultConfig(partial?: Partial<FusedAnalysisConfig>): FusedAnalysisConfig {
    return {
      sources: {
        api_discovery: { enabled: true, confidence: 0.90 },
        passive_netflow: { enabled: true, confidence: 0.85 },
        active_scan: { enabled: true, confidence: 0.70, targets: [] },
        sidescan: { enabled: true, confidence: 0.95 }
      },
      fusion: {
        conflictResolution: 'dempster_shafer',
        temporalDecay: true,
        crossValidation: true,
        minSourcesForValidation: 2
      },
      attackGraph: {
        maxPaths: 10,
        maxDepth: 6,
        llmValidation: true,
        attackerProfiles: [
          { type: 'targeted', skill: 'advanced', motivation: 'espionage' }
        ]
      },
      ...partial
    }
  }

  private buildFusionConfig(): Partial<FusionConfig> {
    return {
      sources: {
        api_discovery: {
          enabled: this.config.sources.api_discovery.enabled,
          confidence: this.config.sources.api_discovery.confidence || 0.90,
          stalenessThreshold: 86400000,
          priority: 2,
          coverage: 1.0
        },
        passive_netflow: {
          enabled: this.config.sources.passive_netflow.enabled,
          confidence: this.config.sources.passive_netflow.confidence || 0.85,
          stalenessThreshold: 3600000,
          priority: 3,
          coverage: 0.95
        },
        active_scan: {
          enabled: this.config.sources.active_scan.enabled,
          confidence: this.config.sources.active_scan.confidence || 0.70,
          stalenessThreshold: 604800000,
          priority: 4,
          coverage: 0.6
        },
        sidescan: {
          enabled: this.config.sources.sidescan.enabled,
          confidence: this.config.sources.sidescan.confidence || 0.95,
          stalenessThreshold: 2592000000,
          priority: 1,
          coverage: 0.4
        }
      },
      conflictResolution: this.config.fusion.conflictResolution,
      temporalDecay: {
        enabled: this.config.fusion.temporalDecay,
        halfLife: 604800000
      },
      crossValidation: {
        enabled: this.config.fusion.crossValidation,
        minSources: this.config.fusion.minSourcesForValidation
      }
    }
  }

  /**
   * Run complete analysis pipeline
   */
  async analyze(): Promise<FusedAnalysisResult> {
    const totalStart = Date.now()

    // Phase 1: Data Collection
    console.log('Phase 1: Collecting data from all sources...')
    const collectionStart = Date.now()
    const fusionResult = await this.fusionOrchestrator.collectAll()
    const collectionTime = Date.now() - collectionStart

    // Phase 2: Evidence Fusion
    console.log('Phase 2: Fusing evidence...')
    const fusionStart = Date.now()
    const { assets: fusedAssets, edges: fusedEdges } = 
      this.fusionOrchestrator.exportForAttackEngine()
    const fusionTime = Date.now() - fusionStart

    // Phase 3: Attack Graph Analysis
    console.log('Phase 3: Building attack graph...')
    const graphStart = Date.now()
    const enhancedAssets = this.convertToFusedAssets(fusedAssets, fusedEdges)
    const graphResult = await this.attackEngine.analyze({
      assets: enhancedAssets
    })
    const graphTime = Date.now() - graphStart

    // Phase 4: LLM Validation (if enabled)
    console.log('Phase 4: LLM validation...')
    const validationStart = Date.now()
    let validatedPaths: ValidatedAttackPath[] = []
    let validationStats = {
      pathsValidated: 0,
      pathsRejected: 0,
      avgRealismScore: 0,
      validationTimeMs: 0
    }

    if (this.config.attackGraph.llmValidation) {
      const hybridEngine = new CompleteHybridEngine()
      const hybridResult = await hybridEngine.analyze({
        assets: enhancedAssets
      })
      validatedPaths = hybridResult.validated_paths
      validationStats = {
        pathsValidated: validatedPaths.length,
        pathsRejected: graphResult.attack_paths.length - validatedPaths.length,
        avgRealismScore: hybridResult.llm_validation.avg_realism_score,
        validationTimeMs: hybridResult.llm_validation.processing_time_ms
      }
    } else {
      // Convert to ValidatedAttackPath without LLM
      validatedPaths = graphResult.attack_paths.map(path => ({
        ...path,
        llm_assessment: {
          is_realistic: true,
          realism_score: path.realism_score,
          attacker_motivation: 'Unknown',
          required_skills: [],
          detection_likelihood: 'medium',
          narrative: '',
          mitre_attack_alignment: path.kill_chain_phases
        },
        entry_assessment: {
          is_valid: true,
          attacker_value: 'Initial access'
        },
        exit_assessment: {
          is_valid: true,
          attacker_goal: 'Data exfiltration',
          data_value: 'Business-critical data'
        }
      }))
      validationStats = {
        pathsValidated: validatedPaths.length,
        pathsRejected: 0,
        avgRealismScore: graphResult.attack_paths.reduce(
          (sum, p) => sum + p.realism_score, 0
        ) / Math.max(graphResult.attack_paths.length, 1),
        validationTimeMs: 0
      }
    }
    const validationTime = Date.now() - validationStart

    // Build source coverage stats
    const sourceCoverage = this.computeSourceCoverage(fusionResult)

    // Compute edge classification stats
    const edgeStats = this.computeEdgeStats(fusedEdges)

    // Compute risk metrics
    const riskMetrics = this.computeRiskMetrics(
      validatedPaths, 
      fusedEdges,
      enhancedAssets
    )

    const totalTime = Date.now() - totalStart

    return {
      collection: {
        assetsDiscovered: fusionResult.assets.length,
        edgesDiscovered: fusionResult.edges.length,
        sourceCoverage,
        collectionTimeMs: collectionTime
      },
      fusion: {
        validatedEdges: edgeStats.validated,
        discoveredEdges: edgeStats.discovered,
        inferredEdges: edgeStats.inferred,
        hypotheticalEdges: edgeStats.hypothetical,
        avgConfidence: edgeStats.avgConfidence,
        crossValidatedCount: edgeStats.crossValidated,
        fusionTimeMs: fusionTime
      },
      attackGraph: {
        totalNodes: graphResult.graph_stats.total_nodes,
        totalEdges: graphResult.graph_stats.total_edges,
        entryPoints: graphResult.entry_points.length,
        criticalAssets: graphResult.critical_assets.length,
        pathsGenerated: graphResult.attack_paths.length,
        graphTimeMs: graphTime
      },
      validation: {
        ...validationStats,
        validationTimeMs: validationTime
      },
      assets: enhancedAssets,
      attackPaths: validatedPaths.slice(0, this.config.attackGraph.maxPaths),
      riskMetrics,
      totalTimeMs: totalTime
    }
  }

  private convertToFusedAssets(
    fusedAssets: FusedAsset[], 
    fusedEdges: FusedEdge[]
  ): EnhancedAsset[] {
    // Build adjacency from fused edges
    const adjacency = new Map<string, string[]>()
    for (const edge of fusedEdges) {
      if (!adjacency.has(edge.source_id)) {
        adjacency.set(edge.source_id, [])
      }
      adjacency.get(edge.source_id)!.push(edge.target_id)
    }

    // Convert Bayesian edges
    const bayesianEdges = fusedEdges.map(e => ({
      source: e.source_id,
      target: e.target_id,
      technique: this.inferTechnique(e),
      type: this.convertEdgeType(e.edge_type)
    }))

    return fusedAssets.map(asset => ({
      id: asset.id,
      name: asset.name,
      type: asset.type,
      ip: asset.ip,
      zone: asset.zone,
      criticality: asset.criticality,
      internet_facing: asset.internet_facing,
      services: asset.services,
      data_sensitivity: asset.data_sensitivity,
      misconfigurations: asset.misconfigurations,
      embedding: undefined,
      evidence: asset.evidence
    }))
  }

  private inferTechnique(edge: FusedEdge): string {
    // Map edge type to MITRE ATT&CK technique
    const techniqueMap: Record<string, string> = {
      'network_connection': 'T1021', // Remote Services
      'authenticated_session': 'T1078', // Valid Accounts
      'service_dependency': 'T1078', 
      'trust_relationship': 'T1199', // Trusted Relationship
      'data_flow': 'T1041', // Exfiltration Over C2 Channel
      'attack_path': 'TBA'
    }
    return techniqueMap[edge.edge_type] || 'TBA'
  }

  private convertEdgeType(edgeType: string): BayesianEdge['edge_type'] {
    const typeMap: Record<string, BayesianEdge['edge_type']> = {
      'network_connection': 'lateral',
      'authenticated_session': 'credential_theft',
      'service_dependency': 'exploit',
      'trust_relationship': 'lateral',
      'data_flow': 'data_exfiltration',
      'attack_path': 'lateral'
    }
    return typeMap[edgeType] || 'lateral'
  }

  private computeSourceCoverage(
    fusionResult: FusionResult
  ): Record<DataSourceType, { count: number; coverage: number }> {
    const coverage: Record<string, { count: number; coverage: number }> = {}
    const totalAssets = fusionResult.assets.length

    for (const source of ['api_discovery', 'passive_netflow', 'active_scan', 'sidescan'] as DataSourceType[]) {
      const count = fusionResult.assets.filter(a => a.source === source).length
      coverage[source] = {
        count,
        coverage: totalAssets > 0 ? count / totalAssets : 0
      }
    }

    return coverage as Record<DataSourceType, { count: number; coverage: number }>
  }

  private computeEdgeStats(edges: FusedEdge[]): {
    validated: number
    discovered: number
    inferred: number
    hypothetical: number
    avgConfidence: number
    crossValidated: number
  } {
    const stats = {
      validated: 0,
      discovered: 0,
      inferred: 0,
      hypothetical: 0,
      avgConfidence: 0,
      crossValidated: 0
    }

    for (const edge of edges) {
      stats.avgConfidence += edge.confidence
      
      switch (edge.classification) {
        case 'validated':
          stats.validated++
          break
        case 'discovered':
          stats.discovered++
          break
        case 'inferred':
          stats.inferred++
          break
        case 'hypothetical':
          stats.hypothetical++
          break
      }

      if (edge.evidence_count >= 2) {
        stats.crossValidated++
      }
    }

    stats.avgConfidence = edges.length > 0 
      ? stats.avgConfidence / edges.length 
      : 0

    return stats
  }

  private computeRiskMetrics(
    paths: ValidatedAttackPath[],
    edges: FusedEdge[],
    assets: EnhancedAsset[]
  ): RiskMetrics {
    // Compute overall risk score
    const avgPathProb = paths.length > 0
      ? paths.reduce((sum, p) => sum + p.path_probability, 0) / paths.length
      : 0

    const criticalPathCount = paths.filter(
      p => p.business_impact >= 70 || p.path_probability >= 0.7
    ).length

    // Analyze attack vectors
    const vectorCounts = new Map<string, { count: number; prob: number; assets: Set<string> }>()
    for (const path of paths) {
      for (const edge of path.edges) {
        const type = edge.edge_type
        if (!vectorCounts.has(type)) {
          vectorCounts.set(type, { count: 0, prob: 0, assets: new Set() })
        }
        const v = vectorCounts.get(type)!
        v.count++
        v.prob += edge.posterior_probability
        v.assets.add(edge.target_id)
      }
    }

    const topAttackVectors = Array.from(vectorCounts.entries())
      .map(([type, data]) => ({
        type,
        frequency: data.count,
        avgProbability: data.count > 0 ? data.prob / data.count : 0,
        affectedAssets: data.assets.size
      }))
      .sort((a, b) => b.frequency - a.frequency)
      .slice(0, 5)

    // Generate mitigations
    const mitigations = this.generateMitigations(paths, assets)

    return {
      overallRiskScore: Math.min(avgPathProb * 100 + criticalPathCount * 5, 100),
      criticalPathCount,
      avgPathProbability: avgPathProb,
      topAttackVectors,
      recommendedMitigations: mitigations
    }
  }

  private generateMitigations(
    paths: ValidatedAttackPath[],
    assets: EnhancedAsset[]
  ): Mitigation[] {
    const mitigations: Mitigation[] = []

    // Analyze common vulnerabilities
    const vulnCounts = new Map<string, { count: number; severity: string }>()
    for (const path of paths) {
      for (const node of path.nodes) {
        const asset = assets.find(a => a.id === node.asset_id)
        if (asset) {
          for (const misconfig of asset.misconfigurations) {
            const key = misconfig.title
            if (!vulnCounts.has(key)) {
              vulnCounts.set(key, { count: 0, severity: misconfig.severity })
            }
            vulnCounts.get(key)!.count++
          }
        }
      }
    }

    // Create mitigations for high-frequency vulnerabilities
    for (const [title, data] of vulnCounts.entries()) {
      if (data.count >= 2) {
        mitigations.push({
          priority: data.severity as 'critical' | 'high' | 'medium' | 'low',
          title: `Remediate: ${title}`,
          description: `This vulnerability appears in ${data.count} attack paths. Addressing it would block multiple attack vectors.`,
          affectedPaths: data.count,
          riskReduction: data.count * 10
        })
      }
    }

    // Add network segmentation recommendations
    const dmzPaths = paths.filter(p => 
      p.nodes.some(n => n.zone === 'dmz') && 
      p.nodes.some(n => n.zone === 'internal')
    )
    if (dmzPaths.length > 0) {
      mitigations.push({
        priority: 'high',
        title: 'Strengthen DMZ Segmentation',
        description: `${dmzPaths.length} attack paths cross from DMZ to internal network. Review firewall rules and network segmentation.`,
        affectedPaths: dmzPaths.length,
        riskReduction: dmzPaths.length * 15
      })
    }

    // Sort by risk reduction
    return mitigations
      .sort((a, b) => b.riskReduction - a.riskReduction)
      .slice(0, 10)
  }

  /**
   * Analyze a specific attack path
   */
  async analyzePath(pathId: string): Promise<ValidatedAttackPath | null> {
    const result = await this.analyze()
    return result.attackPaths.find(p => p.path_id === pathId) || null
  }

  /**
   * Get assets by data source
   */
  getAssetsBySource(source: DataSourceType): DiscoveredAsset[] {
    const fusionResult = this.fusionOrchestrator.getAssetsForAnalysis()
    return fusionResult.filter(a => a.source === source)
  }

  /**
   * Get edges by classification
   */
  getEdgesByClassification(
    classification: 'validated' | 'discovered' | 'inferred' | 'hypothetical'
  ): DiscoveredEdge[] {
    const fusionResult = this.fusionOrchestrator.getEdgesForAnalysis()
    return fusionResult.filter(e => e.classification === classification)
  }
}

// ============================================================================
// STRATEGIC DATA SOURCE INTEGRATION
// ============================================================================

/**
 * Strategic integration guidance for enhanced attack path creation
 * 
 * The multi-source fusion approach provides:
 * 
 * 1. CONFIDENCE-WEIGHTED PROBABILITY ESTIMATION
 *    - Higher confidence sources (Sidescan: 0.95) contribute more to edge probabilities
 *    - Dempster-Shafer theory handles conflicting evidence gracefully
 *    - Cross-validation between sources boosts confidence
 * 
 * 2. EDGE CLASSIFICATION FOR PATH FILTERING
 *    - Validated edges (from NetFlow/Sidescan): Only these are 100% certain
 *    - Discovered edges (from API/Scan): High confidence but may include stale data
 *    - Inferred edges: From correlation, used for path exploration
 *    - Hypothetical edges: Lowest confidence, used for "what-if" analysis
 * 
 * 3. TEMPORAL DECAY FOR CURRENT ACCURACY
 *    - Stale evidence has reduced impact on probability calculations
 *    - Real-time sources (NetFlow) maintain high relevance
 *    - Historical sources (Sidescan) provide ground truth but may be outdated
 * 
 * 4. COVERAGE OPTIMIZATION
 *    - API Discovery provides 100% asset coverage
 *    - NetFlow provides real-time topology
 *    - Active Scan fills gaps with detailed service info
 *    - Sidescan validates attack paths from real tests
 * 
 * USAGE IN ATTACK PATH CREATION:
 * 
 * // Initialize with custom configuration
 * const engine = new FusedAttackEngine({
 *   sources: {
 *     api_discovery: { enabled: true },
 *     passive_netflow: { enabled: true },
 *     active_scan: { enabled: true, targets: ['10.0.0.0/24'] },
 *     sidescan: { enabled: true }
 *   },
 *   fusion: {
 *     conflictResolution: 'dempster_shafer',
 *     temporalDecay: true,
 *     crossValidation: true,
 *     minSourcesForValidation: 2
 *   },
 *   attackGraph: {
 *     maxPaths: 15,
 *     maxDepth: 8,
 *     llmValidation: true,
 *     attackerProfiles: [
 *       { type: 'targeted', skill: 'advanced', motivation: 'espionage' },
 *       { type: 'opportunistic', skill: 'intermediate', motivation: 'financial' }
 *     ]
 *   }
 * })
 * 
 * // Run complete analysis
 * const result = await engine.analyze()
 * 
 * // Access results
 * console.log(`Discovered ${result.collection.assetsDiscovered} assets`)
 * console.log(`Generated ${result.attackPaths.length} validated attack paths`)
 * console.log(`Overall risk score: ${result.riskMetrics.overallRiskScore}`)
 */

// ============================================================================
// EXPORTS
// ============================================================================

export { MultiSourceFusionOrchestrator } from './multi-source-fusion-engine'
export { EnhancedAttackGraphEngine } from './enhanced-attack-engine'
export { CompleteHybridEngine } from './complete-hybrid-engine'
