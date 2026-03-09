// ============================================================================
// COMPLETE HYBRID ATTACK ENGINE
// GNN + Bayesian + MCTS + LLM Integration
// ============================================================================
//
// This is the complete integration that ensures:
// 1. Scalability (GNN embeddings)
// 2. Accuracy (Bayesian inference)
// 3. Optimal paths (MCTS discovery)
// 4. Realistic paths (LLM validation)
//
// The LLM is used STRATEGICALLY for validation, not generation:
// - MCTS generates candidate paths (structured, fast)
// - LLM validates realism (semantic understanding)
// - This gives best of both worlds
// ============================================================================

import { EnhancedAttackGraphEngine, EnhancedAnalysisResult, RealisticAttackPath, EnhancedAsset } from './enhanced-attack-engine'
import { LLMAttackAnalyzer, IntegratedRealismEngine, AttackerProfile, PathRealismAssessment } from './llm-realism-engine'

// ============================================================================
// TYPES
// ============================================================================

export interface CompleteAnalysisResult extends EnhancedAnalysisResult {
  llm_validation: {
    paths_validated: number
    paths_rejected: number
    avg_realism_score: number
    entry_validation_rate: number
    exit_validation_rate: number
    processing_time_ms: number
  }
  attacker_profiles_used: AttackerProfile[]
  validated_paths: ValidatedAttackPath[]
}

export interface ValidatedAttackPath extends RealisticAttackPath {
  llm_assessment: {
    is_realistic: boolean
    realism_score: number
    attacker_motivation: string
    required_skills: string[]
    detection_likelihood: string
    narrative: string
    mitre_attack_alignment: string[]
  }
  entry_assessment: {
    is_valid: boolean
    attacker_value: string
  }
  exit_assessment: {
    is_valid: boolean
    attacker_goal: string
    data_value: string
  }
}

// ============================================================================
// COMPLETE HYBRID ENGINE
// ============================================================================

export class CompleteHybridEngine {
  private graphEngine: EnhancedAttackGraphEngine
  private llmEngine: IntegratedRealismEngine
  private defaultAttackerProfile: AttackerProfile = {
    type: 'targeted',
    skill_level: 'advanced',
    motivation: 'espionage',
    resources: 'high',
    risk_tolerance: 'medium'
  }

  constructor() {
    this.graphEngine = new EnhancedAttackGraphEngine()
    this.llmEngine = new IntegratedRealismEngine()
  }

  /**
   * Complete analysis pipeline
   * 
   * Flow:
   * 1. GNN Embedding (scalability)
   * 2. Bayesian Inference (accuracy)
   * 3. MCTS Discovery (optimal paths)
   * 4. LLM Validation (realism) ← NEW
   */
  async analyze(environment: { assets: EnhancedAsset[] }): Promise<CompleteAnalysisResult> {
    // Phase 1-3: Graph analysis
    console.log('Phase 1-3: Running graph-based analysis (GNN + Bayesian + MCTS)...')
    const graphResult = await this.graphEngine.analyze(environment)

    // Phase 4: LLM validation
    console.log('Phase 4: Running LLM validation for realism...')
    const llmStart = Date.now()
    
    await this.llmEngine.initialize()
    
    const validatedPaths = await this.validatePathsWithLLM(
      graphResult.attack_paths,
      environment.assets
    )

    const llmTime = Date.now() - llmStart

    // Compute LLM statistics
    const validPaths = validatedPaths.filter(p => p.llm_assessment.is_realistic)
    const rejectedPaths = validatedPaths.filter(p => !p.llm_assessment.is_realistic)
    const avgRealism = validPaths.length > 0
      ? validPaths.reduce((sum, p) => sum + p.llm_assessment.realism_score, 0) / validPaths.length
      : 0

    const validEntries = validatedPaths.filter(p => p.entry_assessment.is_valid).length
    const validExits = validatedPaths.filter(p => p.exit_assessment.is_valid).length

    return {
      ...graphResult,
      attack_paths: validPaths,
      validated_paths: validPaths,
      llm_validation: {
        paths_validated: validatedPaths.length,
        paths_rejected: rejectedPaths.length,
        avg_realism_score: avgRealism,
        entry_validation_rate: validEntries / Math.max(validatedPaths.length, 1),
        exit_validation_rate: validExits / Math.max(validatedPaths.length, 1),
        processing_time_ms: llmTime
      },
      attacker_profiles_used: [this.defaultAttackerProfile],
      timing: {
        ...graphResult.timing,
        llm_validation: llmTime,
        total: graphResult.timing.total + llmTime
      }
    }
  }

  private async validatePathsWithLLM(
    paths: RealisticAttackPath[],
    assets: EnhancedAsset[]
  ): Promise<ValidatedAttackPath[]> {
    const validatedPaths: ValidatedAttackPath[] = []

    // Process paths in batches for efficiency
    const batchSize = 5
    for (let i = 0; i < paths.length; i += batchSize) {
      const batch = paths.slice(i, i + batchSize)
      const batchResults = await Promise.all(
        batch.map(path => this.validateSinglePath(path, assets))
      )
      validatedPaths.push(...batchResults)
    }

    return validatedPaths.sort((a, b) => b.realism_score - a.realism_score)
  }

  private async validateSinglePath(
    path: RealisticAttackPath,
    assets: EnhancedAsset[]
  ): Promise<ValidatedAttackPath> {
    const llmAnalyzer = new LLMAttackAnalyzer()
    await llmAnalyzer.initialize()

    // Validate entry point
    const entryAsset = assets.find(a => a.id === path.nodes[0]?.asset_id)
    const entryAssessment = entryAsset
      ? await llmAnalyzer.validateEntryPoints(
          [{
            asset_id: entryAsset.id,
            asset_name: entryAsset.name,
            asset_type: entryAsset.type,
            zone: entryAsset.zone,
            misconfig_title: path.nodes[0]?.misconfig_title || '',
            internet_facing: entryAsset.internet_facing,
            criticality: entryAsset.criticality
          }],
          { total_assets: assets.length, dmz_assets: assets.filter(a => a.zone === 'dmz').length, internet_exposed_count: assets.filter(a => a.internet_facing).length },
          this.defaultAttackerProfile
        ).then(results => results[0])
      : { is_valid_entry: true, validity_score: 0.7, attacker_value: 'Unknown', why_attacker_would_choose: 'Unknown', alternative_entries: [], confidence: 0.7 }

    // Validate exit point
    const exitAsset = assets.find(a => a.id === path.nodes[path.nodes.length - 1]?.asset_id)
    const exitAssessment = exitAsset
      ? await llmAnalyzer.validateExitPoints(
          [{
            asset_id: exitAsset.id,
            asset_name: exitAsset.name,
            asset_type: exitAsset.type,
            zone: exitAsset.zone,
            criticality: exitAsset.criticality,
            data_sensitivity: exitAsset.data_sensitivity || 'unknown',
            services: exitAsset.services || []
          }],
          this.defaultAttackerProfile
        ).then(results => results[0])
      : { is_valid_target: true, validity_score: 0.7, attacker_goal: 'Unknown', why_attacker_would_target: 'Unknown', data_value: 'Unknown', alternative_targets: [], confidence: 0.7 }

    // Assess full path
    const pathAssessment = await llmAnalyzer.assessPathRealism(
      {
        nodes: path.nodes.map(n => ({
          asset_name: n.asset_name,
          asset_type: assets.find(a => a.id === n.asset_id)?.type || 'unknown',
          zone: n.zone,
          misconfig_title: n.misconfig_title
        })),
        edges: path.edges
      },
      this.defaultAttackerProfile
    )

    // Generate narrative
    const narrative = await llmAnalyzer.generateAttackNarrative(
      {
        nodes: path.nodes.map(n => ({
          asset_name: n.asset_name,
          asset_type: assets.find(a => a.id === n.asset_id)?.type || 'unknown',
          zone: n.zone,
          misconfig_title: n.misconfig_title,
          criticality: n.criticality
        })),
        edges: path.edges
      },
      this.defaultAttackerProfile
    )

    // Determine if path is realistic
    const isRealistic = 
      (entryAssessment as any).is_valid_entry !== false &&
      (exitAssessment as any).is_valid_target !== false &&
      pathAssessment.overall_realism >= 0.5

    // Compute final realism score
    const realismScore = 
      (path.realism_score * 0.3) +
      (pathAssessment.overall_realism * 0.4) +
      ((entryAssessment as any).validity_score || 0.7) * 0.15 +
      ((exitAssessment as any).validity_score || 0.7) * 0.15

    return {
      ...path,
      realism_score: realismScore,
      narrative: narrative,
      llm_assessment: {
        is_realistic: isRealistic,
        realism_score: pathAssessment.overall_realism,
        attacker_motivation: this.defaultAttackerProfile.motivation,
        required_skills: this.inferRequiredSkills(path),
        detection_likelihood: this.inferDetectionLikelihood(pathAssessment),
        narrative: narrative,
        mitre_attack_alignment: path.kill_chain_phases
      },
      entry_assessment: {
        is_valid: (entryAssessment as any).is_valid_entry !== false,
        attacker_value: (entryAssessment as any).attacker_value || 'Initial access'
      },
      exit_assessment: {
        is_valid: (exitAssessment as any).is_valid_target !== false,
        attacker_goal: (exitAssessment as any).attacker_goal || 'Data exfiltration',
        data_value: (exitAssessment as any).data_value || 'Business-critical data'
      }
    }
  }

  private inferRequiredSkills(path: RealisticAttackPath): string[] {
    const skills = new Set<string>()
    
    for (const edge of path.edges) {
      switch (edge.edge_type) {
        case 'exploit':
          skills.add('Exploit development')
          skills.add('Vulnerability analysis')
          break
        case 'lateral':
          skills.add('Network pivoting')
          skills.add('Remote execution')
          break
        case 'credential_theft':
          skills.add('Credential harvesting')
          skills.add('Memory forensics')
          break
        case 'privilege_escalation':
          skills.add('Privilege escalation techniques')
          skills.add('Token manipulation')
          break
        case 'data_exfiltration':
          skills.add('Data staging')
          skills.add('Covert channels')
          break
      }
    }
    
    return Array.from(skills)
  }

  private inferDetectionLikelihood(assessment: PathRealismAssessment): string {
    if (!assessment.detection_evasion_realistic) return 'high'
    if (assessment.overall_realism > 0.8) return 'low'
    if (assessment.overall_realism > 0.6) return 'medium'
    return 'high'
  }

  /**
   * Run analysis with multiple attacker profiles
   * This provides comprehensive coverage
   */
  async analyzeMultipleProfiles(
    environment: { assets: EnhancedAsset[] },
    profiles: AttackerProfile[]
  ): Promise<Map<AttackerProfile, CompleteAnalysisResult>> {
    const results = new Map<AttackerProfile, CompleteAnalysisResult>()

    for (const profile of profiles) {
      const previousProfile = this.defaultAttackerProfile
      this.defaultAttackerProfile = profile
      
      const result = await this.analyze(environment)
      results.set(profile, result)
      
      this.defaultAttackerProfile = previousProfile
    }

    return results
  }
}

// ============================================================================
// USAGE EXAMPLE
// ============================================================================

/**
 * Example usage:
 * 
 * const engine = new CompleteHybridEngine()
 * 
 * const result = await engine.analyze({
 *   assets: [
 *     {
 *       id: 'asset-1',
 *       name: 'WEB-001',
 *       type: 'web_server',
 *       ip: '10.0.0.1',
 *       zone: 'dmz',
 *       criticality: 4,
 *       internet_facing: true,
 *       domain_joined: false,
 *       services: ['IIS'],
 *       data_sensitivity: 'app_data',
 *       misconfigurations: [
 *         { id: 'M001', title: 'RDP Exposed', description: '...', category: 'network', severity: 'critical' }
 *       ],
 *       evidence: {
 *         vulnerability_scanner: { confidence: 0.9, last_updated: Date.now(), data: {} },
 *         siem_alerts: { confidence: 0.7, last_updated: Date.now(), data: {} },
 *         threat_intelligence: { confidence: 0.8, last_updated: Date.now(), data: {} },
 *         historical_attacks: { confidence: 0.6, last_updated: Date.now(), data: {} },
 *         network_flow: { confidence: 0.5, last_updated: Date.now(), data: {} }
 *       }
 *     }
 *   ]
 * })
 * 
 * console.log('Validated paths:', result.validated_paths.length)
 * console.log('Average realism:', result.llm_validation.avg_realism_score)
 */

// ============================================================================
// EXPORTS
// ============================================================================

export { EnhancedAttackGraphEngine } from './enhanced-attack-engine'
export { LLMAttackAnalyzer, IntegratedRealismEngine } from './llm-realism-engine'
