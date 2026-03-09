// ============================================================================
// LLM-ENHANCED ATTACK PATH VALIDATION
// Strategic LLM integration for realism without performance sacrifice
// ============================================================================
//
// This module reintegrates LLM at strategic points:
// 1. Entry Point Validation - LLM verifies entry points are realistic
// 2. Path Realism Scoring - LLM evaluates attacker behavior alignment
// 3. Exit Point Validation - LLM confirms target makes sense for attacker
// 4. Attack Narrative Generation - LLM explains WHY this path works
//
// Key insight: LLM is used for VALIDATION, not generation
// - MCTS generates candidate paths (fast, structured)
// - LLM validates realism (semantic understanding)
// - This gives best of both worlds
// ============================================================================

import ZAI from 'z-ai-web-dev-sdk'

// ============================================================================
// TYPES
// ============================================================================

export interface LLMAssessment {
  is_realistic: boolean
  realism_score: number  // 0-1
  attacker_motivation: string
  attack_feasibility: 'trivial' | 'easy' | 'moderate' | 'hard' | 'infeasible'
  required_skills: string[]
  detection_likelihood: 'very_low' | 'low' | 'medium' | 'high' | 'very_high'
  suggested_entry_alternatives: string[]
  suggested_target_alternatives: string[]
  narrative: string
  mitre_attack_alignment: string[]
  confidence: number
}

export interface EntryPointAssessment {
  asset_id: string
  is_valid_entry: boolean
  validity_score: number
  attacker_value: string
  why_attacker_would_choose: string
  alternative_entries: string[]
  confidence: number
}

export interface ExitPointAssessment {
  asset_id: string
  is_valid_target: boolean
  validity_score: number
  attacker_goal: string
  why_attacker_would_target: string
  data_value: string
  alternative_targets: string[]
  confidence: number
}

export interface PathRealismAssessment {
  path_id: string
  overall_realism: number
  entry_valid: boolean
  exit_valid: boolean
  attack_phases_realistic: boolean
  skill_requirements_realistic: boolean
  detection_evasion_realistic: boolean
  improvements: string[]
  narrative: string
  confidence: number
}

export interface AttackerProfile {
  type: 'opportunistic' | 'targeted' | 'apt' | 'insider'
  skill_level: 'script_kiddie' | 'intermediate' | 'advanced' | 'expert'
  motivation: 'financial' | 'espionage' | 'disruption' | 'curiosity'
  resources: 'low' | 'medium' | 'high' | 'nation_state'
  risk_tolerance: 'low' | 'medium' | 'high'
}

// ============================================================================
// LLM ATTACK ANALYZER
// ============================================================================

export class LLMAttackAnalyzer {
  private zai: any = null
  private modelConfig = {
    temperature: 0.3,  // Low for consistency
    max_tokens: 2000
  }

  async initialize(): Promise<void> {
    this.zai = await ZAI.create()
  }

  /**
   * STEP 1: Validate Entry Points
   * LLM evaluates if entry points make sense from attacker perspective
   */
  async validateEntryPoints(
    entryPoints: Array<{
      asset_id: string
      asset_name: string
      asset_type: string
      zone: string
      misconfig_title: string
      internet_facing: boolean
      criticality: number
    }>,
    environment: {
      total_assets: number
      dmz_assets: number
      internet_exposed_count: number
    },
    attackerProfile: AttackerProfile
  ): Promise<EntryPointAssessment[]> {
    if (!this.zai) await this.initialize()

    const prompt = this.buildEntryValidationPrompt(entryPoints, environment, attackerProfile)
    
    const response = await this.zai.chat.completions.create({
      messages: [
        {
          role: 'system',
          content: `You are a senior red team operator with 15+ years of penetration testing experience. 
You think like an attacker and evaluate security from the adversary's perspective.
Provide realistic, practical assessments based on real-world attack patterns.
Always respond in valid JSON format.`
        },
        {
          role: 'user',
          content: prompt
        }
      ],
      temperature: this.modelConfig.temperature,
      max_tokens: this.modelConfig.max_tokens
    })

    const content = response.choices[0]?.message?.content || ''
    return this.parseEntryAssessments(content, entryPoints)
  }

  private buildEntryValidationPrompt(
    entryPoints: Array<{
      asset_id: string
      asset_name: string
      asset_type: string
      zone: string
      misconfig_title: string
      internet_facing: boolean
      criticality: number
    }>,
    environment: {
      total_assets: number
      dmz_assets: number
      internet_exposed_count: number
    },
    attackerProfile: AttackerProfile
  ): string {
    const entries = entryPoints.map((ep, i) => 
      `${i + 1}. ${ep.asset_name} (${ep.asset_type})
         - Zone: ${ep.zone}
         - Internet-facing: ${ep.internet_facing}
         - Vulnerability: ${ep.misconfig_title}
         - Criticality: ${ep.criticality}/5`
    ).join('\n')

    return `You are evaluating potential entry points for a cyber attack. Think like a ${attackerProfile.type} attacker with ${attackerProfile.skill_level} skills.

ENVIRONMENT CONTEXT:
- Total assets: ${environment.total_assets}
- DMZ assets: ${environment.dmz_assets}
- Internet-exposed assets: ${environment.internet_exposed_count}

POTENTIAL ENTRY POINTS:
${entries}

ATTACKER PROFILE:
- Type: ${attackerProfile.type}
- Skill Level: ${attackerProfile.skill_level}
- Motivation: ${attackerProfile.motivation}
- Resources: ${attackerProfile.resources}
- Risk Tolerance: ${attackerProfile.risk_tolerance}

For each entry point, evaluate:
1. Would an attacker with this profile realistically choose this entry point?
2. What value does this entry point provide to an attacker?
3. Are there better alternatives that an attacker would prefer?

Respond in JSON format:
{
  "assessments": [
    {
      "asset_id": "asset_id_here",
      "is_valid_entry": true/false,
      "validity_score": 0.0-1.0,
      "attacker_value": "what attacker gains from this entry",
      "why_attacker_would_choose": "reasoning",
      "alternative_entries": ["list of better alternatives if any"],
      "confidence": 0.0-1.0
    }
  ]
}`
  }

  private parseEntryAssessments(
    content: string,
    entryPoints: Array<{ asset_id: string }>
  ): EntryPointAssessment[] {
    try {
      const jsonMatch = content.match(/\{[\s\S]*\}/)
      if (!jsonMatch) {
        return this.getDefaultEntryAssessments(entryPoints)
      }

      const parsed = JSON.parse(jsonMatch[0])
      const assessments = parsed.assessments || []

      return entryPoints.map((ep, i) => {
        const assessment = assessments[i] || {}
        return {
          asset_id: ep.asset_id,
          is_valid_entry: assessment.is_valid_entry ?? true,
          validity_score: assessment.validity_score ?? 0.7,
          attacker_value: assessment.attacker_value || 'Initial access point',
          why_attacker_would_choose: assessment.why_attacker_would_choose || 'Internet-facing vulnerability',
          alternative_entries: assessment.alternative_entries || [],
          confidence: assessment.confidence ?? 0.8
        }
      })
    } catch (e) {
      return this.getDefaultEntryAssessments(entryPoints)
    }
  }

  private getDefaultEntryAssessments(
    entryPoints: Array<{ asset_id: string }>
  ): EntryPointAssessment[] {
    return entryPoints.map(ep => ({
      asset_id: ep.asset_id,
      is_valid_entry: true,
      validity_score: 0.7,
      attacker_value: 'Initial access point',
      why_attacker_would_choose: 'Internet-facing vulnerability',
      alternative_entries: [],
      confidence: 0.7
    }))
  }

  /**
   * STEP 2: Validate Exit Points (Targets)
   * LLM evaluates if targets make sense from attacker perspective
   */
  async validateExitPoints(
    exitPoints: Array<{
      asset_id: string
      asset_name: string
      asset_type: string
      zone: string
      criticality: number
      data_sensitivity: string
      services: string[]
    }>,
    attackerProfile: AttackerProfile
  ): Promise<ExitPointAssessment[]> {
    if (!this.zai) await this.initialize()

    const prompt = this.buildExitValidationPrompt(exitPoints, attackerProfile)

    const response = await this.zai.chat.completions.create({
      messages: [
        {
          role: 'system',
          content: `You are a senior red team operator specializing in target value assessment.
You understand what assets attackers value most and why.
Consider data exfiltration, ransomware, espionage, and disruption scenarios.
Always respond in valid JSON format.`
        },
        {
          role: 'user',
          content: prompt
        }
      ],
      temperature: this.modelConfig.temperature,
      max_tokens: this.modelConfig.max_tokens
    })

    const content = response.choices[0]?.message?.content || ''
    return this.parseExitAssessments(content, exitPoints)
  }

  private buildExitValidationPrompt(
    exitPoints: Array<{
      asset_id: string
      asset_name: string
      asset_type: string
      zone: string
      criticality: number
      data_sensitivity: string
      services: string[]
    }>,
    attackerProfile: AttackerProfile
  ): string {
    const targets = exitPoints.map((ep, i) => 
      `${i + 1}. ${ep.asset_name} (${ep.asset_type})
         - Zone: ${ep.zone}
         - Criticality: ${ep.criticality}/5
         - Data Sensitivity: ${ep.data_sensitivity}
         - Services: ${ep.services?.join(', ') || 'Unknown'}`
    ).join('\n')

    return `You are evaluating potential attack targets from an attacker's perspective.

ATTACKER PROFILE:
- Type: ${attackerProfile.type}
- Motivation: ${attackerProfile.motivation}
- Resources: ${attackerProfile.resources}

POTENTIAL TARGETS:
${targets}

For each target, evaluate:
1. Would this be a valuable target for this attacker type?
2. What goal would the attacker achieve?
3. What is the data value?

Respond in JSON format:
{
  "assessments": [
    {
      "asset_id": "asset_id_here",
      "is_valid_target": true/false,
      "validity_score": 0.0-1.0,
      "attacker_goal": "what attacker achieves",
      "why_attacker_would_target": "reasoning",
      "data_value": "value of data/asset",
      "alternative_targets": ["better targets if any"],
      "confidence": 0.0-1.0
    }
  ]
}`
  }

  private parseExitAssessments(
    content: string,
    exitPoints: Array<{ asset_id: string }>
  ): ExitPointAssessment[] {
    try {
      const jsonMatch = content.match(/\{[\s\S]*\}/)
      if (!jsonMatch) {
        return this.getDefaultExitAssessments(exitPoints)
      }

      const parsed = JSON.parse(jsonMatch[0])
      const assessments = parsed.assessments || []

      return exitPoints.map((ep, i) => {
        const assessment = assessments[i] || {}
        return {
          asset_id: ep.asset_id,
          is_valid_target: assessment.is_valid_target ?? true,
          validity_score: assessment.validity_score ?? 0.7,
          attacker_goal: assessment.attacker_goal || 'Data exfiltration',
          why_attacker_would_target: assessment.why_attacker_would_target || 'High-value asset',
          data_value: assessment.data_value || 'Business-critical data',
          alternative_targets: assessment.alternative_targets || [],
          confidence: assessment.confidence ?? 0.8
        }
      })
    } catch (e) {
      return this.getDefaultExitAssessments(exitPoints)
    }
  }

  private getDefaultExitAssessments(
    exitPoints: Array<{ asset_id: string }>
  ): ExitPointAssessment[] {
    return exitPoints.map(ep => ({
      asset_id: ep.asset_id,
      is_valid_target: true,
      validity_score: 0.7,
      attacker_goal: 'Data exfiltration',
      why_attacker_would_target: 'High-value asset',
      data_value: 'Business-critical data',
      alternative_targets: [],
      confidence: 0.7
    }))
  }

  /**
   * STEP 3: Assess Path Realism
   * LLM evaluates if the entire attack path makes sense
   */
  async assessPathRealism(
    path: {
      nodes: Array<{
        asset_name: string
        asset_type: string
        zone: string
        misconfig_title: string
      }>
      edges: Array<{
        technique: string
        edge_type: string
        probability: number
      }>
    },
    attackerProfile: AttackerProfile
  ): Promise<PathRealismAssessment> {
    if (!this.zai) await this.initialize()

    const prompt = this.buildPathRealismPrompt(path, attackerProfile)

    const response = await this.zai.chat.completions.create({
      messages: [
        {
          role: 'system',
          content: `You are a senior red team operator and MITRE ATT&CK expert.
You evaluate attack paths for realism based on:
1. Attacker behavior patterns
2. MITRE ATT&CK framework alignment
3. Technical feasibility
4. Risk/reward trade-offs
Always respond in valid JSON format.`
        },
        {
          role: 'user',
          content: prompt
        }
      ],
      temperature: this.modelConfig.temperature,
      max_tokens: this.modelConfig.max_tokens
    })

    const content = response.choices[0]?.message?.content || ''
    return this.parsePathAssessment(content, path)
  }

  private buildPathRealismPrompt(
    path: {
      nodes: Array<{
        asset_name: string
        asset_type: string
        zone: string
        misconfig_title: string
      }>
      edges: Array<{
        technique: string
        edge_type: string
        probability: number
      }>
    },
    attackerProfile: AttackerProfile
  ): string {
    const pathDescription = path.nodes.map((node, i) => {
      const edge = path.edges[i - 1]
      const edgeDesc = edge ? `\n   └─ via ${edge.technique} (${edge.edge_type}, P=${edge.probability.toFixed(2)})` : ''
      return `Step ${i + 1}: ${node.asset_name} (${node.asset_type}) [${node.zone}]${edgeDesc}
   └─ Vulnerability: ${node.misconfig_title}`
    }).join('\n')

    return `Evaluate this attack path for realism:

ATTACKER PROFILE:
- Type: ${attackerProfile.type}
- Skill Level: ${attackerProfile.skill_level}
- Motivation: ${attackerProfile.motivation}

ATTACK PATH:
${pathDescription}

Evaluate:
1. Is the entry point realistic for this attacker?
2. Is the target (final node) valuable enough?
3. Do the attack phases follow realistic progression?
4. Are the skill requirements consistent?
5. Can detection be realistically evaded?

Respond in JSON format:
{
  "overall_realism": 0.0-1.0,
  "entry_valid": true/false,
  "exit_valid": true/false,
  "attack_phases_realistic": true/false,
  "skill_requirements_realistic": true/false,
  "detection_evasion_realistic": true/false,
  "improvements": ["suggested improvements"],
  "narrative": "Step-by-step attack narrative from attacker's perspective",
  "confidence": 0.0-1.0
}`
  }

  private parsePathAssessment(
    content: string,
    path: { nodes: any[] }
  ): PathRealismAssessment {
    try {
      const jsonMatch = content.match(/\{[\s\S]*\}/)
      if (!jsonMatch) {
        return this.getDefaultPathAssessment()
      }

      const parsed = JSON.parse(jsonMatch[0])

      return {
        path_id: `path-${Date.now()}`,
        overall_realism: parsed.overall_realism ?? 0.7,
        entry_valid: parsed.entry_valid ?? true,
        exit_valid: parsed.exit_valid ?? true,
        attack_phases_realistic: parsed.attack_phases_realistic ?? true,
        skill_requirements_realistic: parsed.skill_requirements_realistic ?? true,
        detection_evasion_realistic: parsed.detection_evasion_realistic ?? true,
        improvements: parsed.improvements || [],
        narrative: parsed.narrative || 'Attack path follows logical progression',
        confidence: parsed.confidence ?? 0.8
      }
    } catch (e) {
      return this.getDefaultPathAssessment()
    }
  }

  private getDefaultPathAssessment(): PathRealismAssessment {
    return {
      path_id: `path-${Date.now()}`,
      overall_realism: 0.7,
      entry_valid: true,
      exit_valid: true,
      attack_phases_realistic: true,
      skill_requirements_realistic: true,
      detection_evasion_realistic: true,
      improvements: [],
      narrative: 'Attack path follows logical progression',
      confidence: 0.7
    }
  }

  /**
   * STEP 4: Generate Attack Narrative
   * LLM creates detailed attack scenario description
   */
  async generateAttackNarrative(
    path: {
      nodes: Array<{
        asset_name: string
        asset_type: string
        zone: string
        misconfig_title: string
        criticality: number
      }>
      edges: Array<{
        technique: string
        edge_type: string
      }>
    },
    attackerProfile: AttackerProfile
  ): Promise<string> {
    if (!this.zai) await this.initialize()

    const pathSummary = path.nodes.map((node, i) => {
      const edge = path.edges[i - 1]
      return `${i + 1}. ${node.asset_name} (${node.zone}) - ${node.misconfig_title}`
    }).join('\n')

    const response = await this.zai.chat.completions.create({
      messages: [
        {
          role: 'system',
          content: `You are a cybersecurity analyst who writes clear, engaging attack narratives.
Describe attacks from the perspective of how they unfold, not just technical steps.
Include attacker mindset, decisions, and contingencies.`
        },
        {
          role: 'user',
          content: `Write a realistic attack narrative for this path:

Attacker: ${attackerProfile.type} with ${attackerProfile.skill_level} skills
Motivation: ${attackerProfile.motivation}

Attack Path:
${pathSummary}

Write a 2-3 paragraph narrative describing how this attack would unfold from start to finish.
Include:
- Why the attacker chooses this path
- Key decisions and pivots
- How they evade detection
- What they achieve at the end`
        }
      ],
      temperature: 0.5,
      max_tokens: 1000
    })

    return response.choices[0]?.message?.content || 'Unable to generate narrative'
  }

  /**
   * Batch assess multiple paths efficiently
   */
  async batchAssessPaths(
    paths: Array<{
      nodes: Array<{
        asset_name: string
        asset_type: string
        zone: string
        misconfig_title: string
      }>
      edges: Array<{
        technique: string
        edge_type: string
        probability: number
      }>
    }>,
    attackerProfile: AttackerProfile,
    maxConcurrent: number = 3
  ): Promise<PathRealismAssessment[]> {
    const results: PathRealismAssessment[] = []
    
    // Process in batches to avoid rate limits
    for (let i = 0; i < paths.length; i += maxConcurrent) {
      const batch = paths.slice(i, i + maxConcurrent)
      const batchResults = await Promise.all(
        batch.map(path => this.assessPathRealism(path, attackerProfile))
      )
      results.push(...batchResults)
    }
    
    return results
  }
}

// ============================================================================
// INTEGRATED REALISM ENGINE
// ============================================================================

export class IntegratedRealismEngine {
  private llmAnalyzer: LLMAttackAnalyzer

  constructor() {
    this.llmAnalyzer = new LLMAttackAnalyzer()
  }

  async initialize(): Promise<void> {
    await this.llmAnalyzer.initialize()
  }

  /**
   * Complete realism validation pipeline
   * This ensures paths are realistic from attacker perspective
   */
  async validatePathRealism(
    paths: RealisticAttackPath[],
    assets: Array<{
      id: string
      name: string
      type: string
      zone: string
      criticality: number
      internet_facing: boolean
      data_sensitivity: string
      services: string[]
      misconfigurations: Array<{ id: string; title: string }>
    }>,
    attackerProfile: AttackerProfile = {
      type: 'targeted',
      skill_level: 'advanced',
      motivation: 'espionage',
      resources: 'high',
      risk_tolerance: 'medium'
    }
  ): Promise<RealisticAttackPath[]> {
    // Step 1: Identify entry and exit points
    const entryPoints = this.identifyEntryPoints(paths, assets)
    const exitPoints = this.identifyExitPoints(paths, assets)

    // Step 2: Validate entry points with LLM
    const entryAssessments = await this.llmAnalyzer.validateEntryPoints(
      entryPoints,
      { total_assets: assets.length, dmz_assets: assets.filter(a => a.zone === 'dmz').length, internet_exposed_count: assets.filter(a => a.internet_facing).length },
      attackerProfile
    )

    // Step 3: Validate exit points with LLM
    const exitAssessments = await this.llmAnalyzer.validateExitPoints(exitPoints, attackerProfile)

    // Step 4: Create lookup maps
    const entryMap = new Map(entryAssessments.map(e => [e.asset_id, e]))
    const exitMap = new Map(exitAssessments.map(e => [e.asset_id, e]))

    // Step 5: Assess each path for realism
    const validatedPaths: RealisticAttackPath[] = []

    for (const path of paths) {
      const entryAssetId = path.nodes[0]?.asset_id
      const exitAssetId = path.nodes[path.nodes.length - 1]?.asset_id

      const entryAssessment = entryMap.get(entryAssetId)
      const exitAssessment = exitMap.get(exitAssetId)

      // Skip paths with invalid entry/exit
      if (entryAssessment && !entryAssessment.is_valid_entry) {
        continue  // Attacker wouldn't choose this entry
      }

      if (exitAssessment && !exitAssessment.is_valid_target) {
        continue  // Target doesn't provide value to attacker
      }

      // Assess full path realism
      const pathAssessment = await this.llmAnalyzer.assessPathRealism(
        {
          nodes: path.nodes.map(n => ({
            asset_name: n.asset_name,
            asset_type: assets.find(a => a.id === n.asset_id)?.type || 'unknown',
            zone: n.zone,
            misconfig_title: n.misconfig_title
          })),
          edges: path.edges
        },
        attackerProfile
      )

      // Skip unrealistic paths
      if (pathAssessment.overall_realism < 0.5) {
        continue
      }

      // Generate narrative for realistic paths
      const narrative = await this.llmAnalyzer.generateAttackNarrative(
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
        attackerProfile
      )

      // Update path with LLM insights
      const validatedPath: RealisticAttackPath = {
        ...path,
        realism_score: (path.realism_score + pathAssessment.overall_realism) / 2,
        narrative: narrative,
        // Add LLM-derived metadata
        business_impact: this.computeLLMEnhancedImpact(path, exitAssessment)
      }

      validatedPaths.push(validatedPath)
    }

    // Sort by realism score
    return validatedPaths.sort((a, b) => b.realism_score - a.realism_score)
  }

  private identifyEntryPoints(
    paths: RealisticAttackPath[],
    assets: Array<{ id: string; name: string; type: string; zone: string; criticality: number; internet_facing: boolean; misconfigurations: Array<{ id: string; title: string }> }>
  ): Array<{
    asset_id: string
    asset_name: string
    asset_type: string
    zone: string
    misconfig_title: string
    internet_facing: boolean
    criticality: number
  }> {
    const entryAssetIds = new Set(paths.map(p => p.nodes[0]?.asset_id))
    
    return Array.from(entryAssetIds)
      .map(id => {
        const asset = assets.find(a => a.id === id)
        if (!asset) return null
        
        // Get first misconfig for entry point
        const misconfig = asset.misconfigurations[0]
        
        return {
          asset_id: asset.id,
          asset_name: asset.name,
          asset_type: asset.type,
          zone: asset.zone,
          misconfig_title: misconfig?.title || 'Unknown',
          internet_facing: asset.internet_facing,
          criticality: asset.criticality
        }
      })
      .filter((ep): ep is NonNullable<typeof ep> => ep !== null)
  }

  private identifyExitPoints(
    paths: RealisticAttackPath[],
    assets: Array<{ id: string; name: string; type: string; zone: string; criticality: number; data_sensitivity: string; services: string[] }>
  ): Array<{
    asset_id: string
    asset_name: string
    asset_type: string
    zone: string
    criticality: number
    data_sensitivity: string
    services: string[]
  }> {
    const exitAssetIds = new Set(paths.map(p => p.nodes[p.nodes.length - 1]?.asset_id))
    
    return Array.from(exitAssetIds)
      .map(id => {
        const asset = assets.find(a => a.id === id)
        if (!asset) return null
        
        return {
          asset_id: asset.id,
          asset_name: asset.name,
          asset_type: asset.type,
          zone: asset.zone,
          criticality: asset.criticality,
          data_sensitivity: asset.data_sensitivity || 'unknown',
          services: asset.services || []
        }
      })
      .filter((ep): ep is NonNullable<typeof ep> => ep !== null)
  }

  private computeLLMEnhancedImpact(
    path: RealisticAttackPath,
    exitAssessment?: ExitPointAssessment
  ): number {
    let impact = path.business_impact

    if (exitAssessment) {
      // Enhance impact based on LLM assessment of target value
      impact *= exitAssessment.validity_score
    }

    return Math.min(impact, 100)
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export { LLMAttackAnalyzer, AttackerProfile }
