import { NextRequest, NextResponse } from 'next/server'

// Intelligent security analysis without external LLM
// Uses domain knowledge and heuristics to generate insights

export async function POST(request: NextRequest) {
  let body: any = {}
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ correlations: [], insights: [], topRemediationActions: [], pathAnalyses: [] })
  }
  
  const { findings, topAssets, attackPaths, graphMetrics } = body

  if (!findings || findings.length === 0) {
    return NextResponse.json({ correlations: [], insights: [], topRemediationActions: [], pathAnalyses: [] })
  }

  console.log('API: Analyzing', findings.length, 'findings and', attackPaths?.length || 0, 'attack paths')

  try {
    // Extract key statistics
    const kevFindings = findings.filter((f: any) => f.cisaKev)
    const ransomwareFindings = findings.filter((f: any) => f.ransomware)
    const internetFacingFindings = findings.filter((f: any) => f.internetFacing)
    const criticalFindings = findings.filter((f: any) => f.severity === 'critical')
    const highFindings = findings.filter((f: any) => f.severity === 'high')
    
    // Group findings by kill chain phase
    const killChainGroups: Record<string, any[]> = {}
    findings.forEach((f: any) => {
      const phase = f.killChainPhase || 'unknown'
      if (!killChainGroups[phase]) killChainGroups[phase] = []
      killChainGroups[phase].push(f)
    })
    
    // Group by network zone
    const zoneGroups: Record<string, any[]> = {}
    findings.forEach((f: any) => {
      const zone = f.networkZone || 'unknown'
      if (!zoneGroups[zone]) zoneGroups[zone] = []
      zoneGroups[zone].push(f)
    })

    // Generate correlations
    const correlations = []
    
    // KEV + Internet-facing correlation
    const kevInternetFacing = kevFindings.filter((f: any) => f.internetFacing)
    if (kevInternetFacing.length > 0) {
      correlations.push({
        type: 'critical_exposure',
        title: 'Known Exploited Vulnerabilities Exposed to Internet',
        description: `${kevInternetFacing.length} CISA Known Exploited Vulnerabilities (KEV) are on internet-facing assets. These are actively weaponized by threat actors and represent immediate risk of initial access. Affected assets: ${kevInternetFacing.slice(0, 5).map((f: any) => f.assetName).join(', ')}.`,
        affectedAssets: kevInternetFacing.slice(0, 10).map((f: any) => f.assetName),
        riskAmplification: 10,
        recommendation: 'Immediately patch or isolate affected assets. If patching is not possible, implement compensating controls such as WAF rules or network segmentation.'
      })
    }
    
    // Ransomware + KEV correlation
    const ransomwareKEV = kevFindings.filter((f: any) => f.ransomware)
    if (ransomwareKEV.length > 0) {
      correlations.push({
        type: 'ransomware_risk',
        title: 'Ransomware-Associated Vulnerabilities Detected',
        description: `${ransomwareKEV.length} vulnerabilities are both in CISA KEV and associated with ransomware campaigns. These are top-priority targets for ransomware operators. This significantly increases the risk of data encryption and extortion.`,
        affectedAssets: ransomwareKEV.slice(0, 10).map((f: any) => f.assetName),
        riskAmplification: 9,
        recommendation: 'Prioritize patching these vulnerabilities. Ensure backup systems are offline and tested. Implement ransomware detection and response playbooks.'
      })
    }
    
    // DMZ + High Risk correlation
    const dmzCritical = findings.filter((f: any) => f.networkZone === 'dmz' && f.severity === 'critical')
    if (dmzCritical.length > 0) {
      correlations.push({
        type: 'perimeter_risk',
        title: 'Critical Vulnerabilities in DMZ',
        description: `${dmzCritical.length} critical vulnerabilities in the DMZ represent direct exposure to external threats. Attackers can exploit these to establish an initial foothold without needing to bypass perimeter controls.`,
        affectedAssets: [...new Set(dmzCritical.slice(0, 10).map((f: any) => f.assetName))],
        riskAmplification: 9,
        recommendation: 'Patch DMZ assets immediately. Consider implementing additional network monitoring and intrusion detection for the DMZ segment.'
      })
    }
    
    // Lateral movement chain
    const lateralMovement = killChainGroups['lateral_movement'] || []
    if (lateralMovement.length > 3) {
      correlations.push({
        type: 'lateral_movement',
        title: 'Lateral Movement Vulnerability Cluster',
        description: `${lateralMovement.length} vulnerabilities could enable lateral movement through the network. Combined with initial access vulnerabilities, this creates complete attack paths to critical assets.`,
        affectedAssets: [...new Set(lateralMovement.slice(0, 10).map((f: any) => f.assetName))],
        riskAmplification: 8,
        recommendation: 'Implement network segmentation to limit lateral movement. Enable enhanced logging for authentication events. Consider deploying deception technology.'
      })
    }
    
    // Privilege escalation chain
    const privEsc = killChainGroups['privilege_escalation'] || []
    if (privEsc.length > 2) {
      correlations.push({
        type: 'privilege_escalation',
        title: 'Privilege Escalation Attack Surface',
        description: `${privEsc.length} privilege escalation vulnerabilities detected. Attackers who gain initial access can use these to elevate privileges and access restricted resources.`,
        affectedAssets: [...new Set(privEsc.slice(0, 10).map((f: any) => f.assetName))],
        riskAmplification: 7,
        recommendation: 'Review and minimize local admin rights. Implement Privileged Access Management (PAM). Enable User Account Control (UAC) where applicable.'
      })
    }

    // Generate insights
    const insights = []
    
    // Risk concentration insight
    if (topAssets && topAssets.length > 0) {
      const topAssetRisk = topAssets.slice(0, 3).reduce((sum: number, a: any) => sum + (a.avgRisk || 0), 0)
      if (topAssetRisk > 20) {
        insights.push({
          category: 'risk_concentration',
          insight: `Top 3 highest-risk assets have a combined risk score of ${topAssetRisk.toFixed(1)}. This concentration of risk indicates these assets should be prioritized for immediate remediation.`,
          confidence: 0.95,
          impact: 'high'
        })
      }
    }
    
    // Attack path insight
    if (attackPaths && attackPaths.length > 0) {
      const avgPathLength = attackPaths.reduce((sum: number, p: any) => sum + p.nodes.length, 0) / attackPaths.length
      const highProbPaths = attackPaths.filter((p: any) => p.attackProbability > 0.5).length
      insights.push({
        category: 'attack_paths',
        insight: `${attackPaths.length} distinct attack paths discovered with average length of ${avgPathLength.toFixed(1)} steps. ${highProbPaths} paths have >50% attack probability. This indicates adversaries have multiple routes to compromise critical assets.`,
        confidence: 0.9,
        impact: 'high'
      })
    }
    
    // KEV coverage insight
    const kevPatchRate = kevFindings.length > 0 ? 
      ((kevFindings.length - kevInternetFacing.length) / kevFindings.length * 100).toFixed(0) : '100'
    insights.push({
      category: 'threat_intelligence',
      insight: `${kevFindings.length} CISA KEV vulnerabilities detected. ${kevInternetFacing.length} are internet-facing. Organizations should patch KEV vulnerabilities within 2 weeks per CISA guidelines.`,
      confidence: 0.95,
      impact: 'high'
    })
    
    // Blast radius insight
    if (graphMetrics?.avgBlastRadius > 0) {
      insights.push({
        category: 'blast_radius',
        insight: `Average blast radius score of ${(graphMetrics.avgBlastRadius * 1000).toFixed(2)} indicates potential for rapid threat propagation. High blast radius assets are convergence points for multiple attack paths.`,
        confidence: 0.85,
        impact: 'medium'
      })
    }

    // Generate remediation actions
    const topRemediationActions = []
    
    // Always prioritize KEV
    if (kevFindings.length > 0) {
      topRemediationActions.push({
        action: `Patch ${kevFindings.length} CISA Known Exploited Vulnerabilities (KEV) across ${new Set(kevFindings.map((f: any) => f.assetName)).size} assets`,
        affectedFindings: kevFindings.length,
        riskReduction: 40,
        effort: 'high'
      })
    }
    
    // Internet-facing remediation
    if (internetFacingFindings.length > 0) {
      topRemediationActions.push({
        action: `Remediate ${internetFacingFindings.length} vulnerabilities on internet-facing assets`,
        affectedFindings: internetFacingFindings.length,
        riskReduction: 30,
        effort: 'medium'
      })
    }
    
    // Network segmentation
    if (dmzCritical.length > 0 || (zoneGroups['internal']?.filter((f: any) => f.internetFacing).length > 0)) {
      topRemediationActions.push({
        action: 'Implement network segmentation to isolate critical assets from DMZ and internet-facing systems',
        affectedFindings: (dmzCritical.length + (zoneGroups['internal']?.filter((f: any) => f.internetFacing).length || 0)),
        riskReduction: 25,
        effort: 'high'
      })
    }
    
    // Lateral movement controls
    if (lateralMovement.length > 0) {
      topRemediationActions.push({
        action: `Address ${lateralMovement.length} lateral movement vulnerabilities and implement micro-segmentation`,
        affectedFindings: lateralMovement.length,
        riskReduction: 20,
        effort: 'medium'
      })
    }

    // Generate path analyses
    const pathAnalyses = (attackPaths || []).slice(0, 10).map((path: any, idx: number) => {
      const nodes = path.nodes || []
      const entryNode = nodes[0]
      const targetNode = nodes[nodes.length - 1]
      
      // Generate attack scenario based on path
      let attackScenario = `Starting from ${entryNode?.assetName || 'unknown'}, an attacker exploits ${entryNode?.vulnTitle || 'a vulnerability'} for initial access. `
      
      if (nodes.length > 1) {
        nodes.slice(1).forEach((n: any, i: number) => {
          const phase = n.killChainPhase?.replace('_', ' ') || 'compromise'
          attackScenario += `Using the foothold, they proceed to ${phase} on ${n.assetName} via ${n.vulnTitle}. `
        })
      }
      
      attackScenario += `This attack chain has ${(path.attackProbability * 100).toFixed(1)}% probability of success based on EPSS scores and network reachability.`
      
      // Business impact based on target
      const businessImpact = targetNode ? 
        `Compromise of ${targetNode.assetName} could lead to data exfiltration, service disruption, or lateral movement to additional critical systems. The target has risk score ${targetNode.risk?.toFixed(1) || 'unknown'}/10.` :
        'Successful exploitation could result in unauthorized access to sensitive systems and data.'
      
      // Remediation based on path vulnerabilities
      const remediation = []
      const kevNodes = nodes.filter((n: any) => n.cisaKev)
      if (kevNodes.length > 0) {
        remediation.push(`Patch KEV vulnerabilities: ${kevNodes.map((n: any) => n.vulnTitle).join(', ')}`)
      }
      remediation.push('Implement network segmentation between entry point and target')
      remediation.push('Deploy enhanced monitoring and detection for this attack path')
      if (nodes.some((n: any) => n.killChainPhase === 'lateral_movement')) {
        remediation.push('Restrict lateral movement with micro-segmentation and enhanced authentication')
      }
      
      return {
        pathId: idx + 1,
        summary: `${nodes.length}-step attack path from ${entryNode?.assetName || 'entry'} to ${targetNode?.assetName || 'target'} via ${nodes.map((n: any) => n.vulnTitle).join(' → ')}`,
        attackScenario,
        businessImpact,
        remediation
      }
    })

    console.log('API: Analysis complete')
    
    return NextResponse.json({
      correlations: correlations.slice(0, 5),
      insights: insights.slice(0, 5),
      topRemediationActions: topRemediationActions.slice(0, 4),
      pathAnalyses
    })

  } catch (error) {
    console.error('API: Analysis error:', error)
    return NextResponse.json({
      error: true,
      message: error instanceof Error ? error.message : 'Analysis failed',
      correlations: [],
      insights: [],
      topRemediationActions: [],
      pathAnalyses: []
    })
  }
}
