import { NextRequest, NextResponse } from 'next/server'

const OLLAMA_URL = process.env.OLLAMA_URL || 'http://localhost:11434'
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'mistral:7b'

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
    // Prepare attack path summaries for the prompt
    const pathSummaries = (attackPaths || []).slice(0, 5).map((path: any, i: number) => {
      const steps = (path.nodes || []).map((n: any, idx: number) => 
        `${idx + 1}. ${n.assetName}: ${n.vulnTitle} (${n.killChainPhase}, Risk: ${n.risk?.toFixed(1)}, KEV: ${n.cisaKev ? 'YES' : 'NO'})`
      ).join('\n')
      return `PATH ${i + 1} (Risk: ${path.riskScore}/10, Prob: ${((path.attackProbability || 0) * 100).toFixed(2)}%):\n${steps}`
    }).join('\n\n')

    const kevFindings = findings.filter((f: any) => f.cisaKev)
    const ransomwareFindings = findings.filter((f: any) => f.ransomware)
    const internetFacingFindings = findings.filter((f: any) => f.internetFacing)

    const prompt = `You are a senior cybersecurity analyst. Analyze this vulnerability scan and provide comprehensive security intelligence. Respond ONLY with valid JSON.

SCAN SUMMARY:
- Total Findings: ${findings.length}
- Critical: ${findings.filter((f: any) => f.severity === 'critical').length}
- High: ${findings.filter((f: any) => f.severity === 'high').length}
- Internet-Facing: ${internetFacingFindings.length}
- CISA KEV (Known Exploited): ${kevFindings.length}
- Ransomware-Related: ${ransomwareFindings.length}

TOP RISK ASSETS:
${(topAssets || []).slice(0, 8).map((a: any) => `- ${a.assetName}: Risk ${a.avgRisk?.toFixed(1)}/10`).join('\n')}

INTERNET-FACING KEV VULNS:
${kevFindings.filter((f: any) => f.internetFacing).slice(0, 5).map((f: any) => `- ${f.assetName}: ${f.vulnTitle}`).join('\n') || 'None'}

ATTACK PATHS DISCOVERED:
${pathSummaries || 'None'}

Respond with this EXACT JSON structure (no markdown, no explanation):
{
  "correlations": [
    {"type": "threat_category", "title": "specific title", "description": "detailed description with specific assets/vulns", "affectedAssets": ["asset1", "asset2"], "riskAmplification": 8, "recommendation": "specific action"}
  ],
  "insights": [
    {"category": "strategic", "insight": "specific actionable insight", "confidence": 0.9, "impact": "high"}
  ],
  "topRemediationActions": [
    {"action": "specific action", "affectedFindings": 10, "riskReduction": 30, "effort": "medium"}
  ],
  "pathAnalyses": [
    {
      "pathId": 1,
      "summary": "one sentence summary",
      "attackScenario": "detailed step-by-step attack scenario",
      "businessImpact": "business impact analysis",
      "remediation": ["action 1", "action 2", "action 3"]
    }
  ]
}

Analyze ALL attack paths. Be specific with asset names and vulnerabilities. Focus on real security impact.`

    console.log('API: Sending single LLM request...')
    const startTime = Date.now()
    
    const ollamaResponse = await fetch(`${OLLAMA_URL}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: OLLAMA_MODEL,
        prompt,
        stream: false,
        options: {
          num_predict: 3000,
          temperature: 0.1,
          top_p: 0.9
        }
      }),
      signal: AbortSignal.timeout(180000)
    })

    if (!ollamaResponse.ok) {
      throw new Error(`Ollama request failed: ${ollamaResponse.status}`)
    }

    const result = await ollamaResponse.json()
    const responseText = result.response || ''
    
    // Extract JSON from response
    const jsonMatch = responseText.match(/\{[\s\S]*\}/)
    if (!jsonMatch) {
      throw new Error('No valid JSON in LLM response')
    }
    
    const analysis = JSON.parse(jsonMatch[0])
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1)
    console.log(`API: Analysis complete in ${elapsed}s`)
    
    return NextResponse.json({
      correlations: analysis.correlations || [],
      insights: analysis.insights || [],
      topRemediationActions: analysis.topRemediationActions || [],
      pathAnalyses: analysis.pathAnalyses || []
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
