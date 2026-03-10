import { NextResponse } from 'next/server'

const OPENROUTER_API_KEY = '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'
const OPENROUTER_MODEL = 'stepfun/step-3.5-flash:free'

export async function GET() {
  const prompt = `Evaluate attack pivots. Output JSON array only.

[1] WEB-DMZ01→APP-PRD01 | RDP Exposed→Stale Service Account | crit:4
[2] WEB-DMZ01→DC-RESTR01 | RDP Exposed→Kerberos Pre-Auth Disabled | crit:5

JSON format: [{"idx":1,"prob":0.7,"tech":"T1021","creds":["admin"],"why":"reason"}]
Reject if source tier > target tier.`

  try {
    const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
        'HTTP-Referer': 'https://brave-guardian.ai',
        'X-Title': 'Brave Guardian'
      },
      body: JSON.stringify({
        model: OPENROUTER_MODEL,
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.3,
        max_tokens: 6000
      })
    })

    const data = await response.json()
    
    // Log the full response structure
    const msg = data.choices?.[0]?.message || {}
    
    // Handle stepfun's response format - check both content and reasoning
    let content = msg.content || ''
    const reasoning = msg.reasoning || ''
    
    // Parse JSON from whichever field has it
    let parsed = null
    let source = ''
    
    // Try content first
    if (content) {
      try {
        parsed = JSON.parse(content)
        source = 'content'
      } catch (e) {
        const match = content.match(/\[[\s\S]*\]/)
        if (match) {
          try {
            parsed = JSON.parse(match[0])
            source = 'content (regex)'
          } catch {}
        }
      }
    }
    
    // If not found in content, try reasoning (might have JSON at end)
    if (!parsed && reasoning) {
      const match = reasoning.match(/\[[\s\S]*\]/g)
      if (match) {
        // Try each match from longest to shortest
        for (const m of match.sort((a, b) => b.length - a.length)) {
          try {
            parsed = JSON.parse(m)
            source = 'reasoning (regex)'
            break
          } catch {}
        }
      }
    }

    return NextResponse.json({
      success: true,
      hasContent: !!content,
      contentLength: content.length,
      reasoningLength: reasoning.length,
      parsed: parsed,
      source: source,
      contentPreview: content.substring(0, 300),
      reasoningPreview: reasoning.substring(0, 300)
    })
  } catch (error: any) {
    return NextResponse.json({
      success: false,
      error: error.message
    })
  }
}
