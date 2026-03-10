import { NextResponse } from 'next/server'

export async function GET() {
  const OPENROUTER_API_KEY = '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'
  const OPENROUTER_MODEL = 'stepfun/step-3.5-flash:free'
  
  const prompt = `Output this exact JSON: [{"idx":1,"prob":0.7,"tech":"T1021","creds":["admin"],"why":"test"}]`
  
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
        temperature: 0.1,
        max_tokens: 1000
      })
    })
    
    const data = await response.json()
    const content = data.choices?.[0]?.message?.content || ''
    
    let parsed = null
    try {
      parsed = JSON.parse(content)
    } catch {
      const match = content.match(/\[[\s\S]*\]/)
      if (match) {
        try { parsed = JSON.parse(match[0]) } catch {}
      }
    }
    
    return NextResponse.json({
      status: response.status,
      contentLength: content.length,
      contentPreview: content.substring(0, 200),
      parsed
    })
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 })
  }
}
