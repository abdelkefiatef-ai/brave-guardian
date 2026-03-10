import { NextResponse } from 'next/server'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

// OpenRouter configuration
const OPENROUTER_API_KEY = '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'
const OPENROUTER_MODEL = 'stepfun/step-3.5-flash:free'
const OPENROUTER_BASE_URL = 'https://openrouter.ai/api/v1'

// Check if LLM is available
async function checkLLMStatus(): Promise<{ available: boolean; message: string }> {
  try {
    const response = await fetch(`${OPENROUTER_BASE_URL}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
        'HTTP-Referer': 'https://brave-guardian.ai',
        'X-Title': 'Brave Guardian'
      },
      body: JSON.stringify({
        model: OPENROUTER_MODEL,
        messages: [{ role: 'user', content: 'test' }],
        max_tokens: 5
      })
    })
    
    if (response.ok) {
      return { available: true, message: 'OpenRouter LLM is available' }
    }
    
    const errorText = await response.text()
    
    if (response.status === 401 || response.status === 403) {
      return { available: false, message: 'OpenRouter authentication failed - check API key' }
    }
    
    return { available: false, message: `OpenRouter error: ${response.status}` }
  } catch (error) {
    return { available: false, message: `Connection error: ${error instanceof Error ? error.message : 'Unknown'}` }
  }
}

export async function GET() {
  const status = await checkLLMStatus()
  
  return NextResponse.json({
    llm: status,
    patternAnalysis: {
      available: true,
      message: 'Pattern-based analysis always available'
    },
    config: {
      provider: 'OpenRouter',
      model: OPENROUTER_MODEL,
      endpoint: OPENROUTER_BASE_URL
    }
  })
}
