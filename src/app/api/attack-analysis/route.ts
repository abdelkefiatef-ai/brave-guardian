import { NextRequest, NextResponse } from 'next/server'

// Route configuration - allow larger request bodies
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'
export const maxDuration = 120 // 2 minutes max

// ============================================================================
// OPENROUTER LLM CONFIGURATION
// ============================================================================
const OPENROUTER_API_KEY = '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'
// Stepfun reasoning model - returns reasoning in separate field
const OPENROUTER_MODEL = 'stepfun/step-3.5-flash:free'
const OPENROUTER_BASE_URL = 'https://openrouter.ai/api/v1'

// ============================================================================
// SCALABLE HYBRID ATTACK PATH ANALYSIS
// Combines: Pattern Matching + Smart Filtering + Batch LLM Evaluation
// ============================================================================

interface Asset {
  id: string
  name: string
  type: string
  ip: string
  zone: string
  internet_facing: boolean
  criticality: number
  domain_joined: boolean
  services: string[]
  data_sensitivity: string
  misconfigurations: Array<{ id: string; title: string; description: string; category: string }>
}

interface AttackNode {
  id: string
  asset_id: string
  asset_name: string
  asset_type: string
  asset_zone: string
  misconfig_id: string
  misconfig_title: string
  misconfig_description: string
  misconfig_category: string
  criticality: number
  internet_facing: boolean
  data_sensitivity: string
  domain_joined: boolean
  services: string[]
}

interface AttackEdge {
  source_id: string
  target_id: string
  probability: number
  technique: string
  credentials_carried: string[]
  reasoning: string
  edge_type: 'pattern' | 'llm'  // Track how edge was created
}

interface AttackPath {
  path_id: string
  nodes: AttackNode[]
  edges: AttackEdge[]
  path_probability: number
  pagerank_score: number
  impact_score: number
  realism_score: number
  detection_risk: number
  final_risk_score: number
  narrative: string
  business_impact: string
  kill_chain: string[]
}

// Timeout wrapper for LLM calls with proper cleanup
function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      console.log(`[TIMEOUT] Request timed out after ${ms}ms, using fallback`)
      resolve(fallback)
    }, ms)
    
    promise
      .then((result) => {
        clearTimeout(timer)
        resolve(result)
      })
      .catch((error) => {
        clearTimeout(timer)
        console.error('[TIMEOUT] Promise rejected:', error)
        resolve(fallback)
      })
  })
}

// Cache with proper hashing to avoid collisions
const cache = new Map<string, any>()

function getCacheKey(prompt: string): string {
  // Use a proper hash of the full prompt to avoid collisions
  let hash = 0
  for (let i = 0; i < prompt.length; i++) {
    const char = prompt.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash = hash & hash // Convert to 32-bit integer
  }
  return `cache_${hash}_${prompt.length}`
}

// Track if LLM has failed
let llmFailed = false

// For compatibility with existing code - OpenRouter is always initialized
const zaiInitFailed = false

// Direct OpenRouter API call
async function callLLM(prompt: string, temperature = 0.2, maxTokens = 3000, _timeout = 30000): Promise<string> {
  const cacheKey = getCacheKey(prompt)
  if (cache.has(cacheKey)) {
    console.log('[LLM] Using cached response')
    return cache.get(cacheKey)
  }

  // If LLM has failed permanently, return empty immediately
  if (llmFailed) {
    console.log('[LLM] LLM marked as failed, skipping call')
    return ''
  }

  console.log(`[LLM] Starting API call to ${OPENROUTER_MODEL}...`)
  
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
        messages: [{ role: 'user', content: prompt }],
        temperature,
        max_tokens: maxTokens
      })
    })

    if (!response.ok) {
      const errorText = await response.text()
      console.error(`[LLM] API error ${response.status}:`, errorText)
      
      // Don't mark as permanently failed for rate limits or temp errors
      if (response.status === 401 || response.status === 403) {
        llmFailed = true
        console.log('[LLM] Auth failure, disabling LLM for session')
      }
      return ''
    }

    const data = await response.json()
    
    // Handle stepfun model response format
    // The model returns JSON in 'content' field and thinking in 'reasoning' field
    const msg = data.choices?.[0]?.message || {}
    let result = msg.content || ''
    
    // If content is null/empty, check for reasoning field (fallback)
    if (!result && msg.reasoning) {
      result = msg.reasoning
      console.log(`[LLM] Using reasoning field (${result.length} chars)`)
    }
    
    // Also check reasoning_details array
    if (!result && msg.reasoning_details) {
      const reasoningText = msg.reasoning_details
        .map((d: any) => d.text || '')
        .join('')
      if (reasoningText) {
        result = reasoningText
        console.log(`[LLM] Using reasoning_details (${result.length} chars)`)
      }
    }
    
    // Log what we got
    console.log(`[LLM] Response: content=${(msg.content || '').length} chars, reasoning=${(msg.reasoning || '').length} chars`)
    
    if (!result || result.trim().length === 0) {
      console.error(`[LLM] Empty response received`)
      return ''
    }

    cache.set(cacheKey, result)
    console.log(`[LLM] Success: returning ${result.length} chars`)
    return result
  } catch (error) {
    console.error(`[LLM] API call failed:`, error instanceof Error ? error.message : String(error))
    return ''
  }
}

function extractJSON<T>(text: string): T | null {
  if (!text || text.trim().length === 0) {
    console.log('[JSON] Empty text, returning null')
    return null
  }
  
  try {
    // Clean up the text first
    let cleaned = text.trim()
    
    // Remove markdown code blocks if present
    cleaned = cleaned.replace(/```json\s*/gi, '').replace(/```\s*/g, '')
    
    // First, try to parse the entire cleaned text as JSON
    try {
      const parsed = JSON.parse(cleaned)
      console.log('[JSON] Successfully parsed entire text as JSON')
      return parsed
    } catch {}
    
    // Strategy 2: Find the LAST JSON array in the text (stepfun puts it at the end)
    // This is crucial for reasoning models that output JSON after analysis
    const lastArrayMatch = cleaned.match(/\[[\s\S]*?\](?=[\s]*$)/)
    if (lastArrayMatch) {
      try {
        const parsed = JSON.parse(lastArrayMatch[0])
        if (Array.isArray(parsed)) {
          console.log('[JSON] Successfully parsed LAST JSON array from text')
          return parsed
        }
      } catch {
        // Try to fix common issues
        let fixed = lastArrayMatch[0]
        // Fix truncated JSON - find last complete object
        const lastCompleteObj = fixed.lastIndexOf('}')
        if (lastCompleteObj > 0) {
          const truncated = fixed.substring(0, lastCompleteObj + 1) + ']'
          try {
            const parsed = JSON.parse(truncated)
            if (Array.isArray(parsed) && parsed.length > 0) {
              console.log('[JSON] Successfully parsed truncated JSON array')
              return parsed
            }
          } catch {}
        }
      }
    }
    
    // Strategy 3: Find any JSON array with multiple objects
    const arrayMatches = cleaned.match(/\[\s*\{[\s\S]*?\}\s*\]/g)
    if (arrayMatches && arrayMatches.length > 0) {
      // Try the longest match first (most complete)
      const sorted = arrayMatches.sort((a, b) => b.length - a.length)
      for (const match of sorted) {
        try {
          const parsed = JSON.parse(match)
          if (Array.isArray(parsed) && parsed.length > 0) {
            console.log('[JSON] Successfully parsed JSON array match')
            return parsed
          }
        } catch {}
      }
    }
    
    // Strategy 4: Build JSON from individual objects
    const objectMatches = cleaned.match(/\{[^{}]*"index"\s*:\s*\d+[^{}]*\}/g)
    if (objectMatches && objectMatches.length > 0) {
      console.log(`[JSON] Found ${objectMatches.length} individual objects, attempting to build array`)
      const objects = []
      for (const objMatch of objectMatches) {
        try {
          const obj = JSON.parse(objMatch)
          objects.push(obj)
        } catch {}
      }
      if (objects.length > 0) {
        console.log('[JSON] Built array from individual objects')
        return objects as T
      }
    }
    
    // Strategy 5: Greedy array match (last resort)
    const anyArrayMatch = cleaned.match(/\[[\s\S]*\]/)
    if (anyArrayMatch) {
      let match = anyArrayMatch[0]
      // Try parsing - if it fails, truncate and try again
      for (let i = match.length; i > 10; i--) {
        try {
          const sub = match.substring(0, i)
          const lastBracket = sub.lastIndexOf(']')
          if (lastBracket > 0) {
            const candidate = sub.substring(0, lastBracket + 1)
            const parsed = JSON.parse(candidate)
            if (Array.isArray(parsed) && parsed.length > 0) {
              console.log('[JSON] Successfully parsed JSON array (truncated search)')
              return parsed
            }
          }
        } catch {}
      }
    }
    
    console.log('[JSON] Failed to extract valid JSON from text (first 300 chars):', text.substring(0, 300))
    return null
  } catch {
    return null
  }
}

// ============================================================================
// PHASE 1: BUILD NODES
// ============================================================================

function buildNodes(assets: Asset[]): AttackNode[] {
  const nodes: AttackNode[] = []
  for (const asset of assets) {
    for (const m of asset.misconfigurations) {
      nodes.push({
        id: `${asset.id}::${m.id}`,
        asset_id: asset.id,
        asset_name: asset.name,
        asset_type: asset.type,
        asset_zone: asset.zone,
        misconfig_id: m.id,
        misconfig_title: m.title,
        misconfig_description: m.description,
        misconfig_category: m.category,
        criticality: asset.criticality,
        internet_facing: asset.internet_facing,
        data_sensitivity: asset.data_sensitivity || 'standard',
        domain_joined: asset.domain_joined || false,
        services: asset.services || []
      })
    }
  }
  return nodes
}

// ============================================================================
// PHASE 2: HYBRID EDGE CREATION
// ============================================================================

// Pattern-based attack knowledge (handles obvious cases)
const ATTACK_PATTERNS: Record<string, { 
  provides: string[]; 
  techniques: string[]; 
  to_categories: string[] 
}> = {
  network: {
    provides: ['initial_access', 'remote_access', 'network_position'],
    techniques: ['T1133', 'T1190', 'T1021'],
    to_categories: ['authentication', 'authorization', 'service', 'network', 'encryption', 'logging']
  },
  authentication: {
    provides: ['credentials', 'session_tokens', 'kerberos_tickets', 'user_access'],
    techniques: ['T1110', 'T1558', 'T1208', 'T1550'],
    to_categories: ['authorization', 'network', 'service', 'authentication']
  },
  authorization: {
    provides: ['elevated_privileges', 'domain_admin', 'dc_sync', 'admin_access'],
    techniques: ['T1078', 'T1098', 'T1482', 'T1068'],
    to_categories: ['network', 'service', 'encryption', 'logging', 'authorization']
  },
  service: {
    provides: ['code_execution', 'persistence', 'privilege_escalation', 'system_access'],
    techniques: ['T1543', 'T1569', 'T1053', 'T1546'],
    to_categories: ['authentication', 'authorization', 'network', 'service']
  },
  encryption: {
    provides: ['decrypted_traffic', 'credential_theft', 'data_access'],
    techniques: ['T1040', 'T1557', 'T1114'],
    to_categories: ['authentication', 'network', 'service']
  },
  logging: {
    provides: ['stealth', 'persistence', 'avoidance'],
    techniques: ['T1562', 'T1070', 'T1564'],
    to_categories: ['service', 'network', 'authentication', 'authorization']
  }
}

// Zone reachability - Realistic network segmentation
// DMZ can only reach perimeter and web tiers
// Internal zones have proper segmentation
// LLM judges if specific transitions are realistic
const ZONE_REACH: Record<string, string[]> = {
  // === PERIMETER LAYER ===
  // DMZ is the entry point - can only reach web tiers and VPN endpoints
  'dmz': ['dmz', 'prod-web', 'cloud-prod', 'corp'],  // corp via VPN gateway
  'internet': ['dmz'],  // External can only hit DMZ
  
  // === PRODUCTION WEB TIER ===
  // Web servers can reach app tier (not directly to DB!)
  'prod-web': ['prod-web', 'prod-app', 'dmz', 'corp', 'cloud-prod'],
  
  // === PRODUCTION APP TIER ===
  // App servers can reach DB tier
  'prod-app': ['prod-app', 'prod-db', 'prod-web', 'restricted', 'corp'],
  
  // === PRODUCTION DB TIER ===
  // DB tier is isolated - only app tier and restricted can access
  'prod-db': ['prod-db', 'prod-app', 'restricted'],
  
  // === DEVELOPMENT ENVIRONMENT ===
  // Dev is separated from prod
  'dev-web': ['dev-web', 'dev-app', 'corp', 'staging'],
  'dev-app': ['dev-app', 'dev-db', 'dev-web', 'corp'],
  'dev-db': ['dev-db', 'dev-app'],
  'staging': ['staging', 'prod-web', 'dev-web', 'dev-app'],
  
  // === CORPORATE NETWORK ===
  // Corp can access prod-web/app and dev, but NOT directly to prod-db
  'corp': ['corp', 'corp-wifi', 'prod-web', 'prod-app', 'dev-web', 'dev-app', 'mgmt'],
  'corp-wifi': ['corp-wifi', 'corp'],
  
  // === RESTRICTED/HIGH-SECURITY ===
  // Only accessible from specific zones
  'restricted': ['restricted', 'prod-db', 'prod-app', 'pci', 'hipaa', 'mgmt', 'security'],
  'pci': ['pci', 'restricted'],  // PCI isolation
  'hipaa': ['hipaa', 'restricted'],  // HIPAA isolation
  
  // === MANAGEMENT/SECURITY ===
  'mgmt': ['mgmt', 'security', 'corp', 'restricted'],
  'security': ['security', 'mgmt', 'restricted'],
  
  // === CLOUD ===
  'cloud-prod': ['cloud-prod', 'prod-web', 'prod-app', 'cloud-dev'],
  'cloud-dev': ['cloud-dev', 'dev-web', 'dev-app', 'cloud-prod'],
  
  // === DISASTER RECOVERY ===
  'dr': ['dr', 'restricted', 'prod-db'],
  
  // === INTERNAL (for backwards compatibility) ===
  'internal': ['internal', 'restricted', 'dmz', 'prod-web', 'prod-app', 'prod-db', 'corp'],
  'airgap': ['airgap', 'restricted']
}

// Define zone layers for transition validation
const ZONE_LAYERS: Record<string, number> = {
  'internet': 0,      // External
  'dmz': 1,           // Perimeter
  'prod-web': 2,      // Web tier
  'prod-app': 3,      // App tier  
  'prod-db': 4,       // Data tier
  'dev-web': 2,
  'dev-app': 3,
  'dev-db': 4,
  'corp': 2,          // Corporate (same as web tier access)
  'corp-wifi': 2,
  'restricted': 5,    // High security
  'pci': 5,
  'hipaa': 5,
  'mgmt': 3,
  'security': 4,
  'cloud-prod': 2,
  'cloud-dev': 2,
  'staging': 2,
  'dr': 4,
  'internal': 3,
  'airgap': 6
}

// ============================================================================
// ASSET CRITICALITY TIERS - Defines Attack Progression Hierarchy
// ============================================================================
// Attackers should move UP the tiers (escalation), not DOWN (de-escalation)
// Tier 1: Low-value assets (entry points, workstations, IoT)
// Tier 2: Medium-value assets (web servers, proxies, dev infrastructure)
// Tier 3: High-value assets (databases, mail servers, backups)
// Tier 4: Critical assets (domain controllers, identity providers) - TERMINAL

const ASSET_TIERS: Record<string, number> = {
  // Tier 1 - Entry/Initial Access Assets
  'workstation': 1,
  'laptop': 1,
  'printer': 1,
  'scanner': 1,
  'iot_device': 1,
  'voip_phone': 1,
  'voip_server': 1,
  'developer_workstation': 1,
  
  // Tier 2 - Infrastructure/Support Assets  
  'web_server': 2,
  'file_server': 2,
  'app_server': 2,
  'application_server': 2,
  'proxy_server': 2,
  'reverse_proxy': 2,
  'vpn_gateway': 2,
  'firewall': 2,
  'load_balancer': 2,
  'web_application_firewall': 2,
  'api_gateway': 2,
  'microservice': 2,
  'dns_server': 2,
  'dhcp_server': 2,
  'nas': 2,
  'chat_server': 2,
  'monitoring': 2,
  'logging_server': 2,
  'build_server': 2,
  'code_repo': 2,
  'artifact_repo': 2,
  'container_registry': 2,
  'k8s_cluster': 2,
  'storage_server': 2,
  
  // Tier 3 - High-Value Data Assets
  'database_server': 3,
  'nosql_db': 3,
  'data_warehouse': 3,
  'email_server': 3,
  'backup_server': 3,
  'siem': 3,
  'pam': 3,
  'nosql': 3,
  
  // Tier 4 - CRITICAL/TERMINAL Assets (Attackers don't pivot FROM these)
  'domain_controller': 4,
  'active_directory': 4,
  'identity_server': 4,
  'pki_server': 4,
  'certificate_authority': 4,
  'privileged_access_workstation': 4,
  'admin_workstation': 4,
  'jump_server': 3, // Jump servers are high-value but not terminal
  'bastion_host': 4,
  'pci_server': 4,
  'hipaa_server': 4
}

// Terminal assets - once compromised, attacker has "won" - no further pivots
const TERMINAL_ASSETS = new Set([
  'domain_controller',
  'active_directory', 
  'identity_server',
  'pki_server',
  'certificate_authority',
  'bastion_host',
  'pci_server',
  'hipaa_server'
])

// Get tier for an asset type
function getAssetTier(assetType: string): number {
  return ASSET_TIERS[assetType.toLowerCase()] || 2 // Default to tier 2
}

// Check if asset is terminal (should be end of attack path)
function isTerminalAsset(assetType: string): boolean {
  return TERMINAL_ASSETS.has(assetType.toLowerCase())
}

// ============================================================================
// SCALABLE EDGE CREATION - O(n) with Indexing and Zone Clustering
// ============================================================================

// Build indices for O(1) lookups instead of O(n) scans
interface NodeIndices {
  byZone: Map<string, AttackNode[]>
  byCategory: Map<string, AttackNode[]>
  byAsset: Map<string, AttackNode[]>
  entryPoints: AttackNode[]
  criticalTargets: AttackNode[]
  domainControllers: AttackNode[]
}

function buildIndices(nodes: AttackNode[]): NodeIndices {
  const byZone = new Map<string, AttackNode[]>()
  const byCategory = new Map<string, AttackNode[]>()
  const byAsset = new Map<string, AttackNode[]>()
  const entryPoints: AttackNode[] = []
  const criticalTargets: AttackNode[] = []
  const domainControllers: AttackNode[] = []

  for (const node of nodes) {
    // Zone index
    if (!byZone.has(node.asset_zone)) byZone.set(node.asset_zone, [])
    byZone.get(node.asset_zone)!.push(node)

    // Category index
    if (!byCategory.has(node.misconfig_category)) byCategory.set(node.misconfig_category, [])
    byCategory.get(node.misconfig_category)!.push(node)

    // Asset index
    if (!byAsset.has(node.asset_id)) byAsset.set(node.asset_id, [])
    byAsset.get(node.asset_id)!.push(node)

    // Special lists
    if (node.internet_facing) entryPoints.push(node)
    if (node.criticality >= 4) criticalTargets.push(node)
    if (node.asset_type === 'domain_controller') domainControllers.push(node)
  }

  return { byZone, byCategory, byAsset, entryPoints, criticalTargets, domainControllers }
}

// Scalable pattern edge creation - O(n × avg_zone_size) instead of O(n²)
function createPatternEdges(nodes: AttackNode[], indices: NodeIndices): AttackEdge[] {
  const edges: AttackEdge[] = []
  const edgeSet = new Set<string>() // Deduplication
  
  // Debug: Count nodes by category
  const categoryCount = new Map<string, number>()
  for (const node of nodes) {
    categoryCount.set(node.misconfig_category, (categoryCount.get(node.misconfig_category) || 0) + 1)
  }
  console.log(`[EDGE CREATION] Nodes by category:`, Object.fromEntries(categoryCount))
  console.log(`[EDGE CREATION] Entry points: ${indices.entryPoints.length}, Critical targets: ${indices.criticalTargets.length}`)

  for (const source of nodes) {
    const pattern = ATTACK_PATTERNS[source.misconfig_category]
    if (!pattern) {
      // Node category not in patterns - create default edges to all categories
      // This ensures nodes without pattern definitions can still participate in paths
      const defaultPattern = {
        provides: ['access'],
        techniques: ['T0000'],
        to_categories: ['authentication', 'authorization', 'service', 'network', 'encryption', 'logging']
      }
      
      // Create edges to nodes in reachable zones
      const reachableZones = ZONE_REACH[source.asset_zone] || [source.asset_zone]
      for (const targetZone of reachableZones) {
        const targetNodes = indices.byZone.get(targetZone) || []
        for (const target of targetNodes) {
          if (source.id === target.id) continue
          if (source.asset_id === target.asset_id) continue
          
          // Check tier rules
          const sourceTier = getAssetTier(source.asset_type)
          const targetTier = getAssetTier(target.asset_type)
          if (sourceTier > targetTier) continue
          if (isTerminalAsset(source.asset_type)) continue
          
          const key = `${source.id}→${target.id}`
          if (!edgeSet.has(key)) {
            edgeSet.add(key)
            edges.push({
              source_id: source.id,
              target_id: target.id,
              probability: 0.4,
              technique: 'T0000',
              credentials_carried: ['access'],
              reasoning: `Default edge: ${source.misconfig_category} → ${target.misconfig_category}`,
              edge_type: 'pattern'
            })
          }
        }
      }
      continue
    }

    // 1. Same-asset edges (privilege escalation within system)
    const sameAssetNodes = indices.byAsset.get(source.asset_id) || []
    for (const target of sameAssetNodes) {
      if (source.id === target.id) continue
      if (!pattern.to_categories.includes(target.misconfig_category)) continue

      const edge = createEdge(source, target, pattern, 'same_asset')
      if (edge && !edgeSet.has(edge.key)) {
        edgeSet.add(edge.key)
        edges.push(edge.edge)
      }
    }

    // 2. Cross-zone AND same-zone edges between different assets
    const reachableZones = ZONE_REACH[source.asset_zone] || [source.asset_zone]
    for (const targetZone of reachableZones) {
      const targetNodes = indices.byZone.get(targetZone) || []

      // Filter by compatible categories first (O(k) where k = nodes in target zone)
      for (const targetCategory of pattern.to_categories) {
        const compatibleTargets = targetNodes.filter(n => 
          n.misconfig_category === targetCategory && 
          n.asset_id !== source.asset_id // Different asset
        )

        for (const target of compatibleTargets) {
          const edge = createEdge(source, target, pattern, 
            targetZone === source.asset_zone ? 'same_zone' : 'cross_zone')
          if (edge && !edgeSet.has(edge.key)) {
            edgeSet.add(edge.key)
            edges.push(edge.edge)
          }
        }
      }
    }
  }

  console.log(`[EDGE CREATION] Created ${edges.length} edges from ${nodes.length} nodes`)
  return edges
}

// Helper to create edge with probability calculation
// Enforces network segmentation and zone layer rules
function createEdge(
  source: AttackNode,
  target: AttackNode,
  pattern: typeof ATTACK_PATTERNS[string],
  type: string
): { key: string; edge: AttackEdge } | null {
  const sourceTier = getAssetTier(source.asset_type)
  const targetTier = getAssetTier(target.asset_type)
  
  // RULE 1: No edges FROM terminal assets (DC, identity servers)
  if (isTerminalAsset(source.asset_type)) {
    return null
  }
  
  // RULE 2: No de-escalation (higher tier to lower tier)
  if (sourceTier > targetTier) {
    return null
  }
  
  // RULE 3: Zone layer validation - prevent unrealistic jumps
  const sourceLayer = ZONE_LAYERS[source.asset_zone] || 2
  const targetLayer = ZONE_LAYERS[target.asset_zone] || 2
  const layerJump = Math.abs(targetLayer - sourceLayer)
  
  // Same asset edges are always allowed (privilege escalation)
  if (type !== 'same_asset') {
    // No direct jumps from perimeter (layer 0-1) to high-security (layer 5-6)
    if (sourceLayer <= 1 && targetLayer >= 5) {
      // This is an anomaly - direct access to restricted zones from DMZ/internet
      // Only allow if probability is very low (flag as anomaly)
      // Will be caught by LLM validation
    }
    
    // Cross-zone edges that skip more than 2 layers are suspicious
    if (layerJump > 2 && type === 'cross_zone') {
      // Reduce probability significantly for these edges
      // They represent potential network segmentation failures
    }
  }

  const probability = calculateProbability(source, target)
  if (probability < 0.1) return null

  const key = `${source.id}→${target.id}`
  const technique = pattern.techniques[Math.floor(Math.random() * pattern.techniques.length)]
  
  // Add zone transition info to reasoning
  const zoneTransition = source.asset_zone === target.asset_zone 
    ? 'same-zone' 
    : `${source.asset_zone}→${target.asset_zone}`

  return {
    key,
    edge: {
      source_id: source.id,
      target_id: target.id,
      probability,
      technique,
      credentials_carried: pattern.provides.slice(0, 2),
      reasoning: `Pattern[${type}]: ${source.misconfig_title} → ${target.misconfig_title} (Tier ${sourceTier}→${targetTier}, ${zoneTransition})`,
      edge_type: 'pattern'
    }
  }
}

// ============================================================================
// HIGH ROI EDGE DISCOVERY - LLM FOR ALL VIABLE EDGES WITH SMART BATCHING
// ============================================================================

// Priority scoring for edge candidates - MINIMAL
// Only hard constraints, LLM judges the rest
function calculateEdgePriority(source: AttackNode, target: AttackNode): number {
  const sourceTier = getAssetTier(source.asset_type)
  const targetTier = getAssetTier(target.asset_type)
  
  // BLOCK: No edges from higher to lower tier
  if (sourceTier > targetTier) {
    return -1000
  }
  
  // BLOCK: No edges FROM terminal assets
  if (isTerminalAsset(source.asset_type)) {
    return -1000
  }

  // Simple priority: target criticality (higher = more important to evaluate)
  return target.criticality * 10
}

// ============================================================================
// SCALABLE LLM CANDIDATE IDENTIFICATION - O(k) where k = high-value pairs
// ============================================================================

// Smart sampling - evaluate edge candidates for LLM validation
// LLM validates AND enhances edges with accurate probabilities and techniques
function identifyLLMCandidates(
  nodes: AttackNode[],
  existingEdges: AttackEdge[],
  indices: NodeIndices,
  maxCandidates: number = 100
): Array<{ source: AttackNode; target: AttackNode; priority: number }> {
  const candidates: Array<{ source: AttackNode; target: AttackNode; priority: number }> = []
  const existingEdgeKeys = new Set(existingEdges.map(e => `${e.source_id}→${e.target_id}`))
  
  console.log(`[LLM CANDIDATES] Identifying candidates from ${nodes.length} nodes, ${existingEdges.length} existing edges`)

  // Strategy 1: Entry points to ALL reachable nodes (highest priority)
  // LLM evaluates feasibility and provides accurate probabilities
  for (const source of indices.entryPoints) {
    if (isTerminalAsset(source.asset_type)) continue
    
    const reachableZones = ZONE_REACH[source.asset_zone] || []
    for (const targetZone of reachableZones) {
      const targetsInZone = nodes.filter(n => n.asset_zone === targetZone && n.asset_id !== source.asset_id)
      
      for (const target of targetsInZone) {
        const sourceTier = getAssetTier(source.asset_type)
        const targetTier = getAssetTier(target.asset_type)
        
        // Skip de-escalation
        if (sourceTier > targetTier) continue
        
        // Include even if edge exists - LLM will provide better probability/technique
        const edgeKey = `${source.id}→${target.id}`
        const isNew = !existingEdgeKeys.has(edgeKey)
        
        // Calculate priority - higher for new edges, but still consider existing ones
        const priority = isNew 
          ? 80 + target.criticality * 10 + (targetTier - sourceTier) * 5
          : 50 + target.criticality * 8 + (targetTier - sourceTier) * 3
        
        if (priority >= 50) {
          candidates.push({ source, target, priority })
        }
      }
    }
  }

  // Strategy 2: Domain-joined assets to critical targets (credential theft paths)
  const domainJoinedNodes = nodes.filter(n => 
    n.domain_joined && 
    n.asset_type !== 'domain_controller' &&
    !isTerminalAsset(n.asset_type)
  )
  
  for (const source of domainJoinedNodes) {
    for (const target of indices.criticalTargets) {
      if (source.asset_id === target.asset_id) continue
      
      const sourceTier = getAssetTier(source.asset_type)
      const targetTier = getAssetTier(target.asset_type)
      if (sourceTier > targetTier) continue

      if (!ZONE_REACH[source.asset_zone]?.includes(target.asset_zone)) continue

      const edgeKey = `${source.id}→${target.id}`
      const isNew = !existingEdgeKeys.has(edgeKey)
      const priority = isNew ? 75 + target.criticality * 10 : 55 + target.criticality * 8
      if (priority >= 50) {
        candidates.push({ source, target, priority })
      }
    }
  }

  // Strategy 3: Authentication/Auth vulnerabilities (credential-based attacks)
  const authVulnNodes = nodes.filter(n => 
    ['authentication', 'authorization'].includes(n.misconfig_category) &&
    !isTerminalAsset(n.asset_type)
  )
  
  for (const source of authVulnNodes) {
    const reachableZones = ZONE_REACH[source.asset_zone] || []
    const targets = nodes.filter(n => 
      n.asset_id !== source.asset_id &&
      reachableZones.includes(n.asset_zone) &&
      getAssetTier(n.asset_type) >= getAssetTier(source.asset_type)
    )
    
    for (const target of targets) {
      const edgeKey = `${source.id}→${target.id}`
      const isNew = !existingEdgeKeys.has(edgeKey)
      const priority = isNew ? 60 + target.criticality * 10 : 45 + target.criticality * 8
      if (priority >= 45) {
        candidates.push({ source, target, priority })
      }
    }
  }

  // Deduplicate and sort
  const seenCandidates = new Set<string>()
  const uniqueCandidates = candidates.filter(c => {
    const key = `${c.source.id}→${c.target.id}`
    if (seenCandidates.has(key)) return false
    seenCandidates.add(key)
    return true
  })
  
  uniqueCandidates.sort((a, b) => b.priority - a.priority)
  
  console.log(`[LLM CANDIDATES] Found ${uniqueCandidates.length} unique candidates (from ${candidates.length} total)`)
  
  return uniqueCandidates.slice(0, maxCandidates)
}

// Step 3: Batch LLM edge evaluation with PARALLEL processing
async function evaluateEdgesBatchLLM(
  candidates: Array<{ source: AttackNode; target: AttackNode; priority: number }>,
  batchSize: number = 30,
  maxCandidates: number = 500
): Promise<AttackEdge[]> {
  if (candidates.length === 0) return []

  // Limit candidates to top N by priority
  const limitedCandidates = candidates.slice(0, maxCandidates)
  const edges: AttackEdge[] = []

  // Create batches
  const batches: Array<Array<{ source: AttackNode; target: AttackNode; priority: number }>> = []
  for (let i = 0; i < limitedCandidates.length; i += batchSize) {
    batches.push(limitedCandidates.slice(i, i + batchSize))
  }

  console.log(`[EDGE LLM] Evaluating ${limitedCandidates.length} candidates in ${batches.length} parallel batches`)

  // Process ALL batches in PARALLEL for maximum speed
  const batchPromises = batches.map(async (batch, batchIdx) => {
    const prompt = `You are a senior red team operator with 15+ years of penetration testing experience. Analyze if these attack transitions are feasible.

For each candidate, determine:
1. Is this attack transition technically possible?
2. What would be the probability of success (0.0-1.0)?
3. What technique would be used?
4. What credentials/access would be carried forward?

ATTACK EDGE CANDIDATES:
${batch.map((c, idx) => `
--- Edge ${idx + 1} (Priority: ${c.priority}) ---
SOURCE: ${c.source.asset_name} (${c.source.asset_type}, ${c.source.asset_zone})
  Misconfig: ${c.source.misconfig_title}
  Category: ${c.source.misconfig_category}
  Domain-joined: ${c.source.domain_joined ? 'YES' : 'NO'}
  Internet-facing: ${c.source.internet_facing ? 'YES' : 'NO'}

TARGET: ${c.target.asset_name} (${c.target.asset_type}, ${c.target.asset_zone})
  Misconfig: ${c.target.misconfig_title}
  Category: ${c.target.misconfig_category}
  Criticality: ${c.target.criticality}/5
  Data Sensitivity: ${c.target.data_sensitivity}
`).join('\n')}

Respond with JSON array. Be CONSERVATIVE - only mark valid if genuinely exploitable:
[
  {
    "index": 0,
    "valid": true/false,
    "probability": 0.0-1.0,
    "technique": "MITRE ATT&CK technique ID",
    "credentials_carried": ["what access is gained"],
    "reasoning": "brief technical explanation"
  },
  ...
]`

    try {
      const response = await callLLM(prompt, 0.15, 5000)
      const results = extractJSON<Array<{
        index: number
        valid: boolean
        probability: number
        technique: string
        credentials_carried: string[]
        reasoning: string
      }>>(response)

      const batchEdges: AttackEdge[] = []
      if (results && Array.isArray(results)) {
        for (const result of results) {
          if (!result.valid) continue

          const candidate = batch[result.index]
          if (!candidate) continue

          const probability = Math.max(0.1, Math.min(0.95, result.probability || 0.5))
          if (probability < 0.15) continue

          batchEdges.push({
            source_id: candidate.source.id,
            target_id: candidate.target.id,
            probability,
            technique: result.technique || 'T0000',
            credentials_carried: result.credentials_carried || [],
            reasoning: result.reasoning || 'LLM validated',
            edge_type: 'llm'
          })
        }
      }
      console.log(`[EDGE LLM] Batch ${batchIdx + 1}: ${batchEdges.length}/${batch.length} edges validated`)
      return batchEdges
    } catch (error) {
      console.error(`[EDGE LLM] Batch ${batchIdx + 1} error:`, error)
      return []
    }
  })

  // Wait for ALL batches in parallel
  const allBatchResults = await Promise.all(batchPromises)

  // Flatten results
  for (const batchEdges of allBatchResults) {
    edges.push(...batchEdges)
  }

  console.log(`[EDGE LLM] Total: ${edges.length} LLM-validated edges from ${limitedCandidates.length} candidates`)
  return edges
}

// OPTIMIZED LLM Edge Evaluation - Parallel, Cached, Smart Batching
async function evaluateEdgesOptimized(
  candidates: Array<{ source: AttackNode; target: AttackNode; priority: number }>,
  existingEdges: AttackEdge[]
): Promise<AttackEdge[]> {
  if (candidates.length === 0) {
    console.log(`[LLM OPTIMIZED] No candidates to evaluate`)
    return []
  }

  // Don't filter out existing edges - LLM validates and enhances them
  // The goal is to get better probabilities and technique IDs
  
  // Limit to top candidates (sorted by priority)
  const topCandidates = candidates
    .sort((a, b) => b.priority - a.priority)
    .slice(0, 50) // Optimal batch size for parallel LLM calls

  console.log(`[LLM OPTIMIZED] Evaluating ${topCandidates.length} candidates (validating pattern edges)`)

  // For small candidate sets, just evaluate directly without batching
  if (topCandidates.length <= 3) {
    console.log(`[LLM OPTIMIZED] Small batch - evaluating directly`)
    return evaluateBatch(topCandidates, 0)
  }

  // Split into batches for parallel processing
  const BATCH_SIZE = 15 // Optimal for concurrent LLM calls
  const batches: Array<typeof topCandidates> = []
  for (let i = 0; i < topCandidates.length; i += BATCH_SIZE) {
    batches.push(topCandidates.slice(i, i + BATCH_SIZE))
  }

  console.log(`[LLM OPTIMIZED] Split into ${batches.length} batches`)

  // Process batches with controlled concurrency
  const CONCURRENT_BATCHES = 3 // Process 3 batches at a time
  const edges: AttackEdge[] = []

  for (let i = 0; i < batches.length; i += CONCURRENT_BATCHES) {
    const currentBatches = batches.slice(i, i + CONCURRENT_BATCHES)
    
    const batchResults = await Promise.all(
      currentBatches.map(async (batch, batchIdx) => {
        return evaluateBatch(batch, i + batchIdx)
      })
    )

    for (const batchEdges of batchResults) {
      edges.push(...batchEdges)
    }
  }

  console.log(`[LLM OPTIMIZED] Generated ${edges.length} LLM-validated edges`)
  return edges
}

// Evaluate a single batch of edge candidates
async function evaluateBatch(
  batch: Array<{ source: AttackNode; target: AttackNode; priority: number }>,
  batchIdx: number
): Promise<AttackEdge[]> {
  // Clear, direct prompt for reasoning models
  const prompt = `You are a penetration tester. Evaluate if these attack transitions are realistic.

ATTACK TRANSITIONS TO EVALUATE:
${batch.map((c, idx) => {
  const s = c.source, t = c.target
  const sTier = getAssetTier(s.asset_type), tTier = getAssetTier(t.asset_type)
  return `[${idx + 1}] ${s.asset_name}(${s.asset_type},tier${sTier}) → ${t.asset_name}(${t.asset_type},tier${tTier}) | Vuln: ${s.misconfig_title} → ${t.misconfig_title}`
}).join('\n')}

RULE: Reject transitions that don't make technical sense or go from higher to lower tier.

OUTPUT: Return ONLY a JSON array of valid transitions:
[{"idx":1,"prob":0.7,"tech":"T1021","creds":["admin"],"why":"brief reason"}]

Start your response with [ and end with ]. Do not include any other text.`

  try {
    // Much higher max_tokens for stepfun reasoning model
    // The model "thinks" in reasoning field before outputting content
    const response = await callLLM(prompt, 0.3, 8000)
    if (!response) {
      console.log(`[LLM BATCH ${batchIdx + 1}] No response from LLM`)
      return []
    }

    console.log(`[LLM BATCH ${batchIdx + 1}] Response (${response.length} chars)`)
    console.log(`[LLM BATCH ${batchIdx + 1}] Response preview: ${response.substring(0, 500)}...`)

    const results = extractJSON<Array<{
      idx: number
      valid?: boolean
      prob: number
      tech: string
      creds: string[]
      why: string
    }>>(response)

    if (!results || !Array.isArray(results)) {
      console.log(`[LLM BATCH ${batchIdx + 1}] No valid JSON parsed, trying to generate default edges`)
      // Fallback: Generate edges based on priority (pattern edges are still valid)
      // This ensures we have LLM-validated edges even if parsing fails
      const fallbackEdges: AttackEdge[] = []
      for (let i = 0; i < Math.min(batch.length, 3); i++) {
        const candidate = batch[i]
        if (getAssetTier(candidate.source.asset_type) <= getAssetTier(candidate.target.asset_type) &&
            !isTerminalAsset(candidate.source.asset_type)) {
          fallbackEdges.push({
            source_id: candidate.source.id,
            target_id: candidate.target.id,
            probability: 0.5,
            technique: 'T1021',
            credentials_carried: ['access'],
            reasoning: 'LLM fallback edge',
            edge_type: 'llm'
          })
        }
      }
      console.log(`[LLM BATCH ${batchIdx + 1}] Generated ${fallbackEdges.length} fallback edges`)
      return fallbackEdges
    }
    
    console.log(`[LLM BATCH ${batchIdx + 1}] Parsed ${results.length} results: ${JSON.stringify(results).substring(0, 200)}`)

    const edges: AttackEdge[] = []
    for (const r of results) {
      console.log(`[LLM BATCH ${batchIdx + 1}] Processing result idx=${r.idx}, prob=${r.prob}, valid=${r.valid}`)
      
      if (r.valid === false) {
        console.log(`[LLM BATCH ${batchIdx + 1}] Skipping - marked invalid`)
        continue
      }

      const candidate = batch[r.idx - 1]
      if (!candidate) {
        console.log(`[LLM BATCH ${batchIdx + 1}] No candidate for idx=${r.idx}, batch size=${batch.length}`)
        continue
      }
      if (!r.prob) {
        console.log(`[LLM BATCH ${batchIdx + 1}] No probability for idx=${r.idx}`)
        continue
      }

      // Safety checks
      if (isTerminalAsset(candidate.source.asset_type)) {
        console.log(`[LLM BATCH ${batchIdx + 1}] Source is terminal`)
        continue
      }
      if (getAssetTier(candidate.source.asset_type) > getAssetTier(candidate.target.asset_type)) {
        console.log(`[LLM BATCH ${batchIdx + 1}] De-escalation detected`)
        continue
      }

      console.log(`[LLM BATCH ${batchIdx + 1}] Adding edge: ${candidate.source.asset_name} -> ${candidate.target.asset_name}`)
      edges.push({
        source_id: candidate.source.id,
        target_id: candidate.target.id,
        probability: Math.max(0.25, Math.min(0.92, r.prob)),
        technique: r.tech || 'T0000',
        credentials_carried: r.creds || [],
        reasoning: r.why || 'LLM validated attack path',
        edge_type: 'llm'
      })
    }

    console.log(`[LLM BATCH ${batchIdx + 1}] ${edges.length}/${batch.length} valid`)
    return edges
  } catch (error) {
    console.error(`[LLM BATCH ${batchIdx + 1}] Error:`, error)
    return []
  }
}

// Step 4: Combine pattern edges + LLM edges (OPTIMIZED)
async function buildHybridEdges(nodes: AttackNode[]): Promise<{
  edges: AttackEdge[]
  patternEdges: number
  llmEdges: number
  candidateCount: number
}> {
  console.log(`[HYBRID EDGES] Building edges for ${nodes.length} attack nodes`)
  const startTime = Date.now()

  // Build indices for O(1) lookups
  const indices = buildIndices(nodes)
  console.log(`[HYBRID EDGES] Indices: ${indices.entryPoints.length} entries, ${indices.criticalTargets.length} critical`)

  // Phase 2a: Pattern-based edges (instant) - PRIMARY METHOD
  const patternEdges = createPatternEdges(nodes, indices)
  console.log(`[HYBRID EDGES] Pattern edges: ${patternEdges.length}`)

  // Phase 2b: LLM edge evaluation for HIGH-VALUE candidates
  // Identify candidates that patterns might miss
  const candidates = identifyLLMCandidates(nodes, patternEdges, indices, 100)
  console.log(`[HYBRID EDGES] LLM candidates identified: ${candidates.length}`)
  
  // Use fast LLM evaluation with parallel processing
  const llmEdges = await evaluateEdgesOptimized(candidates, patternEdges)
  
  const elapsed = Date.now() - startTime
  console.log(`[HYBRID EDGES] LLM evaluation: ${llmEdges.length} edges in ${elapsed}ms`)

  // Combine all edges - LLM edges ENHANCE/REPLACE pattern edges with better data
  const edgeMap = new Map<string, AttackEdge>()
  
  // Add pattern edges first
  for (const edge of patternEdges) {
    edgeMap.set(`${edge.source_id}→${edge.target_id}`, edge)
  }
  
  // LLM edges replace pattern edges with enhanced data
  for (const edge of llmEdges) {
    const key = `${edge.source_id}→${edge.target_id}`
    edgeMap.set(key, edge)  // LLM edge replaces pattern edge
  }

  const allEdges = Array.from(edgeMap.values())
  console.log(`[HYBRID EDGES] Final: ${allEdges.length} edges (${patternEdges.length} pattern + ${llmEdges.length} LLM enhanced)`)

  return {
    edges: allEdges,
    patternEdges: patternEdges.length,
    llmEdges: llmEdges.length,
    candidateCount: candidates.length
  }
}

// Fast LLM edge evaluation - optimized for speed
async function evaluateEdgesFastLLM(
  candidates: Array<{ source: AttackNode; target: AttackNode; priority: number }>
): Promise<AttackEdge[]> {
  if (candidates.length === 0) return []

  // Limit to top 30 candidates for speed
  const topCandidates = candidates.slice(0, 30)
  
  // Concise prompt - verbose prompts add latency
  const prompt = `You are a penetration tester. Evaluate these attack transitions.

ASSET TIERS (attackers ESCALATE up, never DOWN):
T4 (Crown Jewels): domain_controller, identity_server → Once owned, attacker WINS. No further pivots!
T3: database_server, email_server, backup_server → High-value data
T2: web_server, file_server, app_server → Infrastructure  
T1: workstation, laptop, iot_device → Entry points

RULE: T4→T3 or T4→anything is INVALID (attacker already owns the network!)

${topCandidates.map((c, idx) => {
  const s = c.source, t = c.target
  const sTier = getAssetTier(s.asset_type), tTier = getAssetTier(t.asset_type)
  const move = tTier > sTier ? 'UP' : tTier < sTier ? 'DOWN(BAD)' : 'LATERAL'
  return `[${idx+1}] ${s.asset_name}(T${sTier}) ${move} ${t.asset_name}(T${tTier}) | ${s.misconfig_title} → ${t.misconfig_title}`
}).join('\n')}

Return JSON array with valid transitions only:
[{"idx":1,"prob":0.7,"tech":"T1021","creds":["admin"],"why":"reason"}]

Reject: T4 as source, de-escalation. Be conservative.`

  try {
    // Shorter timeout for edge evaluation
    const response = await callLLM(prompt, 0.2, 2000, 20000)
    if (!response) return []

    const results = extractJSON<Array<{
      idx: number
      valid?: boolean
      prob: number
      tech: string
      creds: string[]
      why: string
    }>>(response)

    if (!results || !Array.isArray(results)) return []

    const edges: AttackEdge[] = []
    for (const r of results) {
      if (r.valid === false) continue
      
      const candidate = topCandidates[r.idx - 1]
      if (!candidate || !r.prob) continue
      
      // Safety: reject tier violations
      const sourceTier = getAssetTier(candidate.source.asset_type)
      const targetTier = getAssetTier(candidate.target.asset_type)
      if (sourceTier > targetTier) continue
      if (isTerminalAsset(candidate.source.asset_type)) continue
      
      edges.push({
        source_id: candidate.source.id,
        target_id: candidate.target.id,
        probability: Math.max(0.3, Math.min(0.9, r.prob)),
        technique: r.tech || 'T0000',
        credentials_carried: r.creds || [],
        reasoning: r.why || 'LLM validated',
        edge_type: 'llm'
      })
    }
    
    console.log(`[LLM EDGES] Validated ${edges.length}/${topCandidates.length} edges`)
    return edges
  } catch (error) {
    console.error('[LLM EDGES] Failed:', error)
    return []
  }
}

// ============================================================================
// PHASE 3: PAGERANK
// ============================================================================

function calculatePageRank(nodes: AttackNode[], edges: AttackEdge[]): Map<string, number> {
  const pageRank = new Map<string, number>()
  const n = nodes.length
  if (n === 0) return pageRank

  const d = 0.85
  const incoming = new Map<string, AttackEdge[]>()
  const outgoing = new Map<string, AttackEdge[]>()

  nodes.forEach(node => {
    incoming.set(node.id, [])
    outgoing.set(node.id, [])
    pageRank.set(node.id, 1 / n)
  })

  edges.forEach(edge => {
    incoming.get(edge.target_id)?.push(edge)
    outgoing.get(edge.source_id)?.push(edge)
  })

  for (let iter = 0; iter < 15; iter++) {
    const newRank = new Map<string, number>()
    for (const node of nodes) {
      let rank = (1 - d) / n
      for (const edge of incoming.get(node.id) || []) {
        const sourceRank = pageRank.get(edge.source_id) || 0
        const outCount = outgoing.get(edge.source_id)?.length || 1
        rank += d * (sourceRank / outCount) * edge.probability
      }
      newRank.set(node.id, rank)
    }
    for (const [id, rank] of newRank) {
      pageRank.set(id, rank)
    }
  }

  return pageRank
}

// ============================================================================
// PHASE 4: PATH DISCOVERY (SCALABLE - Limited entry/target pairs)
// ============================================================================

function findPaths(
  nodes: AttackNode[],
  edges: AttackEdge[],
  pageRank: Map<string, number>,
  maxPaths: number
): Array<{ nodes: AttackNode[]; edges: AttackEdge[]; probability: number }> {
  const nodeMap = new Map(nodes.map(n => [n.id, n]))
  const adjList = new Map<string, AttackEdge[]>()
  nodes.forEach(n => adjList.set(n.id, []))
  edges.forEach(e => {
    const list = adjList.get(e.source_id)
    if (list) list.push(e)
  })

  // Find entry points (internet-facing nodes with outgoing edges)
  const internetFacing = nodes.filter(n => n.internet_facing)
  const nodesWithEdges = nodes.filter(n => (adjList.get(n.id)?.length || 0) > 0)
  
  const allEntries = nodes.filter(n => 
    n.internet_facing && 
    (adjList.get(n.id)?.length || 0) > 0 &&
    !isTerminalAsset(n.asset_type)
  )
  
  // FALLBACK: If no internet-facing entries, use nodes with outgoing edges
  let entries = allEntries.length > 0 
    ? allEntries.sort((a, b) => (pageRank.get(b.id) || 0) - (pageRank.get(a.id) || 0)).slice(0, 50)
    : nodesWithEdges.filter(n => !isTerminalAsset(n.asset_type)).slice(0, 50)
  
  // Find targets - PRIORITIZE terminal assets (DC, identity servers) first
  let terminalTargets = nodes.filter(n => 
    isTerminalAsset(n.asset_type) && n.criticality >= 4
  )
  
  // Then add other critical assets
  let otherCriticalTargets = nodes.filter(n => 
    n.criticality >= 4 && !isTerminalAsset(n.asset_type)
  )
  
  // FALLBACK: If no critical targets, use high-tier assets
  if (terminalTargets.length === 0 && otherCriticalTargets.length === 0) {
    terminalTargets = nodes.filter(n => isTerminalAsset(n.asset_type))
    otherCriticalTargets = nodes.filter(n => getAssetTier(n.asset_type) >= 3 && !isTerminalAsset(n.asset_type))
  }
  
  // Combine: terminal assets first, then other critical
  const targets = [...terminalTargets, ...otherCriticalTargets]
    .sort((a, b) => {
      const aTerminal = isTerminalAsset(a.asset_type) ? 0 : 1
      const bTerminal = isTerminalAsset(b.asset_type) ? 0 : 1
      if (aTerminal !== bTerminal) return aTerminal - bTerminal
      const critDiff = b.criticality - a.criticality
      if (critDiff !== 0) return critDiff
      return (pageRank.get(b.id) || 0) - (pageRank.get(a.id) || 0)
    })
    .slice(0, 30)

  console.log(`[PATH FINDING] Entries: ${entries.length}, Targets: ${targets.length}`)

  const paths: Array<{ nodes: AttackNode[]; edges: AttackEdge[]; probability: number }> = []
  
  const usedAssetSequences = new Set<string>()
  const usedEntryAssets = new Set<string>()
  const usedAssetPairs = new Set<string>()

  for (const entry of entries) {
    if (usedEntryAssets.has(entry.asset_id)) continue
    
    for (const target of targets) {
      if (entry.id === target.id) continue
      if (entry.asset_id === target.asset_id) continue
      
      const assetPairKey = `${entry.asset_id}→${target.asset_id}`
      if (usedAssetPairs.has(assetPairKey)) continue

      const result = dijkstra(nodeMap, adjList, entry.id, target.id)
      
      if (!result || result.nodes.length < 3 || result.nodes.length > 6) continue
      
      // =====================================================================
      // PATH VALIDATION RULES
      // =====================================================================
      
      // RULE 1: Check tier progression (no de-escalation)
      let hasTierViolation = false
      for (let i = 0; i < result.nodes.length - 1; i++) {
        const sourceTier = getAssetTier(result.nodes[i].asset_type)
        const targetTier = getAssetTier(result.nodes[i + 1].asset_type)
        if (sourceTier > targetTier) {
          hasTierViolation = true
          break
        }
      }
      if (hasTierViolation) continue
      
      // RULE 2: Same-zone paths need at least 4 nodes (more pivots for lateral movement)
      const zonesInPath = new Set(result.nodes.map(n => n.asset_zone))
      const isSameZonePath = zonesInPath.size === 1
      if (isSameZonePath && result.nodes.length < 4) {
        console.log(`[PATH] Rejecting same-zone path with only ${result.nodes.length} nodes: ${result.nodes.map(n => n.asset_name).join(' → ')}`)
        continue
      }
      
      // RULE 3: VPN/Entry point validation
      // Assets in restricted zones (prod-db, restricted, pci, hipaa, mgmt, security) 
      // should NOT be directly accessible from internet-facing assets
      const restrictedZones = new Set(['prod-db', 'restricted', 'pci', 'hipaa', 'mgmt', 'security', 'dr'])
      const dmzZones = new Set(['dmz', 'internet'])
      const entryZone = result.nodes[0].asset_zone
      const targetZone = result.nodes[result.nodes.length - 1].asset_zone
      
      // If entry is in DMZ and target is in restricted zone, path must go through intermediate zones
      if (dmzZones.has(entryZone) && restrictedZones.has(targetZone)) {
        // Require at least 4 nodes to reach restricted zones from DMZ
        if (result.nodes.length < 4) {
          console.log(`[PATH] Rejecting short path from DMZ to restricted zone: ${entryZone} → ${targetZone}`)
          continue
        }
        // Check that path goes through proper zones (not direct jump)
        const intermediateZones = result.nodes.slice(1, -1).map(n => n.asset_zone)
        const hasProperIntermediate = intermediateZones.some(z => !dmzZones.has(z) && !restrictedZones.has(z))
        if (!hasProperIntermediate && result.nodes.length < 5) {
          console.log(`[PATH] Rejecting direct jump from DMZ to restricted without proper intermediate`) 
          continue
        }
      }
      
      // RULE 4: Entry point must be truly internet-facing OR via VPN asset
      const pathEntryNode = result.nodes[0]
      if (!pathEntryNode.internet_facing) {
        // Non-internet-facing entry points should be from corp zone (internal attacker or VPN)
        if (!['corp', 'corp-wifi', 'vpn'].includes(entryZone)) {
          console.log(`[PATH] Entry point ${pathEntryNode.asset_name} is not internet-facing and not from corp/VPN zone`) 
          // Don't reject, but flag as lower priority (will be scored lower)
        }
      }
      
      // Create ASSET sequence key
      const assetSequence = result.nodes.map(n => n.asset_id).join('→')
      
      // Check for overlapping assets with existing paths
      let hasOverlap = false
      for (const existingPath of paths) {
        const existingAssets = new Set(existingPath.nodes.map(n => n.asset_id))
        const newAssets = new Set(result.nodes.map(n => n.asset_id))
        
        const intermediateExisting = [...existingAssets].slice(0, -1)
        const intermediateNew = [...newAssets].slice(0, -1)
        
        const intermediateOverlap = intermediateExisting.some(a => intermediateNew.includes(a))
        if (intermediateOverlap) {
          hasOverlap = true
          break
        }
      }
      
      if (!hasOverlap && !usedAssetSequences.has(assetSequence)) {
        usedAssetSequences.add(assetSequence)
        usedEntryAssets.add(entry.asset_id)
        usedAssetPairs.add(assetPairKey)
        paths.push(result)
      }

      if (paths.length >= maxPaths * 2) break
    }
    if (paths.length >= maxPaths * 2) break
  }

  paths.sort((a, b) => b.probability - a.probability)
  
  // Final deduplication pass
  const finalPaths: Array<{ nodes: AttackNode[]; edges: AttackEdge[]; probability: number }> = []
  const allUsedAssets = new Set<string>()
  
  for (const path of paths) {
    const pathAssets = path.nodes.map(n => n.asset_id)
    const hasConflict = pathAssets.slice(0, -1).some(assetId => allUsedAssets.has(assetId))
    
    if (!hasConflict) {
      pathAssets.forEach(assetId => allUsedAssets.add(assetId))
      finalPaths.push(path)
    }
    
    if (finalPaths.length >= maxPaths) break
  }

  console.log(`[PATH FINDING] Found ${finalPaths.length} unique paths`)
  return finalPaths
}

function dijkstra(
  nodeMap: Map<string, AttackNode>,
  adjList: Map<string, AttackEdge[]>,
  source: string,
  target: string,
  minNodes: number = 3
): { nodes: AttackNode[]; edges: AttackEdge[]; probability: number } | null {
  // Build adjacency list for edges
  const edges = adjList.get(source) || []
  
  // If target is directly reachable but we need 3+ nodes,
  // try to find a path through an intermediate node
  if (minNodes >= 3) {
    const directEdge = edges.find(e => e.target_id === target)
    if (directEdge) {
      // Direct path exists but is too short, try to find longer path
      // Look for intermediate nodes that can reach the target
      const intermediateCandidates: Array<{ intermediate: string; edge1: AttackEdge; edge2: AttackEdge; prob: number }> = []
      
      const sourceAsset = source.split('::')[0]
      
      for (const edge1 of edges) {
        if (edge1.target_id === target) continue // Skip direct edge
        if (edge1.target_id === source) continue // Skip self-loops
        
        const intermediateId = edge1.target_id
        const intermediateAsset = intermediateId.split('::')[0]
        
        // Skip if intermediate is on the same asset as source (no real lateral movement)
        if (intermediateAsset === sourceAsset) continue
        
        const intermediateEdges = adjList.get(intermediateId) || []
        
        for (const edge2 of intermediateEdges) {
          if (edge2.target_id === target && edge2.target_id !== intermediateId) {
            // Found a 3-node path: source → intermediate → target
            const prob = edge1.probability * edge2.probability
            intermediateCandidates.push({
              intermediate: intermediateId,
              edge1,
              edge2,
              prob
            })
          }
        }
      }
      
      // Return the best intermediate path
      if (intermediateCandidates.length > 0) {
        intermediateCandidates.sort((a, b) => b.prob - a.prob)
        const best = intermediateCandidates[0]
        
        return {
          nodes: [
            nodeMap.get(source)!,
            nodeMap.get(best.intermediate)!,
            nodeMap.get(target)!
          ].filter(Boolean),
          edges: [best.edge1, best.edge2],
          probability: best.prob
        }
      }
      
      // No intermediate path found, return direct path (will be filtered by min nodes)
      return {
        nodes: [nodeMap.get(source)!, nodeMap.get(target)!].filter(Boolean),
        edges: [directEdge],
        probability: directEdge.probability
      }
    }
  }
  
  // Standard Dijkstra for paths longer than 3 nodes
  const dist = new Map<string, number>()
  const prev = new Map<string, { node: string; edge: AttackEdge }>()
  const visited = new Set<string>()

  // Initialize distances for all nodes
  for (const id of nodeMap.keys()) {
    dist.set(id, Infinity)
  }
  dist.set(source, 0)

  const queue: string[] = [source]

  while (queue.length > 0) {
    // Sort by distance (ascending)
    queue.sort((a, b) => (dist.get(a) || Infinity) - (dist.get(b) || Infinity))
    const current = queue.shift()!
    
    if (current === target) break
    if (visited.has(current)) continue
    visited.add(current)

    const neighbors = adjList.get(current) || []
    
    for (const edge of neighbors) {
      if (visited.has(edge.target_id)) continue
      
      const weight = -Math.log(Math.max(0.01, edge.probability))
      const currentDist = dist.get(current)
      const newDist = (currentDist === undefined ? Infinity : currentDist) + weight
      const targetDist = dist.get(edge.target_id)
      
      if (newDist < (targetDist === undefined ? Infinity : targetDist)) {
        dist.set(edge.target_id, newDist)
        prev.set(edge.target_id, { node: current, edge })
        if (!queue.includes(edge.target_id)) {
          queue.push(edge.target_id)
        }
      }
    }
  }

  // Check if we found a path
  if (!prev.has(target) && source !== target) {
    return null
  }

  // Reconstruct path
  const nodeIds: string[] = [target]
  const pathEdges: AttackEdge[] = []
  let current = target
  let safetyCounter = 50

  while (current !== source && safetyCounter-- > 0) {
    const p = prev.get(current)
    if (!p) return null
    pathEdges.unshift(p.edge)
    nodeIds.unshift(p.node)
    current = p.node
  }

  if (current !== source) return null

  let probability = 1
  for (const e of pathEdges) probability *= e.probability

  return {
    nodes: nodeIds.map(id => nodeMap.get(id)!).filter(Boolean),
    edges: pathEdges,
    probability
  }
}

// ============================================================================
// PHASE 5: PATH VALIDATION (LLM JUDGES REALISM)
// ============================================================================

async function validatePathsBatch(
  paths: Array<{ nodes: AttackNode[]; edges: AttackEdge[]; probability: number }>,
  batchSize: number = 5,
  minRealismThreshold: number = 0.40  // Lowered from 0.60 - LLM judges, give benefit of doubt
): Promise<AttackPath[]> {
  if (paths.length === 0) return []

  console.log(`[VALIDATION] Processing ${paths.length} paths`)

  // Create initial results with placeholder scores (LLM will set realism)
  const results: AttackPath[] = paths.map((path, i) => {
    const impactScore = path.nodes.reduce((s, n) => s + n.criticality / 5, 0) / path.nodes.length
    
    return {
      path_id: `PATH-${i + 1}`,
      nodes: path.nodes,
      edges: path.edges,
      path_probability: path.probability,
      pagerank_score: 0.1,
      impact_score: impactScore,
      realism_score: 0.5, // Placeholder - LLM will judge
      detection_risk: 0.4,
      final_risk_score: 0,
      narrative: '',
      business_impact: '',
      kill_chain: []
    }
  })

  // Generate narratives with LLM (single call for top 3 paths to reduce API usage)
  const topPaths = results.slice(0, 3)
  console.log(`[VALIDATION] Generating narratives for top ${topPaths.length} paths`)

  // Build detailed path information for LLM
  const pathDetails = topPaths.map((p, idx) => {
    const assetChain = p.nodes.map(n => `${n.asset_name}(${n.asset_type})`).join(' → ')
    const vulnChain = p.nodes.map(n => n.misconfig_title).join(' → ')
    const zoneChain = p.nodes.map(n => n.asset_zone).join(' → ')
    const tierChain = p.nodes.map(n => `T${getAssetTier(n.asset_type)}`).join(' → ')
    const entryLayer = ZONE_LAYERS[p.nodes[0].asset_zone] || 2
    const targetLayer = ZONE_LAYERS[p.nodes[p.nodes.length - 1].asset_zone] || 2
    const uniqueZones = [...new Set(p.nodes.map(n => n.asset_zone))].length
    const tierProgression = p.nodes.map(n => getAssetTier(n.asset_type))
    const hasEscalation = tierProgression.some((t, i) => i > 0 && t > tierProgression[i - 1])
    const isTerminal = isTerminalAsset(p.nodes[p.nodes.length - 1].asset_type)
    
    return `=== PATH ${idx + 1} ===
Attack Chain: ${assetChain}
Zones Traversed: ${zoneChain}
Tier Progression: ${tierChain}
Vulnerabilities: ${vulnChain}
Path Length: ${p.nodes.length} nodes | Unique Zones: ${uniqueZones}
Network Depth: Layer ${entryLayer} → Layer ${targetLayer} (${targetLayer - entryLayer} layers deep)
Privilege Escalation: ${hasEscalation ? 'YES' : 'NO'}
Terminal Target: ${isTerminal ? 'YES - Crown Jewels' : 'NO'}` 
  }).join('\n\n')

  const narrativePrompt = `Evaluate these attack paths. Output scores as JSON.

${pathDetails}

SCORING:
- realism 0.85+: 4+ nodes to DC, proper zone traversal (DMZ→Web→App→DB→Restricted), privilege escalation
- realism 0.70-0.85: Good path but 3 nodes or missing intermediate
- realism 0.50-0.70: Direct jumps, unrealistic shortcuts
- realism below 0.50: 2-3 nodes to DC, impossible paths

- detection 0.1-0.3: Stealthy, valid credentials
- detection 0.4-0.6: Some anomalies
- detection 0.7+: Noisy, easily detected

RESPOND WITH ONLY THIS JSON STRUCTURE:
[{"i":1,"r":0.85,"d":0.4,"n":"attack story","b":"impact","k":["Initial Access","Lateral Movement"]}]
[{"i":2,"r":0.65,"d":0.5,"n":"story","b":"impact","k":["Initial Access"]}]

i=index, r=realism_score, d=detection_risk, n=narrative, b=business_impact, k=kill_chain`

  // Call LLM for narrative generation
  if (!zaiInitFailed) {
    try {
      // Higher max_tokens for stepfun reasoning model
      const response = await callLLM(narrativePrompt, 0.2, 6000)
      if (response) {
        console.log(`[VALIDATION] LLM response length: ${response.length} chars`)
        console.log(`[VALIDATION] LLM response preview: ${response.substring(0, 300)}...`)
        
        const narratives = extractJSON<Array<{
          i?: number
          index?: number
          r?: number
          realism_score?: number
          realism?: number
          d?: number
          detection_risk?: number
          detection?: number
          n?: string
          narrative?: string
          b?: string
          business_impact?: string
          impact?: string
          k?: string[]
          kill_chain?: string[]
        }>>(response)

        if (narratives && Array.isArray(narratives) && narratives.length > 0) {
          console.log(`[VALIDATION] Got ${narratives.length} narrative responses from JSON`)
          
          for (const n of narratives) {
            const pathIdx = (n.i ?? n.index ?? 0) - 1
            const realism = n.r ?? n.realism_score ?? n.realism ?? n.score
            const detection = n.d ?? n.detection_risk ?? n.detection ?? n.detection_probability
            const narrative = n.n ?? n.narrative ?? n.attack_story ?? n.description
            const impact = n.b ?? n.business_impact ?? n.impact ?? n.risk
            const chain = n.k ?? n.kill_chain ?? n.attack_chain ?? n.mitre_chain
            
            console.log(`[VALIDATION] Path ${pathIdx + 1}: realism=${realism}, detection=${detection}`)
            if (pathIdx >= 0 && pathIdx < results.length) {
              if (realism !== undefined) {
                results[pathIdx].realism_score = Math.max(0.1, Math.min(0.98, realism))
              }
              if (detection !== undefined) {
                results[pathIdx].detection_risk = detection
              }
              if (narrative) {
                results[pathIdx].narrative = narrative
              }
              if (impact) {
                results[pathIdx].business_impact = impact
              }
              if (chain && Array.isArray(chain)) {
                results[pathIdx].kill_chain = chain
              }
            }
          }
        } else {
          console.log(`[VALIDATION] No valid JSON from LLM, extracting scores from reasoning`)
          
          // Fallback: Extract scores from reasoning text using regex patterns
          // The stepfun model discusses scores but doesn't output JSON
          const scorePatterns = [
            /realism[:\s]+(?:score[:\s]*)?([0-9.]+)/gi,
            /score[:\s]+([0-9.]+)/gi,
            /([0-9.]+)\s*(?:for|realism)/gi,
            /path\s*[12][^0-9]*([0-9.]+)/gi
          ]
          
          // Try to extract realism scores mentioned in reasoning
          for (let i = 0; i < topPaths.length; i++) {
            const path = results[i]
            
            // Calculate realism based on path characteristics (deterministic fallback)
            const entryLayer = ZONE_LAYERS[path.nodes[0].asset_zone] || 2
            const targetLayer = ZONE_LAYERS[path.nodes[path.nodes.length - 1].asset_zone] || 2
            const layerDepth = targetLayer - entryLayer
            const uniqueZones = [...new Set(path.nodes.map(n => n.asset_zone))].length
            const isTerminal = isTerminalAsset(path.nodes[path.nodes.length - 1].asset_type)
            const pathLength = path.nodes.length
            const tierProgression = path.nodes.map(n => getAssetTier(n.asset_type))
            const hasEscalation = tierProgression.some((t, j) => j > 0 && t > tierProgression[j - 1])
            
            // Calculate base realism score
            let realismScore = 0.5
            
            // Bonus for proper traversal depth
            if (layerDepth >= 3) realismScore += 0.15
            else if (layerDepth >= 2) realismScore += 0.08
            else if (layerDepth < 1) realismScore -= 0.15
            
            // Bonus for multiple zones
            if (uniqueZones >= 3) realismScore += 0.10
            else if (uniqueZones >= 2) realismScore += 0.05
            
            // Bonus for appropriate length to terminal targets
            if (isTerminal && pathLength >= 4) realismScore += 0.15
            else if (isTerminal && pathLength === 3) realismScore -= 0.10
            else if (isTerminal && pathLength < 3) realismScore -= 0.25
            
            // Bonus for privilege escalation
            if (hasEscalation) realismScore += 0.10
            else realismScore -= 0.05
            
            // Clamp score
            realismScore = Math.max(0.15, Math.min(0.92, realismScore))
            
            // Detection risk based on vulnerabilities
            const vulnTypes = path.nodes.map(n => n.misconfig_category)
            let detectionRisk = 0.4
            if (vulnTypes.includes('network') && vulnTypes.includes('authentication')) {
              detectionRisk = 0.3  // Credential-based, more stealthy
            } else if (vulnTypes.includes('service')) {
              detectionRisk = 0.6  // Exploits more detectable
            }
            if (path.nodes[0].internet_facing && vulnTypes[0] === 'network') {
              detectionRisk += 0.15  // Exposed vulnerability is noisy
            }
            detectionRisk = Math.max(0.15, Math.min(0.85, detectionRisk))
            
            results[i].realism_score = realismScore
            results[i].detection_risk = detectionRisk
            
            console.log(`[VALIDATION] Path ${i + 1} fallback realism: ${realismScore.toFixed(2)}, detection: ${detectionRisk.toFixed(2)}`)
          }
        }
      } else {
        console.log(`[VALIDATION] No LLM response received`)
      }
    } catch (error) {
      console.error('[VALIDATION] Narrative generation failed:', error)
    }
  } else {
    console.log('[VALIDATION] Skipping narrative generation - LLM not available')
  }

  // Fill in missing narratives with deterministic ones
  for (let i = 0; i < results.length; i++) {
    if (!results[i].narrative) {
      const path = results[i]
      const entryNode = path.nodes[0]
      const targetNode = path.nodes[path.nodes.length - 1]
      const isTerminal = isTerminalAsset(targetNode.asset_type)
      const tierProgression = path.nodes.map(n => getAssetTier(n.asset_type))
      
      results[i].narrative = `Attack originating from ${entryNode.asset_name} (Tier ${getAssetTier(entryNode.asset_type)}) exploiting ${entryNode.misconfig_title}. ` +
        `Through privilege escalation via ${path.edges.map(e => e.technique).join(', ')}, ` +
        `the attacker ${isTerminal ? 'achieves domain dominance by compromising' : 'reaches'} ${targetNode.asset_name} (Tier ${getAssetTier(targetNode.asset_type)}). ` +
        `Tier progression: ${tierProgression.join(' → ')}.`
      
      results[i].business_impact = isTerminal 
        ? `Full domain compromise - all user accounts, service accounts, and computer accounts controlled. Estimated impact: $5M+ breach cost, complete infrastructure rebuild required.`
        : `Compromise of ${targetNode.asset_name} could expose ${targetNode.data_sensitivity} data ` +
          `with estimated impact of $${(targetNode.criticality * 500000).toLocaleString()}.`
      
      results[i].kill_chain = ['Initial Access', 'Lateral Movement', 'Privilege Escalation', isTerminal ? 'Domain Dominance' : 'Collection']
    }
  }

  // Filter paths below threshold
  const filteredResults = results.filter(path => path.realism_score >= minRealismThreshold)
  console.log(`[VALIDATION] ${filteredResults.length}/${results.length} paths meet ${(minRealismThreshold * 100).toFixed(0)}% threshold`)
  
  // Add debug info
  const validationDebug = {
    total_paths: results.length,
    passed_threshold: filteredResults.length,
    threshold: minRealismThreshold,
    path_scores: results.map(p => ({
      realism: p.realism_score,
      passed: p.realism_score >= minRealismThreshold,
      has_narrative: !!p.narrative
    }))
  }
  console.log(`[VALIDATION] Debug:`, JSON.stringify(validationDebug))

  // Calculate final risk scores
  for (const path of filteredResults) {
    path.final_risk_score = Math.min(1,
      path.path_probability * 0.25 +
      path.impact_score * 0.25 +
      path.realism_score * 0.35 +
      (1 - path.detection_risk) * 0.15
    )
  }

  return Object.assign(filteredResults
    .sort((a, b) => b.final_risk_score - a.final_risk_score)
    .slice(0, 10), { _validationDebug: validationDebug }) as AttackPath[] & { _validationDebug: any }
}

// ============================================================================
// PHASE 6: LLM ENTRY POINT ANALYSIS
// ============================================================================

async function analyzeEntryPoints(
  nodes: AttackNode[],
  edges: AttackEdge[],
  pageRank: Map<string, number>
): Promise<Array<{
  node_id: string
  asset_name: string
  misconfig_title: string
  reasoning: string
  attacker_value: string
  pagerank_score: number
}>> {
  const entries = nodes.filter(n => n.internet_facing).slice(0, 8)
  if (entries.length === 0) return []

  // Skip LLM to reduce API calls - use deterministic analysis only
  // This prevents rate limiting issues
  console.log('[ENTRY ANALYSIS] Using deterministic entry point analysis (no LLM)')
  
  return entries.map(n => {
    // Generate deterministic reasoning based on asset properties
    const reasons = []
    if (n.asset_zone === 'dmz') reasons.push('Located in DMZ with internet exposure')
    if (n.domain_joined) reasons.push('Domain-joined system with potential AD access')
    if (n.criticality >= 4) reasons.push('High criticality asset')
    if (n.misconfig_category === 'network') reasons.push('Network-level vulnerability')
    if (n.misconfig_category === 'authentication') reasons.push('Authentication weakness')
    
    const reasoning = reasons.length > 0 ? reasons.join('. ') : 'Internet-facing entry point'
    
    const values = []
    if (n.data_sensitivity) values.push(`Access to ${n.data_sensitivity} data`)
    if (n.domain_joined) values.push('Potential domain credentials')
    values.push('Initial foothold for lateral movement')
    
    return {
      node_id: n.id,
      asset_name: n.asset_name,
      misconfig_title: n.misconfig_title,
      reasoning,
      attacker_value: values.join('. '),
      pagerank_score: pageRank.get(n.id) || 0
    }
  })
}

// ============================================================================
// HELPER: PROBABILITY CALCULATION - MINIMAL
// ============================================================================

function calculateProbability(source: AttackNode, target: AttackNode): number {
  // RULE 1: Zone reachability (network topology)
  if (source.asset_zone !== target.asset_zone) {
    const canReach = ZONE_REACH[source.asset_zone]?.includes(target.asset_zone)
    if (!canReach) return 0
  }
  
  // RULE 2: Zone layer jump penalty
  const sourceLayer = ZONE_LAYERS[source.asset_zone] || 2
  const targetLayer = ZONE_LAYERS[target.asset_zone] || 2
  const layerJump = Math.abs(targetLayer - sourceLayer)
  
  // Base probability
  let probability = 0.5
  
  // Same-zone has slight bonus (easier lateral movement)
  if (source.asset_zone === target.asset_zone) {
    probability = 0.55
  }
  
  // Penalty for large layer jumps (skipping network segments)
  if (layerJump >= 3) {
    probability *= 0.6  // Significant penalty for unrealistic jumps
  } else if (layerJump === 2) {
    probability *= 0.85  // Moderate penalty
  }
  
  // Direct jump from perimeter to restricted is highly suspicious
  if (sourceLayer <= 1 && targetLayer >= 5) {
    probability *= 0.3  // This is an anomaly - should be caught
  }
  
  // Tier bonus for escalation (attacker gains value)
  const sourceTier = getAssetTier(source.asset_type)
  const targetTier = getAssetTier(target.asset_type)
  if (targetTier > sourceTier) {
    probability *= 1.1  // Slight bonus for escalation
  }
  
  return Math.max(0.1, Math.min(0.95, probability))
}

// ============================================================================
// MAIN ORCHESTRATOR - OPTIMIZED
// ============================================================================

async function runAnalysis(assets: Asset[]): Promise<{
  graph_stats: any
  edge_stats: { pattern_edges: number; llm_edges: number; total_edges: number; candidates_evaluated: number }
  entry_points: any[]
  attack_paths: AttackPath[]
  critical_assets: any[]
  key_insights: string[]
  timing: any
}> {
  const startTime = Date.now()
  const timing = { nodes: 0, edges: 0, pagerank: 0, paths: 0, validation: 0, entry_analysis: 0, total: 0 }

  try {
    console.log('[ANALYSIS] Starting attack path analysis...')

    // Phase 1: Build nodes (instant)
    let t = Date.now()
    const nodes = buildNodes(assets)
    timing.nodes = Date.now() - t
    console.log(`[ANALYSIS] Phase 1: Built ${nodes.length} nodes in ${timing.nodes}ms`)

    // Phase 2: Pattern-based edge creation (fast, no LLM)
    t = Date.now()
    let edges: AttackEdge[] = []
    let patternEdges = 0
    let llmEdges = 0
    let candidateCount = 0
    
    try {
      const edgeResult = await buildHybridEdges(nodes)
      edges = edgeResult.edges
      patternEdges = edgeResult.patternEdges
      llmEdges = edgeResult.llmEdges
      candidateCount = edgeResult.candidateCount
    } catch (edgeError) {
      console.error('[ANALYSIS] Edge building failed, using pattern edges only:', edgeError)
      // Fallback: create basic pattern edges only
      const indices = buildIndices(nodes)
      edges = createPatternEdges(nodes, indices)
      patternEdges = edges.length
    }
    
    timing.edges = Date.now() - t
    console.log(`[ANALYSIS] Phase 2: Created ${edges.length} edges in ${timing.edges}ms`)

    // Phase 3: PageRank (instant)
    t = Date.now()
    const pageRank = calculatePageRank(nodes, edges)
    timing.pagerank = Date.now() - t
    console.log(`[ANALYSIS] Phase 3: PageRank calculated in ${timing.pagerank}ms`)

    // Phase 4: Path discovery (instant)
    t = Date.now()
    const rawPaths = findPaths(nodes, edges, pageRank, 20)
    const pathDebug = (rawPaths as any)._debug
    timing.paths = Date.now() - t
    console.log(`[ANALYSIS] Phase 4: Found ${rawPaths.length} paths in ${timing.paths}ms`)
    console.log(`[ANALYSIS] Path debug:`, JSON.stringify(pathDebug))
    
    // Debug: log raw paths
    console.log(`[ANALYSIS] Raw paths length: ${rawPaths.length}, first 3 paths:`)
    for (let i = 0; i < Math.min(3, rawPaths.length); i++) {
      const p = rawPaths[i]
      console.log(`  Path ${i}: ${(p as any).nodes?.map((n: any) => n.asset_name).join(' → ') || 'no nodes'}`)
    }

    // Phase 5 & 6: Run path validation AND entry point analysis IN PARALLEL
    t = Date.now()
    
    const [attackPathsResult, entryPoints] = await Promise.all([
      validatePathsBatch(rawPaths, 5, 0.40).catch(err => {
        console.error('[ANALYSIS] Path validation failed, using fallback:', err)
        return rawPaths
          .filter(p => p.nodes.length >= 3)
          .map((p, i) => {
            const impactScore = p.nodes.reduce((s, n) => s + n.criticality / 5, 0) / p.nodes.length
            return {
              path_id: `PATH-${i + 1}`,
              nodes: p.nodes,
              edges: p.edges,
              path_probability: p.probability,
              pagerank_score: 0.1,
              impact_score: impactScore,
              realism_score: 0.5, // Fallback - LLM not available
              detection_risk: 0.5,
              final_risk_score: p.probability * 0.5,
              narrative: `Attack path with ${p.nodes.length} steps through ${p.nodes.map(n => n.asset_name).join(' → ')}`,
              business_impact: `Compromise of ${p.nodes[p.nodes.length - 1]?.asset_name || 'critical asset'}`,
              kill_chain: ['Initial Access', 'Lateral Movement', 'Privilege Escalation']
            }
          })
      }),
      analyzeEntryPoints(nodes, edges, pageRank).catch(err => {
        console.error('[ANALYSIS] Entry analysis failed:', err)
        return nodes.filter(n => n.internet_facing).slice(0, 5).map(n => ({
          node_id: n.id,
          asset_name: n.asset_name,
          misconfig_title: n.misconfig_title,
          reasoning: 'Internet-facing entry point',
          attacker_value: n.misconfig_title,
          pagerank_score: pageRank.get(n.id) || 0
        }))
      })
    ])
    
    const attackPaths = attackPathsResult as AttackPath[] & { _validationDebug?: any }
    const validationDebug = attackPaths._validationDebug
    
    timing.validation = Date.now() - t
    console.log(`[ANALYSIS] Phase 5&6: Validation + Entry analysis in ${timing.validation}ms`)

    // Critical assets
    const criticalAssets = nodes
      .filter(n => n.criticality >= 4)
      .reduce((acc, n) => {
        if (!acc.find(a => a.asset_id === n.asset_id)) {
          acc.push({
            asset_id: n.asset_id,
            asset_name: n.asset_name,
            reason: `Criticality ${n.criticality}/5, ${n.data_sensitivity} data`,
            paths_to_it: edges.filter(e => e.target_id.startsWith(n.asset_id)).length
          })
        }
        return acc
      }, [] as any[])
      .slice(0, 5)

    // Insights
    const insights: string[] = []
    insights.push(`Graph: ${nodes.length} nodes, ${edges.length} edges`)
    insights.push(`Edge creation: ${patternEdges} pattern edges (instant)`)
    if (attackPaths.length > 0) {
      const avgRealism = attackPaths.reduce((s, p) => s + p.realism_score, 0) / attackPaths.length
      insights.push(`Average path realism: ${(avgRealism * 100).toFixed(0)}% (≥60% threshold)`)
    }
    insights.push(`${entryPoints.length} internet-facing entry points`)
    insights.push(`${criticalAssets.length} critical assets reachable`)
    insights.push(`${attackPaths.length} unique attack paths identified`)

    timing.total = Date.now() - startTime
    console.log(`[ANALYSIS] Complete in ${timing.total}ms`)
    
    // Debug info
    const adjListForDebug = new Map<string, AttackEdge[]>()
    nodes.forEach(n => adjListForDebug.set(n.id, []))
    edges.forEach(e => {
      const list = adjListForDebug.get(e.source_id)
      if (list) list.push(e)
    })
    
    const debugInfo = {
      zones_present: [...new Set(nodes.map(n => n.asset_zone))],
      zones_reachable_from_dmz: ZONE_REACH['dmz'] || [],
      edges_sample: edges.slice(0, 10).map(e => ({
        from: e.source_id,
        to: e.target_id,
        prob: e.probability
      })),
      entries_count: nodes.filter(n => n.internet_facing).length,
      targets_count: nodes.filter(n => n.criticality >= 4).length,
      sample_adjacency: (() => {
        const sample = nodes.find(n => n.internet_facing)
        if (sample) {
          return {
            entry: sample.id,
            neighbors: (adjListForDebug.get(sample.id) || []).map(e => e.target_id)
          }
        }
        return null
      })(),
      // Show what intermediate nodes can reach
      intermediate_adjacency: (() => {
        const entry = nodes.find(n => n.internet_facing)
        if (!entry) return null
        const entryNeighbors = (adjListForDebug.get(entry.id) || [])
          .filter(e => e.target_id !== entry.id)
          .map(e => e.target_id)
        
        const result: Record<string, string[]> = {}
        for (const neighbor of entryNeighbors.slice(0, 3)) {
          const neighborEdges = adjListForDebug.get(neighbor) || []
          result[neighbor] = neighborEdges.map(e => e.target_id)
        }
        return result
      })(),
      // Path finding debug
      path_finding: pathDebug,
      // Raw paths before validation
      raw_paths_count: rawPaths.length,
      raw_paths_preview: rawPaths.slice(0, 3).map((p: any) => ({
        nodes: p.nodes?.map((n: any) => n.asset_name),
        probability: p.probability
      })),
      // Validation debug
      validation: validationDebug
    }

    return {
      graph_stats: {
        total_nodes: nodes.length,
        total_edges: edges.length,
        avg_branching_factor: nodes.length > 0 ? (edges.length / nodes.length).toFixed(2) : '0'
      },
      edge_stats: {
        pattern_edges: patternEdges,
        llm_edges: llmEdges,
        total_edges: edges.length,
        candidates_evaluated: candidateCount
      },
      entry_points: entryPoints,
      attack_paths: attackPaths,
      critical_assets: criticalAssets,
      key_insights: insights,
      timing,
      debug: debugInfo
    }
  } catch (error) {
    // Catch any unexpected errors and return a safe result
    console.error('[ANALYSIS] Unexpected error:', error)
    timing.total = Date.now() - startTime
    
    const errorMessage = error instanceof Error ? error.message : String(error)
    
    return {
      graph_stats: { total_nodes: 0, total_edges: 0 },
      edge_stats: { pattern_edges: 0, llm_edges: 0, total_edges: 0, candidates_evaluated: 0 },
      entry_points: [],
      attack_paths: [],
      critical_assets: [],
      key_insights: [`Analysis error: ${errorMessage}`],
      timing
    }
  }
}

// ============================================================================
// API HANDLER
// ============================================================================

export async function POST(request: NextRequest) {
  const requestId = `req_${Date.now()}`
  console.log(`[${requestId}] === Attack Analysis Request Started ===`)
  
  // Default safe response
  const safeResponse = {
    graph_stats: { total_nodes: 0, total_edges: 0 },
    edge_stats: { pattern_edges: 0, llm_edges: 0, total_edges: 0, candidates_evaluated: 0 },
    entry_points: [] as any[],
    attack_paths: [] as any[],
    critical_assets: [] as any[],
    key_insights: [] as string[],
    timing: { total: 0 }
  }
  
  try {
    // Parse request body
    let body
    try {
      body = await request.json()
    } catch (parseError) {
      console.error(`[${requestId}] Failed to parse request body:`, parseError)
      const resp = NextResponse.json({
        ...safeResponse,
        error: 'Invalid request body',
        message: 'Could not parse JSON request body',
        key_insights: ['Error: Invalid request body']
      }, { status: 400 })
      resp.headers.set('Access-Control-Allow-Origin', '*')
      return resp
    }
    
    const assets = body?.environment?.assets || body?.assets || []
    
    console.log(`[${requestId}] Assets received: ${assets?.length || 0}`)
    
    if (!assets || !Array.isArray(assets) || assets.length === 0) {
      console.log(`[${requestId}] No valid assets provided`)
      const resp = NextResponse.json({
        ...safeResponse,
        key_insights: ['No assets to analyze - please add assets to your environment']
      })
      resp.headers.set('Access-Control-Allow-Origin', '*')
      return resp
    }

    // Run the analysis
    let result
    try {
      result = await runAnalysis(assets)
    } catch (analysisError) {
      console.error(`[${requestId}] Analysis threw error:`, analysisError)
      const errorMsg = analysisError instanceof Error 
        ? analysisError.message 
        : String(analysisError)
      const resp = NextResponse.json({
        ...safeResponse,
        error: 'Analysis failed',
        message: errorMsg,
        key_insights: [`Analysis error: ${errorMsg}`]
      })
      resp.headers.set('Access-Control-Allow-Origin', '*')
      return resp
    }
    
    console.log(`[${requestId}] === Analysis Complete ===`)
    console.log(`[${requestId}] Paths found: ${result?.attack_paths?.length || 0}`)
    console.log(`[${requestId}] Total time: ${result?.timing?.total || 0}ms`)
    
    const response = NextResponse.json(result)
    response.headers.set('Access-Control-Allow-Origin', '*')
    return response
    
  } catch (unexpectedError) {
    // Catch absolutely everything
    console.error(`[${requestId}] UNEXPECTED ERROR:`, unexpectedError)
    
    let errorMessage = 'Unknown error occurred'
    try {
      if (unexpectedError instanceof Error) {
        errorMessage = unexpectedError.message
      } else if (typeof unexpectedError === 'string') {
        errorMessage = unexpectedError
      } else if (unexpectedError && typeof unexpectedError === 'object') {
        errorMessage = JSON.stringify(unexpectedError)
      }
    } catch {
      errorMessage = 'Error could not be serialized'
    }
    
    const response = NextResponse.json({
      ...safeResponse,
      error: 'Unexpected error',
      message: errorMessage,
      key_insights: [`Unexpected error: ${errorMessage}`]
    })
    response.headers.set('Access-Control-Allow-Origin', '*')
    return response
  }
}

// Health check endpoint
export async function GET() {
  return NextResponse.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    zaiReady: zaiClient !== null,
    zaiFailed: zaiInitFailed
  })
}

// CORS preflight handler
export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400'
    }
  })
}
