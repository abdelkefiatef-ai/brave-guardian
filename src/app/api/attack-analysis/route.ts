import { NextRequest, NextResponse } from 'next/server'
import ZAI from 'z-ai-web-dev-sdk'

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

// LLM cache
const cache = new Map<string, any>()

async function callLLM(prompt: string, temperature = 0.2, maxTokens = 3000): Promise<string> {
  const cacheKey = prompt.substring(0, 150)
  if (cache.has(cacheKey)) return cache.get(cacheKey)

  const zai = await ZAI.create()
  const completion = await zai.chat.completions.create({
    messages: [{ role: 'user', content: prompt }],
    temperature,
    max_tokens: maxTokens
  })

  const result = completion.choices[0]?.message?.content || ''
  cache.set(cacheKey, result)
  return result
}

function extractJSON<T>(text: string): T | null {
  try {
    // Try to find JSON array or object
    const patterns = [/\[[\s\S]*?\](?=\s*$|\s*[\n\r])/gm, /\{[\s\S]*?\}(?=\s*$|\s*[\n\r])/gm]
    
    for (const pattern of patterns) {
      const matches = text.match(pattern)
      if (matches) {
        for (const match of matches) {
          try {
            return JSON.parse(match.replace(/,\s*}/g, '}').replace(/,\s*]/g, ']'))
          } catch {}
        }
      }
    }
    
    // Fallback: try to parse entire text
    return JSON.parse(text.replace(/,\s*}/g, '}').replace(/,\s*]/g, ']'))
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

// Zone reachability
const ZONE_REACH: Record<string, string[]> = {
  dmz: ['internal', 'dmz'],
  internal: ['restricted', 'internal', 'dmz'],
  restricted: ['restricted', 'internal'],
  airgap: ['airgap', 'restricted']
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

  for (const source of nodes) {
    const pattern = ATTACK_PATTERNS[source.misconfig_category]
    if (!pattern) continue

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

    // 2. Cross-zone edges - only check reachable zones
    const reachableZones = ZONE_REACH[source.asset_zone] || []
    for (const targetZone of reachableZones) {
      if (targetZone === source.asset_zone) continue // Different zone only

      const targetNodes = indices.byZone.get(targetZone) || []

      // Filter by compatible categories first (O(k) where k = nodes in target zone)
      for (const targetCategory of pattern.to_categories) {
        const compatibleTargets = targetNodes.filter(n => n.misconfig_category === targetCategory)

        for (const target of compatibleTargets) {
          const edge = createEdge(source, target, pattern, 'cross_zone')
          if (edge && !edgeSet.has(edge.key)) {
            edgeSet.add(edge.key)
            edges.push(edge.edge)
          }
        }
      }
    }
  }

  return edges
}

// Helper to create edge with probability calculation
function createEdge(
  source: AttackNode,
  target: AttackNode,
  pattern: typeof ATTACK_PATTERNS[string],
  type: string
): { key: string; edge: AttackEdge } | null {
  const probability = calculateProbability(source, target)
  if (probability < 0.1) return null

  const key = `${source.id}→${target.id}`
  const technique = pattern.techniques[Math.floor(Math.random() * pattern.techniques.length)]

  return {
    key,
    edge: {
      source_id: source.id,
      target_id: target.id,
      probability,
      technique,
      credentials_carried: pattern.provides.slice(0, 2),
      reasoning: `Pattern[${type}]: ${source.misconfig_title} → ${target.misconfig_title}`,
      edge_type: 'pattern'
    }
  }
}

// ============================================================================
// HIGH ROI EDGE DISCOVERY - LLM FOR ALL VIABLE EDGES WITH SMART BATCHING
// ============================================================================

// Priority scoring for edge candidates (higher = evaluate first)
function calculateEdgePriority(source: AttackNode, target: AttackNode): number {
  let priority = 0

  // Entry points to critical targets = HIGHEST priority
  if (source.internet_facing && target.criticality >= 4) {
    priority += 100
  }

  // Domain escalation paths
  if (source.domain_joined && target.asset_type === 'domain_controller') {
    priority += 80
  }

  // Authentication paths to critical assets
  if (['authentication', 'authorization'].includes(source.misconfig_category)) {
    if (target.criticality >= 4) priority += 70
    if (target.asset_type === 'domain_controller') priority += 60
  }

  // Service misconfig to infrastructure
  if (source.misconfig_category === 'service' &&
      ['domain_controller', 'database_server', 'backup_server'].includes(target.asset_type)) {
    priority += 50
  }

  // Cross-zone attacks
  if (source.asset_zone !== target.asset_zone) {
    priority += 30
  }

  // Same-asset privilege escalation
  if (source.asset_id === target.asset_id && source.misconfig_category !== target.misconfig_category) {
    priority += 25
  }

  // Target criticality bonus
  priority += target.criticality * 5

  // Entry point bonus
  if (source.internet_facing) {
    priority += 15
  }

  return priority
}

// ============================================================================
// SCALABLE LLM CANDIDATE IDENTIFICATION - O(k) where k = high-value pairs
// ============================================================================

// Smart sampling - only evaluate promising edge candidates
function identifyLLMCandidates(
  nodes: AttackNode[],
  existingEdges: AttackEdge[],
  indices: NodeIndices,
  maxCandidates: number = 500
): Array<{ source: AttackNode; target: AttackNode; priority: number }> {
  const candidates: Array<{ source: AttackNode; target: AttackNode; priority: number }> = []
  const existingEdgeKeys = new Set(existingEdges.map(e => `${e.source_id}→${e.target_id}`))

  // Strategy 1: Entry points to critical targets (highest value)
  for (const source of indices.entryPoints) {
    for (const target of indices.criticalTargets) {
      if (source.id === target.id) continue
      if (source.asset_id === target.asset_id) continue
      
      const edgeKey = `${source.id}→${target.id}`
      if (existingEdgeKeys.has(edgeKey)) continue

      // Zone check
      if (!ZONE_REACH[source.asset_zone]?.includes(target.asset_zone)) continue

      const priority = calculateEdgePriority(source, target)
      if (priority >= 50) {
        candidates.push({ source, target, priority })
      }
    }
  }

  // Strategy 2: Domain-joined to Domain Controllers
  const domainJoinedNodes = nodes.filter(n => n.domain_joined && n.asset_type !== 'domain_controller')
  for (const source of domainJoinedNodes) {
    for (const target of indices.domainControllers) {
      if (source.id === target.id) continue
      
      const edgeKey = `${source.id}→${target.id}`
      if (existingEdgeKeys.has(edgeKey)) continue

      if (!ZONE_REACH[source.asset_zone]?.includes(target.asset_zone)) continue

      const priority = calculateEdgePriority(source, target)
      if (priority >= 50) {
        candidates.push({ source, target, priority })
      }
    }
  }

  // Strategy 3: Authentication/Authorization to critical
  const authNodes = nodes.filter(n => 
    ['authentication', 'authorization'].includes(n.misconfig_category)
  )
  for (const source of authNodes) {
    for (const target of indices.criticalTargets) {
      if (source.id === target.id) continue
      
      const edgeKey = `${source.id}→${target.id}`
      if (existingEdgeKeys.has(edgeKey)) continue

      if (!ZONE_REACH[source.asset_zone]?.includes(target.asset_zone)) continue

      const priority = calculateEdgePriority(source, target)
      if (priority >= 30) {
        candidates.push({ source, target, priority })
      }
    }
  }

  // Sort by priority and limit
  candidates.sort((a, b) => b.priority - a.priority)
  
  console.log(`[LLM CANDIDATES] Found ${candidates.length} high-priority candidates`)
  
  return candidates.slice(0, maxCandidates)
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

// Step 4: Combine pattern edges + LLM edges (SCALABLE)
async function buildHybridEdges(nodes: AttackNode[]): Promise<{
  edges: AttackEdge[]
  patternEdges: number
  llmEdges: number
  candidateCount: number
}> {
  console.log(`[HYBRID EDGES] Building edges for ${nodes.length} attack nodes`)

  // Build indices for O(1) lookups
  const indices = buildIndices(nodes)
  console.log(`[HYBRID EDGES] Indices built: ${indices.entryPoints.length} entries, ${indices.criticalTargets.length} critical`)

  // Phase 2a: Pattern-based edges (scalable with indexing)
  const patternEdges = createPatternEdges(nodes, indices)
  console.log(`[HYBRID EDGES] Pattern edges: ${patternEdges.length}`)

  // Phase 2b: Identify high-value LLM candidates (bounded)
  const candidates = identifyLLMCandidates(nodes, patternEdges, indices, 500)
  console.log(`[HYBRID EDGES] LLM candidates identified: ${candidates.length}`)

  // Phase 2c: PARALLEL batch LLM evaluation
  const llmEdges = await evaluateEdgesBatchLLM(candidates, 30, 500)

  // Combine all edges (deduplicate by source→target)
  const edgeMap = new Map<string, AttackEdge>()

  // Add pattern edges first
  for (const edge of patternEdges) {
    edgeMap.set(`${edge.source_id}→${edge.target_id}`, edge)
  }

  // Add LLM edges (may add edges pattern missed)
  for (const edge of llmEdges) {
    const key = `${edge.source_id}→${edge.target_id}`
    if (!edgeMap.has(key)) {
      edgeMap.set(key, edge)
    }
  }

  const allEdges = Array.from(edgeMap.values())
  console.log(`[HYBRID EDGES] Final: ${allEdges.length} edges (${patternEdges.length} pattern + ${llmEdges.length} LLM)`)

  return {
    edges: allEdges,
    patternEdges: patternEdges.length,
    llmEdges: llmEdges.length,
    candidateCount: candidates.length
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
  const allEntries = nodes.filter(n => n.internet_facing && (adjList.get(n.id)?.length || 0) > 0)
  
  // SCALABILITY: Limit to top 50 entry points by PageRank
  const entries = allEntries
    .sort((a, b) => (pageRank.get(b.id) || 0) - (pageRank.get(a.id) || 0))
    .slice(0, 50)
  
  // Find targets (high criticality nodes)
  const allTargets = nodes.filter(n => n.criticality >= 4)
  
  // SCALABILITY: Limit to top 30 targets by criticality and PageRank
  const targets = allTargets
    .sort((a, b) => {
      const critDiff = b.criticality - a.criticality
      if (critDiff !== 0) return critDiff
      return (pageRank.get(b.id) || 0) - (pageRank.get(a.id) || 0)
    })
    .slice(0, 30)

  console.log(`[PATH FINDING] Searching ${entries.length} entries × ${targets.length} targets = ${entries.length * targets.length} paths max`)

  const paths: Array<{ nodes: AttackNode[]; edges: AttackEdge[]; probability: number }> = []
  const foundPathKeys = new Set<string>()

  for (const entry of entries) {
    for (const target of targets) {
      if (entry.id === target.id) continue
      if (entry.asset_id === target.asset_id) continue

      const result = dijkstra(nodeMap, adjList, entry.id, target.id)
      
      if (result && result.nodes.length >= 2 && result.nodes.length <= 6) {
        const pathKey = result.nodes.map(n => n.id).join('->')
        if (!foundPathKeys.has(pathKey)) {
          foundPathKeys.add(pathKey)
          paths.push(result)
        }
      }

      // SCALABILITY: Stop early if we have enough good paths
      if (paths.length >= maxPaths * 2) break
    }
    if (paths.length >= maxPaths * 2) break
  }

  paths.sort((a, b) => b.probability - a.probability)
  return paths.slice(0, maxPaths)
}

function dijkstra(
  nodeMap: Map<string, AttackNode>,
  adjList: Map<string, AttackEdge[]>,
  source: string,
  target: string
): { nodes: AttackNode[]; edges: AttackEdge[]; probability: number } | null {
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
// PHASE 5: LLM PATH VALIDATION (BATCH)
// ============================================================================

async function validatePathsBatch(
  paths: Array<{ nodes: AttackNode[]; edges: AttackEdge[]; probability: number }>,
  batchSize: number = 5
): Promise<AttackPath[]> {
  if (paths.length === 0) return []

  const results: AttackPath[] = []
  let globalPageRank = new Map<string, number>()

  for (let i = 0; i < paths.length; i += batchSize) {
    const batch = paths.slice(i, i + batchSize)

    const prompt = `You are a senior red team operator with 15+ years of penetration testing experience.

Analyze these ${batch.length} attack paths for realism and impact. For each path:

1. REALISM SCORE (0.0-1.0): How likely is this attack to succeed? Be conservative - 0.8+ should be rare.
2. DETECTION RISK (0.0-1.0): How likely to be caught by typical EDR/SIEM?
3. KILL CHAIN: MITRE ATT&CK phases covered
4. NARRATIVE: 2-3 sentences describing the attack
5. BUSINESS IMPACT: What organizational damage occurs?

${batch.map((p, idx) => `
--- PATH ${idx + 1} ---
Mathematical Probability: ${(p.probability * 100).toFixed(1)}%
Steps:
${p.nodes.map((n, i) => {
  const edge = p.edges[i]
  const edgeInfo = edge ? ` [${edge.edge_type}: ${edge.technique}, ${(edge.probability * 100).toFixed(0)}%]` : ''
  return `  ${i + 1}. ${n.asset_name} (${n.asset_zone}, crit:${n.criticality}) - ${n.misconfig_title}${edgeInfo}`
}).join('\n')}
`).join('\n')}

JSON array response:
[{
  "index": 0,
  "realism_score": 0.0-1.0,
  "detection_risk": 0.0-1.0,
  "kill_chain": ["phase1", "phase2"],
  "narrative": "Attack description",
  "business_impact": "Impact description"
}, ...]`

    try {
      const response = await callLLM(prompt, 0.25, 3000)
      const assessments = extractJSON<Array<{
        index: number
        realism_score: number
        detection_risk: number
        kill_chain: string[]
        narrative: string
        business_impact: string
      }>>(response)

      if (assessments && Array.isArray(assessments)) {
        for (const assessment of assessments) {
          const path = batch[assessment.index]
          if (!path) continue

          const impactScore = path.nodes.reduce((s, n) => s + n.criticality / 5, 0) / path.nodes.length
          const pageRankScore = path.nodes.reduce((s, n) => s + (globalPageRank.get(n.id) || 0.1), 0) / path.nodes.length

          results.push({
            path_id: `PATH-${results.length + 1}`,
            nodes: path.nodes,
            edges: path.edges,
            path_probability: path.probability,
            pagerank_score: pageRankScore,
            impact_score: impactScore,
            realism_score: Math.max(0.1, Math.min(0.95, assessment.realism_score || 0.5)),
            detection_risk: Math.max(0.1, Math.min(0.95, assessment.detection_risk || 0.5)),
            final_risk_score: 0,
            narrative: assessment.narrative || 'Attack path analysis',
            business_impact: assessment.business_impact || 'Potential data exposure',
            kill_chain: assessment.kill_chain || []
          })
        }
      }
    } catch (error) {
      console.error('Path validation error:', error)
      // Add with defaults
      for (const path of batch) {
        const impactScore = path.nodes.reduce((s, n) => s + n.criticality / 5, 0) / path.nodes.length
        results.push({
          path_id: `PATH-${results.length + 1}`,
          nodes: path.nodes,
          edges: path.edges,
          path_probability: path.probability,
          pagerank_score: 0.1,
          impact_score: impactScore,
          realism_score: 0.5,
          detection_risk: 0.5,
          final_risk_score: 0,
          narrative: 'Attack path validated',
          business_impact: 'Potential impact',
          kill_chain: []
        })
      }
    }
  }

  // Calculate final scores
  for (const path of results) {
    path.final_risk_score = Math.min(1,
      path.path_probability * 0.3 +
      path.pagerank_score * 0.2 +
      path.impact_score * 0.2 +
      path.realism_score * 0.25 +
      (1 - path.detection_risk) * 0.05
    )
  }

  return results.sort((a, b) => b.final_risk_score - a.final_risk_score)
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

  const prompt = `As a penetration tester with 15+ years experience, rank these entry points:

${entries.map((n, i) => `${i + 1}. ${n.asset_name} (${n.asset_zone}, ${n.asset_type})
   - ${n.misconfig_title}: ${n.misconfig_description}
   - Domain-joined: ${n.domain_joined ? 'YES' : 'NO'}`).join('\n')}

For each, explain:
- Why attractive (technical reason)
- What attacker gains

JSON array:
[{
  "index": 0,
  "reasoning": "why target this",
  "attacker_value": "what you gain"
}]`

  try {
    const response = await callLLM(prompt, 0.2, 2000)
    const analyses = extractJSON<Array<{ index: number; reasoning: string; attacker_value: string }>>(response)

    if (analyses && Array.isArray(analyses)) {
      return analyses.map(a => {
        const node = entries[a.index]
        if (!node) return null
        return {
          node_id: node.id,
          asset_name: node.asset_name,
          misconfig_title: node.misconfig_title,
          reasoning: a.reasoning,
          attacker_value: a.attacker_value,
          pagerank_score: pageRank.get(node.id) || 0
        }
      }).filter(Boolean) as typeof entries
    }
  } catch {}

  return entries.map(n => ({
    node_id: n.id,
    asset_name: n.asset_name,
    misconfig_title: n.misconfig_title,
    reasoning: 'Internet-facing entry point',
    attacker_value: n.misconfig_title,
    pagerank_score: pageRank.get(n.id) || 0
  }))
}

// ============================================================================
// HELPER: PROBABILITY CALCULATION
// ============================================================================

function calculateProbability(source: AttackNode, target: AttackNode): number {
  let prob = 0.3

  // Zone transition factor
  if (source.asset_zone !== target.asset_zone) {
    const canReach = ZONE_REACH[source.asset_zone]?.includes(target.asset_zone)
    if (!canReach) return 0
    prob *= 0.75
  }

  // Same asset bonus
  if (source.asset_id === target.asset_id) {
    prob *= 1.4
  }

  // Criticality factor
  prob *= (0.6 + target.criticality * 0.08)

  // Entry point bonus
  if (source.internet_facing) {
    prob *= 1.15
  }

  // Domain path bonus
  if (source.domain_joined && target.asset_type === 'domain_controller') {
    prob *= 1.2
  }

  return Math.min(0.9, Math.max(0.1, prob))
}

// ============================================================================
// MAIN ORCHESTRATOR
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

  // Phase 1: Build nodes
  let t = Date.now()
  const nodes = buildNodes(assets)
  timing.nodes = Date.now() - t

  // Phase 2: Hybrid edge creation (pattern + parallel batch LLM)
  t = Date.now()
  const { edges, patternEdges, llmEdges, candidateCount } = await buildHybridEdges(nodes)
  timing.edges = Date.now() - t

  // Phase 3: PageRank
  t = Date.now()
  const pageRank = calculatePageRank(nodes, edges)
  timing.pagerank = Date.now() - t

  // Phase 4: Path discovery
  t = Date.now()
  const rawPaths = findPaths(nodes, edges, pageRank, 10)
  timing.paths = Date.now() - t

  // Phase 5: LLM validation
  t = Date.now()
  const attackPaths = await validatePathsBatch(rawPaths, 5)
  timing.validation = Date.now() - t

  // Phase 6: Entry point analysis
  t = Date.now()
  const entryPoints = await analyzeEntryPoints(nodes, edges, pageRank)
  timing.entry_analysis = Date.now() - t

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
  insights.push(`Edge creation: ${patternEdges} pattern + ${llmEdges} LLM (from ${candidateCount} candidates)`)
  if (attackPaths.length > 0) {
    const avgRealism = attackPaths.reduce((s, p) => s + p.realism_score, 0) / attackPaths.length
    insights.push(`Average path realism: ${(avgRealism * 100).toFixed(0)}%`)
    const llmEdgesInPaths = attackPaths.flatMap(p => p.edges).filter(e => e.edge_type === 'llm').length
    if (llmEdgesInPaths > 0) {
      insights.push(`${llmEdgesInPaths} LLM-discovered edges used in attack paths`)
    }
  }
  insights.push(`${entryPoints.length} internet-facing entry points`)
  insights.push(`${criticalAssets.length} critical assets reachable`)

  timing.total = Date.now() - startTime

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
    timing
  }
}

// ============================================================================
// API HANDLER
// ============================================================================

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const assets = body.environment?.assets || body.assets || []

    const result = await runAnalysis(assets)
    return NextResponse.json(result)
  } catch (error) {
    console.error('Analysis error:', error)
    return NextResponse.json({
      error: 'Analysis failed',
      message: error instanceof Error ? error.message : 'Unknown',
      graph_stats: { total_nodes: 0, total_edges: 0 },
      edge_stats: { pattern_edges: 0, llm_edges: 0, total_edges: 0, candidates_evaluated: 0 },
      entry_points: [],
      attack_paths: [],
      critical_assets: [],
      key_insights: ['Analysis failed'],
      timing: { total: 0 }
    }, { status: 500 })
  }
}
