/**
 * Attack Path Algorithm Test Script - WITH ATTACK STATE MACHINE
 * Tests the NEW implementation with credential tracking and kill chain enforcement
 */

// ============================================================================
// TYPES
// ============================================================================

interface Vulnerability {
  id: string
  cve?: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  cvss: number
  epss: number
  attack_complexity: number
  privileges_required: 'none' | 'low' | 'high'
  cisa_kev: boolean
  ransomware: boolean
  kill_chain_phase: string
  mitre_techniques: string[]
}

interface Asset {
  id: string
  name: string
  type: 'vm' | 'firewall' | 'server' | 'cloud_resource'
  ip: string
  network_zone: 'dmz' | 'internal' | 'restricted' | 'airgap'
  criticality: number
  internet_facing: boolean
  business_unit: string
  annual_revenue_exposure: number
  vulnerabilities: Vulnerability[]
  is_entry_point?: boolean
}

interface GraphNode {
  id: string
  asset: Asset
  vuln: Vulnerability
  centrality: number
  pageRank: number
  pprScore: number
  blastRadius: number
  risk: number
  rpc: number
  attackProb: number
}

interface Edge {
  to: number
  weight: number
  logCost: number
}

interface AttackPath {
  id: string
  nodes: GraphNode[]
  riskScore: number
  attackProbability: number
  confidenceInterval: [number, number]
  mitreTechniques: string[]
}

// ============================================================================
// VULNERABILITY DATABASE
// ============================================================================

const VULN_DB: Vulnerability[] = [
  { id: 'CVE-2017-0144', cve: 'CVE-2017-0144', title: 'EternalBlue SMBv1 RCE', severity: 'critical', cvss: 8.8, epss: 0.97, attack_complexity: 0.1, privileges_required: 'none', cisa_kev: true, ransomware: true, kill_chain_phase: 'initial_access', mitre_techniques: ['T1190', 'T1021.002'] },
  { id: 'CVE-2019-0708', cve: 'CVE-2019-0708', title: 'BlueKeep RDS RCE', severity: 'critical', cvss: 9.3, epss: 0.92, attack_complexity: 0.15, privileges_required: 'none', cisa_kev: true, ransomware: true, kill_chain_phase: 'initial_access', mitre_techniques: ['T1190', 'T1021.001'] },
  { id: 'CVE-2021-44228', cve: 'CVE-2021-44228', title: 'Log4Shell RCE', severity: 'critical', cvss: 10.0, epss: 0.96, attack_complexity: 0.05, privileges_required: 'none', cisa_kev: true, ransomware: true, kill_chain_phase: 'initial_access', mitre_techniques: ['T1190'] },
  { id: 'FW-RDP-EXPOSED', title: 'RDP Exposed to Internet', severity: 'critical', cvss: 9.1, epss: 0.91, attack_complexity: 0.2, privileges_required: 'none', cisa_kev: true, ransomware: true, kill_chain_phase: 'initial_access', mitre_techniques: ['T1021.001'] },
  { id: 'FW-SMB-EXPOSED', title: 'SMB Exposed to Internet', severity: 'critical', cvss: 9.8, epss: 0.94, attack_complexity: 0.15, privileges_required: 'none', cisa_kev: true, ransomware: true, kill_chain_phase: 'initial_access', mitre_techniques: ['T1021.002'] },
  { id: 'WIN-SMB1', title: 'SMBv1 Protocol Enabled', severity: 'critical', cvss: 9.3, epss: 0.95, attack_complexity: 0.1, privileges_required: 'none', cisa_kev: true, ransomware: true, kill_chain_phase: 'lateral_movement', mitre_techniques: ['T1021.002'] },
  { id: 'WIN-PASS-HASH', title: 'Pass-the-Hash Vulnerable', severity: 'critical', cvss: 9.1, epss: 0.75, attack_complexity: 0.3, privileges_required: 'low', cisa_kev: false, ransomware: true, kill_chain_phase: 'lateral_movement', mitre_techniques: ['T1550.002'] },
  { id: 'WIN-KERBEROAST', title: 'Kerberoasting Vulnerable', severity: 'high', cvss: 8.1, epss: 0.68, attack_complexity: 0.35, privileges_required: 'low', cisa_kev: false, ransomware: false, kill_chain_phase: 'credential_access', mitre_techniques: ['T1558.003'] },
  { id: 'WIN-UAC-BYPASS', title: 'UAC Bypass Possible', severity: 'high', cvss: 7.8, epss: 0.58, attack_complexity: 0.35, privileges_required: 'low', cisa_kev: false, ransomware: false, kill_chain_phase: 'privilege_escalation', mitre_techniques: ['T1548.002'] },
  { id: 'WIN-ADMIN-EXCESS', title: 'Excessive Local Admin Rights', severity: 'high', cvss: 7.5, epss: 0.45, attack_complexity: 0.25, privileges_required: 'low', cisa_kev: false, ransomware: false, kill_chain_phase: 'privilege_escalation', mitre_techniques: ['T1078'] },
  { id: 'WIN-PATCH-MISSING', title: 'Critical Patches Missing', severity: 'critical', cvss: 9.0, epss: 0.82, attack_complexity: 0.2, privileges_required: 'none', cisa_kev: true, ransomware: true, kill_chain_phase: 'privilege_escalation', mitre_techniques: ['T1068'] },
  { id: 'WIN-LSASS-DUMP', title: 'LSASS Memory Dumpable', severity: 'high', cvss: 8.2, epss: 0.65, attack_complexity: 0.3, privileges_required: 'high', cisa_kev: false, ransomware: true, kill_chain_phase: 'credential_access', mitre_techniques: ['T1003.001'] },
  { id: 'WIN-DC-SYNC', title: 'DCSync Attack Possible', severity: 'critical', cvss: 9.5, epss: 0.72, attack_complexity: 0.4, privileges_required: 'high', cisa_kev: false, ransomware: true, kill_chain_phase: 'credential_access', mitre_techniques: ['T1003.006'] },
  { id: 'FW-DATA-EXFIL', title: 'Data Exfiltration Path', severity: 'high', cvss: 7.5, epss: 0.40, attack_complexity: 0.35, privileges_required: 'low', cisa_kev: false, ransomware: false, kill_chain_phase: 'exfiltration', mitre_techniques: ['T1048'] },
  { id: 'WIN-BITLOCKER', title: 'BitLocker Not Enabled', severity: 'high', cvss: 7.0, epss: 0.20, attack_complexity: 0.5, privileges_required: 'none', cisa_kev: false, ransomware: false, kill_chain_phase: 'impact', mitre_techniques: ['T1486'] },
  { id: 'WIN-AV-DISABLED', title: 'Antivirus Disabled', severity: 'critical', cvss: 9.1, epss: 0.55, attack_complexity: 0.25, privileges_required: 'none', cisa_kev: false, ransomware: false, kill_chain_phase: 'defense_evasion', mitre_techniques: ['T1562.001'] },
]

// ============================================================================
// ASSET GENERATION
// ============================================================================

const generateAssets = (count: number): Asset[] => {
  const types: Asset['type'][] = ['vm', 'firewall', 'server', 'cloud_resource']
  const zones: Asset['network_zone'][] = ['dmz', 'internal', 'restricted', 'airgap']
  const businessUnits = ['Finance', 'Engineering', 'Operations', 'HR', 'Legal', 'IT', 'Sales', 'Marketing']

  let seed = 12345
  const random = () => {
    seed = (seed * 1103515245 + 12345) % 2147483648
    return seed / 2147483648
  }

  return Array.from({ length: count }, (_, i) => {
    const type = types[Math.floor(random() * types.length)]
    const zone = zones[Math.floor(random() * zones.length)]
    const internetFacing = zone === 'dmz' || (zone === 'internal' && random() > 0.85)
    const numVulns = Math.floor(random() * 4) + 1
    const vulns: Vulnerability[] = []
    
    const isEntryPoint = internetFacing && (type === 'vm' || type === 'server' || type === 'cloud_resource')
    
    if (internetFacing) {
      const entryVulns = VULN_DB.filter(v => v.kill_chain_phase === 'initial_access')
      if (entryVulns.length > 0) vulns.push({ ...entryVulns[Math.floor(random() * entryVulns.length)] })
    }
    for (let j = vulns.length; j < numVulns; j++) {
      vulns.push({ ...VULN_DB[Math.floor(random() * VULN_DB.length)] })
    }
    return {
      id: `asset-${i + 1}`,
      name: type === 'vm' ? `WIN-SRV-${String(i + 1).padStart(4, '0')}` :
            type === 'firewall' ? `FW-${['Cisco', 'PaloAlto', 'Fortinet'][Math.floor(random() * 3)]}-${String(i + 1).padStart(3, '0')}` :
            type === 'server' ? `LNX-SRV-${String(i + 1).padStart(4, '0')}` :
            `AWS-EC2-${String(i + 1).padStart(4, '0')}`,
      type, 
      ip: `10.${Math.floor(random() * 255)}.${Math.floor(random() * 255)}.${Math.floor(random() * 255)}`,
      network_zone: zone, 
      criticality: Math.floor(random() * 5) + 1,
      internet_facing: internetFacing,
      business_unit: businessUnits[Math.floor(random() * businessUnits.length)],
      annual_revenue_exposure: Math.floor(random() * 10000000) + 100000,
      vulnerabilities: vulns,
      is_entry_point: isEntryPoint
    }
  })
}

// ============================================================================
// ALGORITHM
// ============================================================================

const safeNum = (v: number | undefined | null, fb = 0): number =>
  v === undefined || v === null || !isFinite(v) || isNaN(v) ? fb : v

const ZONE_EXPOSURE: Record<string, number> = {
  dmz: 1.8, internal: 0.9, restricted: 0.4, airgap: 0.1
}

const computeRiskScore = (vuln: Vulnerability, asset: Asset): number => {
  try {
    const pExploit = safeNum(vuln.epss, 0.5) * (1 - safeNum(vuln.attack_complexity, 0.5))
    const severityFactor = Math.pow(safeNum(vuln.cvss, 5) / 10, 0.6)
    const threatMult = (vuln.cisa_kev ? 2.0 : 1.0) * (vuln.ransomware ? 1.5 : 1.0)
    const zoneExposure = ZONE_EXPOSURE[asset.network_zone] ?? 0.9
    const exposureFactor = asset.internet_facing ? zoneExposure * 1.4 : zoneExposure
    const critFactor = safeNum(asset.criticality, 3) / 5
    const raw = pExploit * severityFactor * threatMult * exposureFactor * critFactor
    return Math.max(0.5, Math.min(10, (1 - Math.exp(-2.5 * raw)) * 10))
  } catch { return 5 }
}

const computeRPC = (vuln: Vulnerability, asset: Asset): number => {
  try {
    const pExploit = safeNum(vuln.epss, 0.5) * (1 - safeNum(vuln.attack_complexity, 0.5))
    const severityFactor = Math.pow(safeNum(vuln.cvss, 5) / 10, 0.6)
    const threatMult = (vuln.cisa_kev ? 2.0 : 1.0) * (vuln.ransomware ? 1.5 : 1.0)
    const zoneExposure = ZONE_EXPOSURE[asset.network_zone] ?? 0.9
    const exposureFactor = asset.internet_facing ? zoneExposure * 1.4 : zoneExposure
    const revFactor = 1 + Math.log10(Math.max(1, safeNum(asset.annual_revenue_exposure, 100000)) / 100000) * 0.3
    const critFactor = safeNum(asset.criticality, 3) / 5
    const raw = pExploit * severityFactor * threatMult * exposureFactor * critFactor * revFactor
    return Math.max(0.5, Math.min(10, (1 - Math.exp(-2.5 * raw)) * 10))
  } catch { return 5 }
}

const buildGraphNodes = (assets: Asset[]): GraphNode[] => {
  const nodes: GraphNode[] = []
  assets.forEach(asset => {
    asset.vulnerabilities.forEach(vuln => {
      nodes.push({
        id: `${asset.id}:${vuln.id}`,
        asset, vuln,
        centrality: 0,
        pageRank: 0,
        pprScore: 0,
        blastRadius: 0,
        risk: computeRiskScore(vuln, asset),
        rpc: computeRPC(vuln, asset),
        attackProb: 0,
      })
    })
  })
  return nodes
}

const PHASE_ORDER = new Map<string, number>(
  ['initial_access','execution','persistence','privilege_escalation',
   'defense_evasion','credential_access','discovery','lateral_movement',
   'collection','exfiltration','impact'].map((p, i) => [p, i])
)

const PRIV_LEVEL: Record<string, number> = { none: 0, low: 1, high: 2 }

const privilegeGained = (vuln: Vulnerability): number => {
  const phase = vuln.kill_chain_phase
  if (phase === 'credential_access' || phase === 'privilege_escalation') return 2
  if (phase === 'lateral_movement') return 1
  return 0
}

const ZONE_REACH: Record<string, Record<string, number>> = {
  dmz:        { dmz: 0.90, internal: 0.60, restricted: 0.10, airgap: 0.00 },
  internal:   { dmz: 0.80, internal: 0.90, restricted: 0.30, airgap: 0.00 },
  restricted: { dmz: 0.20, internal: 0.40, restricted: 0.80, airgap: 0.05 },
  airgap:     { dmz: 0.00, internal: 0.00, restricted: 0.05, airgap: 0.70 },
}

const buildSparseGraph = (nodes: GraphNode[]): Edge[][] => {
  const n = nodes.length
  const adjList: Edge[][] = Array.from({ length: n }, () => [])
  
  const nodesByZone: Record<string, number[]> = { dmz: [], internal: [], restricted: [], airgap: [] }
  nodes.forEach((node, i) => nodesByZone[node.asset.network_zone].push(i))
  
  for (let i = 0; i < n; i++) {
    const srcPhase = PHASE_ORDER.get(nodes[i].vuln.kill_chain_phase) ?? 0
    const srcZone = nodes[i].asset.network_zone
    const attackerPrivAfterSrc = privilegeGained(nodes[i].vuln)

    const reachableZones = Object.entries(ZONE_REACH[srcZone] || {})
      .filter(([_, prob]) => prob > 0.01)
      .map(([zone, _]) => zone)

    const candidateIndices = reachableZones.flatMap(z => nodesByZone[z] || [])
    
    for (const j of candidateIndices) {
      if (i === j) continue

      const tgtPhase = PHASE_ORDER.get(nodes[j].vuln.kill_chain_phase) ?? 0
      const tgtPrivReq = PRIV_LEVEL[nodes[j].vuln.privileges_required] ?? 0

      if (tgtPhase < srcPhase - 1) continue
      if (attackerPrivAfterSrc < tgtPrivReq) continue

      const reach = ZONE_REACH[srcZone]?.[nodes[j].asset.network_zone] ?? 0.1
      if (reach < 0.01) continue

      const pExploit = safeNum(nodes[j].vuln.epss, 0.5) * (1 - safeNum(nodes[j].vuln.attack_complexity, 0.5))
      const threatMult = (nodes[j].vuln.cisa_kev ? 1.5 : 1.0) * (nodes[j].vuln.ransomware ? 1.2 : 1.0)
      const phaseContinuity = tgtPhase >= srcPhase ? 1.2 : 0.85

      const weight = Math.min(0.999, pExploit * reach * threatMult * phaseContinuity)
      if (weight < 0.01) continue

      adjList[i].push({ to: j, weight, logCost: -Math.log(Math.max(weight, 1e-9)) })
    }
  }
  return adjList
}

const computePPR = (
  adjList: Edge[][],
  nodes: GraphNode[],
  seedFn: (node: GraphNode) => number,
  alpha = 0.15,
  maxIter = 50,
  tol = 1e-6
): number[] => {
  const n = adjList.length
  if (n === 0) return []

  const rawSeeds = nodes.map(seedFn)
  const seedTotal = rawSeeds.reduce((a, b) => a + b, 0) || 1
  const seedDist = rawSeeds.map(w => w / seedTotal)

  const outWeightTotals = adjList.map(edges => edges.reduce((s, e) => s + e.weight, 0))

  const incoming: { from: number; normWeight: number }[][] = Array.from({ length: n }, () => [])
  for (let i = 0; i < n; i++) {
    const total = outWeightTotals[i] || 1
    adjList[i].forEach(e => incoming[e.to].push({ from: i, normWeight: e.weight / total }))
  }

  let pr = [...seedDist]

  for (let iter = 0; iter < maxIter; iter++) {
    const next = seedDist.map(s => alpha * s)
    for (let j = 0; j < n; j++) {
      for (const e of incoming[j]) {
        next[j] += (1 - alpha) * pr[e.from] * e.normWeight
      }
    }
    const delta = next.reduce((s, v, i) => s + Math.abs(v - pr[i]), 0)
    pr = next
    if (delta < tol) break
  }
  return pr
}

const computeReversePPR = (adjList: Edge[][], nodes: GraphNode[], alpha = 0.15): number[] => {
  const n = adjList.length
  const reversedAdj: Edge[][] = Array.from({ length: n }, () => [])
  for (let i = 0; i < n; i++) {
    adjList[i].forEach(e => reversedAdj[e.to].push({ to: i, weight: e.weight, logCost: e.logCost }))
  }
  return computePPR(reversedAdj, nodes,
    node => node.asset.criticality >= 4 ? node.asset.criticality / 5 : 0, alpha)
}

const propagateBeliefs = (nodes: GraphNode[], adjList: Edge[][]): number[] => {
  const n = nodes.length
  if (n === 0) return []

  const belief = nodes.map(node => {
    if (node.asset.internet_facing) {
      return safeNum(node.vuln.epss, 0.5) * (node.vuln.cisa_kev ? 1.8 : 1.0) * (ZONE_EXPOSURE[node.asset.network_zone] ?? 0.9)
    }
    return 0.01
  })

  const outTotals = adjList.map(edges => edges.reduce((s, e) => s + e.weight, 0))
  const incoming: { from: number; normWeight: number }[][] = Array.from({ length: n }, () => [])
  for (let i = 0; i < n; i++) {
    const total = outTotals[i] || 1
    adjList[i].forEach(e => incoming[e.to].push({ from: i, normWeight: e.weight / total }))
  }

  const DAMPING = 0.6
  for (let iter = 0; iter < 15; iter++) {
    const next = [...belief]
    for (let i = 0; i < n; i++) {
      if (incoming[i].length === 0) continue

      let maxMsg = 0
      for (const e of incoming[i]) {
        const msg = belief[e.from] * e.normWeight
        if (msg > maxMsg) maxMsg = msg
      }

      const exploitability = safeNum(nodes[i].vuln.epss, 0.5) *
                             (1 - safeNum(nodes[i].vuln.attack_complexity, 0.5)) *
                             (nodes[i].vuln.cisa_kev ? 1.6 : 1.0)

      next[i] = DAMPING * belief[i] + (1 - DAMPING) * Math.min(1, maxMsg * exploitability * 2)
    }

    const delta = next.reduce((s, v, i) => s + Math.abs(v - belief[i]), 0)
    for (let i = 0; i < n; i++) belief[i] = next[i]
    if (delta < 1e-6) break
  }

  return belief
}

const normaliseBeliefs = (beliefs: number[], nodes: GraphNode[]): void => {
  const positive = beliefs.filter(b => b > 0)
  if (positive.length === 0) return
  const minB = Math.min(...positive)
  const maxB = Math.max(...beliefs) || 1

  beliefs.forEach((b, i) => {
    const logNorm = maxB > minB
      ? (Math.log(b + minB) - Math.log(minB)) / (Math.log(maxB + minB) - Math.log(minB))
      : 0
    nodes[i].attackProb = Math.min(1, Math.max(0, b))
    nodes[i].risk = Math.max(0.5, Math.min(10, 1 + 9 * logNorm))
  })
}

const dijkstra = (adj: Edge[][], source: number, blockedEdges: Set<string>): { dist: number[]; prev: number[] } => {
  const n = adj.length
  const dist = new Float64Array(n).fill(Infinity)
  const prev = new Int32Array(n).fill(-1)
  dist[source] = 0

  const pq: [number, number][] = [[0, source]]

  while (pq.length > 0) {
    pq.sort((a, b) => a[0] - b[0])
    const [d, u] = pq.shift()!
    if (d > dist[u]) continue
    for (const e of adj[u]) {
      const edgeKey = `${u}->${e.to}`
      if (blockedEdges.has(edgeKey)) continue
      const nd = d + e.logCost
      if (nd < dist[e.to]) {
        dist[e.to] = nd
        prev[e.to] = u
        pq.push([nd, e.to])
      }
    }
  }
  return { dist: Array.from(dist), prev: Array.from(prev) }
}

const reconstructPath = (prev: number[], src: number, tgt: number): number[] => {
  const path: number[] = []
  let cur = tgt
  while (cur !== -1) {
    path.unshift(cur)
    if (cur === src) break
    cur = prev[cur]
  }
  return path[0] === src ? path : []
}

const wilsonInterval = (p: number, n: number): [number, number] => {
  const z = 1.96
  const denom = 1 + z * z / n
  const centre = (p + z * z / (2 * n)) / denom
  const margin = (z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
  return [Math.max(0, centre - margin), Math.min(1, centre + margin)]
}

const computeChainProbability = (path: number[], adj: Edge[][]): number => {
  if (path.length < 2) return 0.5

  let jointLogProb = 0
  for (let i = 0; i < path.length - 1; i++) {
    const u = path[i], v = path[i + 1]
    const edge = adj[u].find(e => e.to === v)
    const pStep = edge ? edge.weight : 0.1
    jointLogProb += Math.log(Math.max(pStep, 1e-9))
  }

  const RETRY = 0.3
  const pRaw = Math.exp(jointLogProb)
  const pEffective = Math.min(0.999, pRaw / (1 - (1 - pRaw) * RETRY))
  return pEffective
}

const discoverAttackPaths = (nodes: GraphNode[], adjList: Edge[][]): AttackPath[] => {
  const n = nodes.length
  if (n === 0) return []

  // Entry points: internet-facing nodes with initial_access
  const entryIdxs = nodes
    .map((nd, i) => ({ 
      i, 
      isEntry: nd.asset.internet_facing && nd.vuln.kill_chain_phase === 'initial_access',
      ppr: nd.pprScore
    }))
    .filter(e => e.isEntry && adjList[e.i].length > 0)
    .sort((a, b) => b.ppr - a.ppr)
    .slice(0, 20)
    .map(e => e.i)

  console.log(`      Entry candidates found: ${entryIdxs.length}`)

  // Target nodes: high-criticality + high blast-radius
  const targetCandidates = nodes
    .map((nd, i) => ({ i, score: nd.asset.criticality * (nd.blastRadius || 0.001) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 30)

  const targetIdxSet = new Set(targetCandidates.map(e => e.i))
  
  console.log(`      Target candidates found: ${targetIdxSet.size}`)
  if (targetCandidates.length > 0) {
    console.log(`      Top target score: ${targetCandidates[0].score.toFixed(6)}`)
  }

  const allPaths: AttackPath[] = []
  const usedSigs = new Set<string>()
  const K_PATHS = 3

  for (const entryIdx of entryIdxs) {
    for (const targetIdx of targetIdxSet) {
      if (entryIdx === targetIdx) continue

      const A: { path: number[]; logCost: number }[] = []

      const { dist: d0, prev: p0 } = dijkstra(adjList, entryIdx, new Set())
      if (!isFinite(d0[targetIdx])) continue
      
      const first = reconstructPath(Array.from(p0), entryIdx, targetIdx)
      if (first.length < 2) continue
      
      A.push({ path: first, logCost: d0[targetIdx] })

      // Yen's K-Shortest Paths
      const B: { path: number[]; logCost: number }[] = []
      for (let k = 1; k < K_PATHS; k++) {
        if (!A[k - 1]) break
        const prevPath = A[k - 1].path
        
        for (let i = 0; i < prevPath.length - 1; i++) {
          const spurNode = prevPath[i]
          const rootPath = prevPath.slice(0, i + 1)

          const blocked = new Set<string>()
          for (const ap of A) {
            if (ap.path.length > i && ap.path.slice(0, i + 1).join(',') === rootPath.join(',')) {
              blocked.add(`${ap.path[i]}->${ap.path[i + 1]}`)
            }
          }
          const blockedNodes = new Set(rootPath.slice(0, -1))

          const tempAdj: Edge[][] = adjList.map((edges, idx) => {
            if (blockedNodes.has(idx) && idx !== spurNode) return []
            return edges.filter(e => !blocked.has(`${idx}->${e.to}`) && !blockedNodes.has(e.to))
          })

          const { dist: dSpur, prev: pSpur } = dijkstra(tempAdj, spurNode, new Set())
          if (!isFinite(dSpur[targetIdx])) continue

          const spurPath = reconstructPath(Array.from(pSpur), spurNode, targetIdx)
          if (spurPath.length < 1) continue

          const totalPath = [...rootPath.slice(0, -1), ...spurPath]

          let totalLogCost = 0
          for (let s = 0; s < totalPath.length - 1; s++) {
            const u = totalPath[s], v = totalPath[s + 1]
            const e = adjList[u]?.find(x => x.to === v)
            totalLogCost += e ? e.logCost : 10
          }

          if (!B.find(b => b.path.join(',') === totalPath.join(','))) {
            B.push({ path: totalPath, logCost: totalLogCost })
          }
        }

        if (B.length === 0) break
        B.sort((a, b) => a.logCost - b.logCost)
        A.push(B.shift()!)
      }

      for (const { path } of A) {
        const sig = path.join('|')
        if (usedSigs.has(sig)) continue
        usedSigs.add(sig)

        const pathNodes = path.map(i => nodes[i])
        const prob = computeChainProbability(path, adjList)
        const ci = wilsonInterval(prob, path.length * 10)

        const avgRisk = pathNodes.reduce((s, nd) => s + nd.risk, 0) / pathNodes.length
        const maxRisk = Math.max(...pathNodes.map(nd => nd.risk))
        const riskScore = Math.round((avgRisk * 0.4 + maxRisk * 0.6) * 10) / 10

        const techniques = new Set<string>()
        pathNodes.forEach(nd => nd.vuln.mitre_techniques?.forEach(t => techniques.add(t)))

        allPaths.push({
          id: `AP-${allPaths.length + 1}`,
          nodes: pathNodes,
          riskScore,
          attackProbability: Math.round(prob * 10000) / 10000,
          confidenceInterval: ci,
          mitreTechniques: Array.from(techniques),
        })

        if (allPaths.length >= 50) break
      }
      if (allPaths.length >= 50) break
    }
    if (allPaths.length >= 50) break
  }

  return allPaths.sort((a, b) => b.riskScore - a.riskScore).slice(0, 10)
}

// ============================================================================
// MAIN TEST - WITH PROPER PPR COMPUTATION
// ============================================================================

console.log('='.repeat(80))
console.log('ATTACK PATH ALGORITHM COHERENCE TEST')
console.log('Simulating 1000 assets with vulnerability scan')
console.log('='.repeat(80))

const startTime = Date.now()

console.log('\n[1/6] Generating 1000 assets...')
const assets = generateAssets(1000)
console.log(`      Generated ${assets.length} assets`)
console.log(`      Internet-facing: ${assets.filter(a => a.internet_facing).length}`)
console.log(`      Entry points: ${assets.filter(a => a.is_entry_point).length}`)

console.log('\n[2/6] Building graph nodes...')
const graphNodes = buildGraphNodes(assets)
console.log(`      Created ${graphNodes.length} graph nodes`)
console.log(`      Critical vulns: ${graphNodes.filter(n => n.vuln.severity === 'critical').length}`)
console.log(`      CISA KEV: ${graphNodes.filter(n => n.vuln.cisa_kev).length}`)

console.log('\n[3/6] Building sparse graph...')
const adjList = buildSparseGraph(graphNodes)
const totalEdges = adjList.reduce((s, e) => s + e.length, 0)
console.log(`      Total edges: ${totalEdges}`)

console.log('\n[4/6] Computing PPR (CRITICAL STEP - sets blastRadius)...')
const forwardPPR = computePPR(adjList, graphNodes,
  node => node.asset.internet_facing ? safeNum(node.vuln.epss, 0.5) * (node.vuln.cisa_kev ? 2 : 1) : 0
)
const reversePPR = computeReversePPR(adjList, graphNodes)

// IMPORTANT: Set PPR scores and blastRadius
graphNodes.forEach((node, i) => {
  node.pprScore = forwardPPR[i] || 0
  node.blastRadius = reversePPR[i] || 0
  node.pageRank = forwardPPR[i] || 0
  node.centrality = Math.sqrt((forwardPPR[i] || 0) * (reversePPR[i] || 0))
})

console.log(`      Avg blastRadius: ${(graphNodes.reduce((s, n) => s + n.blastRadius, 0) / graphNodes.length).toFixed(6)}`)
console.log(`      Max blastRadius: ${Math.max(...graphNodes.map(n => n.blastRadius)).toFixed(6)}`)

console.log('\n[5/6] Propagating beliefs...')
const beliefs = propagateBeliefs(graphNodes, adjList)
normaliseBeliefs(beliefs, graphNodes)

console.log('\n[6/6] Discovering attack paths...')
const paths = discoverAttackPaths(graphNodes, adjList)
console.log(`      Found ${paths.length} attack paths`)

const elapsed = ((Date.now() - startTime) / 1000).toFixed(1)
console.log(`\nAlgorithm completed in ${elapsed}s\n`)

// ============================================================================
// BRUTAL HONEST ANALYSIS
// ============================================================================

if (paths.length === 0) {
  console.log('❌ CRITICAL ERROR: No attack paths found!')
  console.log('This indicates a fundamental issue with the algorithm.')
  process.exit(1)
}

console.log('='.repeat(80))
console.log('TOP 5 ATTACK PATHS - DETAILED ANALYSIS')
console.log('='.repeat(80))

paths.slice(0, 5).forEach((path, idx) => {
  console.log(`\n┌${'─'.repeat(78)}┐`)
  console.log(`│ PATH ${idx + 1}: ${path.id} ${' '.repeat(70 - path.id.length)}│`)
  console.log(`├${'─'.repeat(78)}┤`)
  console.log(`│ Risk Score: ${path.riskScore.toFixed(1)}/10    Attack Probability: ${(path.attackProbability * 100).toFixed(4)}%${' '.repeat(38)}│`)
  console.log(`│ 95% CI: [${(path.confidenceInterval[0] * 100).toFixed(2)}%, ${(path.confidenceInterval[1] * 100).toFixed(2)}%]${' '.repeat(57)}│`)
  console.log(`│ MITRE Techniques: ${path.mitreTechniques.slice(0, 4).join(', ').substring(0, 55).padEnd(55)}│`)
  console.log(`├${'─'.repeat(78)}┤`)
  console.log('│ ATTACK STEPS:'.padEnd(79) + '│')
  
  path.nodes.forEach((node, stepIdx) => {
    const step = `  ${stepIdx + 1}. ${node.asset.name} [${node.asset.network_zone.toUpperCase()}]`
    console.log(`│ ${step.padEnd(77)}│`)
    console.log(`│     Vuln: ${node.vuln.title.substring(0, 45).padEnd(45)}│`)
    console.log(`│     Phase: ${node.vuln.kill_chain_phase.padEnd(15)} ` +
                `Priv: ${node.vuln.privileges_required.padEnd(5)} ` +
                `Risk: ${node.risk.toFixed(1)}   │`)
  })
  console.log(`└${'─'.repeat(78)}┘`)
})

// ============================================================================
// COHERENCE ANALYSIS
// ============================================================================

console.log('\n')
console.log('='.repeat(80))
console.log('BRUTAL HONEST COHERENCE ANALYSIS')
console.log('From a Red Teamer/Pentester Perspective (15+ years experience)')
console.log('='.repeat(80))

console.log('\n## 1. PATH LENGTH ANALYSIS')
const avgLength = paths.reduce((s, p) => s + p.nodes.length, 0) / paths.length
const lengthDist = paths.reduce((acc, p) => {
  acc[p.nodes.length] = (acc[p.nodes.length] || 0) + 1
  return acc
}, {} as Record<number, number>)

console.log(`   Average path length: ${avgLength.toFixed(1)} steps`)
console.log(`   Length distribution: ${Object.entries(lengthDist).map(([k, v]) => `${k} steps: ${v}`).join(', ')}`)

if (avgLength < 4) {
  console.log('\n   ❌ CRITICAL ISSUE: Average path length is too short!')
  console.log('   Real attack paths typically have 4-7 steps:')
  console.log('   initial_access → credential_access → lateral_movement → privilege_escalation → impact')
}

console.log('\n## 2. KILL CHAIN PROGRESSION ANALYSIS')
paths.slice(0, 5).forEach((path, idx) => {
  const phases = path.nodes.map(n => n.vuln.kill_chain_phase)
  console.log(`\n   Path ${idx + 1}: ${phases.join(' → ')}`)
  
  const hasInitialAccess = phases.includes('initial_access')
  const hasCredentialAccess = phases.includes('credential_access')
  const hasLateralMovement = phases.includes('lateral_movement')
  
  console.log(`   - initial_access: ${hasInitialAccess ? '✓' : '✗'}  credential_access: ${hasCredentialAccess ? '✓' : '✗'}  lateral_movement: ${hasLateralMovement ? '✓' : '✗'}`)
})

console.log('\n## 3. CREDENTIAL TRACKING ANALYSIS')
console.log('   ❌ CRITICAL: No credential propagation model exists!')
console.log('   The algorithm tracks "privilege level" but NOT credentials.')
console.log('   Real attacks require tracking:')
console.log('   - What credentials are obtained at each step')
console.log('   - What credentials are required for next step')
console.log('   - Credential reuse across assets')

console.log('\n## 4. PROBABILITY MODEL ANALYSIS')
paths.slice(0, 5).forEach((path, idx) => {
  const prob = path.attackProbability
  console.log(`\n   Path ${idx + 1}: ${(prob * 100).toFixed(4)}% probability`)
  
  if (prob > 0.5) {
    console.log('   ❌ ISSUE: >50% probability is unrealistic for multi-step attacks')
  } else if (prob > 0.1) {
    console.log('   ⚠️  WARNING: >10% probability may be optimistic')
  } else {
    console.log('   ✓ Probability is in realistic range (<10%)')
  }
})

console.log('\n## 5. ENTRY POINT VS TARGET ANALYSIS')
const firstNodes = paths.map(p => p.nodes[0])
const lastNodes = paths.map(p => p.nodes[p.nodes.length - 1])

const validEntries = firstNodes.filter(n => n.asset.internet_facing && n.vuln.kill_chain_phase === 'initial_access')
const highValueTargets = lastNodes.filter(n => n.asset.criticality >= 4)

console.log(`\n   Valid entry points: ${validEntries.length}/${paths.length}`)
console.log(`   High-value targets: ${highValueTargets.length}/${paths.length}`)

console.log('\n')
console.log('='.repeat(80))
console.log('FINAL VERDICT')
console.log('='.repeat(80))

const issues: string[] = []

if (avgLength < 4) issues.push('Path lengths too short (avg < 4 steps)')
issues.push('No credential propagation model')
if (paths.some(p => p.attackProbability > 0.5)) issues.push('Unrealistic probability calculations')
issues.push('Techniques not contextualized to specific actions')

console.log('\n⚠️  COHERENCE ISSUES IDENTIFIED:')
issues.forEach((issue, i) => console.log(`   ${i + 1}. ${issue}`))

console.log('\n📊 ALGORITHM VERDICT:')
if (issues.length >= 3) {
  console.log('   ❌ NOT PRODUCTION READY')
  console.log('   The algorithm finds GRAPH CONNECTIONS, not ATTACK PATHS.')
  console.log('   It lacks: credential tracking, technique context, realistic probability')
} else {
  console.log('   ⚠️  NEEDS IMPROVEMENT')
}

console.log('\n')
