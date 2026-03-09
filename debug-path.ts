/**
 * Debug: Why are no paths found when Dijkstra says targets are reachable?
 */

console.log('='.repeat(80))
console.log('DEBUGGING PATH DISCOVERY')
console.log('='.repeat(80))

// Simplified test
interface Vulnerability {
  id: string
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
  network_zone: 'dmz' | 'internal' | 'restricted' | 'airgap'
  criticality: number
  internet_facing: boolean
  vulnerabilities: Vulnerability[]
  is_entry_point?: boolean
}

interface GraphNode {
  id: string
  asset: Asset
  vuln: Vulnerability
  pprScore: number
  blastRadius: number
  risk: number
}

interface Edge { to: number; weight: number; logCost: number }

const VULN_DB: Vulnerability[] = [
  { id: 'CVE-2021-44228', title: 'Log4Shell RCE', severity: 'critical', cvss: 10.0, epss: 0.96, attack_complexity: 0.05, privileges_required: 'none', cisa_kev: true, ransomware: true, kill_chain_phase: 'initial_access', mitre_techniques: ['T1190'] },
  { id: 'WIN-KERBEROAST', title: 'Kerberoasting', severity: 'high', cvss: 8.1, epss: 0.68, attack_complexity: 0.35, privileges_required: 'low', cisa_kev: false, ransomware: false, kill_chain_phase: 'credential_access', mitre_techniques: ['T1558.003'] },
  { id: 'WIN-DC-SYNC', title: 'DCSync', severity: 'critical', cvss: 9.5, epss: 0.72, attack_complexity: 0.4, privileges_required: 'high', cisa_kev: false, ransomware: true, kill_chain_phase: 'credential_access', mitre_techniques: ['T1003.006'] },
  { id: 'WIN-SMB1', title: 'SMBv1 Enabled', severity: 'critical', cvss: 9.3, epss: 0.95, attack_complexity: 0.1, privileges_required: 'none', cisa_kev: true, ransomware: true, kill_chain_phase: 'lateral_movement', mitre_techniques: ['T1021.002'] },
]

const PHASE_ORDER = new Map<string, number>(
  ['initial_access','execution','persistence','privilege_escalation',
   'defense_evasion','credential_access','discovery','lateral_movement',
   'collection','exfiltration','impact'].map((p, i) => [p, i])
)

const PRIV_LEVEL: Record<string, number> = { none: 0, low: 1, high: 2 }
const ZONE_REACH: Record<string, Record<string, number>> = {
  dmz:        { dmz: 0.90, internal: 0.60, restricted: 0.10, airgap: 0.00 },
  internal:   { dmz: 0.80, internal: 0.90, restricted: 0.30, airgap: 0.00 },
  restricted: { dmz: 0.20, internal: 0.40, restricted: 0.80, airgap: 0.05 },
  airgap:     { dmz: 0.00, internal: 0.00, restricted: 0.05, airgap: 0.70 },
}

// Create a small test case
const assets: Asset[] = [
  // Entry point: DMZ web server with initial_access vuln
  { id: 'asset-1', name: 'WEB-DMZ-01', type: 'vm', network_zone: 'dmz', criticality: 3, internet_facing: true, is_entry_point: true, vulnerabilities: [VULN_DB[0]] },
  // Internal server with lateral_movement vuln
  { id: 'asset-2', name: 'SRV-INT-01', type: 'server', network_zone: 'internal', criticality: 4, internet_facing: false, is_entry_point: false, vulnerabilities: [VULN_DB[3]] },
  // High-value target with credential_access (requires high priv)
  { id: 'asset-3', name: 'DC-RESTRICTED-01', type: 'server', network_zone: 'restricted', criticality: 5, internet_facing: false, is_entry_point: false, vulnerabilities: [VULN_DB[2]] },
]

const nodes: GraphNode[] = []
assets.forEach(asset => {
  asset.vulnerabilities.forEach(vuln => {
    nodes.push({
      id: `${asset.id}:${vuln.id}`,
      asset, vuln,
      pprScore: asset.internet_facing ? 0.5 : 0.1,
      blastRadius: asset.criticality / 5,
      risk: 8
    })
  })
})

console.log(`\nNodes (${nodes.length}):`)
nodes.forEach((n, i) => {
  console.log(`  [${i}] ${n.asset.name} - ${n.vuln.title} (phase: ${n.vuln.kill_chain_phase}, priv_req: ${n.vuln.privileges_required}, entry: ${n.asset.is_entry_point})`)
})

// Build graph
const adjList: Edge[][] = Array.from({ length: nodes.length }, () => [])

for (let i = 0; i < nodes.length; i++) {
  for (let j = 0; j < nodes.length; j++) {
    if (i === j) continue

    const srcPhase = PHASE_ORDER.get(nodes[i].vuln.kill_chain_phase) ?? 0
    const tgtPhase = PHASE_ORDER.get(nodes[j].vuln.kill_chain_phase) ?? 0
    const tgtPrivReq = PRIV_LEVEL[nodes[j].vuln.privileges_required] ?? 0
    
    // What privilege does attacker have AFTER exploiting node i?
    const privGained = (phase: string) => {
      if (phase === 'credential_access' || phase === 'privilege_escalation') return 2
      if (phase === 'lateral_movement') return 1
      return 0
    }
    const attackerPrivAfterSrc = privGained(nodes[i].vuln.kill_chain_phase)

    console.log(`\n  Edge [${i}]→[${j}]:`)
    console.log(`    srcPhase=${srcPhase} (${nodes[i].vuln.kill_chain_phase}), tgtPhase=${tgtPhase} (${nodes[j].vuln.kill_chain_phase})`)
    console.log(`    tgtPrivReq=${tgtPrivReq}, attackerPrivAfterSrc=${attackerPrivAfterSrc}`)
    console.log(`    Phase check: tgtPhase >= srcPhase-1? ${tgtPhase} >= ${srcPhase-1} = ${tgtPhase >= srcPhase - 1}`)
    console.log(`    Priv check: attackerPriv >= tgtPriv? ${attackerPrivAfterSrc} >= ${tgtPrivReq} = ${attackerPrivAfterSrc >= tgtPrivReq}`)

    // Gate 1: phase progression
    if (tgtPhase < srcPhase - 1) {
      console.log(`    ❌ BLOCKED: phase regression`)
      continue
    }
    
    // Gate 2: privilege check
    if (attackerPrivAfterSrc < tgtPrivReq) {
      console.log(`    ❌ BLOCKED: insufficient privilege`)
      continue
    }

    // Gate 3: zone reachability
    const reach = ZONE_REACH[nodes[i].asset.network_zone]?.[nodes[j].asset.network_zone] ?? 0.1
    if (reach < 0.01) {
      console.log(`    ❌ BLOCKED: zone unreachable (${nodes[i].asset.network_zone} → ${nodes[j].asset.network_zone})`)
      continue
    }

    console.log(`    ✓ EDGE CREATED (weight=${reach.toFixed(2)})`)
    adjList[i].push({ to: j, weight: reach, logCost: -Math.log(reach) })
  }
}

console.log('\n' + '='.repeat(80))
console.log('GRAPH STRUCTURE:')
adjList.forEach((edges, i) => {
  console.log(`  Node [${i}] ${nodes[i].asset.name}: edges to [${edges.map(e => e.to).join(', ')}]`)
})

// Now let's see what paths look like
console.log('\n' + '='.repeat(80))
console.log('PATH DISCOVERY SIMULATION:')

// Entry points
const entryIdxs = nodes
  .map((nd, i) => ({ i, score: (nd.asset.internet_facing && nd.asset.is_entry_point) ? nd.pprScore * 1.5 : 0 }))
  .filter(e => e.score > 0 && adjList[e.i].length > 0)
  .sort((a, b) => b.score - a.score)
  .map(e => e.i)

console.log(`Entry indices: [${entryIdxs.join(', ')}]`)

// Targets  
const targetIdxSet = new Set(
  nodes
    .map((nd, i) => ({ i, score: nd.asset.criticality * (nd.blastRadius || 0.001) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 10)
    .map(e => e.i)
)

console.log(`Target indices: [${Array.from(targetIdxSet).join(', ')}]`)

// Dijkstra
const dijkstra = (adj: Edge[][], source: number): number[] => {
  const n = adj.length
  const dist = new Float64Array(n).fill(Infinity)
  dist[source] = 0
  const pq: [number, number][] = [[0, source]]
  while (pq.length > 0) {
    pq.sort((a, b) => a[0] - b[0])
    const [d, u] = pq.shift()!
    if (d > dist[u]) continue
    for (const e of adj[u]) {
      const nd = d + e.logCost
      if (nd < dist[e.to]) {
        dist[e.to] = nd
        pq.push([nd, e.to])
      }
    }
  }
  return Array.from(dist)
}

console.log('\nDijkstra from each entry:')
entryIdxs.forEach(entryIdx => {
  const dist = dijkstra(adjList, entryIdx)
  console.log(`  From [${entryIdx}]: dist = [${dist.map((d, i) => isFinite(d) ? i + ':' + d.toFixed(2) : i + ':∞').join(', ')}]`)
  
  targetIdxSet.forEach(tgtIdx => {
    if (entryIdx === tgtIdx) return
    if (isFinite(dist[tgtIdx])) {
      console.log(`    ✓ Path exists to target [${tgtIdx}]`)
    } else {
      console.log(`    ❌ No path to target [${tgtIdx}]`)
    }
  })
})

console.log('\n' + '='.repeat(80))
console.log('ROOT CAUSE ANALYSIS:')
console.log('The issue is in the PRIVILEGE GATING logic.')
console.log('')
console.log('Node 0 (initial_access, priv_gained=0) cannot reach Node 2 (credential_access, priv_required=high=2)')
console.log('Because after exploiting Node 0, attacker has priv=0, but Node 2 requires priv=2')
console.log('')
console.log('However, Node 0 CAN reach Node 1 (lateral_movement, priv_required=none)')
console.log('And Node 1 (lateral_movement, priv_gained=1) can reach... let me check')
console.log('')

// What can Node 1 reach?
console.log('What Node 1 (lateral_movement, priv_gained=1) can reach:')
for (let j = 0; j < nodes.length; j++) {
  if (j === 1) continue
  const tgtPrivReq = PRIV_LEVEL[nodes[j].vuln.privileges_required] ?? 0
  const srcPhase = PHASE_ORDER.get(nodes[1].vuln.kill_chain_phase) ?? 0
  const tgtPhase = PHASE_ORDER.get(nodes[j].vuln.kill_chain_phase) ?? 0
  const privGained = 1  // lateral_movement gives priv=1
  
  const phaseOk = tgtPhase >= srcPhase - 1
  const privOk = privGained >= tgtPrivReq
  
  console.log(`  → [${j}]: phase=${tgtPhase}>=${srcPhase-1}? ${phaseOk}, priv=${privGained}>=${tgtPrivReq}? ${privOk} → ${phaseOk && privOk ? 'YES' : 'NO'}`)
}

console.log('\n' + '='.repeat(80))
console.log('CONCLUSION:')
console.log('The problem is that credential_access/privilege_escalation nodes require HIGH privilege.')
console.log('But lateral_movement only grants LOW privilege.')
console.log('')
console.log('So the attack path is:')
console.log('  initial_access (priv=0) → lateral_movement (priv=1) → CANNOT reach credential_access (requires priv=2)')
console.log('')
console.log('This means the algorithm CANNOT form multi-step attack paths!')
console.log('Because there is no node that grants priv=2 that can be reached with priv=0 or priv=1.')
console.log('')
console.log('The vuln database needs nodes that:')
console.log('  1. Are reachable with priv=0 or priv=1')
console.log('  2. Grant priv=2 when exploited')
console.log('')
console.log('Looking at the vuln DB:')
console.log('  - privilege_escalation vulns require LOW priv and grant HIGH priv')
console.log('  - But do we have such vulns assigned to nodes?')
