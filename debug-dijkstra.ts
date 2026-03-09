/**
 * Debug Dijkstra - Why are no paths found?
 */

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

interface Edge {
  to: number
  weight: number
  logCost: number
}

const VULN_DB: Vulnerability[] = [
  { id: 'CVE-2017-0144', title: 'EternalBlue SMBv1 RCE', severity: 'critical', cvss: 8.8, epss: 0.97, attack_complexity: 0.1, privileges_required: 'none', cisa_kev: true, ransomware: true, kill_chain_phase: 'initial_access', mitre_techniques: ['T1190'] },
  { id: 'WIN-SMB1', title: 'SMBv1 Protocol Enabled', severity: 'critical', cvss: 9.3, epss: 0.95, attack_complexity: 0.1, privileges_required: 'none', cisa_kev: true, ransomware: true, kill_chain_phase: 'lateral_movement', mitre_techniques: ['T1021.002'] },
  { id: 'WIN-PASS-HASH', title: 'Pass-the-Hash Vulnerable', severity: 'critical', cvss: 9.1, epss: 0.75, attack_complexity: 0.3, privileges_required: 'low', cisa_kev: false, ransomware: true, kill_chain_phase: 'lateral_movement', mitre_techniques: ['T1550.002'] },
  { id: 'WIN-KERBEROAST', title: 'Kerberoasting Vulnerable', severity: 'high', cvss: 8.1, epss: 0.68, attack_complexity: 0.35, privileges_required: 'low', cisa_kev: false, ransomware: false, kill_chain_phase: 'credential_access', mitre_techniques: ['T1558.003'] },
  { id: 'WIN-LSASS-DUMP', title: 'LSASS Memory Dumpable', severity: 'high', cvss: 8.2, epss: 0.65, attack_complexity: 0.3, privileges_required: 'high', cisa_kev: false, ransomware: true, kill_chain_phase: 'credential_access', mitre_techniques: ['T1003.001'] },
]

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

console.log('='.repeat(80))
console.log('DIJKSTRA DEBUG TEST')
console.log('='.repeat(80))

// Create a simple test case
const testAssets: Asset[] = [
  // Entry point - DMZ with initial_access
  { id: 'entry-1', name: 'WEB-SRV-001', type: 'vm', network_zone: 'dmz', criticality: 3, internet_facing: true, is_entry_point: true,
    vulnerabilities: [{ ...VULN_DB[0] }] }, // EternalBlue - initial_access, priv=none
  
  // Pivot - internal with lateral_movement (needs low priv)
  { id: 'pivot-1', name: 'FILE-SRV-001', type: 'server', network_zone: 'internal', criticality: 4, internet_facing: false,
    vulnerabilities: [{ ...VULN_DB[1] }] }, // SMBv1 - lateral_movement, priv=none
  
  // Target - restricted with credential_access (needs high priv)
  { id: 'target-1', name: 'DC-001', type: 'server', network_zone: 'restricted', criticality: 5, internet_facing: false,
    vulnerabilities: [{ ...VULN_DB[4] }] }, // LSASS Dump - credential_access, priv=high
]

// Build graph nodes
const nodes: GraphNode[] = []
testAssets.forEach(asset => {
  asset.vulnerabilities.forEach(vuln => {
    nodes.push({
      id: `${asset.id}:${vuln.id}`,
      asset, vuln,
      pprScore: asset.internet_facing ? 0.5 : 0.1,
      blastRadius: asset.criticality / 5,
      risk: 8.5
    })
  })
})

console.log(`\nCreated ${nodes.length} nodes:`)
nodes.forEach((n, i) => {
  console.log(`  [${i}] ${n.asset.name} (${n.asset.network_zone}) - Phase: ${n.vuln.kill_chain_phase}, Priv: ${n.vuln.privileges_required}`)
})

// Build edges
const adjList: Edge[][] = Array.from({ length: nodes.length }, () => [])

for (let i = 0; i < nodes.length; i++) {
  for (let j = 0; j < nodes.length; j++) {
    if (i === j) continue
    
    const src = nodes[i]
    const tgt = nodes[j]
    
    const srcPhase = PHASE_ORDER.get(src.vuln.kill_chain_phase) ?? 0
    const tgtPhase = PHASE_ORDER.get(tgt.vuln.kill_chain_phase) ?? 0
    const tgtPrivReq = PRIV_LEVEL[tgt.vuln.privileges_required] ?? 0
    const attackerPrivAfterSrc = privilegeGained(src.vuln)
    
    console.log(`\nChecking edge ${i}→${j}:`)
    console.log(`  src: ${src.asset.name} phase=${src.vuln.kill_chain_phase}(${srcPhase}) privGained=${attackerPrivAfterSrc}`)
    console.log(`  tgt: ${tgt.asset.name} phase=${tgt.vuln.kill_chain_phase}(${tgtPhase}) privReq=${tgtPrivReq}`)
    
    // Gate 1: phase progression
    if (tgtPhase < srcPhase - 1) {
      console.log(`  ❌ BLOCKED: phase regression (tgtPhase ${tgtPhase} < srcPhase ${srcPhase} - 1)`)
      continue
    }
    
    // Gate 2: privilege check
    if (attackerPrivAfterSrc < tgtPrivReq) {
      console.log(`  ❌ BLOCKED: insufficient privilege (have ${attackerPrivAfterSrc}, need ${tgtPrivReq})`)
      continue
    }
    
    // Gate 3: network reachability
    const reach = ZONE_REACH[src.asset.network_zone]?.[tgt.asset.network_zone] ?? 0
    if (reach < 0.01) {
      console.log(`  ❌ BLOCKED: network unreachable (${src.asset.network_zone} → ${tgt.asset.network_zone} = ${reach})`)
      continue
    }
    
    console.log(`  ✓ EDGE CREATED: weight=${reach.toFixed(2)}`)
    adjList[i].push({ to: j, weight: reach, logCost: -Math.log(reach) })
  }
}

console.log('\n' + '='.repeat(80))
console.log('EDGE SUMMARY:')
adjList.forEach((edges, i) => {
  console.log(`Node ${i} (${nodes[i].asset.name}): ${edges.length} outgoing edges`)
  edges.forEach(e => console.log(`  → ${e.to} (${nodes[e.to].asset.name})`))
})

// Now try Dijkstra
console.log('\n' + '='.repeat(80))
console.log('DIJKSTRA TEST:')

const dijkstra = (adj: Edge[][], source: number): { dist: number[]; prev: number[] } => {
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

// Entry point is node 0 (WEB-SRV with initial_access)
const entryIdx = 0
const { dist, prev } = dijkstra(adjList, entryIdx)

console.log(`\nFrom entry node ${entryIdx} (${nodes[entryIdx].asset.name}):`)
dist.forEach((d, i) => {
  console.log(`  To node ${i} (${nodes[i].asset.name}): dist=${isFinite(d) ? d.toFixed(2) : '∞'}`)
})

// Reconstruct path to target (node 2)
const targetIdx = 2
console.log(`\nPath to target (node ${targetIdx}):`)
if (isFinite(dist[targetIdx])) {
  const path: number[] = []
  let cur = targetIdx
  while (cur !== -1) {
    path.unshift(cur)
    if (cur === entryIdx) break
    cur = prev[cur]
  }
  console.log(`Path: ${path.map(i => nodes[i].asset.name).join(' → ')}`)
} else {
  console.log('NO PATH FOUND!')
}

console.log('\n' + '='.repeat(80))
console.log('PROBLEM IDENTIFIED:')
console.log('The initial_access node grants 0 privilege (privilegeGained returns 0 for initial_access)')
console.log('But the lateral_movement node requires "none" privilege (OK)')
console.log('The credential_access node requires "high" privilege (BLOCKED!)')
console.log('')
console.log('The issue is: initial_access → lateral_movement works (both need "none")')
console.log('But lateral_movement only grants privilege level 1 (low)')
console.log('And credential_access requires privilege level 2 (high)')
console.log('')
console.log('The path initial_access → lateral_movement → credential_access is BLOCKED')
console.log('because lateral_movement only grants LOW privilege, not HIGH')
console.log('')
console.log('This is actually CORRECT behavior - you need privilege_escalation in between!')
