/**
 * Debug Test - Why are no attack paths found?
 */

// Same setup as before...

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

console.log('DEBUG: Why are no attack paths found?')
console.log('='.repeat(80))

const assets = generateAssets(1000)
console.log(`Assets: ${assets.length}`)
console.log(`Internet-facing: ${assets.filter(a => a.internet_facing).length}`)
console.log(`Entry points: ${assets.filter(a => a.is_entry_point).length}`)
console.log(`High criticality (4-5): ${assets.filter(a => a.criticality >= 4).length}`)

const graphNodes = buildGraphNodes(assets)
console.log(`\nGraph nodes: ${graphNodes.length}`)

// Count initial_access nodes
const initialAccessNodes = graphNodes.filter(n => n.vuln.kill_chain_phase === 'initial_access')
console.log(`Initial access nodes: ${initialAccessNodes.length}`)

// Count internet-facing nodes
const internetFacingNodes = graphNodes.filter(n => n.asset.internet_facing)
console.log(`Internet-facing nodes: ${internetFacingNodes.length}`)

// Count entry point nodes
const entryPointNodes = graphNodes.filter(n => n.asset.is_entry_point)
console.log(`Entry point nodes: ${entryPointNodes.length}`)

const adjList = buildSparseGraph(graphNodes)
console.log(`\nTotal edges: ${adjList.reduce((s, e) => s + e.length, 0)}`)

// Check if entry point nodes have outgoing edges
const entryIndices = graphNodes
  .map((n, i) => ({ n, i }))
  .filter(({ n }) => n.asset.internet_facing && n.asset.is_entry_point)

console.log(`\nEntry point indices count: ${entryIndices.length}`)

entryIndices.slice(0, 5).forEach(({ n, i }) => {
  console.log(`  Node ${i} (${n.asset.name}): ${adjList[i].length} outgoing edges, phase: ${n.vuln.kill_chain_phase}`)
})

// The problem: we need to check if there are paths from entry points to high-criticality targets
// But wait - blastRadius is 0 for all nodes because we haven't computed PPR yet!

console.log('\n\nISSUE IDENTIFIED:')
console.log('blastRadius is 0 for all nodes because PPR has not been computed!')
console.log('Target selection uses: criticality * blastRadius')
console.log('If blastRadius is 0, target score is 0 for all nodes.')

// Let's see what targets would look like with just criticality
const targetCandidates = graphNodes
  .map((n, i) => ({ i, crit: n.asset.criticality, blast: n.blastRadius, score: n.asset.criticality * n.blastRadius }))
  .sort((a, b) => b.score - a.score)
  .slice(0, 10)

console.log('\nTop target candidates (without PPR):')
targetCandidates.forEach(t => {
  console.log(`  Node ${t.i}: crit=${t.crit}, blast=${t.blast}, score=${t.score}`)
})

// The target selection will select 0 targets because all scores are 0!

console.log('\n\nSOLUTION:')
console.log('1. Either compute PPR before path discovery (as the main algorithm does)')
console.log('2. Or use a different target selection criteria that does not depend on blastRadius')

// Let's check what the actual page.tsx does
console.log('\n\nIn page.tsx, the flow is:')
console.log('1. buildGraphNodes')
console.log('2. buildSparseGraph')
console.log('3. computePPR (forward and reverse)')
console.log('4. Set pprScore and blastRadius on each node')
console.log('5. propagateBeliefs')
console.log('6. discoverAttackPaths')
console.log('\nThis means blastRadius WILL be set before path discovery.')
console.log('But in the test script, we are computing PPR... let me check why it returns 0 paths.')
