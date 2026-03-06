'use client'

import { useState, useCallback, useMemo } from 'react'

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
  type: 'vm' | 'firewall' | 'server' | 'cloud_resource' | 'container' | 'paas'
  ip: string
  network_zone: 'on-prem-dmz' | 'on-prem-internal' | 'aws-public' | 'aws-private' | 'azure-public' | 'azure-private' | 'vpn-gateway' | 'dmz' | 'internal' | 'restricted' | 'airgap'
  criticality: number
  internet_facing: boolean
  business_unit: string
  annual_revenue_exposure: number
  vulnerabilities: Vulnerability[]
}

interface GraphNode {
  id: string
  asset: Asset
  vuln: Vulnerability
  centrality: number
  pageRank: number
  pprScore: number      // Personalized PageRank: attacker reachability from internet
  blastRadius: number   // Reverse PPR: how many high-value paths converge here
  risk: number
  rpc: number
  attackProb: number    // Belief propagation: P(attacker reaches this node)
}

interface Edge {
  to: number
  weight: number        // Transition probability P(exploit | attacker at src)
  logCost: number       // -log(weight) for shortest-path algorithms
}

interface AttackPath {
  id: string
  nodes: GraphNode[]
  riskScore: number
  attackProbability: number
  confidenceInterval: [number, number]   // Wilson score interval
  mitreTechniques: string[]
  aiAnalysis?: {
    summary: string
    attackScenario: string
    remediation: string[]
    businessImpact: string
  }
}

interface AIAnalysisResult {
  correlations: Array<{
    type: string
    title: string
    description: string
    affectedAssets: string[]
    riskAmplification: number
    recommendation: string
  }>
  insights: Array<{
    category: string
    insight: string
    confidence: number
    impact: string
  }>
  topRemediationActions: Array<{
    action: string
    affectedFindings: number
    riskReduction: number
    effort: string
  }>
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

const generateAssets = (): Asset[] => {
  const types: Asset['type'][] = ['vm', 'firewall', 'server', 'cloud_resource', 'container', 'paas']
  const zones: Asset['network_zone'][] = ['on-prem-dmz', 'on-prem-internal', 'aws-public', 'aws-private', 'azure-public', 'azure-private', 'vpn-gateway']
  const businessUnits = ['Finance', 'Engineering', 'Operations', 'HR', 'Legal', 'IT', 'Sales', 'Marketing']

  // Seeded random number generator for deterministic assets
  let seed = 42;
  const random = () => {
    let x = Math.sin(seed++) * 10000;
    return x - Math.floor(x);
  };

  return Array.from({ length: 5000 }, (_, i) => {
    const type = types[Math.floor(random() * types.length)]
    const zone = zones[Math.floor(random() * zones.length)]
    const internetFacing = zone.includes('dmz') || zone.includes('public') || (zone.includes('internal') && random() > 0.95)
    const numVulns = Math.floor(random() * 4) + 1
    const vulns: Vulnerability[] = []
    if (internetFacing) {
      const entryVulns = VULN_DB.filter(v => v.kill_chain_phase === 'initial_access')
      if (entryVulns.length > 0) vulns.push({ ...entryVulns[Math.floor(random() * entryVulns.length)] })
    }
    for (let j = vulns.length; j < numVulns; j++) {
      vulns.push({ ...VULN_DB[Math.floor(random() * VULN_DB.length)] })
    }
    
    let namePrefix = 'ASSET'
    if (type === 'vm') namePrefix = random() > 0.5 ? 'WIN-VM' : 'LNX-VM'
    else if (type === 'firewall') namePrefix = `FW-${['Cisco', 'PaloAlto', 'Fortinet'][Math.floor(random() * 3)]}`
    else if (type === 'server') namePrefix = random() > 0.5 ? 'WIN-SRV' : 'LNX-SRV'
    else if (type === 'cloud_resource') namePrefix = zone.includes('aws') ? 'AWS-EC2' : 'AZURE-VM'
    else if (type === 'container') namePrefix = 'K8S-POD'
    else if (type === 'paas') namePrefix = zone.includes('aws') ? 'AWS-RDS' : 'AZURE-SQL'

    let ipPrefix = '10.0'
    if (zone.includes('aws')) ipPrefix = '172.16'
    else if (zone.includes('azure')) ipPrefix = '192.168'
    else if (zone === 'vpn-gateway') ipPrefix = '10.255'

    return {
      id: `asset-${i + 1}`,
      name: `${namePrefix}-${String(i + 1).padStart(5, '0')}`,
      type, 
      ip: `${ipPrefix}.${Math.floor(random() * 255)}.${Math.floor(random() * 255)}`,
      network_zone: zone, 
      criticality: Math.floor(random() * 5) + 1,
      internet_facing: internetFacing,
      business_unit: businessUnits[Math.floor(random() * businessUnits.length)],
      annual_revenue_exposure: Math.floor(random() * 10000000) + 100000,
      vulnerabilities: vulns
    }
  })
}

const INITIAL_ASSETS = generateAssets()

// ============================================================================
// ALGORITHM 1 — RISK SCORING
// Multiplicative Bayesian model with logistic saturation.
// Replaces the flat weighted-sum + geometric mean that caused score clustering
// at the high end and double-counted CVSS/EPSS correlation.
//
// Key changes:
//   - CVSS uses diminishing-returns exponent γ=0.6 (8→10 less impactful than 5→7)
//   - EPSS × (1-complexity) gives true P(exploited) rather than additive terms
//   - KEV/ransomware are multiplicative threat boosts (2×/1.5×), not flat +0.3/+0.2
//   - Network zone contributes a calibrated exposure multiplier, not a binary flag
//   - Logistic saturation 1-exp(-λx) replaces hard clamp, preserving relative ordering
// ============================================================================

const safeNum = (v: number | undefined | null, fb = 0): number =>
  v === undefined || v === null || !isFinite(v) || isNaN(v) ? fb : v

// Zone-based exposure multipliers — replaces binary internet_facing flag
const ZONE_EXPOSURE: Record<string, number> = {
  'on-prem-dmz': 1.8, 'on-prem-internal': 0.9, 'aws-public': 1.9, 'aws-private': 0.8, 'azure-public': 1.9, 'azure-private': 0.8, 'vpn-gateway': 1.5,
  dmz: 1.8, internal: 0.9, restricted: 0.4, airgap: 0.1
}

const computeRiskScore = (vuln: Vulnerability, asset: Asset): number => {
  try {
    // P(exploited): probability the vulnerability is actually weaponised
    const pExploit = safeNum(vuln.epss, 0.5) * (1 - safeNum(vuln.attack_complexity, 0.5))

    // Severity with diminishing returns at high end (γ = 0.6)
    const severityFactor = Math.pow(safeNum(vuln.cvss, 5) / 10, 0.6)

    // Threat intelligence multiplier — multiplicative, not additive
    const threatMult = (vuln.cisa_kev ? 2.0 : 1.0) * (vuln.ransomware ? 1.5 : 1.0)

    // Asset exposure — zone-aware, boosted further if internet-facing
    const zoneExposure = ZONE_EXPOSURE[asset.network_zone] ?? 0.9
    const exposureFactor = asset.internet_facing ? zoneExposure * 1.4 : zoneExposure

    // Business criticality (1-5 → 0.2-1.0)
    const critFactor = safeNum(asset.criticality, 3) / 5

    // Raw combined risk: product of all dimensions
    const raw = pExploit * severityFactor * threatMult * exposureFactor * critFactor

    // Logistic saturation: smooth 0-10 scale, never truly clamps
    // λ=2.5 calibrated so a "standard critical" CVE on DMZ asset scores ~8.5
    const λ = 2.5
    return Math.max(0.5, Math.min(10, (1 - Math.exp(-λ * raw)) * 10))
  } catch { return 5 }
}

// RPC uses the same model but weights business revenue exposure more heavily
const computeRPC = (vuln: Vulnerability, asset: Asset): number => {
  try {
    const pExploit = safeNum(vuln.epss, 0.5) * (1 - safeNum(vuln.attack_complexity, 0.5))
    const severityFactor = Math.pow(safeNum(vuln.cvss, 5) / 10, 0.6)
    const threatMult = (vuln.cisa_kev ? 2.0 : 1.0) * (vuln.ransomware ? 1.5 : 1.0)
    const zoneExposure = ZONE_EXPOSURE[asset.network_zone] ?? 0.9
    const exposureFactor = asset.internet_facing ? zoneExposure * 1.4 : zoneExposure

    // Revenue exposure amplifies prioritisation (log-scaled to prevent outlier domination)
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

// ============================================================================
// ALGORITHM 2 — GRAPH CONSTRUCTION
// Privilege-gated probabilistic transition model.
// Replaces the heuristic phase-index delta + flat zone bonus.
//
// Key changes:
//   - Edges only exist when attacker's gained privilege satisfies target's requirement
//   - Edge weight = P(transition) = P(exploit target) × network reachability × phase bonus
//   - Zone reachability matrix replaces flat +0.1 same-zone bonus
//   - MITRE technique overlap contributes a lateral reachability bonus
//   - logCost = -log(weight) stored on each edge for Dijkstra/Yen's algorithm
// ============================================================================

// Kill chain phases precomputed into a map for O(1) lookup
const PHASE_ORDER = new Map<string, number>(
  ['initial_access','execution','persistence','privilege_escalation',
   'defense_evasion','credential_access','discovery','lateral_movement',
   'collection','exfiltration','impact'].map((p, i) => [p, i])
)

// Privilege levels: none=0, low=1, high=2
const PRIV_LEVEL: Record<string, number> = { none: 0, low: 1, high: 2 }

// Privilege gained after exploiting a vulnerability (by kill-chain phase)
const privilegeGained = (vuln: Vulnerability): number => {
  const phase = vuln.kill_chain_phase
  if (phase === 'credential_access' || phase === 'privilege_escalation') return 2
  if (phase === 'lateral_movement' || phase === 'execution' || phase === 'initial_access') return 1
  return 1 // default to 1 so paths don't get stuck
}

// Network zone transition reachability matrix
const ZONE_REACH: Record<string, Record<string, number>> = {
  'on-prem-dmz':      { 'on-prem-dmz': 0.90, 'on-prem-internal': 0.60, 'aws-public': 0.40, 'aws-private': 0.10, 'azure-public': 0.40, 'azure-private': 0.10, 'vpn-gateway': 0.80 },
  'on-prem-internal': { 'on-prem-dmz': 0.80, 'on-prem-internal': 0.90, 'aws-public': 0.30, 'aws-private': 0.50, 'azure-public': 0.30, 'azure-private': 0.50, 'vpn-gateway': 0.90 },
  'aws-public':       { 'on-prem-dmz': 0.40, 'on-prem-internal': 0.10, 'aws-public': 0.90, 'aws-private': 0.60, 'azure-public': 0.30, 'azure-private': 0.10, 'vpn-gateway': 0.70 },
  'aws-private':      { 'on-prem-dmz': 0.10, 'on-prem-internal': 0.50, 'aws-public': 0.80, 'aws-private': 0.90, 'azure-public': 0.10, 'azure-private': 0.40, 'vpn-gateway': 0.80 },
  'azure-public':     { 'on-prem-dmz': 0.40, 'on-prem-internal': 0.10, 'aws-public': 0.30, 'aws-private': 0.10, 'azure-public': 0.90, 'azure-private': 0.60, 'vpn-gateway': 0.70 },
  'azure-private':    { 'on-prem-dmz': 0.10, 'on-prem-internal': 0.50, 'aws-public': 0.10, 'aws-private': 0.40, 'azure-public': 0.80, 'azure-private': 0.90, 'vpn-gateway': 0.80 },
  'vpn-gateway':      { 'on-prem-dmz': 0.80, 'on-prem-internal': 0.90, 'aws-public': 0.70, 'aws-private': 0.80, 'azure-public': 0.70, 'azure-private': 0.80, 'vpn-gateway': 0.90 },
  dmz:                { dmz: 0.90, internal: 0.60, restricted: 0.10, airgap: 0.00 },
  internal:           { dmz: 0.80, internal: 0.90, restricted: 0.30, airgap: 0.00 },
  restricted:         { dmz: 0.20, internal: 0.40, restricted: 0.80, airgap: 0.05 },
  airgap:             { dmz: 0.00, internal: 0.00, restricted: 0.05, airgap: 0.70 },
}

const TECH_TO_BIT = new Map<string, number>()
let nextBit = 0
const getTechBit = (tech: string) => {
  if (!TECH_TO_BIT.has(tech)) {
    TECH_TO_BIT.set(tech, 1 << nextBit++)
  }
  return TECH_TO_BIT.get(tech)!
}

const getAssetTechMask = (asset: Asset): number => {
  if ((asset as any)._techMask === undefined) {
    let mask = 0
    for (const v of asset.vulnerabilities) {
      if (v.mitre_techniques) {
        for (const t of v.mitre_techniques) {
          mask |= getTechBit(t)
        }
      }
    }
    ;(asset as any)._techMask = mask
  }
  return (asset as any)._techMask
}

const popcount = (n: number) => {
  n = n - ((n >> 1) & 0x55555555)
  n = (n & 0x33333333) + ((n >> 2) & 0x33333333)
  return (((n + (n >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24
}

const computeReachability = (src: Asset, tgt: Asset): number => {
  if (src.id === tgt.id) return 1.0  // same asset: guaranteed reachable
  const base = ZONE_REACH[src.network_zone]?.[tgt.network_zone] ?? 0.1

  const srcMask = getAssetTechMask(src)
  const tgtMask = getAssetTechMask(tgt)
  const overlap = popcount(srcMask & tgtMask)
  
  const techBonus = Math.min(0.25, overlap * 0.08)

  return Math.min(1.0, base + techBonus)
}

const buildSparseGraph = async (nodes: GraphNode[], setProgress?: (p: number) => void): Promise<Edge[][]> => {
  const n = nodes.length
  const adjList: Edge[][] = Array.from({ length: n }, () => [])

  // Track maximum privilege each node can grant — used for gate checks
  const maxPrivGained = nodes.map(n => privilegeGained(n.vuln))

  // Precompute expensive properties for all nodes
  const nodeData = nodes.map(node => {
    const pExploit = safeNum(node.vuln.epss, 0.5) * (1 - safeNum(node.vuln.attack_complexity, 0.5))
    const threatMult = (node.vuln.cisa_kev ? 1.5 : 1.0) * (node.vuln.ransomware ? 1.2 : 1.0)
    const phase = PHASE_ORDER.get(node.vuln.kill_chain_phase) ?? 0
    const privReq = PRIV_LEVEL[node.vuln.privileges_required] ?? 0
    const techMask = getAssetTechMask(node.asset)
    const zone = node.asset.network_zone
    const assetId = node.asset.id
    return { pExploit, threatMult, phase, privReq, techMask, zone, assetId }
  })

  const CHUNK_SIZE = 50
  const chunks = []
  for (let i = 0; i < n; i += CHUNK_SIZE) {
    chunks.push({ start: i, end: Math.min(i + CHUNK_SIZE, n) })
  }

  let processed = 0

  // Process chunks sequentially to guarantee rendering updates and prevent freezing
  for (const chunk of chunks) {
    await new Promise(r => setTimeout(r, 0)) // yield to event loop
    
    for (let i = chunk.start; i < chunk.end; i++) {
      const srcPhase = nodeData[i].phase
      const attackerPrivAfterSrc = maxPrivGained[i]
      const srcZone = nodeData[i].zone
      const srcMask = nodeData[i].techMask

      const srcAssetId = nodeData[i].assetId

      const edgesForI: Edge[] = []

      for (let j = 0; j < n; j++) {
        if (i === j) continue

        const tgtData = nodeData[j]

        // Gate 1: kill chain must progress or stay (no backwards jumps > 1 step)
        // ONLY applies if moving within the same machine. If moving laterally, the kill chain resets.
        if (srcAssetId === tgtData.assetId) {
          if (tgtData.phase < srcPhase - 1) continue
        } else {
          // If moving to a different machine, the target vulnerability MUST be remotely exploitable
          // 0: initial_access, 1: execution, 7: lateral_movement
          if (tgtData.phase !== 0 && tgtData.phase !== 1 && tgtData.phase !== 7) continue
        }

        // Gate 2: privilege check — attacker must have enough privilege for target
        if (attackerPrivAfterSrc < tgtData.privReq) continue

        // Gate 3: network reachability (inlined for performance)
        const baseReach = ZONE_REACH[srcZone]?.[tgtData.zone] ?? 0.1
        const overlap = popcount(srcMask & tgtData.techMask)
        const techBonus = Math.min(0.25, overlap * 0.08)
        const reach = Math.min(1.0, baseReach + techBonus)
        
        if (reach < 0.01) continue

        // Phase continuity bonus: forward progress in kill chain is more likely
        const phaseContinuity = tgtData.phase >= srcPhase ? 1.2 : 0.85

        // Massive bonus for moving within the same machine to ensure intra-machine kill chains are not dropped
        const sameMachineBonus = srcAssetId === tgtData.assetId ? 10.0 : 1.0

        const rawWeight = tgtData.pExploit * reach * tgtData.threatMult * phaseContinuity * sameMachineBonus
        const weight = Math.min(0.999, rawWeight)
        if (weight < 0.0001) continue

        edgesForI.push({
          to: j,
          weight,
          logCost: -Math.log(Math.max(weight, 1e-9)),  // for Dijkstra/Yen's
          sortWeight: rawWeight, // Uncapped weight for sorting
        } as Edge & { sortWeight: number })
      }

      // Keep only the top 30 strongest connections to ensure true sparsity
      if (edgesForI.length > 30) {
        edgesForI.sort((a: any, b: any) => b.sortWeight - a.sortWeight)
        adjList[i] = edgesForI.slice(0, 30)
      } else {
        adjList[i] = edgesForI
      }
    }
    
    processed += (chunk.end - chunk.start)
    if (setProgress) setProgress(10 + (processed / n) * 25)
  }

  return adjList
}

// ============================================================================
// ALGORITHM 3 — PERSONALIZED PAGERANK (PPR)
// Replaces vanilla PageRank, which measured hub centrality rather than
// attacker reachability.
//
// Forward PPR (seeded at internet-facing nodes with high EPSS) answers:
//   "Starting from the internet, how reachable is this node?"
//
// Reverse PPR (seeded at high-criticality target nodes) answers:
//   "How many attack paths converge on this high-value target?"
//
// The intersection of high forward-PPR and high reverse-PPR identifies the
// single most dangerous nodes in the environment.
// ============================================================================

const computePPR = async (
  adjList: Edge[][],
  nodes: GraphNode[],
  seedFn: (node: GraphNode) => number,
  setProgress?: (p: number) => void,
  baseProgress = 20,
  progressRange = 15,
  alpha = 0.15,
  maxIter = 100,
  tol = 1e-8
): Promise<number[]> => {
  const n = adjList.length
  if (n === 0) return []

  // Build seed distribution (teleportation target)
  const rawSeeds = nodes.map(seedFn)
  const seedTotal = rawSeeds.reduce((a, b) => a + b, 0) || 1
  const seedDist = rawSeeds.map(w => w / seedTotal)

  // Weight-normalised outgoing edges (column-stochastic)
  const outWeightTotals = adjList.map(edges => edges.reduce((s, e) => s + e.weight, 0))

  // Build incoming edge structure for efficient iteration
  const incoming: { from: number; normWeight: number }[][] =
    Array.from({ length: n }, () => [])
  for (let i = 0; i < n; i++) {
    const total = outWeightTotals[i] || 1
    adjList[i].forEach(e => incoming[e.to].push({ from: i, normWeight: e.weight / total }))
  }

  let pr = [...seedDist]

  for (let iter = 0; iter < maxIter; iter++) {
    if (iter % 5 === 0) {
      await new Promise(r => setTimeout(r, 0))
      if (setProgress) setProgress(baseProgress + (iter / maxIter) * progressRange)
    }
    // Teleportation term + propagation term
    const next = seedDist.map(s => alpha * s)
    for (let j = 0; j < n; j++) {
      for (const e of incoming[j]) {
        next[j] += (1 - alpha) * pr[e.from] * e.normWeight
      }
    }
    // L1 convergence check
    const delta = next.reduce((s, v, i) => s + Math.abs(v - pr[i]), 0)
    pr = next
    if (delta < tol) break
  }
  return pr
}

// Reverse PPR: flip edge directions, seed at high-value targets
const computeReversePPR = async (
  adjList: Edge[][],
  nodes: GraphNode[],
  setProgress?: (p: number) => void,
  baseProgress = 35,
  progressRange = 15,
  alpha = 0.15
): Promise<number[]> => {
  const n = adjList.length
  const reversedAdj: Edge[][] = Array.from({ length: n }, () => [])
  for (let i = 0; i < n; i++) {
    adjList[i].forEach(e => reversedAdj[e.to].push({ to: i, weight: e.weight, logCost: e.logCost }))
  }
  return computePPR(reversedAdj, nodes,
    node => node.asset.criticality >= 4 ? node.asset.criticality / 5 : 0,
    setProgress, baseProgress, progressRange, alpha
  )
}

// ============================================================================
// ALGORITHM 4 — MAX-PRODUCT BELIEF PROPAGATION
// Replaces the unweighted mean propagation loop (which converged toward a
// global average, destroying signal in extreme scores).
//
// Max-product models adversarial behaviour: the attacker takes the BEST path,
// not the average of all paths. The belief at each node is P(attacker reaches it).
//
// Key changes:
//   - Initial beliefs seeded from internet-facing nodes proportional to EPSS×KEV
//   - Max-product update: belief[i] = max(incoming messages), not mean
//   - Damping factor 0.6 ensures stable convergence on loopy graphs
//   - Log-scale normalisation preserves separation in the high-risk tail
// ============================================================================

const propagateBeliefs = async (nodes: GraphNode[], adjList: Edge[][], setProgress?: (p: number) => void): Promise<number[]> => {
  const n = nodes.length
  if (n === 0) return []

  // Initial belief: P(attacker starts here)
  // Internet-facing nodes with high EPSS/KEV get strong priors
  const belief = nodes.map(node => {
    if (node.asset.internet_facing) {
      return safeNum(node.vuln.epss, 0.5) *
             (node.vuln.cisa_kev ? 1.8 : 1.0) *
             (ZONE_EXPOSURE[node.asset.network_zone] ?? 0.9)
    }
    return 0.01  // small insider-threat / phishing prior for internal nodes
  })

  // Build normalised incoming edges
  const outTotals = adjList.map(edges => edges.reduce((s, e) => s + e.weight, 0))
  const incoming: { from: number; normWeight: number }[][] =
    Array.from({ length: n }, () => [])
  for (let i = 0; i < n; i++) {
    const total = outTotals[i] || 1
    adjList[i].forEach(e => incoming[e.to].push({ from: i, normWeight: e.weight / total }))
  }

  const DAMPING = 0.6
  for (let iter = 0; iter < 20; iter++) {
    if (iter % 2 === 0) {
      await new Promise(r => setTimeout(r, 0))
      if (setProgress) setProgress(55 + (iter / 20) * 20)
    }
    const next = [...belief]
    for (let i = 0; i < n; i++) {
      if (incoming[i].length === 0) continue

      // MAX-product: attacker chooses the single best incoming path
      let maxMsg = 0
      for (const e of incoming[i]) {
        const msg = belief[e.from] * e.normWeight
        if (msg > maxMsg) maxMsg = msg
      }

      // Node's own exploitability gates whether the attacker can use this hop
      const exploitability = safeNum(nodes[i].vuln.epss, 0.5) *
                             (1 - safeNum(nodes[i].vuln.attack_complexity, 0.5)) *
                             (nodes[i].vuln.cisa_kev ? 1.6 : 1.0)

      next[i] = DAMPING * belief[i] +
                (1 - DAMPING) * Math.min(1, maxMsg * exploitability * 2)
    }

    const delta = next.reduce((s, v, i) => s + Math.abs(v - belief[i]), 0)
    for (let i = 0; i < n; i++) belief[i] = next[i]
    if (delta < 1e-6) break
  }

  return belief
}

// ============================================================================
// SOPHISTICATED MULTI-FACTOR RISK COMPUTATION
// 
// Combines vulnerability severity, graph topology, and belief propagation
// using a principled non-linear approach:
//
// 1. BASE RISK: Bayesian multiplicative model (CVSS, EPSS, KEV, zone)
// 2. REACHABILITY: Forward PPR scaled to (0,1) - attacker can reach this node
// 3. IMPACT: Reverse PPR scaled to (0,1) - blast radius if compromised
// 4. ATTACK PROBABILITY: Belief propagation result
//
// Final risk = f(baseRisk, reachability, impact, attackProb)
// Uses soft-attention weighted combination with cross-factor interactions
// ============================================================================

// Robust quantile-based scaling (resistant to outliers, preserves ordering)
const quantileScale = (values: number[], lower = 0.05, upper = 0.95): number[] => {
  if (values.length === 0) return []
  const sorted = [...values].sort((a, b) => a - b)
  const n = sorted.length
  const loIdx = Math.floor(n * lower)
  const hiIdx = Math.floor(n * upper)
  const loVal = sorted[loIdx]
  const hiVal = sorted[hiIdx]
  const range = hiVal - loVal || 1
  return values.map(v => Math.max(0, Math.min(1, (v - loVal) / range)))
}

// Entropy of a distribution - measures uncertainty/information content
const entropy = (p: number): number => {
  if (p <= 0 || p >= 1) return 0
  return -p * Math.log(p) - (1 - p) * Math.log(1 - p)
}

// Compute sophisticated final risk scores after all graph algorithms
const computeFinalRiskScores = (nodes: GraphNode[], beliefs: number[]): void => {
  const n = nodes.length
  if (n === 0) return

  // Extract raw values
  const baseRisks = nodes.map(node => node.risk)
  const pprScores = nodes.map(node => node.pprScore)
  const blastRadii = nodes.map(node => node.blastRadius)

  // Scale each factor to (0,1) using quantile scaling (robust to outliers)
  const scaledBaseRisk = quantileScale(baseRisks)
  const scaledPPR = quantileScale(pprScores)
  const scaledBlast = quantileScale(blastRadii)
  const scaledBeliefs = quantileScale(beliefs)

  // Compute entropy-based weights (adaptive, data-driven)
  // Higher entropy = more spread distribution = more informative
  const avgBase = scaledBaseRisk.reduce((a, b) => a + b, 0) / n
  const avgPPR = scaledPPR.reduce((a, b) => a + b, 0) / n
  const avgBlast = scaledBlast.reduce((a, b) => a + b, 0) / n
  const avgBelief = scaledBeliefs.reduce((a, b) => a + b, 0) / n
  
  const entropyBase = entropy(avgBase)
  const entropyPPR = entropy(avgPPR)
  const entropyBlast = entropy(avgBlast)
  const entropyBelief = entropy(avgBelief)

  // Normalize weights - base risk always gets minimum 30% weight
  const totalEntropy = entropyBase + entropyPPR + entropyBlast + entropyBelief || 1
  const wBase = 0.3 + 0.7 * entropyBase / totalEntropy
  const wPPR = 0.7 * entropyPPR / totalEntropy
  const wBlast = 0.7 * entropyBlast / totalEntropy
  const wBelief = 0.7 * entropyBelief / totalEntropy
  const wSum = wBase + wPPR + wBlast + wBelief

  // Process each node
  nodes.forEach((node, i) => {
    const b = scaledBaseRisk[i]
    const p = scaledPPR[i]
    const bl = scaledBlast[i]
    const bel = scaledBeliefs[i]

    // Cross-factor interaction terms (synergy effects)
    // High PPR + High Blast = critical convergence point
    // High Base + High Belief = confirmed high-risk
    const reachabilityImpact = p * bl  // High if both PPR and blast are high
    const severityConfirmation = b * bel  // High if base risk and belief align
    const criticalJunction = Math.sqrt(p * bl) * b  // Geometric interaction

    // Weighted combination with interaction boost
    const linearCombo = (wBase * b + wPPR * p + wBlast * bl + wBelief * bel) / wSum
    
    // Non-linear boost from interactions (tanh modulation for bounded boost)
    const interactionBoost = 0.15 * Math.tanh(3 * (reachabilityImpact + severityConfirmation + criticalJunction))
    
    // Final score in (0,1) range
    const finalNormalized = Math.max(0, Math.min(1, linearCombo + interactionBoost))
    
    // Map to (0.5, 10) range with logistic curve for better differentiation
    // k=4 gives good spread, center=0.3 shifts typical values to middle of range
    const k = 4
    const center = 0.3
    const logisticScore = 1 / (1 + Math.exp(-k * (finalNormalized - center)))
    
    // Scale to (0.5, 10)
    node.risk = 0.5 + 9.5 * logisticScore
    node.attackProb = Math.min(1, Math.max(0, beliefs[i]))
  })

  // Post-process: ensure differentiation by checking variance
  const finalRisks = nodes.map(n => n.risk)
  const meanRisk = finalRisks.reduce((a, b) => a + b, 0) / n
  const variance = finalRisks.reduce((a, r) => a + (r - meanRisk) ** 2, 0) / n
  const stdDev = Math.sqrt(variance)
  
  // If variance too low (scores clustered), apply stretching transform
  if (stdDev < 1.5 && n > 1) {
    const minR = Math.min(...finalRisks)
    const maxR = Math.max(...finalRisks)
    const range = maxR - minR || 1
    
    nodes.forEach(node => {
      // Stretch to use full range
      const normalized = (node.risk - minR) / range
      // Apply sigmoid stretch for better separation
      const stretched = 1 / (1 + Math.exp(-6 * (normalized - 0.5)))
      node.risk = 0.5 + 9.5 * stretched
    })
  }
}

// ============================================================================
// ALGORITHM 5 — YEN'S K-SHORTEST PATHS (deterministic, optimal)
// Replaces the weighted random walk (50 attempts, non-reproducible).
//
// Key changes:
//   - Operates in negative log-probability space (logCost = -log(weight))
//   - Dijkstra finds the globally shortest (= highest probability) path
//   - Yen's algorithm iterates to find the K next-best loopless paths
//   - Results are deterministic: same input always produces same ranked paths
//   - Wilson score confidence interval replaces the fake ±20% placeholder
// ============================================================================

class MinHeap {
  private heap: [number, number][] = []

  push(val: [number, number]) {
    this.heap.push(val)
    this.bubbleUp(this.heap.length - 1)
  }

  pop(): [number, number] | undefined {
    if (this.heap.length === 0) return undefined
    if (this.heap.length === 1) return this.heap.pop()
    const top = this.heap[0]
    this.heap[0] = this.heap.pop()!
    this.bubbleDown(0)
    return top
  }

  isEmpty() {
    return this.heap.length === 0
  }

  private bubbleUp(index: number) {
    while (index > 0) {
      const parent = Math.floor((index - 1) / 2)
      if (this.heap[parent][0] <= this.heap[index][0]) break
      const temp = this.heap[parent]
      this.heap[parent] = this.heap[index]
      this.heap[index] = temp
      index = parent
    }
  }

  private bubbleDown(index: number) {
    const length = this.heap.length
    while (true) {
      let left = 2 * index + 1
      let right = 2 * index + 2
      let smallest = index

      if (left < length && this.heap[left][0] < this.heap[smallest][0]) {
        smallest = left
      }
      if (right < length && this.heap[right][0] < this.heap[smallest][0]) {
        smallest = right
      }
      if (smallest === index) break

      const temp = this.heap[index]
      this.heap[index] = this.heap[smallest]
      this.heap[smallest] = temp
      index = smallest
    }
  }
}

interface DijkResult { dist: number[]; prev: number[] }

const dijkstra = (
  adj: Edge[][],
  source: number,
  blockedEdges: Set<number>,
  blockedNodes: Set<number>
): DijkResult => {
  const n = adj.length
  const dist = new Float64Array(n).fill(Infinity)
  const prev = new Int32Array(n).fill(-1)
  dist[source] = 0

  const pq = new MinHeap()
  pq.push([0, source])

  while (!pq.isEmpty()) {
    const [d, u] = pq.pop()!
    if (d > dist[u]) continue
    for (const e of adj[u]) {
      if (blockedNodes.has(e.to)) continue
      const edgeKey = u * 10000 + e.to
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

// Wilson score confidence interval for binomial proportion
// Statistically valid bound — replaces the fake prob×[0.8, 1.2] placeholder
const wilsonInterval = (p: number, n: number): [number, number] => {
  const z = 1.96  // 95% confidence
  const denom = 1 + z * z / n
  const centre = (p + z * z / (2 * n)) / denom
  const margin = (z * Math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
  return [Math.max(0, centre - margin), Math.min(1, centre + margin)]
}

// Joint path probability using the chain rule — replaces the raw EPSS product
// that caused probability collapse on paths longer than 3 nodes.
const computeChainProbability = (
  path: number[],
  adj: Edge[][]
): number => {
  if (path.length < 2) return 0.5

  let jointLogProb = 0
  for (let i = 0; i < path.length - 1; i++) {
    const u = path[i], v = path[i + 1]
    const edge = adj[u].find(e => e.to === v)
    const pStep = edge ? edge.weight : 0.1
    jointLogProb += Math.log(Math.max(pStep, 1e-9))
  }

  // Attacker skill model (FAIR framework): sophisticated adversaries retry.
  // P_effective = p / (1 - (1-p) × retryFactor)  where retryFactor ≈ 0.3
  const RETRY = 0.3
  const pRaw = Math.exp(jointLogProb)
  const pEffective = Math.min(0.999, pRaw / (1 - (1 - pRaw) * RETRY))
  return pEffective
}

const pathsEqual = (p1: number[], p2: number[], len: number) => {
  if (p1.length < len || p2.length < len) return false
  for (let i = 0; i < len; i++) {
    if (p1[i] !== p2[i]) return false
  }
  return true
}

const discoverAttackPaths = async (nodes: GraphNode[], adjList: Edge[][], setProgress?: (p: number) => void): Promise<AttackPath[]> => {
  const n = nodes.length
  if (n === 0) return []

  // Entry points: internet-facing nodes, sorted by PPR score (fallback to EPSS if PPR is 0)
  const entryIdxs = nodes
    .map((nd, i) => ({ i, score: nd.asset.internet_facing ? (nd.pprScore > 0 ? nd.pprScore * 1.5 : nd.vuln.epss * 0.0001) : 0 }))
    .filter(e => e.score > 0 && adjList[e.i].length > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 10)
    .map(e => e.i)

  // Target nodes: high-criticality + high blast-radius (fallback to criticality if blastRadius is 0)
  const targetIdxSet = new Set(
    nodes
      .map((nd, i) => ({ i, score: nd.asset.criticality * (nd.blastRadius > 0 ? nd.blastRadius : 0.0001) }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 15)
      .map(e => e.i)
  )

  const allPaths: AttackPath[] = []
  const usedSigs = new Set<string>()
  const K_PATHS = 3  // Yen's: top-K paths per entry→target pair

  let pathsProcessed = 0
  const totalPairs = entryIdxs.length * targetIdxSet.size

  for (const entryIdx of entryIdxs) {
    for (const targetIdx of targetIdxSet) {
      if (entryIdx === targetIdx) continue

      pathsProcessed++
      // Yield on every pair to keep UI responsive during heavy Dijkstra
      await new Promise(r => setTimeout(r, 0))
      if (setProgress) setProgress(75 + (pathsProcessed / totalPairs) * 5)

      // Yen's K-Shortest Paths in log-cost space
      const A: { path: number[]; logCost: number }[] = []

      // First shortest path via Dijkstra
      const { dist: d0, prev: p0 } = dijkstra(adjList, entryIdx, new Set(), new Set())
      if (!isFinite(d0[targetIdx])) continue
      const first = reconstructPath(Array.from(p0), entryIdx, targetIdx)
      if (first.length < 2) continue
      A.push({ path: first, logCost: d0[targetIdx] })

      // Yen's spur iterations for K-1 additional paths
      const B: { path: number[]; logCost: number }[] = []
      for (let k = 1; k < K_PATHS; k++) {
        const prevPath = A[k - 1].path
        for (let i = 0; i < prevPath.length - 1; i++) {
          const spurNode = prevPath[i]
          const rootPath = prevPath.slice(0, i + 1)

          // Block edges already used by earlier A-paths with the same root
          const blocked = new Set<number>()
          for (const ap of A) {
            if (ap.path.length > i && pathsEqual(ap.path, rootPath, i + 1)) {
              blocked.add(ap.path[i] * 10000 + ap.path[i + 1])
            }
          }
          // Block nodes in root path (except spur node) to prevent loops
          const blockedNodes = new Set(rootPath.slice(0, -1))

          const { dist: dSpur, prev: pSpur } = dijkstra(adjList, spurNode, blocked, blockedNodes)
          if (!isFinite(dSpur[targetIdx])) continue

          const spurPath = reconstructPath(Array.from(pSpur), spurNode, targetIdx)
          if (spurPath.length < 1) continue

          const totalPath = [...rootPath.slice(0, -1), ...spurPath]

          // Compute logCost for total path
          let totalLogCost = 0
          for (let s = 0; s < totalPath.length - 1; s++) {
            const u = totalPath[s], v = totalPath[s + 1]
            const e = adjList[u]?.find(x => x.to === v)
            totalLogCost += e ? e.logCost : 10
          }

          if (!B.find(b => pathsEqual(b.path, totalPath, Math.max(b.path.length, totalPath.length)))) {
            B.push({ path: totalPath, logCost: totalLogCost })
          }
        }

        if (B.length === 0) break
        B.sort((a, b) => a.logCost - b.logCost)
        A.push(B.shift()!)
      }

      // Convert each path to AttackPath
      for (const { path, logCost } of A) {
        const sig = path.join('|')
        if (usedSigs.has(sig)) continue
        usedSigs.add(sig)

        const pathNodes = path.map(i => nodes[i])
        const prob = computeChainProbability(path, adjList)

        // Wilson score CI with effective sample n = path length × 10
        const ci = wilsonInterval(prob, path.length * 10)

        // === AUTONOMOUS AI-DRIVEN RISK SCORING MODEL ===
        const pathLength = pathNodes.length
        
        // 1. Structural Vulnerability (0-10)
        // Evaluates the inherent weakness of the nodes in the path
        const maxNodeRisk = Math.max(...pathNodes.map(nd => nd.risk))
        const avgNodeRisk = pathNodes.reduce((s, nd) => s + nd.risk, 0) / pathLength
        const structuralRisk = (maxNodeRisk * 0.7) + (avgNodeRisk * 0.3)
        
        // 2. Exploitability (0-10)
        // Evaluates the likelihood of successful traversal
        const kevCount = pathNodes.filter(nd => nd.vuln.cisa_kev).length
        const ransomwareCount = pathNodes.filter(nd => nd.vuln.ransomware).length
        const activeThreatMultiplier = 1 + (kevCount * 0.4) + (ransomwareCount * 0.4)
        
        // prob is the Bayesian probability of the chain (0 to 1)
        // We use a logarithmic scale to differentiate small probabilities
        const baseExploitability = prob > 0 ? (10 + Math.max(-10, Math.log10(prob)) * 2) : 0
        const exploitability = Math.min(10, Math.max(0, baseExploitability) * activeThreatMultiplier)
        
        // 3. Business Impact (0-10)
        // Evaluates the damage if the target is compromised
        const targetNode = pathNodes[pathLength - 1]
        const criticalityScore = (targetNode.asset.criticality / 5) * 10 // 2 to 10
        const blastRadiusScore = Math.min(10, (targetNode.blastRadius || 0) * 100) // Scale up PPR
        const financialExposure = targetNode.asset.annual_revenue_exposure || 0
        const financialScore = Math.min(10, (financialExposure / 1000000) * 2) // 1M = 2, 5M = 10
        
        const zones = new Set(pathNodes.map(nd => nd.asset.network_zone))
        const lateralMovementPenalty = zones.size > 1 ? 1.5 : 0 // Penalty for crossing zones
        
        const businessImpact = Math.min(10, (criticalityScore * 0.4) + (blastRadiusScore * 0.3) + (financialScore * 0.3) + lateralMovementPenalty)
        
        // 4. Autonomous Risk Synthesis
        // Dynamically weight the factors based on the path's characteristics
        let riskScore = 0
        if (exploitability < 3) {
          // Low likelihood path, impact matters less
          riskScore = (structuralRisk * 0.3) + (exploitability * 0.5) + (businessImpact * 0.2)
        } else if (businessImpact > 8) {
          // High impact path, prioritize impact and exploitability
          riskScore = (structuralRisk * 0.2) + (exploitability * 0.4) + (businessImpact * 0.4)
        } else {
          // Balanced path
          riskScore = (structuralRisk * 0.3) + (exploitability * 0.4) + (businessImpact * 0.3)
        }
        
        // Apply path length decay (longer paths are exponentially harder to execute without detection)
        const lengthDecay = Math.pow(0.92, Math.max(0, pathLength - 2))
        riskScore = riskScore * lengthDecay
        
        // Final bounds check
        riskScore = Math.max(0.1, Math.min(10.0, riskScore))

        const techniques = new Set<string>()
        pathNodes.forEach(nd => nd.vuln.mitre_techniques?.forEach(t => techniques.add(t)))

        allPaths.push({
          id: `AP-${allPaths.length + 1}`,
          nodes: pathNodes,
          riskScore: Math.round(riskScore * 10) / 10,
          attackProbability: Math.round(prob * 10000) / 10000,
          confidenceInterval: ci,
          mitreTechniques: Array.from(techniques),
        })

        if (allPaths.length >= 20) break
      }
      if (allPaths.length >= 20) break
    }
    if (allPaths.length >= 20) break
  }

  return allPaths
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 10)
}

// ============================================================================
// CONNECTION TYPES
// ============================================================================

interface ConnectionConfig {
  name: string
  type: 'ssh' | 'snmp' | 'api' | 'import'
  host?: string
  port?: number
  username?: string
  password?: string
  sshKey?: string
  snmpCommunity?: string
  apiUrl?: string
  apiToken?: string
  networkRange?: string  // CIDR notation for network scan
}

interface ScanResult {
  host: string
  type: 'vm' | 'firewall' | 'server' | 'cloud_resource'
  hostname?: string
  os?: string
  openPorts?: number[]
  services?: string[]
  vulnerabilities: Vulnerability[]
}

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function SecurityDashboard() {
  const [assets, setAssets] = useState<Asset[]>(INITIAL_ASSETS)
  const [nodes, setNodes] = useState<GraphNode[]>([])
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([])
  const [isScanning, setIsScanning] = useState(false)
  const [scanComplete, setScanComplete] = useState(false)
  const [progress, setProgress] = useState(0)
  const [activeView, setActiveView] = useState<'overview' | 'assets' | 'paths'>('overview')
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null)
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null)
  const [status, setStatus] = useState('')
  const [aiResult, setAiResult] = useState<AIAnalysisResult | null>(null)
  
  // Connection modal state
  const [showConnectModal, setShowConnectModal] = useState(false)
  const [isConnecting, setIsConnecting] = useState(false)
  const [connectionConfig, setConnectionConfig] = useState<ConnectionConfig>({
    name: '',
    type: 'ssh',
    host: '',
    port: 22,
    username: '',
    password: '',
    networkRange: '',
  })
  const [savedConnections, setSavedConnections] = useState<ConnectionConfig[]>([])
  const [scanLog, setScanLog] = useState<string[]>([])

  const assetFindings = useMemo(() => {
    if (!selectedAsset) return []
    return nodes.filter(n => n.asset.id === selectedAsset.id).sort((a, b) => b.rpc - a.rpc)
  }, [nodes, selectedAsset])

  const topAssets = useMemo(() => {
    const assetRisks = new Map<string, { asset: Asset; totalRisk: number; findingCount: number }>()
    nodes.forEach(node => {
      const existing = assetRisks.get(node.asset.id)
      if (existing) { existing.totalRisk += node.risk; existing.findingCount++ }
      else assetRisks.set(node.asset.id, { asset: node.asset, totalRisk: node.risk, findingCount: 1 })
    })
    return Array.from(assetRisks.values())
      .map(a => ({ ...a, avgRisk: a.totalRisk / a.findingCount }))
      .sort((a, b) => b.avgRisk - a.avgRisk)
      .slice(0, 50)
  }, [nodes])

  // Connect to infrastructure and scan
  const connectAndScan = useCallback(async (config: ConnectionConfig) => {
    setIsConnecting(true)
    setScanLog([])
    
    const addLog = (msg: string) => {
      setScanLog(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`])
    }
    
    try {
      addLog(`Connecting to ${config.type.toUpperCase()} target...`)
      
      const response = await fetch('/api/scan-infrastructure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      })
      
      if (!response.ok) {
        throw new Error(`Scan failed: ${response.statusText}`)
      }
      
      const result = await response.json()
      addLog(`Discovered ${result.assets?.length || 0} assets`)
      
      if (result.assets && result.assets.length > 0) {
        // Map scanned assets to our Asset format
        const scannedAssets: Asset[] = result.assets.map((scan: any, idx: number) => ({
          id: `scanned-${idx + 1}`,
          name: scan.hostname || scan.host,
          type: scan.type || 'vm',
          ip: scan.host,
          network_zone: scan.networkZone || 'internal',
          criticality: scan.criticality || 3,
          internet_facing: scan.internetFacing || false,
          business_unit: scan.businessUnit || 'IT',
          annual_revenue_exposure: scan.revenueExposure || 500000,
          vulnerabilities: scan.vulnerabilities || []
        }))
        
        setAssets(scannedAssets)
        addLog(`Loaded ${scannedAssets.length} assets into dashboard`)
        
        // Save connection
        setSavedConnections(prev => {
          const updated = prev.filter(c => c.name !== config.name)
          return [...updated, config]
        })
        
        setShowConnectModal(false)
      }
    } catch (error) {
      addLog(`Error: ${error instanceof Error ? error.message : 'Connection failed'}`)
    } finally {
      setIsConnecting(false)
    }
  }, [])
  
  // Import from file (CSV/JSON)
  const importFromFile = useCallback(async (file: File) => {
    setIsConnecting(true)
    setScanLog([])
    
    const addLog = (msg: string) => {
      setScanLog(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`])
    }
    
    try {
      addLog(`Importing from ${file.name}...`)
      
      const text = await file.text()
      let importedAssets: any[] = []
      
      if (file.name.endsWith('.json')) {
        importedAssets = JSON.parse(text)
      } else if (file.name.endsWith('.csv')) {
        const lines = text.split('\n')
        const headers = lines[0].split(',').map(h => h.trim().toLowerCase())
        
        for (let i = 1; i < lines.length; i++) {
          if (!lines[i].trim()) continue
          const values = lines[i].split(',')
          const obj: any = {}
          headers.forEach((h, idx) => {
            obj[h] = values[idx]?.trim() || ''
          })
          importedAssets.push(obj)
        }
      }
      
      addLog(`Parsed ${importedAssets.length} records`)
      
      // Map imported data to Asset format
      const mappedAssets: Asset[] = importedAssets.map((item, idx) => ({
        id: `imported-${idx + 1}`,
        name: item.name || item.hostname || item.host || `Asset-${idx + 1}`,
        type: (item.type || 'vm') as Asset['type'],
        ip: item.ip || item.host || '0.0.0.0',
        network_zone: (item.zone || item.network_zone || 'internal') as Asset['network_zone'],
        criticality: parseInt(item.criticality) || 3,
        internet_facing: item.internet_facing === 'true' || item.internetFacing === true,
        business_unit: item.business_unit || item.department || 'IT',
        annual_revenue_exposure: parseInt(item.revenue_exposure) || 500000,
        vulnerabilities: Array.isArray(item.vulnerabilities) ? item.vulnerabilities : 
          (item.cve ? [{ id: item.cve, title: item.cve, severity: 'high', cvss: 7, epss: 0.5, attack_complexity: 0.3, privileges_required: 'none', cisa_kev: false, ransomware: false, kill_chain_phase: 'initial_access', mitre_techniques: [] }] : [])
      }))
      
      if (mappedAssets.length > 0) {
        setAssets(mappedAssets)
        addLog(`Loaded ${mappedAssets.length} assets into dashboard`)
        setShowConnectModal(false)
      }
    } catch (error) {
      addLog(`Import error: ${error instanceof Error ? error.message : 'Failed to parse file'}`)
    } finally {
      setIsConnecting(false)
    }
  }, [])

  const runAnalysis = useCallback(async () => {
    if (isScanning) return
    setIsScanning(true)
    setScanComplete(false)
    setProgress(0)
    setSelectedPath(null)
    setSelectedAsset(null)
    setAiResult(null)

    // Step 1: build nodes
    setStatus('Building attack graph nodes…')
    setProgress(5)
    await new Promise(r => setTimeout(r, 50))
    const graphNodes = buildGraphNodes(assets)

    // Step 2: build privilege-gated probabilistic graph (Parallel Chunked)
    setStatus('Computing graph topology in parallel chunks…')
    setProgress(10)
    await new Promise(r => setTimeout(r, 50))
    const adjList = await buildSparseGraph(graphNodes, setProgress)

    // Step 3: Personalized PageRank (forward + reverse)
    setStatus('Running Personalized PageRank…')
    setProgress(35)
    await new Promise(r => setTimeout(r, 50))

    const forwardPPR = await computePPR(adjList, graphNodes,
      node => node.asset.internet_facing
        ? safeNum(node.vuln.epss, 0.5) * (node.vuln.cisa_kev ? 2 : 1)
        : 0,
      setProgress, 35, 10
    )
    const reversePPR = await computeReversePPR(adjList, graphNodes, setProgress, 45, 10)
    
    graphNodes.forEach((node, i) => {
      node.pprScore = forwardPPR[i] || 0
      node.blastRadius = reversePPR[i] || 0
      node.pageRank = forwardPPR[i] || 0
      node.centrality = Math.sqrt((forwardPPR[i] || 0) * (reversePPR[i] || 0))
    })

    // Step 4: Max-product belief propagation
    setStatus('Propagating attack beliefs…')
    setProgress(55)
    await new Promise(r => setTimeout(r, 50))
    const beliefs = await propagateBeliefs(graphNodes, adjList, setProgress)
    computeFinalRiskScores(graphNodes, beliefs)
    setNodes([...graphNodes])

    // Step 5: Yen's K-Shortest Paths
    setStatus('Discovering optimal attack paths…')
    setProgress(75)
    await new Promise(r => setTimeout(r, 50))
    
    const paths = await discoverAttackPaths(graphNodes, adjList, setProgress)
    
    // SHOW GRAPH RESULTS IMMEDIATELY
    setAttackPaths(paths)
    setProgress(80)
    setIsScanning(false)
    setScanComplete(true)

    // Step 6: AI analysis - RUN IN BACKGROUND
    setStatus('Running AI analysis (background)…')
    
    // Compute topAssets from graphNodes (not from stale state)
    const computedTopAssets = (() => {
      const assetRisks = new Map<string, { asset: Asset; totalRisk: number; findingCount: number }>()
      graphNodes.forEach(node => {
        const existing = assetRisks.get(node.asset.id)
        if (existing) { existing.totalRisk += node.risk; existing.findingCount++ }
        else assetRisks.set(node.asset.id, { asset: node.asset, totalRisk: node.risk, findingCount: 1 })
      })
      return Array.from(assetRisks.values())
        .map(a => ({ ...a, avgRisk: a.totalRisk / a.findingCount }))
        .sort((a, b) => b.avgRisk - a.avgRisk)
        .slice(0, 20)
    })()
    
    // Store paths reference for AI callback
    const currentPaths = paths
    
    // Fire and forget AI analysis
    const runAIAnalysis = async () => {
      try {
        const findings = graphNodes.map(n => ({
          assetId: n.asset.id, assetName: n.asset.name, networkZone: n.asset.network_zone,
          businessUnit: n.asset.business_unit, vulnTitle: n.vuln.title, severity: n.vuln.severity,
          cvss: n.vuln.cvss, epss: n.vuln.epss, killChainPhase: n.vuln.kill_chain_phase,
          cisaKev: n.vuln.cisa_kev, ransomware: n.vuln.ransomware,
          risk: n.risk, rpc: n.rpc, attackProb: n.attackProb,
          pprScore: n.pprScore, blastRadius: n.blastRadius,
          internetFacing: n.asset.internet_facing,
        }))
        const attackPathsData = currentPaths.map(p => ({
          id: p.id,
          nodes: p.nodes.map(n => ({
            assetName: n.asset.name, vulnTitle: n.vuln.title,
            killChainPhase: n.vuln.kill_chain_phase, risk: n.risk,
            attackProb: n.attackProb, epss: n.vuln.epss,
            cisaKev: n.vuln.cisa_kev, ransomware: n.vuln.ransomware,
          })),
          riskScore: p.riskScore, attackProbability: p.attackProbability,
          confidenceInterval: p.confidenceInterval, mitreTechniques: p.mitreTechniques,
        }))
        const graphMetrics = {
          totalNodes: graphNodes.length,
          avgPPR: graphNodes.reduce((s, n) => s + n.pprScore, 0) / graphNodes.length,
          avgBlastRadius: graphNodes.reduce((s, n) => s + n.blastRadius, 0) / graphNodes.length,
          maxRisk: Math.max(...graphNodes.map(n => n.risk)),
          maxAttackProb: Math.max(...graphNodes.map(n => n.attackProb)),
          criticalCount: graphNodes.filter(n => n.vuln.severity === 'critical').length,
        }

        const response = await fetch('/api/analyze-correlations', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ findings, topAssets: computedTopAssets, attackPaths: attackPathsData, graphMetrics }),
        })
        
        if (response.ok) {
          const result = await response.json()
          setAiResult(result)
          // Update attack paths with AI analysis - create new array for proper React update
          if (result.pathAnalyses && result.pathAnalyses.length > 0) {
            setAttackPaths(prevPaths => 
              prevPaths.map((path, idx) => 
                result.pathAnalyses[idx] 
                  ? { ...path, aiAnalysis: result.pathAnalyses[idx] }
                  : path
              )
            )
          }
          setStatus('AI analysis complete')
        } else {
          setStatus('AI analysis unavailable')
        }
      } catch (error) {
        console.error('AI analysis failed:', error)
        setStatus('AI analysis failed')
      }
    }
    
    // Run AI in background - don't await
    runAIAnalysis()
    
  }, [isScanning, assets])

  const stats = useMemo(() => {
    if (nodes.length === 0) return { totalNodes: 0, avgRisk: 0, maxRisk: 0, criticalCount: 0, highCount: 0, avgRPC: 0 }
    const risks = nodes.map(n => n.risk)
    return {
      totalNodes: nodes.length,
      avgRisk: Math.round(risks.reduce((s, r) => s + r, 0) / risks.length * 10) / 10,
      maxRisk: Math.round(Math.max(...risks) * 10) / 10,
      criticalCount: nodes.filter(n => n.vuln.severity === 'critical').length,
      highCount: nodes.filter(n => n.vuln.severity === 'high').length,
      avgRPC: Math.round(nodes.reduce((s, n) => s + n.rpc, 0) / nodes.length * 10) / 10,
    }
  }, [nodes])

  const zoneDist = useMemo(() => {
    const dist: Record<string, number> = { 'on-prem-dmz': 0, 'on-prem-internal': 0, 'aws-public': 0, 'aws-private': 0, 'azure-public': 0, 'azure-private': 0, 'vpn-gateway': 0 }
    nodes.forEach(n => { 
      if (dist[n.asset.network_zone] !== undefined) {
        dist[n.asset.network_zone]++ 
      } else {
        dist[n.asset.network_zone] = 1
      }
    })
    return dist
  }, [nodes])

  const killChainDist = useMemo(() => {
    const phases: Record<string, number> = {}
    nodes.forEach(n => { phases[n.vuln.kill_chain_phase] = (phases[n.vuln.kill_chain_phase] || 0) + 1 })
    return Object.entries(phases).sort((a, b) => b[1] - a[1])
  }, [nodes])

  const getRiskColor = (score: number) => {
    if (score >= 8) return 'text-red-500'
    if (score >= 6) return 'text-orange-500'
    if (score >= 4) return 'text-yellow-500'
    return 'text-emerald-500'
  }

  const getRiskBg = (score: number) => {
    if (score >= 8) return 'bg-red-500'
    if (score >= 6) return 'bg-orange-500'
    if (score >= 4) return 'bg-yellow-500'
    return 'bg-emerald-500'
  }

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Header */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-50">
        <div className="max-w-[1600px] mx-auto px-8 py-4 flex items-center justify-between">
          <div className="flex items-center gap-10">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-slate-900 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <div>
                <h1 className="text-xl font-bold text-slate-900">Brave Guardian</h1>
                <p className="text-xs text-slate-500">Enterprise Security Intelligence Platform</p>
              </div>
            </div>
            <nav className="flex items-center bg-slate-100 rounded-lg p-1">
              {[
                { id: 'overview', label: 'Dashboard' },
                { id: 'assets', label: 'Assets' },
                { id: 'paths', label: 'Attack Paths' },
              ].map(tab => (
                <button key={tab.id} onClick={() => setActiveView(tab.id as typeof activeView)}
                  className={`px-4 py-2 text-sm font-medium rounded-md transition-all ${activeView === tab.id ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-900'}`}>
                  {tab.label}
                </button>
              ))}
            </nav>
          </div>
          <div className="flex items-center gap-4">
            {/* Data source indicator */}
            <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-100 rounded-lg">
              <div className={`w-2 h-2 rounded-full ${assets[0]?.id.startsWith('asset-') ? 'bg-yellow-500' : 'bg-emerald-500'}`} />
              <span className="text-xs text-slate-600">
                {assets[0]?.id.startsWith('asset-') ? 'Simulated Data' : assets[0]?.id.startsWith('scanned-') ? 'Scanned' : 'Imported'} ({assets.length} assets)
              </span>
            </div>
            {status && (
              <div className="flex items-center gap-2 text-sm text-slate-600">
                <div className="w-4 h-4 border-2 border-slate-300 border-t-slate-600 rounded-full animate-spin" />
                {status}
              </div>
            )}
            <button onClick={() => setShowConnectModal(true)}
              className="px-4 py-2.5 rounded-lg font-medium text-sm border border-slate-300 bg-white hover:bg-slate-50 transition-all flex items-center gap-2">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
              </svg>
              Connect
            </button>
            <button onClick={runAnalysis} disabled={isScanning}
              className={`px-5 py-2.5 rounded-lg font-medium text-sm transition-all ${isScanning ? 'bg-slate-200 text-slate-500 cursor-not-allowed' : 'bg-slate-900 text-white hover:bg-slate-800 shadow-sm'}`}>
              {isScanning ? 'Analyzing…' : 'Run Analysis'}
            </button>
          </div>
        </div>
        {isScanning && (
          <div className="h-0.5 bg-slate-200">
            <div className="h-full bg-slate-900 transition-all duration-300" style={{ width: `${progress}%` }} />
          </div>
        )}
      </header>

      <main className="max-w-[1600px] mx-auto px-8 py-8">
        {/* OVERVIEW */}
        {activeView === 'overview' && (
          <div className="space-y-8">
            <div className="grid grid-cols-6 gap-4">
              {[
                { label: 'Total Findings', value: stats.totalNodes },
                { label: 'Critical', value: stats.criticalCount, variant: 'danger' },
                { label: 'High', value: stats.highCount, variant: 'warning' },
                { label: 'Avg Risk Score', value: stats.avgRisk },
                { label: 'Max Risk Score', value: stats.maxRisk, variant: 'danger' },
                { label: 'Avg RPC', value: stats.avgRPC },
              ].map((stat, i) => (
                <div key={i} className="bg-white rounded-lg border border-slate-200 p-5">
                  <p className="text-xs font-medium text-slate-500 uppercase tracking-wide">{stat.label}</p>
                  <p className={`text-2xl font-bold mt-1 ${stat.variant === 'danger' ? 'text-red-600' : stat.variant === 'warning' ? 'text-orange-600' : 'text-slate-900'}`}>
                    {stat.value}
                  </p>
                </div>
              ))}
            </div>

            <div className="grid grid-cols-3 gap-6">
              {/* Network Zones */}
              <div className="bg-white rounded-lg border border-slate-200 p-6">
                <h3 className="text-sm font-semibold text-slate-900 mb-4">Network Zone Distribution</h3>
                <div className="space-y-3">
                  {Object.entries(zoneDist).map(([zone, count]) => {
                    const total = Object.values(zoneDist).reduce((a, b) => a + b, 0) || 1
                    const pct = Math.round((count / total) * 100)
                    return (
                      <div key={zone}>
                        <div className="flex justify-between text-sm mb-1">
                          <span className="font-medium text-slate-700 uppercase">{zone}</span>
                          <span className="text-slate-500">{count} ({pct}%)</span>
                        </div>
                        <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                          <div className={`h-full rounded-full ${zone.includes('dmz') || zone.includes('public') ? 'bg-red-500' : zone.includes('internal') || zone.includes('private') ? 'bg-orange-500' : zone === 'restricted' ? 'bg-blue-500' : 'bg-emerald-500'}`} style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Kill Chain */}
              <div className="bg-white rounded-lg border border-slate-200 p-6">
                <h3 className="text-sm font-semibold text-slate-900 mb-4">Kill Chain Phases</h3>
                <div className="space-y-2">
                  {killChainDist.slice(0, 5).map(([phase, count]) => (
                    <div key={phase} className="flex items-center justify-between py-2 border-b border-slate-100 last:border-0">
                      <span className="text-sm text-slate-600 capitalize">{phase.replace('_', ' ')}</span>
                      <span className="text-sm font-semibold text-slate-900">{count}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Top Assets */}
              <div className="bg-white rounded-lg border border-slate-200 p-6">
                <h3 className="text-sm font-semibold text-slate-900 mb-4">Highest Risk Assets</h3>
                <div className="space-y-2">
                  {topAssets.slice(0, 5).map((item, i) => (
                    <div key={item.asset.id}
                      onClick={() => { setSelectedAsset(item.asset); setActiveView('assets') }}
                      className="flex items-center justify-between py-2 px-3 -mx-3 rounded-lg hover:bg-slate-50 cursor-pointer transition-colors">
                      <div className="flex items-center gap-3">
                        <span className={`w-6 h-6 rounded text-xs font-bold flex items-center justify-center ${i < 2 ? 'bg-red-100 text-red-600' : 'bg-slate-100 text-slate-600'}`}>{i + 1}</span>
                        <span className="text-sm font-medium text-slate-700">{item.asset.name}</span>
                      </div>
                      <span className={`text-sm font-bold ${getRiskColor(item.avgRisk)}`}>{item.avgRisk.toFixed(1)}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Attack Paths Summary */}
            {attackPaths.length > 0 && (
              <div className="bg-white rounded-lg border border-slate-200 overflow-hidden">
                <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-slate-900">Discovered Attack Paths</h3>
                  <button onClick={() => setActiveView('paths')} className="text-sm text-blue-600 hover:text-blue-700 font-medium">View All →</button>
                </div>
                <div className="divide-y divide-slate-100">
                  {attackPaths.slice(0, 5).map((path, idx) => (
                    <div key={path.id}
                      onClick={() => { setSelectedPath(path); setActiveView('paths') }}
                      className="px-6 py-4 hover:bg-slate-50 cursor-pointer transition-colors flex items-center justify-between">
                      <div className="flex items-center gap-4">
                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-sm font-bold text-white ${getRiskBg(path.riskScore)}`}>{idx + 1}</div>
                        <div>
                          <p className="text-sm font-medium text-slate-900">{path.nodes.length} step attack chain</p>
                          <p className="text-xs text-slate-500">
                            {path.mitreTechniques.length} MITRE techniques • P={(path.attackProbability * 100).toFixed(2)}% • 95% CI [{(path.confidenceInterval[0] * 100).toFixed(1)}%–{(path.confidenceInterval[1] * 100).toFixed(1)}%]
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className={`text-lg font-bold ${getRiskColor(path.riskScore)}`}>{path.riskScore.toFixed(1)}</span>
                        <svg className="w-4 h-4 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* AI Insights */}
            {aiResult && aiResult.correlations && aiResult.correlations.length > 0 && (
              <div className="bg-white rounded-lg border border-slate-200 overflow-hidden">
                <div className="px-6 py-4 border-b border-slate-200 bg-slate-50">
                  <h3 className="text-sm font-semibold text-slate-900">AI-Generated Insights</h3>
                </div>
                <div className="divide-y divide-slate-100">
                  {aiResult.correlations.slice(0, 4).map((corr, idx) => (
                    <div key={idx} className="px-6 py-4">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-xs font-semibold uppercase bg-slate-100 text-slate-600">{corr.type}</span>
                          <span className="text-sm font-semibold text-red-600">Risk: {corr.riskAmplification}/10</span>
                        </div>
                      </div>
                      <h4 className="text-sm font-medium text-slate-900 mb-1">{corr.title}</h4>
                      <p className="text-sm text-slate-600">{corr.description}</p>
                      <p className="text-xs text-blue-600 mt-2 font-medium">→ {corr.recommendation}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Remediation */}
            {aiResult?.topRemediationActions && aiResult.topRemediationActions.length > 0 && (
              <div className="bg-white rounded-lg border border-slate-200 p-6">
                <h3 className="text-sm font-semibold text-slate-900 mb-4">Recommended Remediation Actions</h3>
                <div className="grid grid-cols-3 gap-4">
                  {aiResult.topRemediationActions.slice(0, 3).map((action, idx) => (
                    <div key={idx} className="border border-slate-200 rounded-lg p-4">
                      <div className="flex items-center gap-2 mb-3">
                        <span className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${idx === 0 ? 'bg-red-500 text-white' : idx === 1 ? 'bg-orange-500 text-white' : 'bg-slate-500 text-white'}`}>{idx + 1}</span>
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${action.effort === 'low' ? 'bg-emerald-100 text-emerald-700' : action.effort === 'medium' ? 'bg-orange-100 text-orange-700' : 'bg-red-100 text-red-700'}`}>{action.effort.toUpperCase()}</span>
                      </div>
                      <p className="text-sm font-medium text-slate-900">{action.action}</p>
                      <div className="flex items-center gap-4 mt-2 text-xs text-slate-500">
                        <span>{action.affectedFindings} findings affected</span>
                        <span>~{action.riskReduction}% risk reduction</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {!scanComplete && !isScanning && (
              <div className="bg-white rounded-lg border border-slate-200 p-16 text-center">
                <div className="w-16 h-16 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <svg className="w-8 h-8 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <h3 className="text-lg font-semibold text-slate-900 mb-2">Ready for Analysis</h3>
                <p className="text-sm text-slate-500 mb-6 max-w-md mx-auto">
                  Click &quot;Run Analysis&quot; to discover attack paths using Personalized PageRank, max-product belief propagation, and Yen&apos;s K-Shortest Paths algorithm.
                </p>
              </div>
            )}
          </div>
        )}

        {/* ASSETS */}
        {activeView === 'assets' && (
          <div className="grid grid-cols-3 gap-6">
            <div className="bg-white rounded-lg border border-slate-200 overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-200">
                <h3 className="text-sm font-semibold text-slate-900">Assets by Risk</h3>
              </div>
              <div className="max-h-[600px] overflow-auto">
                {topAssets.map((item, idx) => (
                  <div key={item.asset.id} onClick={() => setSelectedAsset(item.asset)}
                    className={`px-5 py-3 cursor-pointer border-b border-slate-100 last:border-0 transition-colors ${selectedAsset?.id === item.asset.id ? 'bg-blue-50' : 'hover:bg-slate-50'}`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className={`w-6 h-6 rounded text-xs font-bold flex items-center justify-center ${idx < 3 ? 'bg-red-100 text-red-600' : 'bg-slate-100 text-slate-600'}`}>{idx + 1}</span>
                        <div>
                          <p className="text-sm font-medium text-slate-900">{item.asset.name}</p>
                          <p className="text-xs text-slate-500">{item.asset.network_zone} • {item.findingCount} findings</p>
                        </div>
                      </div>
                      <span className={`text-sm font-bold ${getRiskColor(item.avgRisk)}`}>{item.avgRisk.toFixed(1)}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="col-span-2 bg-white rounded-lg border border-slate-200 overflow-hidden">
              {selectedAsset ? (
                <div className="p-6">
                  <div className="flex items-start justify-between mb-6">
                    <div>
                      <h3 className="text-lg font-semibold text-slate-900">{selectedAsset.name}</h3>
                      <p className="text-sm text-slate-500">{selectedAsset.ip} • {selectedAsset.business_unit}</p>
                    </div>
                    <div className="text-right">
                      <p className={`text-3xl font-bold ${getRiskColor(topAssets.find(a => a.asset.id === selectedAsset.id)?.avgRisk || 5)}`}>
                        {(topAssets.find(a => a.asset.id === selectedAsset.id)?.avgRisk || 5).toFixed(1)}
                      </p>
                      <p className="text-xs text-slate-500">Risk Score</p>
                    </div>
                  </div>
                  <div className="grid grid-cols-4 gap-4 mb-6">
                    {[
                      { label: 'Criticality', value: `${selectedAsset.criticality}/5` },
                      { label: 'Network Zone', value: selectedAsset.network_zone.toUpperCase() },
                      { label: 'Internet Facing', value: selectedAsset.internet_facing ? 'Yes' : 'No', color: selectedAsset.internet_facing ? 'text-red-600' : 'text-emerald-600' },
                      { label: 'Findings', value: String(assetFindings.length) },
                    ].map(({ label, value, color }) => (
                      <div key={label} className="bg-slate-50 rounded-lg p-4">
                        <p className="text-xs text-slate-500 mb-1">{label}</p>
                        <p className={`text-sm font-semibold ${color || 'text-slate-900'}`}>{value}</p>
                      </div>
                    ))}
                  </div>

                  {/* PPR & Blast Radius for selected asset */}
                  {(() => {
                    const assetNodes = nodes.filter(n => n.asset.id === selectedAsset.id)
                    const avgPPR = assetNodes.reduce((s, n) => s + n.pprScore, 0) / (assetNodes.length || 1)
                    const avgBlast = assetNodes.reduce((s, n) => s + n.blastRadius, 0) / (assetNodes.length || 1)
                    return assetNodes.length > 0 ? (
                      <div className="grid grid-cols-2 gap-4 mb-6">
                        <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
                          <p className="text-xs text-orange-700 mb-1 font-medium">Attacker Reachability (PPR)</p>
                          <p className="text-lg font-bold text-orange-900">{(avgPPR * 1000).toFixed(2)}</p>
                          <p className="text-xs text-orange-600 mt-1">Higher = more reachable from internet</p>
                        </div>
                        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                          <p className="text-xs text-red-700 mb-1 font-medium">Blast Radius (Reverse PPR)</p>
                          <p className="text-lg font-bold text-red-900">{(avgBlast * 1000).toFixed(2)}</p>
                          <p className="text-xs text-red-600 mt-1">Higher = more attack paths converge here</p>
                        </div>
                      </div>
                    ) : null
                  })()}

                  <h4 className="text-sm font-semibold text-slate-900 mb-3">Vulnerabilities</h4>
                  <div className="space-y-2 max-h-[300px] overflow-auto">
                    {assetFindings.map((finding, i) => (
                      <div key={i} className="flex items-center gap-3 p-3 bg-slate-50 rounded-lg">
                        <span className={`px-2 py-1 rounded text-xs font-bold ${finding.rpc >= 8 ? 'bg-red-100 text-red-700' : finding.rpc >= 6 ? 'bg-orange-100 text-orange-700' : 'bg-slate-200 text-slate-700'}`}>
                          RPC {finding.rpc.toFixed(1)}
                        </span>
                        <div className="flex-1">
                          <p className="text-sm font-medium text-slate-900">{finding.vuln.title}</p>
                          <p className="text-xs text-slate-500">{finding.vuln.severity} • {finding.vuln.kill_chain_phase.replace('_', ' ')} • P(reach)={(finding.attackProb * 100).toFixed(1)}%</p>
                        </div>
                        <span className={`text-sm font-bold ${getRiskColor(finding.risk)}`}>{finding.risk.toFixed(1)}</span>
                        {finding.vuln.cisa_kev && <span className="px-1.5 py-0.5 rounded text-xs bg-purple-100 text-purple-700">KEV</span>}
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="p-16 text-center">
                  <p className="text-slate-500">Select an asset to view details</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ATTACK PATHS */}
        {activeView === 'paths' && (
          <div className="grid grid-cols-3 gap-6">
            <div className="bg-white rounded-lg border border-slate-200 overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-200">
                <h3 className="text-sm font-semibold text-slate-900">Attack Paths</h3>
                <p className="text-xs text-slate-500 mt-1">{attackPaths.length} optimal paths (Yen&apos;s K-Shortest)</p>
              </div>
              <div className="max-h-[600px] overflow-auto">
                {attackPaths.map((path, idx) => (
                  <div key={path.id} onClick={() => setSelectedPath(path)}
                    className={`px-5 py-4 cursor-pointer border-b border-slate-100 last:border-0 transition-colors ${selectedPath?.id === path.id ? 'bg-blue-50' : 'hover:bg-slate-50'}`}>
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <span className={`w-6 h-6 rounded flex items-center justify-center text-xs font-bold text-white ${getRiskBg(path.riskScore)}`}>{idx + 1}</span>
                        <span className="text-sm font-medium text-slate-900">{path.nodes.length} steps</span>
                      </div>
                      <span className={`text-sm font-bold ${getRiskColor(path.riskScore)}`}>{path.riskScore.toFixed(1)}</span>
                    </div>
                    <p className="text-xs text-slate-500">{path.mitreTechniques.length} techniques • P={(path.attackProbability * 100).toFixed(2)}%</p>
                    {path.aiAnalysis && <p className="text-xs text-blue-600 mt-1 font-medium">✓ AI analyzed</p>}
                  </div>
                ))}
              </div>
            </div>

            <div className="col-span-2 bg-white rounded-lg border border-slate-200 overflow-hidden">
              {selectedPath ? (
                <div className="p-6">
                  <div className="flex items-start justify-between mb-6">
                    <div>
                      <h3 className="text-lg font-semibold text-slate-900">Attack Path Analysis</h3>
                      <p className="text-sm text-slate-500">{selectedPath.nodes.length} step deterministic attack chain</p>
                    </div>
                    <div className="text-right">
                      <p className={`text-4xl font-bold ${getRiskColor(selectedPath.riskScore)}`}>{selectedPath.riskScore.toFixed(1)}</p>
                      <p className="text-xs text-slate-500">Risk Score</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-4 mb-6">
                    <div className="bg-slate-50 rounded-lg p-4">
                      <p className="text-xs text-slate-500 mb-1">Attack Probability</p>
                      <p className="text-lg font-semibold text-slate-900">{(selectedPath.attackProbability * 100).toFixed(2)}%</p>
                    </div>
                    <div className="bg-slate-50 rounded-lg p-4">
                      <p className="text-xs text-slate-500 mb-1">95% Wilson CI</p>
                      <p className="text-sm font-semibold text-slate-900">
                        [{(selectedPath.confidenceInterval[0] * 100).toFixed(1)}%, {(selectedPath.confidenceInterval[1] * 100).toFixed(1)}%]
                      </p>
                    </div>
                    <div className="bg-slate-50 rounded-lg p-4">
                      <p className="text-xs text-slate-500 mb-1">MITRE Techniques</p>
                      <p className="text-lg font-semibold text-slate-900">{selectedPath.mitreTechniques.length}</p>
                    </div>
                  </div>

                  <h4 className="text-sm font-semibold text-slate-900 mb-3">Attack Chain</h4>
                  <div className="overflow-x-auto pb-4 mb-6">
                    <div className="flex items-start gap-2 min-w-max">
                      {selectedPath.nodes.map((node, i) => (
                        <div key={i} className="flex items-center">
                          <div className={`w-52 p-3 rounded-lg border-2 ${node.asset.internet_facing ? 'bg-red-50 border-red-200' : 'bg-slate-50 border-slate-200'}`}>
                            <div className="flex items-center gap-1 mb-1">
                              {node.asset.internet_facing && <span className="text-xs text-red-600">🌐</span>}
                              <span className="text-xs text-slate-500 capitalize">{node.vuln.kill_chain_phase.replace('_', ' ')}</span>
                            </div>
                            <p className="text-sm font-semibold text-slate-900 truncate">{node.asset.name}</p>
                            <p className="text-xs text-slate-600 truncate mt-1">{node.vuln.title}</p>
                            <div className="flex items-center gap-2 mt-2 flex-wrap">
                              <span className={`text-xs font-bold ${getRiskColor(node.risk)}`}>R:{node.risk.toFixed(1)}</span>
                              <span className="text-xs text-slate-400">P:{(node.attackProb * 100).toFixed(0)}%</span>
                              {node.vuln.cisa_kev && <span className="px-1 py-0.5 rounded text-xs bg-purple-100 text-purple-700">KEV</span>}
                            </div>
                          </div>
                          {i < selectedPath.nodes.length - 1 && (
                            <svg className="w-6 h-6 text-slate-300 mx-1 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                            </svg>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-2 mb-6">
                    {selectedPath.mitreTechniques.map(t => (
                      <span key={t} className="px-2 py-1 bg-slate-100 text-slate-700 rounded text-xs font-mono">{t}</span>
                    ))}
                  </div>

                  {selectedPath.aiAnalysis ? (
                    <div className="space-y-4">
                      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                        <h4 className="text-sm font-semibold text-blue-900 mb-2">AI Analysis</h4>
                        <p className="text-sm text-blue-800">{selectedPath.aiAnalysis.summary}</p>
                      </div>
                      <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
                        <h4 className="text-sm font-semibold text-orange-900 mb-2">Attack Scenario</h4>
                        <p className="text-sm text-orange-800">{selectedPath.aiAnalysis.attackScenario}</p>
                      </div>
                      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                        <h4 className="text-sm font-semibold text-red-900 mb-2">Business Impact</h4>
                        <p className="text-sm text-red-800">{selectedPath.aiAnalysis.businessImpact}</p>
                      </div>
                      <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-4">
                        <h4 className="text-sm font-semibold text-emerald-900 mb-2">Remediation Steps</h4>
                        <ul className="space-y-1">
                          {selectedPath.aiAnalysis.remediation.map((step, i) => (
                            <li key={i} className="text-sm text-emerald-800 flex items-start gap-2">
                              <span className="font-bold">{i + 1}.</span>
                              <span>{step}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  ) : (
                    <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 text-center">
                      <p className="text-sm text-slate-500">AI analysis will appear after a full run</p>
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-16 text-center">
                  <p className="text-slate-500">Select an attack path to view details</p>
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      {/* Connect Modal */}
      {showConnectModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-xl max-w-lg w-full mx-4 max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-slate-200">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-bold text-slate-900">Connect to Infrastructure</h2>
                <button onClick={() => setShowConnectModal(false)} className="text-slate-400 hover:text-slate-600">
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>
            
            <div className="p-6 space-y-4">
              {/* Connection Type Tabs */}
              <div className="flex gap-2 p-1 bg-slate-100 rounded-lg">
                {[
                  { id: 'ssh', label: 'SSH', icon: '🔐' },
                  { id: 'snmp', label: 'SNMP', icon: '📡' },
                  { id: 'api', label: 'API', icon: '🔌' },
                  { id: 'import', label: 'Import', icon: '📁' },
                ].map(tab => (
                  <button key={tab.id}
                    onClick={() => setConnectionConfig(c => ({ ...c, type: tab.id as any }))}
                    className={`flex-1 px-3 py-2 text-sm font-medium rounded-md transition-all flex items-center justify-center gap-2 ${connectionConfig.type === tab.id ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-600 hover:text-slate-900'}`}>
                    <span>{tab.icon}</span>
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* Connection Name */}
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Connection Name</label>
                <input type="text" value={connectionConfig.name} 
                  onChange={e => setConnectionConfig(c => ({ ...c, name: e.target.value }))}
                  placeholder="e.g., Production Network"
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-500" />
              </div>

              {/* SSH/SNMP/API Config */}
              {connectionConfig.type !== 'import' && (
                <>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">Network Range (CIDR)</label>
                    <input type="text" value={connectionConfig.networkRange || ''}
                      onChange={e => setConnectionConfig(c => ({ ...c, networkRange: e.target.value }))}
                      placeholder="e.g., 192.168.1.0/24"
                      className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-500" />
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-1">Host</label>
                      <input type="text" value={connectionConfig.host || ''}
                        onChange={e => setConnectionConfig(c => ({ ...c, host: e.target.value }))}
                        placeholder="IP or hostname"
                        className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-500" />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-1">Port</label>
                      <input type="number" value={connectionConfig.port || ''}
                        onChange={e => setConnectionConfig(c => ({ ...c, port: parseInt(e.target.value) }))}
                        placeholder={connectionConfig.type === 'ssh' ? '22' : connectionConfig.type === 'snmp' ? '161' : '443'}
                        className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-500" />
                    </div>
                  </div>

                  {connectionConfig.type === 'ssh' && (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-1">Username</label>
                        <input type="text" value={connectionConfig.username || ''}
                          onChange={e => setConnectionConfig(c => ({ ...c, username: e.target.value }))}
                          placeholder="SSH username"
                          className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-500" />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-1">Password / SSH Key</label>
                        <textarea value={connectionConfig.password || ''}
                          onChange={e => setConnectionConfig(c => ({ ...c, password: e.target.value }))}
                          placeholder="Password or paste SSH private key"
                          rows={3}
                          className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-500 font-mono" />
                      </div>
                    </>
                  )}

                  {connectionConfig.type === 'snmp' && (
                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-1">SNMP Community String</label>
                      <input type="password" value={connectionConfig.snmpCommunity || ''}
                        onChange={e => setConnectionConfig(c => ({ ...c, snmpCommunity: e.target.value }))}
                        placeholder="e.g., public"
                        className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-500" />
                    </div>
                  )}

                  {connectionConfig.type === 'api' && (
                    <>
                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-1">API URL</label>
                        <input type="text" value={connectionConfig.apiUrl || ''}
                          onChange={e => setConnectionConfig(c => ({ ...c, apiUrl: e.target.value }))}
                          placeholder="https://api.example.com/v1/scan"
                          className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-500" />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-1">API Token</label>
                        <input type="password" value={connectionConfig.apiToken || ''}
                          onChange={e => setConnectionConfig(c => ({ ...c, apiToken: e.target.value }))}
                          placeholder="API token or key"
                          className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-slate-500" />
                      </div>
                    </>
                  )}
                </>
              )}

              {/* Import from file */}
              {connectionConfig.type === 'import' && (
                <div className="border-2 border-dashed border-slate-300 rounded-lg p-8 text-center">
                  <input type="file" id="importFile" accept=".json,.csv" className="hidden"
                    onChange={e => {
                      const file = e.target.files?.[0]
                      if (file) importFromFile(file)
                    }} />
                  <label htmlFor="importFile" className="cursor-pointer">
                    <div className="w-12 h-12 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-3">
                      <svg className="w-6 h-6 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                      </svg>
                    </div>
                    <p className="text-sm font-medium text-slate-700">Drop files here or click to upload</p>
                    <p className="text-xs text-slate-500 mt-1">JSON or CSV files supported</p>
                  </label>
                </div>
              )}

              {/* Scan Log */}
              {scanLog.length > 0 && (
                <div className="bg-slate-900 rounded-lg p-3 max-h-32 overflow-y-auto">
                  {scanLog.map((log, i) => (
                    <p key={i} className="text-xs text-emerald-400 font-mono">{log}</p>
                  ))}
                </div>
              )}

              {/* Saved Connections */}
              {savedConnections.length > 0 && connectionConfig.type !== 'import' && (
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">Recent Connections</label>
                  <div className="space-y-1">
                    {savedConnections.slice(0, 3).map((conn, i) => (
                      <button key={i}
                        onClick={() => setConnectionConfig(conn)}
                        className="w-full px-3 py-2 text-left text-sm bg-slate-50 hover:bg-slate-100 rounded-lg flex items-center justify-between">
                        <span className="font-medium">{conn.name}</span>
                        <span className="text-slate-400 uppercase text-xs">{conn.type}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="p-6 border-t border-slate-200 flex gap-3 justify-end">
              <button onClick={() => { setAssets(INITIAL_ASSETS); setShowConnectModal(false) }}
                className="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-900">
                Use Demo Data
              </button>
              <button onClick={() => connectAndScan(connectionConfig)}
                disabled={isConnecting || (connectionConfig.type !== 'import' && !connectionConfig.host && !connectionConfig.networkRange)}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${isConnecting || (connectionConfig.type !== 'import' && !connectionConfig.host && !connectionConfig.networkRange) ? 'bg-slate-200 text-slate-500 cursor-not-allowed' : 'bg-slate-900 text-white hover:bg-slate-800'}`}>
                {isConnecting ? 'Connecting…' : 'Connect & Scan'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
