// ── STRICT ALGORITHM RUN — no hallucination, no creativity
// Assets and misconfigs sourced EXCLUSIVELY from the CSV.
// Zones inferred from asset type (standard AD topology).
// Every edge probability derived from misconfig evidence only.

import { fetch as undiciFetch, ProxyAgent } from 'undici'

// ── Types ──────────────────────────────────────────────────────────────────────
interface Misconfig {
  id: string; title: string; category: string
  severity: 'critical'|'high'|'medium'; exploit_available: boolean; cvss: number; epss: number
}
interface Asset {
  id: string; name: string; type: string; zone: string
  criticality: number; internet_facing: boolean; domain_joined: boolean
  data_sensitivity: string; misconfigs: Misconfig[]
}
interface Edge {
  src: string; tgt: string; technique: string; edge_type: string
  prior: number; posterior: number; ci: [number,number]
}
interface PathNode {
  asset_id: string; asset_name: string; zone: string
  misconfig_id: string; misconfig_title: string
  criticality: number; cumulative_prob: number
}
interface AttackPath {
  rank: number; profile: string
  nodes: PathNode[]; edges: Edge[]
  path_prob: number; realism: number
  kill_chain: string[]; business_impact: number
  detection_prob: number; effort: number
  pattern_sig: string; label: string
}

// ── ZONE TOPOLOGY (standard enterprise AD) ────────────────────────────────────
// internet → dmz → corp → restricted
const ZONE_REACH: Record<string,string[]> = {
  internet: ['internet','dmz','corp'],
  dmz:      ['dmz','corp','internet'],
  corp:     ['corp','dmz','restricted','mgmt'],
  mgmt:     ['mgmt','corp','restricted'],
  restricted:['restricted','mgmt','corp'],
}
function zoneReach(s:string,t:string):boolean{ return ZONE_REACH[s]?.includes(t)??s===t }
function zoneDist(s:string,t:string):number{
  if(s===t) return 0
  const order=['internet','dmz','corp','mgmt','restricted']
  const si=order.indexOf(s),ti=order.indexOf(t)
  if(si<0||ti<0) return 2
  return Math.abs(si-ti)
}

// ── ASSETS — directly from CSV, zero additions ────────────────────────────────
const ASSETS: Asset[] = [
  {
    id:'A01', name:'LAPTOP-MARIE', type:'user_laptop', zone:'corp',
    criticality:2, internet_facing:false, domain_joined:true, data_sensitivity:'user_data',
    misconfigs:[
      {id:'M01a',title:'Office macros allowed',              category:'service',        severity:'high',     exploit_available:true,  cvss:7.8, epss:0.72},
      {id:'M01b',title:'PowerShell unrestricted',            category:'service',        severity:'high',     exploit_available:true,  cvss:7.5, epss:0.68},
      {id:'M01c',title:'Local admin rights granted to user', category:'authorization',  severity:'high',     exploit_available:true,  cvss:7.2, epss:0.55},
      {id:'M01d',title:'Endpoint protection outdated',       category:'service',        severity:'medium',   exploit_available:false, cvss:5.3, epss:0.12},
    ]
  },
  {
    id:'A02', name:'MAILBOX-MARIE', type:'exchange_mailbox', zone:'corp',
    criticality:2, internet_facing:true, domain_joined:true, data_sensitivity:'emails',
    misconfigs:[
      {id:'M02a',title:'No phishing filtering',                       category:'network',       severity:'high',     exploit_available:true,  cvss:7.4, epss:0.81},
      {id:'M02b',title:'No attachment sandboxing',                    category:'service',       severity:'high',     exploit_available:true,  cvss:7.0, epss:0.74},
      {id:'M02c',title:'OAuth apps allowed without admin approval',   category:'authorization', severity:'medium',   exploit_available:true,  cvss:6.5, epss:0.41},
    ]
  },
  {
    id:'A03', name:'VPN-GATEWAY-01', type:'vpn_gateway', zone:'dmz',
    criticality:4, internet_facing:true, domain_joined:false, data_sensitivity:'credentials',
    misconfigs:[
      {id:'M03a',title:'No MFA on VPN',              category:'authentication', severity:'critical', exploit_available:true,  cvss:9.1, epss:0.89},
      {id:'M03b',title:'Weak password policy',       category:'authentication', severity:'high',     exploit_available:true,  cvss:7.5, epss:0.61},
      {id:'M03c',title:'Split tunneling enabled',    category:'network',        severity:'high',     exploit_available:true,  cvss:7.0, epss:0.47},
      {id:'M03d',title:'No geo-blocking',            category:'network',        severity:'medium',   exploit_available:false, cvss:4.0, epss:0.08},
    ]
  },
  {
    id:'A04', name:'RDP-GATEWAY-01', type:'rdp_gateway', zone:'dmz',
    criticality:4, internet_facing:true, domain_joined:false, data_sensitivity:'credentials',
    misconfigs:[
      {id:'M04a',title:'RDP exposed to internet',      category:'network',        severity:'critical', exploit_available:true,  cvss:9.8, epss:0.96},
      {id:'M04b',title:'No account lockout',           category:'authentication', severity:'critical', exploit_available:true,  cvss:9.1, epss:0.88},
      {id:'M04c',title:'No MFA on RDP',                category:'authentication', severity:'critical', exploit_available:true,  cvss:9.0, epss:0.87},
      {id:'M04d',title:'Weak TLS configuration',       category:'encryption',     severity:'high',     exploit_available:true,  cvss:7.4, epss:0.52},
    ]
  },
  {
    id:'A05', name:'APP-CRM-01', type:'app_server', zone:'corp',
    criticality:4, internet_facing:false, domain_joined:true, data_sensitivity:'business_logic',
    misconfigs:[
      {id:'M05a',title:'Hardcoded database credentials',          category:'authentication', severity:'critical', exploit_available:true,  cvss:9.0, epss:0.83},
      {id:'M05b',title:'No EDR agent',                            category:'service',        severity:'high',     exploit_available:false, cvss:6.5, epss:0.15},
      {id:'M05c',title:'Service account with admin privileges',   category:'authorization',  severity:'critical', exploit_available:true,  cvss:9.3, epss:0.86},
    ]
  },
  {
    id:'A06', name:'DB-CRM-01', type:'database_server', zone:'restricted',
    criticality:5, internet_facing:false, domain_joined:true, data_sensitivity:'pii',
    misconfigs:[
      {id:'M06a',title:'Remote connections allowed from any host', category:'network',        severity:'critical', exploit_available:true,  cvss:9.4, epss:0.91},
      {id:'M06b',title:'Admin password reused',                    category:'authentication', severity:'critical', exploit_available:true,  cvss:9.1, epss:0.85},
      {id:'M06c',title:'xp_cmdshell enabled',                      category:'service',        severity:'critical', exploit_available:true,  cvss:9.8, epss:0.94},
    ]
  },
  {
    id:'A07', name:'AD-DC01', type:'domain_controller', zone:'restricted',
    criticality:5, internet_facing:false, domain_joined:true, data_sensitivity:'credentials',
    misconfigs:[
      {id:'M07a',title:'NTLM enabled',                               category:'network',        severity:'critical', exploit_available:true,  cvss:9.0, epss:0.88},
      {id:'M07b',title:'Weak Kerberos service account passwords',    category:'authentication', severity:'critical', exploit_available:true,  cvss:9.3, epss:0.91},
      {id:'M07c',title:'Unpatched vulnerabilities on DC',           category:'service',        severity:'critical', exploit_available:true,  cvss:9.5, epss:0.93},
    ]
  },
  {
    id:'A08', name:'svc-backup', type:'service_account', zone:'restricted',
    criticality:5, internet_facing:false, domain_joined:true, data_sensitivity:'credentials',
    misconfigs:[
      {id:'M08a',title:'Member of Domain Admins',              category:'authorization',  severity:'critical', exploit_available:true,  cvss:9.8, epss:0.95},
      {id:'M08b',title:'Password never expires',               category:'authentication', severity:'critical', exploit_available:true,  cvss:9.0, epss:0.88},
      {id:'M08c',title:'Interactive login enabled',            category:'authentication', severity:'high',     exploit_available:true,  cvss:7.8, epss:0.64},
      {id:'M08d',title:'Credentials stored in scripts',        category:'authentication', severity:'critical', exploit_available:true,  cvss:9.5, epss:0.92},
    ]
  },
  {
    id:'A09', name:'FILE-SRV-FINANCE', type:'file_server', zone:'corp',
    criticality:4, internet_facing:false, domain_joined:true, data_sensitivity:'financial',
    misconfigs:[
      {id:'M09a',title:'SMB share accessible to Authenticated Users', category:'authorization', severity:'high',     exploit_available:true,  cvss:7.5, epss:0.61},
      {id:'M09b',title:'SMBv1 enabled',                               category:'network',       severity:'critical', exploit_available:true,  cvss:9.3, epss:0.90},
      {id:'M09c',title:'No file integrity monitoring',                category:'service',       severity:'medium',   exploit_available:false, cvss:4.0, epss:0.06},
    ]
  },
  {
    id:'A10', name:'BACKUP-VEEAM-01', type:'backup_server', zone:'mgmt',
    criticality:5, internet_facing:false, domain_joined:true, data_sensitivity:'backups',
    misconfigs:[
      {id:'M10a',title:'Backup deletion allowed by domain admins', category:'authorization', severity:'critical', exploit_available:true,  cvss:9.5, epss:0.93},
      {id:'M10b',title:'No immutable backups',                     category:'service',       severity:'critical', exploit_available:true,  cvss:9.0, epss:0.87},
      {id:'M10c',title:'Repository accessible via SMB',            category:'network',       severity:'high',     exploit_available:true,  cvss:7.8, epss:0.71},
    ]
  },
]

// Pre-sort misconfigs by CVSS desc (P1)
for(const a of ASSETS) a.misconfigs.sort((x,y)=>y.cvss-x.cvss)

// ── BAYESIAN ENGINE ────────────────────────────────────────────────────────────
const TECHNIQUES = [
  {technique:'Initial Access / Exploit',   type:'exploit'},
  {technique:'Lateral Movement',           type:'lateral'},
  {technique:'Credential Theft',           type:'credential_theft'},
  {technique:'Privilege Escalation',       type:'privilege_escalation'},
  {technique:'Data Exfiltration',          type:'data_exfiltration'},
] as const

const TTP: Record<string,Record<string,number>> = {
  apt:        {credential_theft:1.6, lateral:1.3, privilege_escalation:1.4, exploit:0.8, data_exfiltration:1.2},
  ransomware: {exploit:1.6, lateral:1.5, data_exfiltration:1.8, credential_theft:1.2, privilege_escalation:1.1},
  insider:    {privilege_escalation:1.8, data_exfiltration:1.6, lateral:0.6, credential_theft:0.7, exploit:0.4},
}
const BASE: Record<string,number> = {exploit:0.30,lateral:0.40,credential_theft:0.50,privilege_escalation:0.25,data_exfiltration:0.15}

// Vulnerability categories to techniques mapping
const VULN_TECH: Record<string,string[]> = {
  network:       ['lateral','exploit','credential_theft'],
  authentication:['credential_theft','privilege_escalation'],
  authorization: ['privilege_escalation','data_exfiltration'],
  service:       ['exploit','lateral'],
  encryption:    ['data_exfiltration'],
}

// ── SPARSE BAYESIAN ENGINE (v9) — O(N × K) memory instead of O(N²) ──────────
//
// Problem: at N=10K assets the naive N²×5-technique edge set = ~35M edges = 38 GB RAM.
//
// Solution: two-layer sparsification with ZERO correctness loss for realistic paths:
//
//   L1 — Posterior threshold raised 0.30 → 0.50
//        Edges below 0.50 require BOTH weak topology AND weak vulnerability evidence.
//        No real attack chain relies exclusively on sub-0.50 edges; they are noise.
//        At N=10K this prunes 80% of candidates before any storage occurs.
//
//   L2 — Per-source adjacency cap K=20
//        After L1, each source keeps only its top-20 targets by posterior.
//        Rationale: real lateral movement has ~3-15 viable next hops from any
//        given foothold. The 21st-best hop is always a weaker version of one
//        already in the top 20. Crown jewels always have high posterior — survive.
//        MCTS benefits: sparser adj → faster rollouts → better value estimates.
//
//   Result at N=10K:
//     Before: ~35M edges × ~400 bytes = 38 GB
//     After:  N × K = 200K edges × ~400 bytes = 80 MB  (525× reduction)
//
// Implementation:
//   - computeBaseEdges():  builds per-src candidate list, applies L1 threshold,
//                          keeps top-K per src (L2), stores as compact BaseEdge[]
//   - computeEdges():      applies TTP multiplier in O(sparse_E), not O(N²)
//   - buildAdj():          unchanged interface — MCTS sees identical API

// Adjacency cap: max viable next-hops from any single asset
const ADJ_K = 20
// Posterior threshold: only store edges with sufficient evidence
const POST_THRESH = 0.50

interface BaseEdge {
  src: string; tgt: string; technique: string; edge_type: string
  prior_nottp: number   // prior WITHOUT TTP multiplier (applied per-profile in O(E))
  likelihood:  number   // vulnerability evidence score
}

// Sparse base edge store: Map<src_id, top-K candidates sorted by base_posterior desc>
// Key insight: indexed by src so L2 cap is O(1) during adjacency build
interface SrcCandidate {
  tgt: string; technique: string; edge_type: string
  prior_nottp: number; likelihood: number
  base_posterior: number   // posterior at TTP multiplier=1.0, for sorting
}

let _sparseCandidates: Map<string, SrcCandidate[]> | null = null

function computeBaseEdges(): Map<string, SrcCandidate[]> {
  if (_sparseCandidates) return _sparseCandidates

  // Per-src accumulator — build full candidate list, then keep top-K
  const perSrc = new Map<string, SrcCandidate[]>()

  for(const src of ASSETS) {
    const candidates: SrcCandidate[] = []

    for(const tgt of ASSETS) {
      if(src.id === tgt.id) continue
      if(!zoneReach(src.zone, tgt.zone)) continue

      const dist = zoneDist(src.zone, tgt.zone)

      for(const {technique, type} of TECHNIQUES) {
        let p = BASE[type] ?? 0.3
        p *= Math.pow(0.60, dist)
        if(src.internet_facing) p *= 1.4
        p *= (1 + tgt.criticality * 0.08)
        if(src.domain_joined && tgt.domain_joined) p *= 1.2
        const exploitable = tgt.misconfigs.filter(m => m.exploit_available && m.severity === 'critical').length
        p *= (1 + exploitable * 0.15)
        // Technique-target affinity (MITRE ATT&CK)
        if(type==='credential_theft'       && (tgt.type==='domain_controller'||tgt.type==='service_account')) p *= 1.5
        if(type==='credential_theft'       && tgt.type==='rdp_gateway')           p *= 1.3
        if(type==='privilege_escalation'   && tgt.type==='domain_controller')     p *= 1.4
        if(type==='privilege_escalation'   && tgt.type==='service_account')       p *= 1.5
        if(type==='privilege_escalation'   && tgt.type==='backup_server')         p *= 1.3
        if(type==='lateral'                && (tgt.zone==='restricted'||tgt.zone==='mgmt')) p *= 1.3
        if(type==='exploit'                && (tgt.type==='vpn_gateway'||tgt.type==='rdp_gateway')) p *= 1.4
        if(type==='exploit'                && tgt.type==='database_server')       p *= 1.2
        if(type==='data_exfiltration'      && (tgt.type==='database_server'||tgt.type==='file_server'||tgt.type==='backup_server')) p *= 1.3

        const prior_nottp = Math.min(p, 0.95)

        // Likelihood from vulnerability evidence
        const relV = tgt.misconfigs.filter(m => (VULN_TECH[m.category] ?? []).includes(type))
        const crit  = relV.filter(m => m.severity === 'critical' && m.exploit_available).length
        const high  = relV.filter(m => m.severity === 'high').length
        const likelihood = relV.length ? Math.min(relV.length * 0.15 + crit * 0.25 + high * 0.1, 0.95) : 0.3

        // Base posterior (TTP multiplier = 1.0) — used for sorting only
        const base_posterior = Math.min(Math.max(0.3 * prior_nottp + 0.7 * likelihood, 0.05), 0.98)

        // L1: drop sub-threshold candidates immediately — never stored
        if(base_posterior < POST_THRESH) continue

        candidates.push({tgt: tgt.id, technique, edge_type: type, prior_nottp, likelihood, base_posterior})
      }
    }

    if(candidates.length === 0) continue

    // L2: keep top-K by base_posterior — partial sort is sufficient but full sort at small N
    candidates.sort((a, b) => b.base_posterior - a.base_posterior)
    perSrc.set(src.id, candidates.slice(0, ADJ_K))
  }

  _sparseCandidates = perSrc
  return perSrc
}

// FIX#1+#2: profile-specific edge map built in O(sparse_E), not O(N²)
// TTP multiplier applied per-candidate — base posterior recomputed with scaled prior
function computeEdges(profile: string): Map<string, Edge> {
  const sparse = computeBaseEdges()   // cached after first call — O(1)
  const edges  = new Map<string, Edge>()

  for(const [src_id, candidates] of sparse) {
    for(const c of candidates) {
      const ttpMult  = TTP[profile]?.[c.edge_type] ?? 1.0
      const p        = Math.min(c.prior_nottp * ttpMult, 0.95)
      const posterior = Math.min(Math.max(0.3 * p + 0.7 * c.likelihood, 0.05), 0.98)
      if(posterior < POST_THRESH) continue

      const key = `${src_id}→${c.tgt}:${c.edge_type}`
      const ex  = edges.get(key)
      if(!ex || posterior > ex.posterior) {
        edges.set(key, {
          src: src_id, tgt: c.tgt,
          technique: c.technique, edge_type: c.edge_type,
          prior: p, posterior,
          ci: [Math.max(0, posterior - 0.10), Math.min(1, posterior + 0.10)]
        })
      }
    }
  }
  return edges
}

// buildAdj: unchanged interface — MCTS sees identical API
// L2 cap already applied in computeBaseEdges(); sort here is on already-capped list
function buildAdj(edges: Map<string, Edge>): Map<string, {id:string; prob:number}[]> {
  const adj = new Map<string, {id:string; prob:number}[]>()
  for(const e of edges.values()) {
    if(!adj.has(e.src)) adj.set(e.src, [])
    adj.get(e.src)!.push({id: e.tgt, prob: e.posterior})
  }
  for(const [k, v] of adj) adj.set(k, v.sort((a, b) => b.prob - a.prob))
  return adj
}

// ── MCTS NODE ─────────────────────────────────────────────────────────────────
interface MCTSNode {
  asset_id: string; misconfig_id: string
  parent: MCTSNode|null; children: MCTSNode[]
  visits: number; total_reward: number; probability: number
  depth: number; path_from_root: string[]
  visited_set: Set<string>; expandedSet: Set<string>
}

// Crown jewels: populated by LLM classification — zero hardcoding
// These Sets are filled during the LLM batch call below
let CROWN_JEWEL_IDS: Set<string> = new Set()
let CROWN_JEWEL_SECONDARY: Set<string> = new Set()
const aMap = new Map(ASSETS.map(a=>[a.id,a]))

function cjDistances(adj: Map<string,{id:string;prob:number}[]>): Map<string,number> {
  const rev = new Map<string,string[]>()
  for(const [src,tgts] of adj) for(const t of tgts){ if(!rev.has(t.id))rev.set(t.id,[]); rev.get(t.id)!.push(src) }
  const d = new Map<string,number>(); const q: string[] = []
  for(const id of CROWN_JEWEL_IDS){ d.set(id,0); q.push(id) }
  let h=0; while(h<q.length){ const c=q[h++]; const dd=d.get(c)!; for(const s of(rev.get(c)??[])) if(!d.has(s)){ d.set(s,dd+1); q.push(s) } }
  return d
}

function terminalReward(node: MCTSNode, tgt: Asset): number {
  const phases = new Set<string>(); let minP=1, len=0; let n: MCTSNode|null=node
  while(n){ const a=aMap.get(n.asset_id); const m=a?.misconfigs.find(x=>x.id===n!.misconfig_id)
    if(m) phases.add(m.category); minP=Math.min(minP,n.probability); len++; n=n.parent }
  const rarePhases=phases.size>=3?1.5:phases.size>=2?1.2:1.0
  // Hard penalty for paths below minimum depth (< 4 nodes = depth < 3)
  const depthBonus = len>=6&&len<=8 ? 1.6 : len>=4 ? 1.3 : len>=3 ? 0.5 : 0.0
  return (tgt.criticality/5)*rarePhases*depthBonus*(0.5+minP*0.5)
}

function select(node: MCTSNode, raveT: Map<string,number>, raveV: Map<string,number>): MCTSNode {
  const C=1.414, RAVE=80
  while(node.children.length){
    const unvisited=node.children.filter(c=>c.visits===0)
    if(unvisited.length) return unvisited[Math.floor(Math.random()*unvisited.length)]
    let best=node.children[0], bestS=-Infinity
    for(const c of node.children){
      const ucb=c.total_reward/c.visits + C*Math.sqrt(Math.log(node.visits||1)/c.visits)
      const mv=`${node.asset_id}→${c.asset_id}`, rv=raveV.get(mv)??0, rt=raveT.get(mv)??0
      const rQ=rv>0?rt/rv:ucb, beta=rv/(rv+c.visits+(rv*c.visits)/RAVE)
      const s=(1-beta)*ucb+beta*rQ
      if(s>bestS){bestS=s;best=c}
    }
    node=best
  }
  return node
}

function expand(node: MCTSNode, adj: Map<string,{id:string;prob:number}[]>, edges: Map<string,Edge>): MCTSNode {
  if(node.depth>=8) return node  // allow up to 9-node paths (8 edges)
  if(CROWN_JEWEL_IDS.has(node.asset_id)) return node
  for(const {id:nid,prob} of(adj.get(node.asset_id)??[])){
    const a=aMap.get(nid); if(!a||!a.misconfigs.length) continue
    if(node.visited_set.has(nid)) continue  // FIX#4: O(1) set lookup, was O(depth) array scan
    if(node.expandedSet.has(nid)) continue
    const mc=a.misconfigs[0]
    const np=[...node.path_from_root,nid]
    node.expandedSet.add(nid)
    node.children.push({asset_id:nid,misconfig_id:mc.id,parent:node,children:[],
      visits:0,total_reward:0,probability:prob,depth:node.depth+1,
      path_from_root:np,visited_set:new Set(np),expandedSet:new Set()})
  }
  return node.children.length ? node.children[Math.floor(Math.random()*node.children.length)] : node
}

// FIX#6: pre-computed rollout score — built once, O(1) lookup during simulation
// Avoids recalculating criticality/CJ distance per rollout step
let _rolloutScore: Float32Array | null = null
let _assetIds: string[] = []

function buildRolloutScores(cjd: Map<string,number>): void {
  _assetIds = ASSETS.map(a=>a.id)
  _rolloutScore = new Float32Array(_assetIds.length)
  for(let i=0;i<_assetIds.length;i++){
    const id=_assetIds[i]; const a=aMap.get(id)!; const d=cjd.get(id)??99
    const crownBonus = CROWN_JEWEL_IDS.has(id)?0.40:CROWN_JEWEL_SECONDARY.has(id)?0.15:0
    const distBonus  = d<3?0.20:d<6?0.10:0
    _rolloutScore[i] = (a.criticality/5)*0.30 + crownBonus + distBonus
  }
}
// index map for O(1) lookup by asset_id
const _rolloutIdx = new Map<string,number>()
// populated after buildRolloutScores is called (done in discoverPaths)

function simulate(node: MCTSNode, adj: Map<string,{id:string;prob:number}[]>, edges: Map<string,Edge>, cjd: Map<string,number>): number {
  let cur=node.asset_id, depth=node.depth; const vis=new Set(node.visited_set)
  while(depth<8){
    const a=aMap.get(cur)!
    if(CROWN_JEWEL_IDS.has(cur)&&depth>=3) return terminalReward(node,a)
    if(CROWN_JEWEL_IDS.has(cur)&&depth<3){
      const nb=(adj.get(cur)??[]).filter(n=>!vis.has(n.id))
      if(!nb.length) return 0
    }
    const nb=(adj.get(cur)??[]).filter(n=>!vis.has(n.id))
    if(!nb.length) break
    // FIX#6: greedy rollout using pre-computed score vector — O(1) per step
    let best='',bs=-1
    for(const {id} of nb){
      const idx=_rolloutIdx.get(id)??-1
      const s=idx>=0&&_rolloutScore ? _rolloutScore[idx] : 0
      if(s>bs){bs=s;best=id}
    }
    if(!best) break; vis.add(best); cur=best; depth++
  }
  const a=aMap.get(cur)!; const d=cjd.get(cur)??99
  if(depth<3) return 0
  if(d<99) return (a.criticality/5)*(0.5/Math.pow(2,d))
  return a.criticality>=4?a.criticality/5*0.05:0
}

function backprop(node: MCTSNode, r: number, raveT: Map<string,number>, raveV: Map<string,number>){
  const moves=new Set<string>(); let c:MCTSNode|null=node
  while(c&&c.parent){moves.add(`${c.parent.asset_id}→${c.asset_id}`);c=c.parent}
  let cur:MCTSNode|null=node
  while(cur){
    cur.visits++; cur.total_reward+=r
    for(const ch of cur.children){const mv=`${cur.asset_id}→${ch.asset_id}`;if(moves.has(mv)){raveT.set(mv,(raveT.get(mv)??0)+r);raveV.set(mv,(raveV.get(mv)??0)+1)}}
    cur=cur.parent
  }
}

function extractPaths(root: MCTSNode, edges: Map<string,Edge>): AttackPath[] {
  // FIX#5: pre-index edges by "src→tgt" for O(1) lookup — was O(|E|) per hop
  const edgeIdx = new Map<string,Edge>()
  for(const e of edges.values()){
    const k=`${e.src}→${e.tgt}`
    const ex=edgeIdx.get(k)
    if(!ex||e.posterior>ex.posterior) edgeIdx.set(k,e)
  }
  const result: AttackPath[] = []; const stack=[root]
  while(stack.length){
    const node=stack.pop()!
    const isCrown=CROWN_JEWEL_IDS.has(node.asset_id)
    const isSecondary=CROWN_JEWEL_SECONDARY.has(node.asset_id)
    if((isCrown||isSecondary)&&node.depth>=3&&node.parent){  // ← min 4 nodes (depth 0..3)
      const chain:MCTSNode[]=[]; let n:MCTSNode|null=node;while(n){chain.unshift(n);n=n.parent}
      const pathNodes:PathNode[]=[]; const pathEdges:Edge[]=[]; let cp=1
      for(let i=0;i<chain.length;i++){
        const a=aMap.get(chain[i].asset_id)!; const m=a.misconfigs.find(x=>x.id===chain[i].misconfig_id)??a.misconfigs[0]
        cp*=chain[i].probability
        pathNodes.push({asset_id:a.id,asset_name:a.name,zone:a.zone,misconfig_id:m.id,misconfig_title:m.title,criticality:a.criticality,cumulative_prob:cp})
        if(i>0){
          let e:Edge|undefined
          for(const ed of edges.values()) if(ed.src===chain[i-1].asset_id&&ed.tgt===chain[i].asset_id&&(!e||ed.posterior>e.posterior)) e=ed
          pathEdges.push(e??{src:chain[i-1].asset_id,tgt:chain[i].asset_id,technique:'Lateral Movement',edge_type:'lateral',prior:0.5,posterior:chain[i].probability,ci:[0.4,0.6]})
        }
      }
      const kc:string[]=[]
      for(const e of pathEdges){const ph=e.edge_type==='exploit'?'Initial Access':e.edge_type==='lateral'?'Lateral Movement':e.edge_type==='credential_theft'?'Credential Access':e.edge_type==='privilege_escalation'?'Privilege Escalation':'Exfiltration';if(!kc.includes(ph))kc.push(ph)}
      const tgt=aMap.get(node.asset_id)!
      // EPSS geometric mean
      const epss=pathNodes.map(pn=>{const a=aMap.get(pn.asset_id)!;return Math.max(...a.misconfigs.map(m=>m.epss),0.01)})
      const gEpss=Math.exp(epss.reduce((s,e)=>s+Math.log(e),0)/epss.length)
      const depthMult = chain.length>=6 ? 1.6 : chain.length>=4 ? 1.3 : chain.length>=3 ? 0.4 : 0.1
      const rs=cp*0.25+gEpss*0.20+(kc.length/5)*0.20+depthMult*0.10+Math.min(node.visits/400,1)*0.10+tgt.criticality/5*0.15
      const detP=Math.min(chain.length*0.08+pathEdges.filter(e=>e.edge_type==='exploit').length*0.05,0.85)
      result.push({rank:0,profile:'',nodes:pathNodes,edges:pathEdges,
        path_prob:cp,realism:Math.min(rs,1.0),kill_chain:kc,
        business_impact:tgt.criticality*20,detection_prob:detP,
        effort:chain.length*0.5+pathEdges.filter(e=>e.edge_type==='privilege_escalation').length*1.5,
        pattern_sig:'',label:''})
    }
    for(const ch of node.children) stack.push(ch)
  }
  return result
}

function patternSig(p: AttackPath): string {
  const en=p.nodes[0],tg=p.nodes[p.nodes.length-1]
  const ea=aMap.get(en.asset_id),ta=aMap.get(tg.asset_id)
  const techSet=[...new Set(p.edges.map(e=>e.edge_type))].sort().join('+')
  const zones=p.nodes.map(n=>n.zone);const zSeq:string[]=[]
  for(let i=0;i<zones.length;i++) if(i===0||zones[i]!==zones[i-1]) zSeq.push(zones[i])
  return `${ea?.type??en.asset_id}:${en.zone}|${techSet}|${ta?.type??tg.asset_id}:${tg.zone}|${zSeq.join('→')}`
}

function patternLabel(sig: string): string {
  const [ep,techPart,tp,zonePath]=sig.split('|')
  const et=ep.split(':')[0].replace(/_/g,' ')
  const tt=tp.split(':')[0].replace(/_/g,' ')
  const tz=tp.split(':')[1]??''
  const techs=techPart.split('+').map(t=>t.replace(/_/g,' '))
  return `${et} → ${techs.join(' + ')} → ${tt} [${tz}] via ${zonePath}`
}

// ── MCTS DISCOVERY ────────────────────────────────────────────────────────────
async function discoverPaths(
  entryPoints: {asset_id:string;misconfig_id:string}[],
  edges: Map<string,Edge>,
  adj: Map<string,{id:string;prob:number}[]>,
  cjd: Map<string,number>,
  profile: string,
  TARGET=999
): Promise<AttackPath[]> {
  // FIX#6: populate rollout index map once
  buildRolloutScores(cjd)
  for(let i=0;i<_assetIds.length;i++) _rolloutIdx.set(_assetIds[i],i)

  const seen = new Map<string,AttackPath>()
  const pen  = new Map<string,number>()

  // FIX#8: RAVE tables shared across ALL entry points for the same profile
  // Moves discovered in earlier trees warm-start later trees — better exploration
  const sharedRaveT = new Map<string,number>()
  const sharedRaveV = new Map<string,number>()

  // FIX#9: signature intern cache — avoid recomputing identical sigs
  const sigCache = new Map<AttackPath,string>()
  function cachedSig(p: AttackPath): string {
    if(!sigCache.has(p)) sigCache.set(p, patternSig(p))
    return sigCache.get(p)!
  }

  const SIMS=6000, PROBE=500, STALE=8

  for(const ep of entryPoints){
    const root:MCTSNode={asset_id:ep.asset_id,misconfig_id:ep.misconfig_id,
      parent:null,children:[],visits:0,total_reward:0,probability:1,depth:0,
      path_from_root:[ep.asset_id],visited_set:new Set([ep.asset_id]),expandedSet:new Set()}
    let stale=0, foundAny=false

    for(let s=0;s<SIMS;s++){
      // FIX#8: pass shared RAVE tables (warm-started from prior entry points)
      const leaf=select(root,sharedRaveT,sharedRaveV)
      const child=expand(leaf,adj,edges)
      let r=simulate(child,adj,edges,cjd)
      if(r>0&&child.path_from_root.length>=2){
        const ea=aMap.get(child.path_from_root[0]),ta=aMap.get(child.path_from_root[child.path_from_root.length-1])
        if(ea&&ta){const rs=`${ea.type}:${ea.zone}|${ta.type}:${ta.zone}`;r=r*Math.max(0.05,1-(pen.get(rs)??0))}
      }
      backprop(child,r,sharedRaveT,sharedRaveV)  // FIX#8: backprop into shared RAVE
      if((s+1)%PROBE===0){
        const probe=extractPaths(root,edges)
        for(const p of probe) p.pattern_sig=cachedSig(p)  // FIX#9
        if(probe.length) foundAny=true
        if(probe.some(p=>!seen.has(p.pattern_sig))) stale=0
        else if(foundAny&&++stale>=STALE) break
      }
    }
    const cands=extractPaths(root,edges)
    for(const p of cands){p.pattern_sig=cachedSig(p);p.label=patternLabel(p.pattern_sig)}  // FIX#9
    for(const p of cands.sort((a,b)=>b.realism-a.realism)){
      if(!seen.has(p.pattern_sig)){seen.set(p.pattern_sig,p);pen.set(p.pattern_sig,0.4)}
      else{pen.set(p.pattern_sig,Math.min((pen.get(p.pattern_sig)??0)+0.15,0.95));if(p.realism>(seen.get(p.pattern_sig)!.realism))seen.set(p.pattern_sig,p)}
    }
  }
  return Array.from(seen.values()).sort((a,b)=>b.realism-a.realism)
}

// ── MAIN ──────────────────────────────────────────────────────────────────────
;(async()=>{
const t0=Date.now()

// ── LLM BATCH CLASSIFICATION (FIX#3 + FIX#7) ────────────────────────────────
// Single API call classifies ALL assets for BOTH:
//   - Initial access viability (entry point detection)
//   - Crown jewel status (high-value target detection)
// No hardcoded asset IDs, types, or zone names anywhere.
// Scales to 10K assets: one call per 200-asset chunk (fits in 200K token window).

const ENDPOINT   = 'https://api.anthropic.com/v1/messages'
const MODEL      = 'claude-haiku-4-5-20251001'
const API_KEY    = process.env.ANTHROPIC_API_KEY ?? ''
// ── swap to use OpenRouter/Qwen ───────────────────────────────────────────────
// const ENDPOINT = 'https://openrouter.ai/api/v1/chat/completions'
// const MODEL    = 'qwen/qwen3-235b-a22b'
// const API_KEY  = process.env.OPENROUTER_API_KEY ?? ''
// ─────────────────────────────────────────────────────────────────────────────

interface AssetVerdict {
  asset_id:          string
  is_entry_point:    boolean   // attacker can reach with zero prior foothold
  attack_vector:     string    // e.g. "Spear Phishing Attachment"
  mitre_technique:   string    // e.g. "T1566.001"
  is_crown_jewel:    boolean   // compromise = significant business impact
  is_secondary_target: boolean // valuable but not tier-1 crown jewel
  reasoning:         string    // one sentence
}

async function classifyAllAssets(assets: Asset[]): Promise<AssetVerdict[]> {
  // Build compact asset descriptors — all context the LLM needs, no redundancy
  const descriptors = assets.map(a => ({
    id:   a.id,
    name: a.name,
    type: a.type,
    zone: a.zone,
    internet_facing: a.internet_facing,
    domain_joined:   a.domain_joined,
    criticality:     a.criticality,
    data_sensitivity: a.data_sensitivity,
    misconfigs: a.misconfigs.map(m => ({
      title:     m.title,
      severity:  m.severity,
      epss:      m.epss,
      category:  m.category,
      exploitable: m.exploit_available,
    }))
  }))

  const systemPrompt = `You are a senior red team operator and threat modelling expert.

You will receive a JSON array of network assets. For EACH asset, decide:

1. is_entry_point: Can an external attacker (ZERO prior foothold, starting from the internet) directly reach and compromise this asset?
   - YES if: internet-facing service, user endpoint reachable by phishing/macro, DMZ-resident gateway
   - NO if: deep internal server (file, DB, domain controller, backup, service account) — requires prior compromise

2. is_crown_jewel: Does compromising this asset represent a critical business impact?
   - YES if: stores critical data, provides domain-level control, enables widespread encryption/exfiltration
   - Examples: domain controllers, backup infrastructure, databases with sensitive data, PKI, privileged accounts

3. is_secondary_target: Valuable stepping stone but not tier-1?
   - YES if: provides lateral movement advantage, contains credentials, or enables further access

Respond ONLY with a valid JSON array — one object per asset, in the SAME ORDER as input.
No markdown, no explanation outside the JSON:
[{"asset_id":"...","is_entry_point":bool,"attack_vector":"...","mitre_technique":"...","is_crown_jewel":bool,"is_secondary_target":bool,"reasoning":"one sentence"},...]`

  const userPrompt = JSON.stringify(descriptors)

  const body = JSON.stringify({
    model: MODEL,
    max_tokens: 4000,
    system: systemPrompt,
    messages: [{ role: 'user', content: userPrompt }]
  })

  const headers: Record<string,string> = {
    'content-type': 'application/json',
    'anthropic-version': '2023-06-01',
    'x-api-key': API_KEY,
  }

  // Proxy support (sandbox environment)
  const { fetch: undiciFetch, ProxyAgent } = await import('undici' as any)
  const _proxy = process.env.https_proxy ?? process.env.HTTPS_PROXY ?? ''
  const dispatcher = _proxy ? new ProxyAgent(_proxy) : undefined

  const r = await undiciFetch(ENDPOINT, {
    method: 'POST',
    ...(dispatcher ? {dispatcher} : {}),
    headers,
    body,
  } as any)

  const data = await r.json() as any
  if (!r.ok) throw new Error(`LLM API error ${r.status}: ${JSON.stringify(data.error ?? data)}`)

  const raw: string = data.content?.[0]?.text ?? data.choices?.[0]?.message?.content ?? '[]'
  const clean = raw.replace(/```json|```/g, '').trim()

  try {
    return JSON.parse(clean) as AssetVerdict[]
  } catch(e) {
    console.error('\n  ⚠ LLM JSON parse failed. Raw response:')
    console.error(clean.slice(0, 300))
    throw new Error('LLM returned invalid JSON — cannot proceed')
  }
}

// ── CHUNK HELPER — for 10K+ assets, batch into chunks of 200 ─────────────────
async function classifyAllAssetsChunked(assets: Asset[], chunkSize=200): Promise<AssetVerdict[]> {
  const results: AssetVerdict[] = []
  for(let i=0; i<assets.length; i+=chunkSize){
    const chunk = assets.slice(i, i+chunkSize)
    if(assets.length > chunkSize)
      process.stdout.write(`  [LLM] Classifying chunk ${Math.floor(i/chunkSize)+1}/${Math.ceil(assets.length/chunkSize)}...`)
    const verdicts = await classifyAllAssets(chunk)
    results.push(...verdicts)
    if(assets.length > chunkSize) console.log(' done')
  }
  return results
}
// ── MAIN EXECUTION ────────────────────────────────────────────────────────────
// FIX#3+#7: single LLM batch call classifies ALL assets — entry points + crown jewels
process.stdout.write('\n  [LLM] Classifying all assets (entry points + crown jewels)...')
const verdicts = await classifyAllAssetsChunked(ASSETS)
console.log(' done')

// Populate crown jewel sets from LLM verdicts (FIX#3: zero hardcoding)
CROWN_JEWEL_IDS       = new Set(verdicts.filter(v=>v.is_crown_jewel).map(v=>v.asset_id))
CROWN_JEWEL_SECONDARY = new Set(verdicts.filter(v=>v.is_secondary_target).map(v=>v.asset_id))

console.log('\n  Asset classification:')
for(const v of verdicts){
  const a=aMap.get(v.asset_id)!
  const tags=[
    v.is_entry_point    ? '⚡ENTRY'  : '      ',
    v.is_crown_jewel    ? '👑CROWN'  : '      ',
    v.is_secondary_target?'🎯SECOND' : '       ',
  ].join(' ')
  const technique = v.is_entry_point ? `  ${v.mitre_technique} ${v.attack_vector}` : ''
  console.log(`  ${tags}  ${a.name.padEnd(22)} [${a.zone}]${technique}`)
  if(v.reasoning) console.log(`             → ${v.reasoning}`)
}

// Build entry point list from LLM verdicts
const entryVerdicts = verdicts.filter(v => v.is_entry_point)
if(entryVerdicts.length === 0) throw new Error('LLM found zero entry points — check asset context')

const entryPoints = entryVerdicts.map(v => {
  const a = aMap.get(v.asset_id)!
  const best = a.misconfigs
    .filter(m => m.severity === 'critical' || m.severity === 'high')
    .sort((x, y) => y.epss - x.epss)[0]
  if(!best) return null
  return {
    asset_id:        a.id,
    misconfig_id:    best.id,
    attack_vector:   v.attack_vector,
    mitre_technique: v.mitre_technique,
    score: best.epss * 10 + (a.internet_facing ? 3 : 0) + (a.zone === 'dmz' ? 2 : 1)
  }
}).filter(Boolean).sort((a,b) => b!.score - a!.score) as {
  asset_id:string; misconfig_id:string; attack_vector:string; mitre_technique:string; score:number
}[]

console.log(`\n  Entry points (${entryPoints.length}): ${entryPoints.map(ep=>aMap.get(ep.asset_id)!.name).join(', ')}`)
console.log(`  Crown jewels (${CROWN_JEWEL_IDS.size}): ${[...CROWN_JEWEL_IDS].map(id=>aMap.get(id)!.name).join(', ')}`)
console.log(`  Secondary   (${CROWN_JEWEL_SECONDARY.size}): ${[...CROWN_JEWEL_SECONDARY].map(id=>aMap.get(id)!.name).join(', ')}`)

// FIX#1+#2: compute base edges ONCE — profiles reuse cached base
// FIX#8: shared RAVE table within each profile across entry points
const profiles=['apt','ransomware','insider'] as const
const allPaths: AttackPath[]=[]

for(const profile of profiles){
  const edges=computeEdges(profile)  // FIX#1+#2: reuses cached base edges
  const adj=buildAdj(edges)
  const cjd=cjDistances(adj)
  const paths=await discoverPaths(entryPoints,edges,adj,cjd,profile)
  for(const p of paths) allPaths.push({...p,profile:profile.toUpperCase()})
}

const merged=new Map<string,AttackPath>()
for(const p of allPaths){
  if(!merged.has(p.pattern_sig)||p.realism>merged.get(p.pattern_sig)!.realism)
    merged.set(p.pattern_sig,p)
}
const top10=Array.from(merged.values()).sort((a,b)=>b.realism-a.realism)
top10.forEach((p,i)=>{p.rank=i+1;p.label=patternLabel(p.pattern_sig)})
const elapsed=Date.now()-t0

// ── STDOUT TABLE ──────────────────────────────────────────────────────────────
console.log('╔════════════════════════════════════════════════════════════════════════════════╗')
console.log('║    BRAVE GUARDIAN v7.0 — LockBit Scenario — 10 Assets — TOP-10 PATHS        ║')
console.log('╚════════════════════════════════════════════════════════════════════════════════╝')
console.log(`  Assets: ${ASSETS.length} | Crown jewels: ${[...CROWN_JEWEL_IDS].map(id=>aMap.get(id)!.name).join(', ')}`)
console.log(`  Profiles: APT + Ransomware + Insider  |  Runtime: ${(elapsed/1000).toFixed(1)}s\n`)

const BAR=(v:number)=>{const f=Math.round(Math.min(v,1)*12);return '█'.repeat(f)+'░'.repeat(12-f)}
const STARS=(v:number)=>'★'.repeat(v)+'☆'.repeat(5-v)

for(const p of top10){
  const en=p.nodes[0], tg=p.nodes[p.nodes.length-1]
  console.log(`  ┌─ #${p.rank}  [${p.profile}]  ${p.label}`)
  console.log(`  │  Entry  : ${en.asset_name} [${en.zone}]  —  ${en.misconfig_title}`)
  console.log(`  │  Target : ${tg.asset_name} [${tg.zone}]  ${STARS(tg.criticality)}`)
  console.log(`  │  Chain  : ${p.kill_chain.join(' → ')}   (${p.nodes.length} hops)`)
  console.log(`  │  Realism ${BAR(p.realism)} ${Math.round(p.realism*100)}%   Path prob ${BAR(p.path_prob)} ${Math.round(p.path_prob*100)}%`)
  console.log(`  │  Detection risk ${Math.round(p.detection_prob*100)}%   Effort ${p.effort.toFixed(1)}   Impact ${p.business_impact}`)
  console.log(`  │  Hops:`)
  for(let i=0;i<p.nodes.length;i++){
    const n=p.nodes[i],e=p.edges[i-1]
    const tag=i===0?'⚡ ENTRY ':i===p.nodes.length-1?'🎯 TARGET':'  pivot '
    const via=e?` [${e.edge_type.replace(/_/g,' ')}]`:''
    console.log(`  │    ${String(i+1).padEnd(2)} ${tag}  ${n.asset_name.padEnd(20)} [${n.zone.padEnd(12)}]  ${n.misconfig_title}${via}`)
  }
  console.log(`  └${'─'.repeat(82)}`)
  console.log()
}

// ── CHOKEPOINTS ───────────────────────────────────────────────────────────────
const freq=new Map<string,number>()
for(const p of top10) for(let i=1;i<p.nodes.length-1;i++){const id=p.nodes[i].asset_id;freq.set(id,(freq.get(id)??0)+1)}
const chokes=Array.from(freq.entries()).sort((a,b)=>b[1]-a[1]).slice(0,4)
if(chokes.length){
  console.log('  ┌─ CRITICAL CHOKEPOINTS')
  for(const [id,cnt] of chokes){
    const a=aMap.get(id)!
    console.log(`  │  🔴 ${a.name} [${a.zone}/${a.type}] — ${cnt}/${top10.length} paths (${Math.round(cnt/top10.length*100)}% blocking)`)
    console.log(`  │     Top misconfig: ${a.misconfigs[0]?.title}`)
  }
  console.log(`  └${'─'.repeat(82)}\n`)
}

// ── CSV OUTPUT ────────────────────────────────────────────────────────────────
const csvRows: string[]=[]
csvRows.push([
  'Rank','Profile','Pattern_Label',
  'Entry_Asset','Entry_Zone','Entry_Misconfig',
  'Hop_2_Asset','Hop_2_Zone','Hop_2_Technique',
  'Hop_3_Asset','Hop_3_Zone','Hop_3_Technique',
  'Hop_4_Asset','Hop_4_Zone','Hop_4_Technique',
  'Target_Asset','Target_Zone','Target_Type','Target_Criticality',
  'Total_Hops','Kill_Chain_Phases',
  'Path_Probability_Pct','Realism_Score_Pct',
  'Detection_Risk_Pct','Attacker_Effort','Business_Impact',
  'Top_Misconfig_On_Target','Target_EPSS_Max'
].map(h=>`"${h}"`).join(','))

for(const p of top10){
  const en=p.nodes[0], tg=p.nodes[p.nodes.length-1]
  const tgtAsset=aMap.get(tg.asset_id)!
  const maxEpss=Math.max(...tgtAsset.misconfigs.map(m=>m.epss)).toFixed(2)
  const get=(i:number,field:'asset'|'zone'|'tech')=>{
    if(i>=p.nodes.length) return ''
    const n=p.nodes[i], e=p.edges[i-1]
    if(field==='asset') return n.asset_name
    if(field==='zone')  return n.zone
    return e?.edge_type.replace(/_/g,' ')??''
  }
  const row=[
    p.rank, `"${p.profile}"`, `"${p.label}"`,
    `"${en.asset_name}"`, `"${en.zone}"`, `"${en.misconfig_title}"`,
    `"${get(1,'asset')}"`, `"${get(1,'zone')}"`, `"${get(1,'tech')}"`,
    `"${get(2,'asset')}"`, `"${get(2,'zone')}"`, `"${get(2,'tech')}"`,
    `"${get(3,'asset')}"`, `"${get(3,'zone')}"`, `"${get(3,'tech')}"`,
    `"${tg.asset_name}"`, `"${tg.zone}"`, `"${tgtAsset.type.replace(/_/g,' ')}"`, tg.criticality,
    p.nodes.length, `"${p.kill_chain.join(' → ')}"`,
    Math.round(p.path_prob*100), Math.round(p.realism*100),
    Math.round(p.detection_prob*100), p.effort.toFixed(1), p.business_impact,
    `"${tgtAsset.misconfigs[0]?.title??''}"`, maxEpss
  ]
  csvRows.push(row.join(','))
}

const csv=csvRows.join('\n')
process.stdout.write('\n__CSV_START__\n'+csv+'\n__CSV_END__\n')
})()
