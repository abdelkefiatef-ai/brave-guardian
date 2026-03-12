// ============================================================================
// ENHANCED ATTACK GRAPH ENGINE  v4.0
// Bayesian-GNN-MCTS Hybrid — Optimized
// ============================================================================
// Optimizations applied:
//   • GNN similarity cache      — O(1) lookups vs O(d) dot-product per call
//   • MCTS neighbour score cache — eliminates repeated score computation
//   • Entry points capped at 10 — prevents MCTS explosion on large graphs
//   • MCTS depth: 4–7 nodes    — no triple compounding penalty
//   • Batch Qwen3 narratives    — single LLM call for all paths
// ============================================================================

import { EventEmitter } from 'events'

// ─── OPENROUTER / QWEN3 ──────────────────────────────────────────────────────

async function callQwen(prompt: string, maxTokens = 300): Promise<string> {
  const key = process.env.OPENROUTER_API_KEY
  if (!key) throw new Error('OPENROUTER_API_KEY env var not set')
  const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${key}`,
      'Content-Type': 'application/json',
      'HTTP-Referer': 'https://brave-guardian.vercel.app',
      'X-Title': 'Brave Guardian',
    },
    body: JSON.stringify({
      model: 'qwen/qwen3-235b-a22b',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: maxTokens,
      temperature: 0.1,
      thinking: { type: 'disabled' },
    }),
  })
  if (!res.ok) throw new Error(`OpenRouter ${res.status}: ${await res.text()}`)
  const data = await res.json()
  const content = data.choices?.[0]?.message?.content
  if (!content) throw new Error('Qwen3 returned empty response')
  return content
}

// ─── TYPES ───────────────────────────────────────────────────────────────────

export interface Misconfiguration {
  id: string
  title: string
  description: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  cvss?: number
  epss?: number
  exploit_available?: boolean
}

export interface EvidenceSource {
  confidence: number
  last_updated: number
  data: Record<string, unknown>
}

export interface EvidenceBundle {
  vulnerability_scanner: EvidenceSource
  siem_alerts: EvidenceSource
  threat_intelligence: EvidenceSource
  historical_attacks: EvidenceSource
  network_flow: EvidenceSource
}

export interface EnhancedAsset {
  id: string
  name: string
  type: string
  ip: string
  zone: string
  criticality: number
  internet_facing: boolean
  domain_joined?: boolean
  services?: string[]
  data_sensitivity?: string
  misconfigurations: Misconfiguration[]
  embedding?: number[]
  evidence?: EvidenceBundle
}

export interface BayesianEdge {
  source_id: string
  target_id: string
  prior_probability: number
  posterior_probability: number
  evidence_sources: string[]
  confidence_interval: [number, number]
  technique: string
  edge_type: 'exploit' | 'lateral' | 'privilege_escalation' | 'credential_theft' | 'data_exfiltration'
}

export interface MCTSNode {
  id: string
  asset_id: string
  misconfig_id: string
  parent: MCTSNode | null
  children: MCTSNode[]
  visits: number
  total_reward: number
  ucb_score: number
  probability: number
  depth: number
  path_from_root: string[]
  // G: Set for O(1) cycle detection in expand() — replaces O(depth) includes()
  visited_set: Set<string>
  // P2: Set of already-expanded neighbor asset IDs — O(1) duplicate check
  expandedSet: Set<string>
}

export interface PathNode {
  asset_id: string
  asset_name: string
  misconfig_id: string
  misconfig_title: string
  criticality: number
  zone: string
  cumulative_probability: number
}

export interface RealisticAttackPath {
  path_id: string
  nodes: PathNode[]
  edges: BayesianEdge[]
  path_probability: number
  confidence_interval: [number, number]
  attacker_effort: number
  detection_probability: number
  business_impact: number
  realism_score: number
  kill_chain_phases: string[]
  required_capabilities: string[]
  timeline_estimate: string
  // Pattern diversity
  pattern_signature: string  // structural fingerprint for dedup
  pattern_label: string      // human-readable attack pattern name
  pattern_rank: number       // 1 = highest-scoring unique pattern
}

export interface MCTSTelemetry {
  simulations_executed:   number   // total sim steps run across all entry points
  entry_points_processed: number   // how many entry points were actually explored
  early_stops:            number   // trees cut short by stale-probe limit
  patterns_found:         number   // distinct structural patterns discovered
  stop_reason: 'target_reached' | 'budget_exhausted' | 'stale_all_entries'
}

export interface EntryPoint {
  node_id: string
  asset_name: string
  misconfig_title: string
  probability: number
  confidence: number
  attacker_value: string
  gnn_attention_weight: number
}

export interface CriticalAsset {
  asset_id: string
  asset_name: string
  reason: string
  paths_to_it: number
  cumulative_risk: number
  gnn_importance_score: number
}

export interface RiskMetrics {
  overall_risk_score: number
  risk_distribution: Record<string, number>
  top_attack_vectors: string[]
  recommended_mitigations: string[]
}

export interface EnhancedAnalysisResult {
  graph_stats: {
    total_nodes: number
    total_edges: number
    embedding_dimensions: number
    avg_branching_factor: number
  }
  bayesian_stats: {
    total_evidence_sources: number
    avg_edge_confidence: number
    high_confidence_edges: number
    low_confidence_edges: number
  }
  mcts_stats: {
    total_simulations: number
    exploration_constant: number
    best_path_reward: number
    avg_path_depth: number
  }
  attack_paths: RealisticAttackPath[]
  entry_points: EntryPoint[]
  critical_assets: CriticalAsset[]
  risk_metrics: RiskMetrics
  chokepoints: { asset_id: string; asset_name: string; asset_type: string; zone: string; paths_through: number; blocking_impact: number }[]  // S6
  timing: {
    gnn_embedding: number
    bayesian_inference: number
    mcts_discovery: number
    total: number
  }
}

// ─── ZONE REACHABILITY ───────────────────────────────────────────────────────
// Defines which zones can reach which — used in edge generation and scoring

const ZONE_REACH: Record<string, string[]> = {
  'dmz':        ['dmz', 'prod-web', 'corp'],
  'internet':   ['dmz'],
  'prod-web':   ['prod-web', 'prod-app', 'dmz'],
  'prod-app':   ['prod-app', 'prod-db', 'prod-web', 'corp', 'restricted'],
  'prod-db':    ['prod-db', 'prod-app', 'restricted'],
  'dev-web':    ['dev-web', 'dev-app', 'corp', 'staging'],
  'dev-app':    ['dev-app', 'dev-db', 'dev-web', 'corp'],
  'dev-db':     ['dev-db', 'dev-app'],
  'staging':    ['staging', 'prod-web', 'dev-web', 'dev-app'],
  'corp':       ['corp', 'corp-wifi', 'prod-web', 'prod-app', 'dev-web', 'dev-app', 'mgmt', 'dmz'],
  'corp-wifi':  ['corp-wifi', 'corp'],
  'restricted': ['restricted', 'prod-db', 'prod-app', 'pci', 'hipaa', 'mgmt', 'security'],
  'pci':        ['pci', 'restricted'],
  'hipaa':      ['hipaa', 'restricted'],
  'mgmt':       ['mgmt', 'security', 'corp', 'restricted'],
  'security':   ['security', 'mgmt', 'restricted'],
  'cloud-prod': ['cloud-prod', 'prod-web', 'prod-app', 'cloud-dev'],
  'cloud-dev':  ['cloud-dev', 'dev-web', 'dev-app', 'cloud-prod'],
  'dr':         ['dr', 'restricted', 'prod-db'],
  'internal':   ['internal', 'restricted', 'dmz', 'prod-web', 'prod-app', 'prod-db', 'corp'],
}

function zoneCanReach(source: string, target: string): boolean {
  return ZONE_REACH[source]?.includes(target) ?? source === target
}

// ─── LAYER 1: GNN EMBEDDING ENGINE ───────────────────────────────────────────

class GNNEmbeddingEngine {
  private readonly DIM = 128
  private readonly HEADS = 4
  // F: Float32Array halves memory vs number[] (64-bit) and is CPU-cache-friendly
  // for dot-product loops. cosine similarity inner loop is the hot path.
  private nodeEmbeddings = new Map<string, Float32Array>()
  private similarityCache = new Map<string, number>()

  async computeEmbeddings(assets: EnhancedAsset[], edges: { source: string; target: string }[]): Promise<void> {
    // Initialise embeddings
    for (const asset of assets) {
      this.nodeEmbeddings.set(asset.id, this.initEmbedding(this.extractFeatures(asset)))
    }
    // Two-layer attention propagation
    const neighborMap = this.buildNeighborMap(edges)
    for (let layer = 0; layer < 2; layer++) {
      this.propagateAttention(assets, neighborMap)
    }
  }

  private buildNeighborMap(edges: { source: string; target: string }[]) {
    const m = new Map<string, string[]>()
    for (const e of edges) {
      if (!m.has(e.source)) m.set(e.source, [])
      if (!m.has(e.target)) m.set(e.target, [])
      m.get(e.source)!.push(e.target)
      m.get(e.target)!.push(e.source)
    }
    return m
  }

  private extractFeatures(asset: EnhancedAsset): Float32Array {
    const TYPES = ['domain_controller', 'file_server', 'web_server', 'database_server',
                   'app_server', 'workstation', 'jump_server', 'email_server', 'backup_server', 'other']
    const SENSITIVITY: Record<string, number> = {
      credentials: 1.0, pii: 0.9, financial: 0.85, user_files: 0.6,
      business_logic: 0.7, user_data: 0.5
    }
    const sev = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const m of asset.misconfigurations) sev[m.severity]++

    // All 18 zones get their own one-hot dimension so the GNN learns
    // genuine zone-level structural separation — mgmt and corp are distinct
    // embedding regions, not collapsed into the same sparse encoding.
    const ALL_ZONES = [
      'dmz','prod-web','prod-app','prod-db','dev-web','dev-app','dev-db',
      'staging','corp','corp-wifi','restricted','pci','hipaa',
      'mgmt','security','cloud-prod','cloud-dev','dr',
    ]
    const f: number[] = [
      ...TYPES.map(t => asset.type === t ? 1 : 0),            // 10 dims: asset type
      asset.criticality / 5,                                   //  1 dim:  criticality
      ...ALL_ZONES.map(z => asset.zone === z ? 1 : 0),         // 18 dims: zone identity (one-hot)
      asset.internet_facing ? 1 : 0,                           //  1 dim:  internet exposure
      asset.domain_joined   ? 1 : 0,                           //  1 dim:  AD membership
      Math.min(sev.critical / 3, 1),                           //  4 dims: vuln severity distribution
      Math.min(sev.high     / 5, 1),
      Math.min(sev.medium   / 10, 1),
      Math.min(sev.low      / 15, 1),
      SENSITIVITY[asset.data_sensitivity ?? 'user_data'] ?? 0.5, // 1 dim: data sensitivity
    ]  // total: 36 meaningful dims; padded to DIM=128
    while (f.length < this.DIM) f.push(0)
    return new Float32Array(f.slice(0, this.DIM))
  }

  private initEmbedding(features: Float32Array): Float32Array {
    const scale = Math.sqrt(2 / features.length)
    const out = new Float32Array(features.length)
    for (let i = 0; i < features.length; i++) out[i] = features[i] * scale * (Math.random() * 2 - 1)
    return out
  }

  private propagateAttention(assets: EnhancedAsset[], neighborMap: Map<string, string[]>): void {
    // Opt #1: double-buffer so each asset reads from the *previous* layer's
    // embeddings only — no dirty reads from partially-updated neighbours.
    // Cache is flushed once at the end of the layer, not N times mid-loop.
    const headDim  = this.DIM / this.HEADS
    const snapshot = new Map<string, Float32Array>()
    for (const asset of assets) {
      snapshot.set(asset.id, new Float32Array(this.nodeEmbeddings.get(asset.id)!))
    }

    for (const asset of assets) {
      const emb       = this.nodeEmbeddings.get(asset.id)!   // write target
      const neighbors = neighborMap.get(asset.id) ?? []
      if (neighbors.length === 0) continue
      // V: softmax attention over all neighbours — replaces per-neighbour sigmoid.
      // Sigmoid independently upweights every neighbour; softmax normalises across
      // them so the model concentrates weight on the most structurally similar
      // neighbour rather than diffusely averaging all of them.
      for (let h = 0; h < this.HEADS; h++) {
        const s = h * headDim
        // Pass 1: compute raw dot products and stable softmax (subtract max for numerical stability)
        const dots: number[] = []
        const validNeighbors: Float32Array[] = []
        for (const nid of neighbors) {
          const ne = snapshot.get(nid)
          if (!ne) continue
          let dot = 0
          for (let i = 0; i < headDim; i++) dot += emb[s + i] * ne[s + i]
          dots.push(dot)
          validNeighbors.push(ne)
        }
        if (dots.length === 0) continue
        const maxDot = Math.max(...dots)
        let expSum = 0
        const expDots = dots.map(d => { const e = Math.exp(d - maxDot); expSum += e; return e })
        // Pass 2: weighted sum using softmax weights
        const weighted = new Float32Array(headDim)
        for (let n = 0; n < validNeighbors.length; n++) {
          const w = expDots[n] / expSum
          const ne = validNeighbors[n]
          for (let i = 0; i < headDim; i++) weighted[i] += w * ne[s + i]
        }
        for (let i = 0; i < headDim; i++) {
          emb[s + i] = 0.7 * emb[s + i] + 0.3 * weighted[i]
        }
      }
      this.nodeEmbeddings.set(asset.id, emb)
    }
    // Single cache flush per layer instead of per-asset during the loop
    this.similarityCache.clear()
  }

  /** Cosine similarity — cached after first computation */
  computeSimilarity(id1: string, id2: string): number {
    const key = id1 < id2 ? `${id1}:${id2}` : `${id2}:${id1}`
    if (this.similarityCache.has(key)) return this.similarityCache.get(key)!
    const e1 = this.nodeEmbeddings.get(id1)
    const e2 = this.nodeEmbeddings.get(id2)
    if (!e1 || !e2) { this.similarityCache.set(key, 0); return 0 }
    // F: Float32Array — tight loop with no boxing
    let dot = 0, n1 = 0, n2 = 0
    for (let i = 0; i < e1.length; i++) { dot += e1[i] * e2[i]; n1 += e1[i] * e1[i]; n2 += e2[i] * e2[i] }
    const sim = dot / (Math.sqrt(n1) * Math.sqrt(n2) + 1e-8)
    this.similarityCache.set(key, sim)
    return sim
  }

  getEmbedding(id: string): Float32Array | undefined { return this.nodeEmbeddings.get(id) }
}

// ─── ZONE DISTANCE ───────────────────────────────────────────────────────────
// Pre-computed BFS distance matrix over all zone pairs.
// There are only ~18×18 = 324 possible pairs — computing on demand meant
// ~31,000 BFS traversals per analysis run (5 techniques × N² asset pairs).
// Now computed once at module load: O(1) lookup per call.
function buildZoneDistanceMatrix(): Map<string, number> {
  const m = new Map<string, number>()
  const zones = Object.keys(ZONE_REACH)
  for (const src of zones) {
    m.set(`${src}:${src}`, 0)
    const visited = new Set([src])
    const queue: [string, number][] = [[src, 0]]
    while (queue.length) {
      const [cur, d] = queue.shift()!
      for (const next of (ZONE_REACH[cur] ?? [])) {
        if (!visited.has(next)) {
          visited.add(next)
          m.set(`${src}:${next}`, d + 1)
          queue.push([next, d + 1])
        }
      }
    }
  }
  return m
}
const ZONE_DIST_MATRIX = buildZoneDistanceMatrix()

function zoneDistance(a: string, b: string): number {
  if (a === b) return 0
  return ZONE_DIST_MATRIX.get(`${a}:${b}`) ?? 99
}

// ─── ATTACKER TTP PROFILES ───────────────────────────────────────────────────
// S5: Three empirically-grounded threat actor profiles. Each re-weights the
// Bayesian base rates to reflect how that actor class actually operates in
// real-world intrusion data (MITRE ATT&CK, CrowdStrike, Mandiant reports).
// APT (nation-state): patient, credential-focused, lives off the land.
// Ransomware: fast lateral spread, prioritises exfiltration before encryption.
// Insider: already inside, abuses legitimate privileges, avoids noisy exploits.

export type TTPProfile = 'apt' | 'ransomware' | 'insider'

export const TTP_MULTIPLIERS: Record<TTPProfile, Partial<Record<string, number>>> = {
  apt: {
    credential_theft:     1.6,   // T1003, T1558 — primary initial access path
    lateral:              1.3,   // T1021 — slow methodical lateral movement
    privilege_escalation: 1.4,   // T1484 — targeted domain escalation
    exploit:              0.8,   // APT avoids noisy exploits when possible
    data_exfiltration:    1.2,
  },
  ransomware: {
    exploit:              1.6,   // initial access via unpatched services
    lateral:              1.5,   // fast horizontal spread (worm-like)
    data_exfiltration:    1.8,   // double-extortion — exfil before encrypt
    credential_theft:     1.2,
    privilege_escalation: 1.1,
  },
  insider: {
    privilege_escalation: 1.8,   // abuse of legitimate elevated access
    data_exfiltration:    1.6,   // primary objective
    lateral:              0.6,   // insiders usually don't need to pivot
    credential_theft:     0.7,   // already have creds
    exploit:              0.4,   // insiders avoid exploits (too detectable)
  },
}

// ─── LAYER 2: BAYESIAN PROBABILITY ENGINE — PACKED TYPED ARRAYS ──────────────
//
// Memory model (v8.0):
//   PackedEdgeStore  — all candidate edges in 5 parallel typed arrays
//   SparseAdj        — top-K neighbours per asset, rebuilt per profile in O(E)
//
// At 10K assets:
//   Old: Map<string, BayesianEdge>  → 35M objects × 200 bytes = 7 GB
//   New: 5 typed arrays + N×K adj  → 35M entries × 14 bytes  = 490 MB  (93% reduction)
//
// Profile switching cost:
//   Old: full O(N² × 5) rebuild per profile  (3× total = 3 full passes)
//   New: base store cached after first call, per-profile SparseAdj in O(E)
//
// Encoding:
//   src_idx, tgt_idx  → Uint16  (supports up to 65,535 assets)
//   prior_nottp       → Float32 (prior without TTP multiplier)
//   likelihood        → Float32 (vulnerability evidence score)
//   type_id           → Uint8   (0-4 for 5 techniques)

const _TECH_TYPES: BayesianEdge['edge_type'][] = [
  'exploit', 'lateral', 'credential_theft', 'privilege_escalation', 'data_exfiltration'
]
const _TECH_NAMES = [
  'Initial Access', 'Lateral Movement', 'Credential Theft', 'Privilege Escalation', 'Data Exfiltration'
]

interface PackedEdgeStore {
  src:        Uint16Array   // source asset index
  tgt:        Uint16Array   // target asset index
  prior:      Float32Array  // base prior without TTP multiplier
  likelihood: Float32Array  // vulnerability evidence score
  type_id:    Uint8Array    // index into _TECH_TYPES (0-4)
  count:      number
}

// top-K neighbours per asset, profile-specific posteriors
// Layout: asset_i × K_ADJ + k → neighbour slot
// ── Adaptive posterior threshold ──────────────────────────────────────────────
// A single global cutoff over-prunes legitimate paths through high-value or
// privileged-zone targets: a crit-5 DC in the restricted zone with moderate
// evidence is far more interesting than a crit-1 workstation with strong evidence.
//
// Floor is derived from three signals, applied additively:
//   base              = 0.50  (same as the former flat cutoff)
//   target criticality: crit 5 → −0.15 | crit 4 → −0.10 | crit 3 → −0.05
//   sensitive zone    : restricted/mgmt/security/pci/hipaa/dr → −0.08
//   zone distance     : dist ≥ 2 → +0.05  (long-range edges need stronger evidence)
//   clamped to [0.25, 0.55]
//
// Net effect:
//   Low-crit peripheral asset, dist≥2  → floor ≈ 0.55  (strict)
//   Average asset, same zone           → floor ≈ 0.50  (unchanged)
//   Crit-5 target in restricted zone   → floor ≈ 0.27  (permissive)
//
// Memory impact: borderline high-value edges that were pruned at 0.50 now survive
// (~3–8% more entries at N=100–1K), which is negligible against the typed-array
// budget but materially improves path coverage for crown-jewel corridors.

const _POST_THRESH_BASE = 0.50

const _SENSITIVE_ZONES = new Set([
  'restricted', 'mgmt', 'security', 'pci', 'hipaa', 'dr'
])

function adaptivePostThresh(tgt: EnhancedAsset, dist: number): number {
  let floor = _POST_THRESH_BASE
  if      (tgt.criticality === 5) floor -= 0.15
  else if (tgt.criticality === 4) floor -= 0.10
  else if (tgt.criticality === 3) floor -= 0.05
  if (_SENSITIVE_ZONES.has(tgt.zone)) floor -= 0.08
  if (dist >= 2) floor += 0.05
  return Math.max(0.25, Math.min(0.55, floor))
}

const _K_ADJ = 20

interface SparseAdj {
  tgt:  Uint16Array   // target asset index
  post: Float32Array  // posterior probability
  slot: Uint32Array   // index into PackedEdgeStore (for edge reconstruction)
  deg:  Uint8Array    // actual degree per asset (≤ K_ADJ)
}

class BayesianProbabilityEngine {
  ttpProfile: TTPProfile = 'apt'

  // ── Singleton packed store ─────────────────────────────────────────────────
  // Built once for the asset set, shared across all profile instances.
  // Keyed by asset-set fingerprint so cache invalidates on new asset sets.
  private static _store:       PackedEdgeStore | null = null
  private static _storeKey:    string = ''
  private static _assetIdx:    Map<string, number> = new Map()
  private static _assets:      EnhancedAsset[] = []

  private readonly evidenceWeights = {
    vulnerability_scanner: 0.30,
    siem_alerts:           0.25,
    threat_intelligence:   0.20,
    historical_attacks:    0.15,
    network_flow:          0.10,
  }

  // ── Build or retrieve the packed edge store ────────────────────────────────
  private buildPackedStore(assets: EnhancedAsset[], gnnSim: (a: string, b: string) => number): PackedEdgeStore {
    const key = assets.map(a => a.id).join(',')
    if (BayesianProbabilityEngine._store && BayesianProbabilityEngine._storeKey === key) {
      return BayesianProbabilityEngine._store
    }

    const assetIdx = new Map(assets.map((a, i) => [a.id, i]))
    const N = assets.length

    // Pre-group by zone for O(zone_pairs × assets_per_zone²) instead of O(N²)
    const byZone = new Map<string, EnhancedAsset[]>()
    for (const a of assets) {
      if (!byZone.has(a.zone)) byZone.set(a.zone, [])
      byZone.get(a.zone)!.push(a)
    }

    // Capacity estimate: zone-reachable pairs × techniques × survival fraction.
    // Adaptive threshold prunes ~75–85% of candidates at write time (L1 threshold).
    // Survival fraction ≈ 0.20 on average, 0.40 safety margin for high-crit-dense inventories.
    const _SURVIVAL = 0.40   // conservative upper bound on fraction surviving L1
    let capacity = 0
    for (const [srcZone, srcList] of byZone) {
      const reachable = ZONE_REACH[srcZone] ?? []
      for (const tgtZone of reachable) {
        const tgtList = byZone.get(tgtZone)
        if (tgtList) capacity += srcList.length * tgtList.length * 5
      }
      capacity += srcList.length * (srcList.length - 1) * 5  // intra-zone
    }
    capacity = Math.ceil(capacity * _SURVIVAL) + 1000  // +1000 guard against empty sets

    const store: PackedEdgeStore = {
      src:        new Uint16Array(capacity),
      tgt:        new Uint16Array(capacity),
      prior:      new Float32Array(capacity),
      likelihood: new Float32Array(capacity),
      type_id:    new Uint8Array(capacity),
      count:      0,
    }

    let i = 0
    const assetMap = new Map(assets.map(a => [a.id, a]))

    const processPair = (srcA: EnhancedAsset, tgtA: EnhancedAsset) => {
      if (srcA.id === tgtA.id) return
      const dist = zoneDistance(srcA.zone, tgtA.zone)
      const gnnSim_ = dist <= 1 ? gnnSim(srcA.id, tgtA.id) : 0

      for (let t = 0; t < 5; t++) {
        const type = _TECH_TYPES[t]
        const pNoTtp = this.computePriorNoTtp(type, srcA, tgtA, dist, gnnSim_)
        const lk     = this.computeLikelihoodScore(tgtA, type)

        // L1 adaptive threshold — per-edge floor from criticality, zone, distance.
        // Crit-5 / restricted zone → floor ≈ 0.27; average → 0.50; peripheral → 0.55.
        const base_post = Math.min(Math.max(0.3 * pNoTtp + 0.7 * lk, 0.05), 0.98)
        if (base_post < adaptivePostThresh(tgtA, dist)) continue

        store.src[i]        = assetIdx.get(srcA.id)!
        store.tgt[i]        = assetIdx.get(tgtA.id)!
        store.prior[i]      = pNoTtp
        store.likelihood[i] = lk
        store.type_id[i]    = t
        i++
      }
    }

    // Inter-zone pairs (reachable zone-pairs only)
    for (const [srcZone, srcList] of byZone) {
      const reachable = ZONE_REACH[srcZone] ?? []
      for (const tgtZone of reachable) {
        const tgtList = byZone.get(tgtZone)
        if (!tgtList) continue
        for (const srcA of srcList) {
          for (const tgtA of tgtList) processPair(srcA, tgtA)
        }
      }
      // Intra-zone
      for (let a = 0; a < srcList.length; a++) {
        for (let b = 0; b < srcList.length; b++) {
          if (a !== b) processPair(srcList[a], srcList[b])
        }
      }
    }

    store.count = i

    // Sanity check: log actual vs allocated capacity in dev
    if (typeof process !== 'undefined' && process.env.NODE_ENV !== 'production') {
      const allocated_mb = (capacity * 14 / 1e6).toFixed(1)
      const used_mb      = (i * 14 / 1e6).toFixed(1)
      console.debug(`[BayesianEngine] N=${assets.length} assets: ${i.toLocaleString()} edges stored / ${capacity.toLocaleString()} allocated (${used_mb} MB / ${allocated_mb} MB)`)
    }

    BayesianProbabilityEngine._store    = store
    BayesianProbabilityEngine._storeKey = key
    BayesianProbabilityEngine._assetIdx = assetIdx
    BayesianProbabilityEngine._assets   = assets

    return store
  }

  // ── Build top-K sparse adjacency for a specific TTP profile ───────────────
  // O(E) — applies TTP multiplier to cached priors, keeps top-K per asset.
  buildSparseAdj(assets: EnhancedAsset[], gnnSim: (a: string, b: string) => number): SparseAdj {
    const store    = this.buildPackedStore(assets, gnnSim)
    const N        = assets.length
    const ttpRow   = TTP_MULTIPLIERS[this.ttpProfile] ?? {}

    // Per-asset candidate list: best posterior per (src, tgt) pair across techniques
    type Cand = { post: number; slot: number; tgt: number }
    const buckets: Cand[][] = Array.from({ length: N }, () => [])

    for (let i = 0; i < store.count; i++) {
      const type  = _TECH_TYPES[store.type_id[i]]
      const ttp   = ttpRow[type] ?? 1.0
      const p     = Math.min(store.prior[i] * ttp, 0.95)
      const post  = Math.min(Math.max(0.3 * p + 0.7 * store.likelihood[i], 0.05), 0.98)
      // L2 adaptive threshold — uses target asset quality; dist=0 because topology
      // cost was already encoded in the prior stored at L1 write time.
      if (post < adaptivePostThresh(BayesianProbabilityEngine._assets[store.tgt[i]], 0)) continue

      const si = store.src[i], ti = store.tgt[i]
      const bucket = buckets[si]
      let found = false
      for (const c of bucket) {
        if (c.tgt === ti) { if (post > c.post) { c.post = post; c.slot = i }; found = true; break }
      }
      if (!found) bucket.push({ post, tgt: ti, slot: i })
    }

    const adj: SparseAdj = {
      tgt:  new Uint16Array(N * _K_ADJ),
      post: new Float32Array(N * _K_ADJ),
      slot: new Uint32Array(N * _K_ADJ),
      deg:  new Uint8Array(N),
    }

    for (let si = 0; si < N; si++) {
      const bucket = buckets[si].sort((a, b) => b.post - a.post)
      const deg    = Math.min(bucket.length, _K_ADJ)
      adj.deg[si]  = deg
      const base   = si * _K_ADJ
      for (let k = 0; k < deg; k++) {
        adj.tgt [base + k] = bucket[k].tgt
        adj.post[base + k] = bucket[k].post
        adj.slot[base + k] = bucket[k].slot
      }
    }
    return adj
  }

  // ── Reconstruct BayesianEdge from a packed slot (for path annotation) ─────
  // O(1) — no Map lookup, no iteration
  edgeFromSlot(slot: number, posterior_val: number): BayesianEdge {
    const store  = BayesianProbabilityEngine._store!
    const assets = BayesianProbabilityEngine._assets
    const t      = store.type_id[slot]
    return {
      source_id:            assets[store.src[slot]].id,
      target_id:            assets[store.tgt[slot]].id,
      prior_probability:    store.prior[slot],
      posterior_probability: posterior_val,
      evidence_sources:     ['vulnerability_scanner'],
      confidence_interval:  [Math.max(0, posterior_val - 0.10), Math.min(1, posterior_val + 0.10)],
      technique:            _TECH_NAMES[t],
      edge_type:            _TECH_TYPES[t],
    }
  }

  // ── Get adjacency as Map<string, string[]> for backward-compat with MCTS ──
  buildAdjacencyMap(assets: EnhancedAsset[], gnnSim: (a: string, b: string) => number): Map<string, string[]> {
    const sparse = this.buildSparseAdj(assets, gnnSim)
    const N      = assets.length
    const adj    = new Map<string, string[]>()
    for (let si = 0; si < N; si++) {
      const base = si * _K_ADJ
      const deg  = sparse.deg[si]
      if (deg === 0) continue
      const neighbours: string[] = []
      for (let k = 0; k < deg; k++) neighbours.push(assets[sparse.tgt[base + k]].id)
      adj.set(assets[si].id, neighbours)
    }
    return adj
  }

  // ── Get a specific edge (for MCTS path reconstruction) ────────────────────
  getEdgeFromAdj(sparse: SparseAdj, srcId: string, tgtId: string): BayesianEdge | undefined {
    const assetIdx = BayesianProbabilityEngine._assetIdx
    const assets   = BayesianProbabilityEngine._assets
    const si = assetIdx.get(srcId)
    const ti = assetIdx.get(tgtId)
    if (si === undefined || ti === undefined) return undefined
    const base = si * _K_ADJ
    const deg  = sparse.deg[si]
    for (let k = 0; k < deg; k++) {
      if (sparse.tgt[base + k] === ti) {
        return this.edgeFromSlot(sparse.slot[base + k], sparse.post[base + k])
      }
    }
    return undefined
  }

  // ── Backward-compat shims (used by MCTS for path edge lookup) ─────────────
  async computeProbabilities(
    assets: EnhancedAsset[],
    _potentialEdges: unknown,
    gnnSim: (a: string, b: string) => number = () => 0
  ): Promise<void> {
    // Build packed store eagerly so subsequent buildSparseAdj calls are O(E) not O(N²)
    this.buildPackedStore(assets, gnnSim)
  }

  getEdge(src: string, tgt: string): BayesianEdge | undefined {
    // Fallback for any legacy callers — reconstruct from sparse adj if available
    if (!BayesianProbabilityEngine._store) return undefined
    const assetIdx = BayesianProbabilityEngine._assetIdx
    const assets   = BayesianProbabilityEngine._assets
    const store    = BayesianProbabilityEngine._store
    const si = assetIdx.get(src), ti = assetIdx.get(tgt)
    if (si === undefined || ti === undefined) return undefined
    const ttpRow = TTP_MULTIPLIERS[this.ttpProfile] ?? {}
    let bestPost = 0, bestSlot = -1
    for (let i = 0; i < store.count; i++) {
      if (store.src[i] !== si || store.tgt[i] !== ti) continue
      const type = _TECH_TYPES[store.type_id[i]]
      const ttp  = ttpRow[type] ?? 1.0
      const p    = Math.min(store.prior[i] * ttp, 0.95)
      const post = Math.min(Math.max(0.3 * p + 0.7 * store.likelihood[i], 0.05), 0.98)
      if (post > bestPost) { bestPost = post; bestSlot = i }
    }
    return bestSlot >= 0 ? this.edgeFromSlot(bestSlot, bestPost) : undefined
  }

  getAllEdges(): BayesianEdge[] {
    // Only materialise if explicitly needed (e.g. stats reporting)
    const store    = BayesianProbabilityEngine._store
    const assets   = BayesianProbabilityEngine._assets
    const ttpRow   = TTP_MULTIPLIERS[this.ttpProfile] ?? {}
    if (!store) return []
    const best = new Map<number, { post: number; slot: number }>()
    for (let i = 0; i < store.count; i++) {
      const type = _TECH_TYPES[store.type_id[i]]
      const ttp  = ttpRow[type] ?? 1.0
      const p    = Math.min(store.prior[i] * ttp, 0.95)
      const post = Math.min(Math.max(0.3 * p + 0.7 * store.likelihood[i], 0.05), 0.98)
      if (post < adaptivePostThresh(BayesianProbabilityEngine._assets[store.tgt[i]], 0)) continue
      const key = store.src[i] * 65536 + store.tgt[i]
      const ex  = best.get(key)
      if (!ex || post > ex.post) best.set(key, { post, slot: i })
    }
    return Array.from(best.values()).map(({ post, slot }) => this.edgeFromSlot(slot, post))
  }

  // ── Prior computation (no TTP multiplier — applied per-profile in O(E)) ───
  private computePriorNoTtp(
    type: BayesianEdge['edge_type'],
    src: EnhancedAsset, tgt: EnhancedAsset,
    dist: number, gnnSim: number
  ): number {
    const base: Record<string, number> = {
      exploit: 0.30, lateral: 0.40, privilege_escalation: 0.25,
      credential_theft: 0.50, data_exfiltration: 0.15,
    }
    let p = base[type] ?? 0.3
    p *= Math.pow(0.60, dist)
    if (src.internet_facing) p *= 1.4
    p *= (1 + tgt.criticality * 0.08)
    if (dist <= 1) p *= (1 + Math.max(0, gnnSim) * 0.3)
    if (src.domain_joined && tgt.domain_joined) p *= 1.2
    const exploitable = tgt.misconfigurations.filter(m => m.exploit_available && m.severity === 'critical').length
    p *= (1 + exploitable * 0.15)
    const tt = tgt.type
    if (type === 'credential_theft') {
      if (tt === 'domain_controller' || tt === 'identity_server') p *= 1.5
      else if (tt === 'jump_server'  || tt === 'email_server')    p *= 1.25
    }
    if (type === 'privilege_escalation') {
      if (tt === 'domain_controller')                      p *= 1.4
      else if (tt === 'pki_server' || tt === 'ca_server') p *= 1.3
      else if (tt === 'identity_server')                   p *= 1.3
    }
    if (type === 'lateral') {
      if (tgt.zone === 'restricted' || tgt.zone === 'security' || tgt.zone === 'mgmt') p *= 1.3
    }
    if (type === 'exploit') {
      if (tt === 'web_server' || tt === 'app_server') p *= 1.2
    }
    if (type === 'data_exfiltration') {
      if (tt === 'database_server' || tt === 'backup_server' || tt === 'file_server') p *= 1.3
    }
    // NOTE: TTP multiplier intentionally omitted — applied per-profile in buildSparseAdj()
    return Math.min(p, 0.95)
  }

  // ── Likelihood from vulnerability evidence ─────────────────────────────────
  private computeLikelihoodScore(tgt: EnhancedAsset, type: BayesianEdge['edge_type']): number {
    const relV = tgt.misconfigurations.filter(m => {
      const ts = this.vulnTechniques(m.category)
      return ts.includes(type) || ts.includes('any')
    })
    if (relV.length === 0) return 0.3  // base likelihood when no specific evidence
    const crit = relV.filter(m => m.severity === 'critical' && m.exploit_available).length
    const high = relV.filter(m => m.severity === 'high').length
    let lk = Math.min(relV.length * 0.15 + crit * 0.25 + high * 0.1, 0.95)
    // SIEM and threat intel evidence
    const siem = tgt.evidence?.siem_alerts
    if (siem && siem.confidence > 0) lk = Math.min(lk + siem.confidence * 0.1, 0.95)
    const ti = tgt.evidence?.threat_intelligence
    if (ti && ti.confidence > 0) lk = Math.min(lk + ti.confidence * 0.05, 0.95)
    return lk
  }

  private vulnTechniques(category: string): string[] {
    const m: Record<string, string[]> = {
      network:        ['lateral', 'exploit', 'credential_theft'],
      authentication: ['credential_theft', 'privilege_escalation'],
      authorization:  ['privilege_escalation', 'data_exfiltration'],
      service:        ['exploit', 'lateral'],
      encryption:     ['data_exfiltration'],
      logging:        ['any'],
    }
    return m[category] ?? ['any']
  }
}

// ─── LAYER 3: MCTS PATH DISCOVERY ENGINE ─────────────────────────────────────

// ─── LAYER 3: MCTS PATH DISCOVERY ENGINE ─────────────────────────────────────

class MCTSPathDiscoveryEngine {
  private readonly C       = 1.414   // UCB exploration constant (√2)
  private readonly SIMS    = 2500    // reduced from 5000: ε-greedy rollout explores more efficiently
  private readonly MAX_D   = 7
  private readonly MIN_D   = 4

  private gnn:     GNNEmbeddingEngine
  private bayes:   BayesianProbabilityEngine
  private cjCache    = new Map<string, boolean>()   // Crown jewel cache
  private scoreCache = new Map<string, number>()    // Rollout neighbour scores
  // D: RAVE tables — global move statistics across all simulations in one tree.
  // raveTotal[move]  = sum of all rewards from simulations that included this move
  // raveVisits[move] = count of simulations that included this move
  // A "move" is an asset_id transition string "src→tgt".
  // RAVE makes early simulations much more informative: a good asset transition
  // seen once anywhere in the tree immediately raises the UCB score for that
  // transition at every node where it's available.
  private raveTotal  = new Map<string, number>()
  private raveVisits = new Map<string, number>()

  constructor(gnn: GNNEmbeddingEngine, bayes: BayesianProbabilityEngine) {
    this.gnn = gnn; this.bayes = bayes
  }

  getStats(): { best_reward: number } {
    return { best_reward: 0 }
  }

  // I: BFS from every asset to nearest crown jewel in the adjacency graph.
  // Returns Map<asset_id, hops> where 0 = is a crown jewel, 99 = unreachable.
  // Used in simulate() to give graduated partial rewards that steer rollouts
  // toward crown jewels even when they don't reach one in MAX_D steps.
  buildCrownJewelDistances(
    adj: Map<string, string[]>,
    targetAssets: Set<string>
  ): Map<string, number> {
    // Build reverse adjacency once — O(E) — then multi-source BFS is O(V+E).
    // The naive approach (scanning all adj for each BFS step) was O(V×E).
    const revAdj = new Map<string, string[]>()
    for (const [src, tgts] of adj) {
      for (const tgt of tgts) {
        if (!revAdj.has(tgt)) revAdj.set(tgt, [])
        revAdj.get(tgt)!.push(src)
      }
    }
    const dist = new Map<string, number>()
    const queue: string[] = []
    for (const id of targetAssets) { dist.set(id, 0); queue.push(id) }
    let head = 0
    while (head < queue.length) {
      const cur = queue[head++]
      const d   = dist.get(cur)!
      for (const src of (revAdj.get(cur) ?? [])) {
        if (!dist.has(src)) { dist.set(src, d + 1); queue.push(src) }
      }
    }
    return dist
  }

  async discoverPaths(
    entryPoints: { asset_id: string; misconfig_id: string }[],
    targetAssets: Set<string>,
    adj: Map<string, string[]>,
    assetMap: Map<string, EnhancedAsset>,
    cjDist: Map<string, number> = new Map(),
    skipCjEval = false   // S5: set true when CJ cache is pre-populated from main engine
  ): Promise<{ paths: RealisticAttackPath[]; telemetry: MCTSTelemetry }> {

    // ── Feature 2: Deterministic CJ guardrails ────────────────────────────────
    // Three-tier classification replaces the old "send all CJ_TYPES to LLM" approach.
    //
    // Tier-1 (deterministic CJ — no LLM call needed):
    //   Critical identity infrastructure that unconditionally provides full-environment
    //   control.  Sending these to the LLM adds latency and nondeterminism for zero
    //   semantic benefit — the answer is always "yes".
    //
    // Tier-2 (borderline — LLM evaluates contextually):
    //   High-criticality assets whose CJ status depends on context: data sensitivity,
    //   zone, role, and real-world attacker objectives.  LLM semantic evaluation adds
    //   genuine value here.
    //
    // Tier-3 (never CJ):
    //   Everything with criticality < 4 or a type not in Tier-1/Tier-2.
    if (!skipCjEval) {
      const CJ_DETERMINISTIC = new Set([
        'domain_controller', 'identity_server', 'pki_server', 'ca_server', 'key_management',
      ])
      const CJ_BORDERLINE = new Set([
        'backup_server', 'file_server', 'jump_server', 'bastion',
        'secrets_manager', 'hsm', 'privileged_access_workstation',
      ])
      console.log('[MCTS] Evaluating crown jewels (deterministic + LLM)…')
      const llmCandidates: EnhancedAsset[] = []
      let deterministicCount = 0
      for (const asset of assetMap.values()) {
        const key = `${asset.id}:${asset.type}:${asset.criticality}`
        if (this.cjCache.has(key)) continue   // already evaluated — idempotent
        if (asset.criticality >= 4 && CJ_DETERMINISTIC.has(asset.type)) {
          // Tier-1: mark immediately, no LLM call
          this.cjCache.set(key, true)
          deterministicCount++
          console.log(`[CROWN JEWEL] ${asset.name}: 👑 (deterministic — ${asset.type})`)
        } else if (asset.criticality >= 4 && CJ_BORDERLINE.has(asset.type)) {
          // Tier-2: LLM evaluates semantic context
          llmCandidates.push(asset)
        } else {
          // Tier-3: definitively not CJ
          this.cjCache.set(key, false)
        }
      }
      if (llmCandidates.length > 0) {
        await Promise.all(llmCandidates.map(a => this.isTerminalAssetLLM(a)))
      }
      const crowns = Array.from(this.cjCache.values()).filter(Boolean).length
      console.log(
        `[MCTS] ${crowns} crown jewels found ` +
        `(${deterministicCount} deterministic, ${crowns - deterministicCount} LLM-evaluated)`
      )
    }

    // ── Feature 4: LLM-blended entry-point ranking ────────────────────────────
    // Two-step ranking: fast heuristic pre-scores all candidates, then LLM
    // re-ranks the top-15 with semantic understanding of exploit likelihood,
    // attack vector, and MITRE technique frequency.
    //
    // LLM score is blended 40 % into the final rank — heuristic still anchors
    // ordering so a bad LLM parse degrades gracefully to the S4 score.
    //
    // Top-10 entry points are taken after blending.

    const heuristicScored = entryPoints.map(ep => {
      const a = assetMap.get(ep.asset_id)!
      const m = a.misconfigurations.find(x => x.id === ep.misconfig_id)
      const sevScore  = m?.severity === 'critical' ? 4 : m?.severity === 'high' ? 3 : 2
      const proxBonus = ((cjDist.get(ep.asset_id) ?? 99) <= 2) ? 5 : 0
      const epssBonus = (m?.epss ?? 0) * 3
      const hScore    = a.criticality * sevScore + (a.internet_facing ? 5 : 0) + proxBonus + epssBonus
      return { ep, a, m, hScore, llmScore: hScore }
    }).sort((a, b) => b.hScore - a.hScore).slice(0, 15)

    if (!skipCjEval && process.env.OPENROUTER_API_KEY) {
      try {
        const descriptors = heuristicScored.map(({ ep, a, m }) => ({
          asset_id:        ep.asset_id,
          name:            a.name,
          type:            a.type,
          zone:            a.zone,
          internet_facing: a.internet_facing,
          criticality:     a.criticality,
          misconfig:       m ? {
            title:             m.title,
            severity:          m.severity,
            epss:              m.epss ?? 0,
            exploit_available: m.exploit_available ?? false,
          } : null,
          data_sensitivity: a.data_sensitivity,
        }))
        const prompt =
          `You are a senior red team operator. Score each asset as an initial-access entry point.\n` +
          `Score 1–10 (10 = trivially exploitable from the internet; 1 = internal-only, very unlikely).\n` +
          `Consider: internet exposure, exploit availability, EPSS, asset type, MITRE ATT&CK frequency.\n\n` +
          `Assets:\n${JSON.stringify(descriptors)}\n\n` +
          `Reply JSON array in SAME ORDER as input:\n` +
          `[{"asset_id":"...","entry_score":8,"attack_vector":"...","mitre_technique":"T1190","reasoning":"one line"},...]`
        const raw = await callQwen(prompt, 900)
        const arrMatch = raw.match(/\[[\s\S]*\]/)
        if (arrMatch) {
          const rankings: { asset_id: string; entry_score: number }[] = JSON.parse(arrMatch[0])
          const rankMap = new Map(rankings.map(r => [r.asset_id, r.entry_score / 10]))
          const maxH    = Math.max(...heuristicScored.map(x => x.hScore), 1)
          for (const s of heuristicScored) {
            const llm = rankMap.get(s.ep.asset_id)
            if (llm !== undefined) {
              const normH  = s.hScore / maxH
              s.llmScore   = normH * 0.60 + llm * 0.40
              console.log(
                `[ENTRY] ${s.a.name}: ` +
                `heuristic=${s.hScore.toFixed(1)} ` +
                `llm=${(llm * 10).toFixed(1)}/10 ` +
                `blended=${s.llmScore.toFixed(3)}`
              )
            }
          }
        }
      } catch (err) {
        console.warn('[ENTRY] LLM ranking failed — using heuristic scores only:', err)
      }
    }

    const scored = heuristicScored
      .sort((a, b) => b.llmScore - a.llmScore)
      .slice(0, 10)
      .map(x => x.ep)

    // ── Pattern-diversity state + telemetry counters ──────────────────────────
    const TARGET_PATTERNS  = 5
    const seenPatterns     = new Map<string, RealisticAttackPath>()
    const patternPenalty   = new Map<string, number>()
    let   simsTotal        = 0
    let   epProcessed      = 0
    let   earlyStops       = 0
    let   stopReason: MCTSTelemetry['stop_reason'] = 'budget_exhausted'

    for (const entry of scored) {
      if (seenPatterns.size >= TARGET_PATTERNS) {
        console.log(`[MCTS] ${TARGET_PATTERNS} unique patterns found — skipping remaining entry points`)
        stopReason = 'target_reached'
        break
      }

      epProcessed++
      // Clear per-tree caches — RAVE stats and rollout scores from a different
      // root don't transfer meaningfully to a new topology context (IV).
      this.raveTotal.clear()
      this.raveVisits.clear()
      this.scoreCache.clear()

      const root: MCTSNode = {
        id: `${entry.asset_id}:${entry.misconfig_id}`,
        asset_id: entry.asset_id, misconfig_id: entry.misconfig_id,
        parent: null, children: [],
        visits: 0, total_reward: 0, ucb_score: 0,
        probability: 1.0, depth: 0,
        path_from_root: [entry.asset_id],
        visited_set: new Set([entry.asset_id]),
        expandedSet: new Set<string>(),
      }

      // E: adaptive budget — probe every PROBE_INTERVAL sims for new patterns.
      // STALE_LIMIT consecutive stale probes → early stop for this entry point.
      const PROBE_INTERVAL = 250
      const STALE_LIMIT    = 4
      let   staleProbes    = 0
      let   foundAnyPath   = false
      let   simBudgetUsed  = 0

      for (let sim = 0; sim < this.SIMS; sim++) {
        const leaf  = this.select(root)
        const child = this.expand(leaf, adj, assetMap)
        let   rew   = this.simulate(child, targetAssets, adj, assetMap, cjDist)

        // Reward shaping: penalise paths toward already-saturated patterns
        if (rew > 0 && child.path_from_root.length >= 2) {
          const entryA  = assetMap.get(child.path_from_root[0])
          const targetA = assetMap.get(child.path_from_root[child.path_from_root.length - 1])
          if (entryA && targetA) {
            const roughSig = `${entryA.type}:${entryA.zone}|${targetA.type}:${targetA.zone}`
            rew = rew * Math.max(0.05, 1 - (patternPenalty.get(roughSig) ?? 0))
          }
        }

        this.backpropagate(child, rew)
        simBudgetUsed++

        if ((sim + 1) % PROBE_INTERVAL === 0) {
          const probe = this.extractBestPaths(root, targetAssets, assetMap)
          for (const p of probe) p.pattern_signature = this.patternSignature(p, assetMap)
          if (probe.length > 0) foundAnyPath = true
          const newPatternFound = probe.some(p => !seenPatterns.has(p.pattern_signature))
          if (newPatternFound) {
            staleProbes = 0
          } else if (foundAnyPath) {
            staleProbes++
            if (staleProbes >= STALE_LIMIT) { earlyStops++; break }
          }
        }
      }
      simsTotal += simBudgetUsed

      const candidates = this.extractBestPaths(root, targetAssets, assetMap)
      for (const p of candidates) {
        p.pattern_signature = this.patternSignature(p, assetMap)
        p.pattern_label     = this.patternLabel(p.pattern_signature)
      }

      for (const p of candidates.sort((a, b) => b.realism_score - a.realism_score)) {
        const sig = p.pattern_signature
        if (!seenPatterns.has(sig)) {
          seenPatterns.set(sig, p)
          patternPenalty.set(sig, 0.4)
          console.log(`[MCTS] New pattern #${seenPatterns.size}: ${p.pattern_label}`)
          if (seenPatterns.size >= TARGET_PATTERNS) break
        } else {
          patternPenalty.set(sig, Math.min((patternPenalty.get(sig) ?? 0) + 0.15, 0.95))
          if (p.realism_score > seenPatterns.get(sig)!.realism_score) seenPatterns.set(sig, p)
        }
      }
    }

    if (epProcessed === scored.length && seenPatterns.size < TARGET_PATTERNS) {
      stopReason = 'stale_all_entries'
    }

    const uniquePaths = Array.from(seenPatterns.values())
      .sort((a, b) => b.realism_score - a.realism_score)
    uniquePaths.forEach((p, i) => { p.pattern_rank = i + 1 })

    const telemetry: MCTSTelemetry = {
      simulations_executed:   simsTotal,
      entry_points_processed: epProcessed,
      early_stops:            earlyStops,
      patterns_found:         seenPatterns.size,
      stop_reason:            stopReason,
    }
    console.log(
      `[MCTS] done — ${simsTotal} sims | ${epProcessed} entries | ` +
      `${earlyStops} early stops | ${seenPatterns.size} patterns | ${stopReason}`
    )
    return { paths: uniquePaths, telemetry }
  }

  // ── UCB1-RAVE Selection ──────────────────────────────────────────────────────
  // Standard UCB1 blended with RAVE (Rapid Action Value Estimation).
  // RAVE weight β decays from 1→0 as node visits increase, so early in search
  // RAVE dominates (fast global signal), late in search UCB1 dominates (precise).
  // β = raveVisits / (raveVisits + visits + raveVisits*visits / RAVE_EQUIV)
  // RAVE_EQUIV ≈ 100: node needs ~100 visits before UCB1 takes over from RAVE.

  private select(node: MCTSNode): MCTSNode {
    const RAVE_EQUIV = 100
    while (node.children.length > 0) {
      let best: MCTSNode = node.children[0]
      let bestScore = -Infinity
      for (const child of node.children) {
        if (child.visits === 0) { best = child; break }
        // UCB1 term
        const exploit = child.total_reward / child.visits
        const explore = this.C * Math.sqrt(Math.log(node.visits || 1) / child.visits)
        const ucb1 = exploit + explore
        // RAVE term — global average reward for this asset transition
        const move   = `${node.asset_id}→${child.asset_id}`
        const rv     = this.raveVisits.get(move) ?? 0
        const rt     = this.raveTotal.get(move)  ?? 0
        const raveQ  = rv > 0 ? rt / rv : exploit
        // Blend weight β
        const beta = rv / (rv + child.visits + (rv * child.visits) / RAVE_EQUIV)
        const score = (1 - beta) * ucb1 + beta * raveQ
        if (score > bestScore) { bestScore = score; best = child }
      }
      node = best
    }
    return node
  }

  // ── Expansion ───────────────────────────────────────────────────────────────

  private expand(node: MCTSNode, adj: Map<string, string[]>, assetMap: Map<string, EnhancedAsset>): MCTSNode {
    if (node.depth >= this.MAX_D) return node
    const cur = assetMap.get(node.asset_id)
    if (cur && this.isCrownJewelCached(cur)) return node

    const neighbors = adj.get(node.asset_id) ?? []
    for (const nid of neighbors) {
      const asset = assetMap.get(nid)
      if (!asset || asset.misconfigurations.length === 0) continue
      if (node.path_from_root.includes(nid)) continue  // depth≤7: O(7) beats Set alloc
      if (node.children.some(c => c.asset_id === nid)) continue

      // Opt #5: one child per neighbour — highest-severity misconfig only
      const mc = asset.misconfigurations
        .slice()
        .sort((a, b) => {
          const sev = { critical: 4, high: 3, medium: 2, low: 1 }
          return (sev[b.severity] ?? 0) - (sev[a.severity] ?? 0)
        })[0]
      const edge = this.bayes.getEdge(node.asset_id, nid)
      // G: Set built once on child creation; used by simulate() hot path
      const newPath = [...node.path_from_root, nid]
      node.children.push({
        id: `${nid}:${mc.id}`, asset_id: nid, misconfig_id: mc.id,
        parent: node, children: [],
        visits: 0, total_reward: 0, ucb_score: 0,
        probability: edge?.posterior_probability ?? 0.5,
        depth: node.depth + 1,
        path_from_root: newPath,
        visited_set: new Set(newPath),
        expandedSet: new Set<string>(),
      })
    }

    return node.children.length > 0
      ? node.children[Math.floor(Math.random() * node.children.length)]
      : node
  }

  // ── Simulation (rollout) — depth-limited, synchronous, no probability cutoff ─

  private simulate(
    node: MCTSNode,
    targetAssets: Set<string>,
    adj: Map<string, string[]>,
    assetMap: Map<string, EnhancedAsset>,
    cjDist: Map<string, number> = new Map()
  ): number {
    let current = node.asset_id
    let cumProb  = node.probability
    let depth    = node.depth
    // G: seed from visited_set (O(1) per lookup) rather than rebuilding from path_from_root array
    const visited = new Set(node.visited_set)
    let reward = 0

    while (depth < this.MAX_D) {
      const curAsset = assetMap.get(current)
      if (curAsset && this.isCrownJewelCached(curAsset)) {
        reward = this.terminalReward(node, curAsset, assetMap)
        break
      }
      if (targetAssets.has(current)) {
        reward = this.terminalReward(node, assetMap.get(current)!, assetMap)
        break
      }

      const neighbors = (adj.get(current) ?? []).filter(n => !visited.has(n))
      if (neighbors.length === 0) break

      // Opt #6: ε-greedy rollout — 85% greedy, 15% random.
      // Pure greedy made all rollouts from the same node deterministic after
      // the first pass, so 5000 sims mostly revisited the same paths.
      // Epsilon-greedy gives MCTS the variance to find the 5 distinct patterns
      // faster, enabling SIMS to be halved to 2500 with equal pattern coverage.
      let bestN = ''
      if (Math.random() < 0.15) {
        // Random exploration
        bestN = neighbors[Math.floor(Math.random() * neighbors.length)]
      } else {
        // Greedy: pick highest-scored neighbour (cached)
        let bestS = -1
        for (const nid of neighbors) {
          const cacheKey = `${current}:${nid}`
          let score = this.scoreCache.get(cacheKey)
          if (score === undefined) {
            const edge = this.bayes.getEdge(current, nid)
            const prob = edge?.posterior_probability ?? 0.1
            const sim  = this.gnn.computeSimilarity(current, nid)
            const crit = (assetMap.get(nid)?.criticality ?? 1) / 5
            const isT  = targetAssets.has(nid) || this.isCrownJewelCached(assetMap.get(nid)!)
            score = prob * 0.35 + sim * 0.20 + crit * 0.15 + (isT ? 0.30 : 0)
            this.scoreCache.set(cacheKey, score)
          }
          if (score > bestS) { bestS = score; bestN = nid }
        }
      }
      if (!bestN) break

      visited.add(bestN)
      const edge = this.bayes.getEdge(current, bestN)
      cumProb *= edge?.posterior_probability ?? 0.5
      current = bestN
      depth++
    }

    // I: graduated partial reward toward nearest crown jewel.
    // If rollout didn't reach a CJ, reward scales with (proximity to CJ × criticality).
    // This gives every simulation a useful gradient signal instead of binary 0/1:
    // rollouts that got closer to a crown jewel receive proportionally higher rewards,
    // steering the tree toward CJ-reachable corridors even in early simulations.
    if (reward === 0) {
      const d   = cjDist.get(current) ?? 99
      const a   = assetMap.get(current)
      const crit = (a?.criticality ?? 1) / 5
      if (d < 99) {
        // Proximity bonus: 1 hop away = 0.25, 2 hops = 0.125, 3 hops = 0.0625…
        reward = crit * (0.5 / Math.pow(2, d))
      } else if (a && a.criticality >= 4) {
        reward = crit * 0.05   // tiny signal for high-crit non-CJ dead ends
      }
    }

    return reward
  }

  // ── Terminal Reward — single traversal (III) ────────────────────────────────
  // Previously terminalReward() walked the MCTSNode chain, then called
  // detectionRisk() which walked it again. Merged into one pass: phases,
  // minEdgeP, pathLen, and risk are all collected in the same loop.

  private terminalReward(node: MCTSNode, target: EnhancedAsset, assetMap: Map<string, EnhancedAsset>): number {
    const critReward = target.criticality / 5
    const phases = new Set<string>()
    let pathLen  = 0
    let minEdgeP = 1.0
    let risk     = 0
    let cur: MCTSNode | null = node

    while (cur) {
      const a = assetMap.get(cur.asset_id)
      const m = a?.misconfigurations.find(x => x.id === cur!.misconfig_id)
      if (m) {
        phases.add(m.category)
        // detection risk contribution (was a separate traversal)
        if      (m.severity === 'critical')        risk += 0.08
        else if (m.category === 'authentication')  risk += 0.02
        else                                        risk += 0.04
      }
      if (cur.depth === 0) risk += 0.15
      minEdgeP = Math.min(minEdgeP, cur.probability)
      pathLen++
      cur = cur.parent
    }

    const killChainBonus = 1 + Math.min(phases.size / 5, 1) * 1.5
    const lenMod   = pathLen < 4 ? 0.4 : pathLen <= 7 ? 1.3 : pathLen <= 10 ? 1.0 : 0.7
    const stealth  = 0.5 + minEdgeP * 0.5
    const detRisk  = Math.min(risk, 0.5)

    return critReward * killChainBonus * lenMod * stealth * (1 - detRisk)
  }

  // ── Backpropagation + RAVE update ───────────────────────────────────────────
  // On each backprop pass, collect all asset transitions in this path and
  // update the RAVE tables so that future selections at any tree node can
  // leverage this simulation's outcome immediately.

  private backpropagate(node: MCTSNode, reward: number): void {
    // Collect all moves in this path for RAVE
    const movesInPath = new Set<string>()
    let c: MCTSNode | null = node
    while (c && c.parent) {
      movesInPath.add(`${c.parent.asset_id}→${c.asset_id}`)
      c = c.parent
    }
    // Update node stats and RAVE tables in one pass
    let cur: MCTSNode | null = node
    while (cur) {
      cur.visits++
      cur.total_reward += reward
      // RAVE: credit all moves in this simulation that are available from cur
      for (const child of cur.children) {
        const move = `${cur.asset_id}→${child.asset_id}`
        if (movesInPath.has(move)) {
          this.raveTotal.set(move,  (this.raveTotal.get(move)  ?? 0) + reward)
          this.raveVisits.set(move, (this.raveVisits.get(move) ?? 0) + 1)
        }
      }
      cur = cur.parent
    }
  }

  // ── Path Extraction ─────────────────────────────────────────────────────────

  private extractBestPaths(root: MCTSNode, targetAssets: Set<string>, assetMap: Map<string, EnhancedAsset>): RealisticAttackPath[] {
    // Opt #8: DFS using only node references — no [...path, child] spread.
    // Path reconstruction uses parent pointers (already on every MCTSNode),
    // eliminating per-step array allocations and GC pressure.
    const paths: RealisticAttackPath[] = []
    const stack: MCTSNode[] = [root]

    while (stack.length > 0) {
      const node     = stack.pop()!
      const asset    = assetMap.get(node.asset_id)
      const isTarget = targetAssets.has(node.asset_id)
      const isCJ     = asset && this.isCrownJewelCached(asset)

      if ((isTarget || isCJ) && node.depth + 1 >= this.MIN_D) {
        // Walk parent pointers to reconstruct path — O(depth), zero allocations
        const chain: MCTSNode[] = []
        let cur: MCTSNode | null = node
        while (cur) { chain.push(cur); cur = cur.parent }
        chain.reverse()
        paths.push(this.constructPath(chain, assetMap))
      }

      if (!isCJ) {
        for (const child of node.children) stack.push(child)
      }
    }

    return paths
  }

  private constructPath(nodes: MCTSNode[], assetMap: Map<string, EnhancedAsset>): RealisticAttackPath {
    const pathNodes: PathNode[] = []
    const edges: BayesianEdge[] = []
    let cumProb = 1.0

    for (let i = 0; i < nodes.length; i++) {
      const n   = nodes[i]
      const a   = assetMap.get(n.asset_id)!
      const mc  = a.misconfigurations.find(m => m.id === n.misconfig_id)!
      cumProb  *= n.probability
      pathNodes.push({
        asset_id: n.asset_id, asset_name: a.name,
        misconfig_id: n.misconfig_id, misconfig_title: mc.title,
        criticality: a.criticality, zone: a.zone, cumulative_probability: cumProb,
      })
      if (i > 0) {
        const e = this.bayes.getEdge(nodes[i - 1].asset_id, n.asset_id)
        if (e) edges.push(e)
      }
    }

    // Fix B: placeholder sig must NOT use asset_id — two paths with different
    // assets but the same structural pattern would get different placeholder sigs
    // and slip past the dedup in discoverPaths before patternSignature() runs.
    // Use zone only as placeholder; discoverPaths overwrites with the real sig.
    const entryNode  = pathNodes[0]
    const targetNode = pathNodes[pathNodes.length - 1]
    const edgePart   = edges.map(e => e.edge_type).join('→')
    const sig = `__pending__|${entryNode.zone}|${edgePart}|${targetNode.zone}`
    return {
      path_id: `path-${nodes[0].asset_id.slice(-6)}-${nodes[nodes.length - 1].asset_id.slice(-6)}-${Date.now()}`,
      nodes: pathNodes, edges,
      path_probability: cumProb,
      confidence_interval: this.pathCI(edges),
      attacker_effort: this.attackerEffort(nodes, edges),
      detection_probability: nodes.length * 0.03,
      business_impact: this.businessImpact(pathNodes),
      realism_score: this.realismScore(nodes, edges, cumProb, pathNodes, assetMap),
      kill_chain_phases: this.killChainPhases(edges),
      required_capabilities: this.capabilities(edges),
      timeline_estimate: `${nodes.length * 4}–${nodes.length * 8} hours`,
      pattern_signature: sig,
      pattern_label: '',   // filled by discoverPaths
      pattern_rank: 0,     // filled by discoverPaths
    }
  }

  // ── Pattern diversity helpers ─────────────────────────────────────────────

  // S1: Canonical technique-set — sort edge types so ct→lat and lat→ct
  // map to the same pattern. Previously these counted as different patterns,
  // creating false diversity in the top-5 output.
  //
  // S2: Zone-sequence fingerprint — the unique ordered sequence of zones
  // traversed matters for remediation. mgmt→restricted and mgmt→corp→restricted
  // require different controls even with identical technique sets.
  patternSignature(path: RealisticAttackPath, assetMap: Map<string, EnhancedAsset>): string {
    const entry  = path.nodes[0]
    const target = path.nodes[path.nodes.length - 1]
    const ea     = assetMap.get(entry.asset_id)
    const ta     = assetMap.get(target.asset_id)
    const entryPart  = `${ea?.type ?? entry.asset_id}:${entry.zone}`
    const targetPart = `${ta?.type ?? target.asset_id}:${target.zone}`
    // S1: canonical (sorted) technique set — order-independent
    const techSet = [...new Set(path.edges.map(e => e.edge_type))].sort().join('+')
    // S2: unique zone sequence (deduplicate consecutive same-zone steps)
    const zones = path.nodes.map(n => n.zone)
    const zoneSeq: string[] = []
    for (let i = 0; i < zones.length; i++) {
      if (i === 0 || zones[i] !== zones[i-1]) zoneSeq.push(zones[i])
    }
    return `${entryPart}|${techSet}|${targetPart}|${zoneSeq.join('→')}`
  }

  // Human-readable label — shows canonical technique set + zone path (S1+S2).
  patternLabel(sig: string): string {
    if (sig === '__pending__') return '—'
    const parts      = sig.split('|')
    const entryPart  = parts[0]
    const techPart   = parts[1]
    const targetPart = parts[2]
    const zonePath   = parts[3] ?? ''
    const entryType  = entryPart.split(':')[0].replace(/_/g, ' ')
    const targetType = targetPart.split(':')[0].replace(/_/g, ' ')
    const targetZone = targetPart.split(':')[1] ?? ''
    const techs      = techPart.split('+').map(t => t.replace(/_/g, ' '))
    const zoneLabel  = zonePath ? ` via ${zonePath}` : ''
    return `${entryType} → ${techs.join(' + ')} → ${targetType} [${targetZone}]${zoneLabel}`
  }

  private realismScore(nodes: MCTSNode[], edges: BayesianEdge[], prob: number, pathNodes?: PathNode[], assetMap?: Map<string, EnhancedAsset>): number {
    const evidenceSources = new Set(edges.flatMap(e => e.evidence_sources))
    const avgCIWidth = edges.reduce((s, e) => s + (e.confidence_interval[1] - e.confidence_interval[0]), 0) / Math.max(edges.length, 1)
    const lenScore = Math.max(0, 1 - Math.abs(nodes.length - 5) * 0.05)
    const visits = nodes.reduce((s, n) => s + n.visits, 0)

    // S3: EPSS/CVSS-weighted realism — paths through assets with actively
    // exploited vulnerabilities (high EPSS) are far more imminent threats.
    // Geometric mean of per-node max EPSS scores: a single high-EPSS vuln
    // on any node should elevate the entire path's realism.
    let epssScore = 0.5  // neutral default when no EPSS data available
    if (pathNodes && assetMap) {
      const nodeMaxEpss = pathNodes.map(pn => {
        const asset = assetMap.get(pn.asset_id)
        if (!asset) return 0.05
        const scores = asset.misconfigurations
          .map(m => m.epss ?? (m.severity === 'critical' && m.exploit_available ? 0.7 : m.severity === 'critical' ? 0.3 : m.severity === 'high' ? 0.15 : 0.05))
        return Math.max(...scores, 0.01)
      })
      // Geometric mean — a path is only as stealthy as its weakest link
      const logSum = nodeMaxEpss.reduce((s, e) => s + Math.log(e), 0)
      epssScore = Math.exp(logSum / nodeMaxEpss.length)
    }

    return (
      prob        * 0.25 +
      epssScore   * 0.20 +   // S3: EPSS weight replaces partial evidence credit
      Math.min(evidenceSources.size / 3, 1) * 0.20 +
      (1 - avgCIWidth) * 0.15 +
      lenScore    * 0.10 +
      Math.min(visits / (this.SIMS * 0.5), 1) * 0.10
    )
  }

  private pathCI(edges: BayesianEdge[]): [number, number] {
    if (edges.length === 0) return [0.5, 0.5]
    let variance = 0
    for (const e of edges) {
      const w = (e.confidence_interval[1] - e.confidence_interval[0]) / 3.92
      variance += w * w
    }
    const std  = Math.sqrt(variance)
    const prob = edges.reduce((p, e) => p * e.posterior_probability, 1)
    return [Math.max(0.01, prob - 1.96 * std), Math.min(0.99, prob + 1.96 * std)]
  }

  private attackerEffort(nodes: MCTSNode[], edges: BayesianEdge[]): number {
    let e = nodes.length * 0.5
    e += edges.filter(x => x.edge_type === 'privilege_escalation').length * 1.5
    e += edges.filter(x => x.edge_type === 'credential_theft').length * 1.0
    const avgP = edges.reduce((s, x) => s + x.posterior_probability, 0) / Math.max(edges.length, 1)
    e += (1 - avgP) * 3
    return Math.min(e, 10)
  }

  private businessImpact(nodes: PathNode[]): number {
    let impact = 0
    for (let i = 0; i < nodes.length; i++) impact += nodes[i].criticality * ((i + 1) / nodes.length)
    return Math.min((impact / nodes.length) * 20, 100)
  }

  private killChainPhases(edges: BayesianEdge[]): string[] {
    const phases = ['Reconnaissance']
    for (const e of edges) {
      switch (e.edge_type) {
        case 'exploit':              phases.push('Weaponization', 'Delivery', 'Exploitation'); break
        case 'lateral':              phases.push('Installation', 'Command & Control', 'Lateral Movement'); break
        case 'credential_theft':     phases.push('Credential Access'); break
        case 'privilege_escalation': phases.push('Privilege Escalation'); break
        case 'data_exfiltration':    phases.push('Collection', 'Exfiltration'); break
      }
    }
    return [...new Set(phases)]
  }

  private capabilities(edges: BayesianEdge[]): string[] {
    const caps = new Set<string>()
    for (const e of edges) {
      switch (e.edge_type) {
        case 'exploit':              caps.add('Exploit Development'); caps.add('Vulnerability Research'); break
        case 'lateral':              caps.add('Network Traversal'); caps.add('Post-Exploitation'); break
        case 'credential_theft':     caps.add('Credential Harvesting'); break
        case 'privilege_escalation': caps.add('Privilege Escalation'); break
        case 'data_exfiltration':    caps.add('Data Exfiltration'); break
      }
    }
    return Array.from(caps)
  }

  // ── Crown Jewel Evaluation ──────────────────────────────────────────────────

  private async isTerminalAssetLLM(asset: EnhancedAsset): Promise<boolean> {
    const key = `${asset.id}:${asset.type}:${asset.criticality}`
    if (this.cjCache.has(key)) return this.cjCache.get(key)!

    const prompt = `You are a senior red team operator. Is compromising this asset "ATTACKER WINS"?

Asset: ${asset.name} | Type: ${asset.type} | Zone: ${asset.zone} | Criticality: ${asset.criticality}/5
Services: ${asset.services?.join(', ') || 'unknown'} | Data: ${asset.data_sensitivity}

Crown jewels = assets giving FULL ENVIRONMENT control (DC, IdP, PKI/CA).
NOT crown jewels: web/app/db servers (valuable but not game-over).

Reply JSON only: {"is_crown_jewel":true/false,"reasoning":"one line"}`

    try {
      const raw  = await callQwen(prompt, 150)
      const m    = raw.match(/\{[\s\S]*\}/)
      const result = m ? JSON.parse(m[0]) : null
      const isCJ = result?.is_crown_jewel === true
      this.cjCache.set(key, isCJ)
      console.log(`[CROWN JEWEL] ${asset.name}: ${isCJ ? '👑' : '❌'} ${result?.reasoning ?? ''}`)
      return isCJ
    } catch (err) {
      console.error('[CROWN JEWEL] Qwen3 error:', err)
      throw err
    }
  }

  isCrownJewelCached(asset: EnhancedAsset): boolean {
    const key = `${asset.id}:${asset.type}:${asset.criticality}`
    return this.cjCache.get(key) ?? false
  }
}

// ─── MAIN ENGINE ─────────────────────────────────────────────────────────────

export class EnhancedAttackGraphEngine extends EventEmitter {
  private gnn   = new GNNEmbeddingEngine()
  private bayes = new BayesianProbabilityEngine()
  private mcts  = new MCTSPathDiscoveryEngine(this.gnn, this.bayes)

  async analyze(env: { assets: EnhancedAsset[] }): Promise<EnhancedAnalysisResult> {
    const t0 = Date.now()
    const { assets } = env

    // Phase 1: GNN embeddings — bootstrap with zone-topology edges so attention
    // propagation has real neighbours. Assets in adjacent zones get similar
    // embeddings; distant zones diverge. Previously called with [] (no-op).
    // We connect one representative asset per zone to one representative per
    // each reachable zone — O(zones² × 1) edges, not O(N²) asset pairs.
    // This gives the GNN genuine structural signal without the N² blowup.
    this.emit('progress', 'Computing GNN embeddings…')
    const t1 = Date.now()
    const byZone = new Map<string, string>()   // zone → first asset id in that zone
    for (const a of assets) {
      if (!byZone.has(a.zone)) byZone.set(a.zone, a.id)
    }
    const topoEdges: { source: string; target: string }[] = []
    for (const [zone, srcId] of byZone) {
      for (const neighborZone of (ZONE_REACH[zone] ?? [])) {
        const tgtId = byZone.get(neighborZone)
        if (tgtId && tgtId !== srcId) topoEdges.push({ source: srcId, target: tgtId })
      }
    }
    await this.gnn.computeEmbeddings(assets, topoEdges)
    const gnnTime = Date.now() - t1

    // Phase 2: Bayesian packed store — built ONCE, shared across all profiles.
    // PackedEdgeStore uses typed arrays (14 bytes/edge vs 200 bytes for JS objects).
    // At 10K assets: 490 MB instead of 7 GB (93% reduction).
    this.emit('progress', 'Computing Bayesian probabilities…')
    const t2 = Date.now()
    const gnnSim = (a: string, b: string) => this.gnn.computeSimilarity(a, b)
    // Warm the singleton packed store. All three profiles share this store;
    // profile-specific SparseAdj is built in O(E) per profile, not O(N²).
    this.bayes.ttpProfile = 'apt'
    await this.bayes.computeProbabilities(assets, null, gnnSim)
    const bayesTime = Date.now() - t2

    // Phase 3: MCTS — three TTP profiles in parallel (S5)
    this.emit('progress', 'Running MCTS path discovery…')
    const t3 = Date.now()
    // P1: pre-sort misconfigurations by severity once so expand() always uses [0]
    const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }
    for (const a of assets) {
      a.misconfigurations.sort((x, y) => (SEV_ORDER[y.severity] ?? 0) - (SEV_ORDER[x.severity] ?? 0))
    }
    const assetMap = new Map(assets.map(a => [a.id, a]))
    const targetAssets = new Set(
      Array.from(assetMap.values())
        .filter(a => this.mcts.isCrownJewelCached(a))
        .map(a => a.id)
    )

    // APT adjacency — built from shared packed store in O(E)
    const adj    = this.bayes.buildAdjacencyMap(assets, gnnSim)
    const cjDist = this.mcts.buildCrownJewelDistances(adj, targetAssets)
    const entryPoints = this.identifyEntryPoints(assets, cjDist)

    // S5: APT profile first (LLM CJ eval + LLM EP ranking), then Ransomware + Insider in parallel.
    // All three use the same PackedEdgeStore — only the SparseAdj differs per profile.
    const { paths: aptPaths, telemetry: aptTelemetry } =
      await this.mcts.discoverPaths(entryPoints, targetAssets, adj, assetMap, cjDist)

    // Snapshot CJ cache after APT eval — reused by other profiles (no LLM calls)
    const sharedCjMap = new Map<string, boolean>()
    for (const a of assetMap.values()) {
      sharedCjMap.set(`${a.id}:${a.type}:${a.criticality}`, this.mcts.isCrownJewelCached(a))
    }

    // Ransomware + Insider: build profile-specific SparseAdj in O(E) each —
    // no O(N²) rebuild, no object allocation, shared PackedEdgeStore underneath.
    const makeProfilePaths = async (profile: 'ransomware' | 'insider') => {
      const bayesProfile = new BayesianProbabilityEngine()
      bayesProfile.ttpProfile = profile
      const adjProfile    = bayesProfile.buildAdjacencyMap(assets, gnnSim)
      const cjDistProfile = this.mcts.buildCrownJewelDistances(adjProfile, targetAssets)
      const epProfile     = this.identifyEntryPoints(assets, cjDistProfile)
      const mctsProfile   = new MCTSPathDiscoveryEngine(this.gnn, bayesProfile)
      const cloneCache    = (mctsProfile as unknown as { cjCache: Map<string, boolean> }).cjCache
      for (const [k, v] of sharedCjMap) cloneCache.set(k, v)
      return mctsProfile.discoverPaths(epProfile, targetAssets, adjProfile, assetMap, cjDistProfile, true)
    }
    const [
      { paths: ransomPaths, telemetry: ransomTelemetry },
      { paths: insiderPaths, telemetry: insiderTelemetry },
    ] = await Promise.all([
      makeProfilePaths('ransomware'),
      makeProfilePaths('insider'),
    ])

    // ── Merge: unique sig → best realism_score, label with profile ─────────
    const label = (paths: RealisticAttackPath[], tag: string) =>
      paths.map(p => ({ ...p, pattern_label: `[${tag}] ${p.pattern_label}` }))

    const merged = new Map<string, RealisticAttackPath>()
    for (const p of [
      ...label(aptPaths, 'APT'),
      ...label(ransomPaths, 'RANSOM'),
      ...label(insiderPaths, 'INSIDER'),
    ]) {
      const existing = merged.get(p.pattern_signature)
      if (!existing || p.realism_score > existing.realism_score) merged.set(p.pattern_signature, p)
    }
    const attackPaths = Array.from(merged.values())
      .sort((a, b) => b.realism_score - a.realism_score)
      .slice(0, 5)
    attackPaths.forEach((p, i) => { p.pattern_rank = i + 1 })
    const mctsTime = Date.now() - t3

    const totalSims = aptTelemetry.simulations_executed
                    + ransomTelemetry.simulations_executed
                    + insiderTelemetry.simulations_executed

    const allEdges  = this.bayes.getAllEdges()
    const highConf  = allEdges.filter(e => e.confidence_interval[1] - e.confidence_interval[0] < 0.3)
    const lowConf   = allEdges.filter(e => e.confidence_interval[1] - e.confidence_interval[0] > 0.5)

    return {
      graph_stats: {
        total_nodes: assets.length,
        total_edges: allEdges.length,
        embedding_dimensions: 128,
        avg_branching_factor: allEdges.length / Math.max(assets.length, 1),
      },
      bayesian_stats: {
        total_evidence_sources: 5,
        avg_edge_confidence: allEdges.reduce((s, e) => s + (1 - (e.confidence_interval[1] - e.confidence_interval[0])), 0) / Math.max(allEdges.length, 1),
        high_confidence_edges: highConf.length,
        low_confidence_edges:  lowConf.length,
      },
      mcts_stats: {
        total_simulations: totalSims,
        exploration_constant: 1.414,
        best_path_reward: 0,
        avg_path_depth: attackPaths.reduce((s, p) => s + p.nodes.length, 0) / Math.max(attackPaths.length, 1),
      },
      attack_paths: attackPaths,
      entry_points: this.formatEntryPoints(entryPoints, assets),
      critical_assets: this.criticalAssets(assets, attackPaths),
      risk_metrics: this.riskMetrics(attackPaths),
      chokepoints: this.identifyChokepoints(attackPaths, assetMap),  // S6
      timing: { gnn_embedding: gnnTime, bayesian_inference: bayesTime, mcts_discovery: mctsTime, total: Date.now() - t0 },
    }
  }

  // ── Edge Generation ──────────────────────────────────────────────────────────


  // S4: Entry point scoring with crown-jewel proximity.
  // Previously scored by criticality × severity — this always picks the most
  // critical internet-facing asset regardless of how far it is from a crown jewel.
  // Now incorporates cjDist so entry points near DCs/IdPs rank higher than ones
  // that are topologically isolated from crown jewels.
  // Also: expand scope to include ALL internet-facing OR dmz OR mgmt assets with
  // any high/critical misconfig — not just internet_facing. Lateral movement often
  // starts from compromised internal jump points exposed via phishing.
  private identifyEntryPoints(
    assets: EnhancedAsset[],
    cjDist?: Map<string, number>
  ): { asset_id: string; misconfig_id: string }[] {
    const candidates: { asset_id: string; misconfig_id: string; score: number }[] = []
    for (const a of assets) {
      // Expanded entry criteria: internet-facing, dmz, mgmt, or high-crit with external exposure
      const isCandidate = a.internet_facing || a.zone === 'dmz' || a.zone === 'mgmt'
        || (a.criticality >= 4 && (a.zone === 'corp' || a.zone === 'staging'))
      if (!isCandidate) continue
      for (const m of a.misconfigurations) {
        if (m.severity !== 'critical' && m.severity !== 'high') continue
        const sevScore = m.severity === 'critical' ? 4 : 3
        // S4: proximity bonus — entry points closer to crown jewels score higher
        const dist     = cjDist?.get(a.id) ?? 99
        const proxBonus = dist <= 1 ? 8 : dist <= 2 ? 5 : dist <= 3 ? 2 : 0
        const epssBonus = (m.epss ?? 0) * 3   // actively exploited vulns are hot
        candidates.push({
          asset_id: a.id,
          misconfig_id: m.id,
          score: a.criticality * sevScore + (a.internet_facing ? 5 : 0) + proxBonus + epssBonus,
        })
      }
    }
    return candidates
      .sort((a, b) => b.score - a.score)
      .slice(0, 10)
      .map(({ asset_id, misconfig_id }) => ({ asset_id, misconfig_id }))
  }

  // S6: Chokepoint analysis — assets that appear in the most attack paths.
  // A chokepoint is a node where a single control (MFA enforcement, network
  // segmentation, patch) would block multiple attack chains simultaneously.
  // This is the most actionable red-team output: fix the chokepoints first.
  private identifyChokepoints(
    paths: RealisticAttackPath[],
    assetMap: Map<string, EnhancedAsset>
  ): { asset_id: string; asset_name: string; asset_type: string; zone: string; paths_through: number; blocking_impact: number }[] {
    const freq = new Map<string, number>()
    for (const path of paths) {
      // Count intermediate nodes (not entry or crown jewel) — blocking these is actionable
      for (let i = 1; i < path.nodes.length - 1; i++) {
        const nid = path.nodes[i].asset_id
        freq.set(nid, (freq.get(nid) ?? 0) + 1)
      }
    }
    return Array.from(freq.entries())
      .filter(([, count]) => count >= 1)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([id, count]) => {
        const a = assetMap.get(id)
        return {
          asset_id: id,
          asset_name: a?.name ?? id,
          asset_type: a?.type ?? 'unknown',
          zone: a?.zone ?? 'unknown',
          paths_through: count,
          blocking_impact: Math.round((count / Math.max(paths.length, 1)) * 100),
        }
      })
  }

  private formatEntryPoints(eps: { asset_id: string; misconfig_id: string }[], assets: EnhancedAsset[]): EntryPoint[] {
    return eps.slice(0, 10).map(ep => {
      const a  = assets.find(x => x.id === ep.asset_id)!
      const m  = a.misconfigurations.find(x => x.id === ep.misconfig_id)!
      const emb = this.gnn.getEmbedding(ep.asset_id)
      return {
        node_id: `${ep.asset_id}:${ep.misconfig_id}`,
        asset_name: a.name,
        misconfig_title: m.title,
        probability: 0.8,
        confidence: 0.9,
        attacker_value: `${a.zone} zone · criticality ${a.criticality}/5`,
        gnn_attention_weight: emb ? Math.max(...Array.from(emb.slice(0, 10))) : 0.5,
      }
    })
  }

  private criticalAssets(assets: EnhancedAsset[], paths: RealisticAttackPath[]): CriticalAsset[] {
    const counts = new Map<string, number>()
    const risk   = new Map<string, number>()
    for (const p of paths) {
      for (const n of p.nodes) {
        counts.set(n.asset_id, (counts.get(n.asset_id) ?? 0) + 1)
        risk.set(n.asset_id, (risk.get(n.asset_id) ?? 0) + p.path_probability * p.business_impact)
      }
    }
    return assets
      .filter(a => a.criticality >= 4 || (counts.get(a.id) ?? 0) > 0)
      .map(a => ({
        asset_id: a.id, asset_name: a.name,
        reason: a.criticality >= 5 ? 'Highest criticality asset' :
                a.criticality >= 4 ? 'High criticality — sensitive data' :
                `${counts.get(a.id) ?? 0} attack paths converge here`,
        paths_to_it: counts.get(a.id) ?? 0,
        cumulative_risk: risk.get(a.id) ?? 0,
        gnn_importance_score: 0.5,
      }))
      .sort((a, b) => b.cumulative_risk - a.cumulative_risk)
      .slice(0, 5)
  }

  private riskMetrics(paths: RealisticAttackPath[]): RiskMetrics {
    const avgP = paths.reduce((s, p) => s + p.path_probability, 0) / Math.max(paths.length, 1)
    const avgR = paths.reduce((s, p) => s + p.realism_score,    0) / Math.max(paths.length, 1)
    return {
      overall_risk_score: Math.round(avgP * avgR * 100),
      risk_distribution: {
        critical: paths.filter(p => p.business_impact >= 80).length,
        high:     paths.filter(p => p.business_impact >= 50 && p.business_impact < 80).length,
        medium:   paths.filter(p => p.business_impact >= 25 && p.business_impact < 50).length,
        low:      paths.filter(p => p.business_impact < 25).length,
      },
      top_attack_vectors: [...new Set(paths.flatMap(p => p.edges.map(e => e.technique)))].slice(0, 5),
      recommended_mitigations: [
        'Patch critical vulnerabilities on internet-facing assets',
        'Implement network segmentation between zones',
        'Enable multi-factor authentication across all domain assets',
        'Deploy credential monitoring and LAPS',
        'Enhance SIEM detection for lateral movement patterns',
      ],
    }
  }
}

export { GNNEmbeddingEngine, BayesianProbabilityEngine, MCTSPathDiscoveryEngine }
