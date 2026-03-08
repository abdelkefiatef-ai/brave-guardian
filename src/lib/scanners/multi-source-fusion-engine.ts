// ============================================================================
// MULTI-SOURCE DATA FUSION ENGINE
// Strategic Integration of API Discovery, NetFlow, Active Scan, and Sidescan
// ============================================================================
//
// This engine implements a hierarchical evidence fusion strategy:
//
// Data Sources (by confidence):
// ├── Sidescan (highest confidence 0.95) - Validated attack paths
// ├── API Discovery (high confidence 0.90) - 100% coverage, API-based
// ├── Passive NetFlow (high confidence 0.85) - Real-time topology
// └── Active Scan (medium confidence 0.70) - Targeted, may miss some assets
//
// Edge Classification:
// ├── Validated: From NetFlow/Sidescan (measured, not inferred)
// ├── Discovered: From API Discovery (complete but may include stale data)
// ├── Inferred: From Active Scan (targeted sampling)
// └── Hypothetical: From vulnerability correlation (lowest confidence)
//
// Fusion Strategy:
// 1. Weighted evidence combination based on source reliability
// 2. Conflict resolution using Dempster-Shafer theory
// 3. Temporal decay for stale evidence
// 4. Cross-validation between sources
// ============================================================================

import { EventEmitter } from 'events'

// ============================================================================
// TYPES
// ============================================================================

export type DataSourceType = 'api_discovery' | 'passive_netflow' | 'active_scan' | 'sidescan'

export interface DataSourceConfig {
  enabled: boolean
  confidence: number
  stalenessThreshold: number  // milliseconds
  priority: number
  coverage: number  // 0-1
}

export interface FusionConfig {
  sources: Record<DataSourceType, DataSourceConfig>
  conflictResolution: 'dempster_shafer' | 'weighted_average' | 'max_confidence'
  temporalDecay: {
    enabled: boolean
    halfLife: number  // milliseconds
  }
  crossValidation: {
    enabled: boolean
    minSources: number  // minimum sources to validate an edge
  }
}

export interface DiscoveredAsset {
  id: string
  name: string
  type: AssetType
  ip: string
  mac?: string
  zone: string
  criticality: number
  internetFacing: boolean
  services: DiscoveredService[]
  source: DataSourceType
  lastSeen: number
  confidence: number
}

export interface DiscoveredService {
  name: string
  port: number
  protocol: 'tcp' | 'udp'
  version?: string
  banner?: string
  authenticated: boolean
  vulnerabilities: DiscoveredVulnerability[]
}

export interface DiscoveredVulnerability {
  id: string
  cve?: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  cvss: number
  exploitAvailable: boolean
  epss?: number
}

export interface DiscoveredEdge {
  id: string
  sourceAssetId: string
  targetAssetId: string
  edgeType: EdgeType
  protocol: string
  port?: number
  
  // Evidence from each source
  evidence: EdgeEvidence[]
  
  // Fused confidence
  fusedConfidence: number
  fusedProbability: number
  
  // Classification
  classification: 'validated' | 'discovered' | 'inferred' | 'hypothetical'
  
  // Temporal info
  firstSeen: number
  lastSeen: number
  observationCount: number
}

export type EdgeType = 
  | 'network_connection'
  | 'authenticated_session'
  | 'service_dependency'
  | 'trust_relationship'
  | 'data_flow'
  | 'attack_path'

export interface EdgeEvidence {
  source: DataSourceType
  confidence: number
  probability: number
  rawData: Record<string, any>
  timestamp: number
  observationType: 'direct' | 'inferred' | 'reported'
}

export type AssetType = 
  | 'workstation'
  | 'server'
  | 'domain_controller'
  | 'database_server'
  | 'web_server'
  | 'application_server'
  | 'file_server'
  | 'mail_server'
  | 'backup_server'
  | 'jump_server'
  | 'firewall'
  | 'router'
  | 'switch'
  | 'load_balancer'
  | 'container'
  | 'container_host'
  | 'iot_device'
  | 'unknown'

// ============================================================================
// DATA SOURCE COLLECTORS
// ============================================================================

/**
 * API Discovery Source
 * - 100% coverage
 * - High confidence (0.90)
 * - Sources: CMDB, Cloud APIs, Virtualization APIs, AD
 */
export class APIDiscoverySource extends EventEmitter {
  private config: DataSourceConfig
  private assets: Map<string, DiscoveredAsset> = new Map()
  private edges: Map<string, DiscoveredEdge> = new Map()

  constructor(config: DataSourceConfig) {
    super()
    this.config = config
  }

  /**
   * Collect assets from various APIs
   */
  async collect(): Promise<{
    assets: DiscoveredAsset[]
    edges: DiscoveredEdge[]
  }> {
    const assets: DiscoveredAsset[] = []
    const edges: DiscoveredEdge[] = []

    // Collect from multiple API sources in parallel
    const [cmdbAssets, cloudAssets, virtualizationAssets, adAssets] = await Promise.all([
      this.collectFromCMDB(),
      this.collectFromCloudAPIs(),
      this.collectFromVirtualizationAPIs(),
      this.collectFromActiveDirectory()
    ])

    // Merge and deduplicate
    const allAssets = this.mergeAssets([
      ...cmdbAssets,
      ...cloudAssets,
      ...virtualizationAssets,
      ...adAssets
    ])

    // Collect relationship data
    const [cmdbRelations, cloudRelations, adRelations] = await Promise.all([
      this.collectCMDBRelations(),
      this.collectCloudRelations(),
      this.collectADRelations()
    ])

    const allEdges = this.mergeEdges([
      ...cmdbRelations,
      ...cloudRelations,
      ...adRelations
    ])

    return { assets: allAssets, edges: allEdges }
  }

  private async collectFromCMDB(): Promise<DiscoveredAsset[]> {
    // Integration with ServiceNow, BMC Remedy, etc.
    // This would make actual API calls in production
    return []
  }

  private async collectFromCloudAPIs(): Promise<DiscoveredAsset[]> {
    // AWS EC2, Azure VMs, GCP Compute
    // Cloud-native asset discovery
    return []
  }

  private async collectFromVirtualizationAPIs(): Promise<DiscoveredAsset[]> {
    // VMware vCenter, Hyper-V, Proxmox
    return []
  }

  private async collectFromActiveDirectory(): Promise<DiscoveredAsset[]> {
    // AD computer objects, service accounts
    return []
  }

  private async collectCMDBRelations(): Promise<DiscoveredEdge[]> {
    return []
  }

  private async collectCloudRelations(): Promise<DiscoveredEdge[]> {
    return []
  }

  private async collectADRelations(): Promise<DiscoveredEdge[]> {
    return []
  }

  private mergeAssets(assetLists: DiscoveredAsset[][]): DiscoveredAsset[] {
    const merged = new Map<string, DiscoveredAsset>()
    
    for (const list of assetLists) {
      for (const asset of list) {
        const existing = merged.get(asset.id)
        if (!existing || asset.lastSeen > existing.lastSeen) {
          merged.set(asset.id, asset)
        }
      }
    }
    
    return Array.from(merged.values())
  }

  private mergeEdges(edgeLists: DiscoveredEdge[][]): DiscoveredEdge[] {
    const merged = new Map<string, DiscoveredEdge>()
    
    for (const list of edgeLists) {
      for (const edge of list) {
        const key = `${edge.sourceAssetId}:${edge.targetAssetId}:${edge.edgeType}`
        merged.set(key, edge)
      }
    }
    
    return Array.from(merged.values())
  }
}

/**
 * Passive NetFlow Source
 * - Real-time topology
 * - High confidence (0.85)
 * - Non-intrusive, always-on
 */
export class PassiveNetFlowSource extends EventEmitter {
  private config: DataSourceConfig
  private flowBuffer: NetFlowRecord[] = []
  private assetConnections: Map<string, Set<string>> = new Map()

  constructor(config: DataSourceConfig) {
    super()
    this.config = config
  }

  /**
   * Process NetFlow/sFlow records
   */
  async processFlow(flowData: NetFlowRecord[]): Promise<void> {
    for (const flow of flowData) {
      this.flowBuffer.push(flow)
      this.updateConnections(flow)
    }
    
    // Trim old flows
    const cutoff = Date.now() - this.config.stalenessThreshold
    this.flowBuffer = this.flowBuffer.filter(f => f.timestamp > cutoff)
  }

  private updateConnections(flow: NetFlowRecord): void {
    // Track bidirectional connections
    const sourceKey = `${flow.sourceIP}:${flow.sourcePort}`
    const destKey = `${flow.destIP}:${flow.destPort}`
    
    if (!this.assetConnections.has(sourceKey)) {
      this.assetConnections.set(sourceKey, new Set())
    }
    this.assetConnections.get(sourceKey)!.add(destKey)
  }

  /**
   * Extract topology from observed flows
   */
  async extractTopology(): Promise<{
    assets: DiscoveredAsset[]
    edges: DiscoveredEdge[]
  }> {
    const assets: DiscoveredAsset[] = []
    const edges: DiscoveredEdge[] = []

    // Aggregate unique IPs as assets
    const uniqueIPs = new Set<string>()
    for (const flow of this.flowBuffer) {
      uniqueIPs.add(flow.sourceIP)
      uniqueIPs.add(flow.destIP)
    }

    for (const ip of uniqueIPs) {
      assets.push({
        id: `netflow-${ip}`,
        name: ip,
        type: 'unknown',
        ip: ip,
        zone: this.inferZone(ip),
        criticality: 1,
        internetFacing: this.isInternetIP(ip),
        services: [],
        source: 'passive_netflow',
        lastSeen: Date.now(),
        confidence: this.config.confidence
      })
    }

    // Create edges from observed connections
    const edgeMap = new Map<string, DiscoveredEdge>()
    
    for (const flow of this.flowBuffer) {
      const key = `${flow.sourceIP}:${flow.destIP}:${flow.protocol}`
      
      if (!edgeMap.has(key)) {
        edgeMap.set(key, {
          id: `netflow-edge-${key}`,
          sourceAssetId: `netflow-${flow.sourceIP}`,
          targetAssetId: `netflow-${flow.destIP}`,
          edgeType: 'network_connection',
          protocol: flow.protocol,
          port: flow.destPort,
          evidence: [{
            source: 'passive_netflow',
            confidence: this.config.confidence,
            probability: 1.0, // Observed connection
            rawData: { bytes: flow.bytes, packets: flow.packets },
            timestamp: flow.timestamp,
            observationType: 'direct'
          }],
          fusedConfidence: this.config.confidence,
          fusedProbability: 1.0,
          classification: 'validated',
          firstSeen: flow.timestamp,
          lastSeen: flow.timestamp,
          observationCount: 1
        })
      } else {
        const edge = edgeMap.get(key)!
        edge.lastSeen = Math.max(edge.lastSeen, flow.timestamp)
        edge.firstSeen = Math.min(edge.firstSeen, flow.timestamp)
        edge.observationCount++
      }
    }

    return { assets, edges: Array.from(edgeMap.values()) }
  }

  private inferZone(ip: string): string {
    // Basic IP-based zone inference
    if (ip.startsWith('10.')) return 'internal'
    if (ip.startsWith('192.168.')) return 'internal'
    if (ip.startsWith('172.')) {
      const secondOctet = parseInt(ip.split('.')[1])
      if (secondOctet >= 16 && secondOctet <= 31) return 'internal'
    }
    return 'dmz'
  }

  private isInternetIP(ip: string): boolean {
    // Check if IP is public
    return !ip.startsWith('10.') && 
           !ip.startsWith('192.168.') &&
           !ip.startsWith('172.') &&
           !ip.startsWith('127.') &&
           !ip.startsWith('169.254.')
  }
}

export interface NetFlowRecord {
  sourceIP: string
  sourcePort: number
  destIP: string
  destPort: number
  protocol: string
  bytes: number
  packets: number
  timestamp: number
  duration: number
}

/**
 * Active Scan Source
 * - Targeted scanning
 * - Medium confidence (0.70)
 * - May miss assets due to firewall, timing, etc.
 */
export class ActiveScanSource extends EventEmitter {
  private config: DataSourceConfig
  private scanResults: Map<string, ActiveScanResult> = new Map()

  constructor(config: DataSourceConfig) {
    super()
    this.config = config
  }

  /**
   * Execute targeted scans
   */
  async scanTargets(targets: string[]): Promise<{
    assets: DiscoveredAsset[]
    edges: DiscoveredEdge[]
  }> {
    const assets: DiscoveredAsset[] = []
    const edges: DiscoveredEdge[] = []

    for (const target of targets) {
      const result = await this.scanTarget(target)
      
      if (result.alive) {
        assets.push(this.convertToAsset(result))
        
        // Create edges for discovered services
        for (const service of result.services) {
          edges.push({
            id: `scan-edge-${target}-${service.port}`,
            sourceAssetId: 'scanner', // Would be the scanning host
            targetAssetId: `scan-${target}`,
            edgeType: 'network_connection',
            protocol: service.protocol,
            port: service.port,
            evidence: [{
              source: 'active_scan',
              confidence: this.config.confidence,
              probability: 1.0,
              rawData: { banner: service.banner, version: service.version },
              timestamp: Date.now(),
              observationType: 'direct'
            }],
            fusedConfidence: this.config.confidence,
            fusedProbability: 1.0,
            classification: 'discovered',
            firstSeen: Date.now(),
            lastSeen: Date.now(),
            observationCount: 1
          })
        }
      }
    }

    return { assets, edges }
  }

  private async scanTarget(target: string): Promise<ActiveScanResult> {
    // This would integrate with nmap, masscan, etc.
    return {
      target,
      alive: false,
      services: [],
      os: undefined,
      timestamp: Date.now()
    }
  }

  private convertToAsset(result: ActiveScanResult): DiscoveredAsset {
    return {
      id: `scan-${result.target}`,
      name: result.target,
      type: this.inferAssetType(result.services),
      ip: result.target,
      zone: 'unknown',
      criticality: 1,
      internetFacing: true, // Active scan targets are typically accessible
      services: result.services.map(s => ({
        name: s.name,
        port: s.port,
        protocol: s.protocol,
        version: s.version,
        banner: s.banner,
        authenticated: false,
        vulnerabilities: []
      })),
      source: 'active_scan',
      lastSeen: result.timestamp,
      confidence: this.config.confidence
    }
  }

  private inferAssetType(services: ScannedService[]): AssetType {
    const ports = services.map(s => s.port)
    
    if (ports.includes(88) || ports.includes(389)) return 'domain_controller'
    if (ports.includes(3306) || ports.includes(1433) || ports.includes(5432)) return 'database_server'
    if (ports.includes(80) || ports.includes(443)) return 'web_server'
    if (ports.includes(25) || ports.includes(110) || ports.includes(143)) return 'mail_server'
    if (ports.includes(445) || ports.includes(139)) return 'file_server'
    if (ports.includes(22)) return 'server'
    
    return 'unknown'
  }
}

export interface ActiveScanResult {
  target: string
  alive: boolean
  services: ScannedService[]
  os?: string
  timestamp: number
}

export interface ScannedService {
  port: number
  name: string
  protocol: 'tcp' | 'udp'
  version?: string
  banner?: string
  state: 'open' | 'filtered' | 'closed'
}

/**
 * Sidescan Source
 * - Validated attack paths
 * - Highest confidence (0.95)
 * - From previous assessments, penetration tests
 */
export class SidescanSource extends EventEmitter {
  private config: DataSourceConfig
  private validatedPaths: ValidatedPath[] = []

  constructor(config: DataSourceConfig) {
    super()
    this.config = config
  }

  /**
   * Load validated paths from previous assessments
   */
  async loadValidatedPaths(source: 'file' | 'database', location: string): Promise<void> {
    // Load from previous penetration tests, red team exercises
    // This would load actual data in production
  }

  /**
   * Import from common security tools
   */
  async importFromTool(tool: 'bloodhound' | 'crackmapexec' | 'cobaltstrike' | 'custom', data: any): Promise<{
    assets: DiscoveredAsset[]
    edges: DiscoveredEdge[]
  }> {
    // Parse tool-specific formats
    const assets: DiscoveredAsset[] = []
    const edges: DiscoveredEdge[] = []

    switch (tool) {
      case 'bloodhound':
        return this.parseBloodHound(data)
      case 'crackmapexec':
        return this.parseCrackMapExec(data)
      case 'cobaltstrike':
        return this.parseCobaltStrike(data)
      default:
        return { assets, edges }
    }
  }

  private parseBloodHound(data: any): { assets: DiscoveredAsset[]; edges: DiscoveredEdge[] } {
    // Parse BloodHound JSON export
    return { assets: [], edges: [] }
  }

  private parseCrackMapExec(data: any): { assets: DiscoveredAsset[]; edges: DiscoveredEdge[] } {
    return { assets: [], edges: [] }
  }

  private parseCobaltStrike(data: any): { assets: DiscoveredAsset[]; edges: DiscoveredEdge[] } {
    return { assets: [], edges: [] }
  }

  /**
   * Get validated attack paths
   */
  getValidatedPaths(): ValidatedPath[] {
    return this.validatedPaths
  }
}

export interface ValidatedPath {
  id: string
  name: string
  source: string
  target: string
  path: string[]
  technique: string
  validatedAt: number
  validator: string // 'pentest', 'redteam', 'automated'
  confidence: number
}

// ============================================================================
// EVIDENCE FUSION ENGINE
// ============================================================================

/**
 * Core fusion engine using Dempster-Shafer theory
 * for combining evidence from multiple sources
 */
export class EvidenceFusionEngine {
  private config: FusionConfig

  constructor(config: FusionConfig) {
    this.config = config
  }

  /**
   * Fuse multiple evidence for an edge into a single probability
   */
  fuseEvidence(evidence: EdgeEvidence[]): {
    probability: number
    confidence: number
    classification: DiscoveredEdge['classification']
  } {
    if (evidence.length === 0) {
      return { probability: 0, confidence: 0, classification: 'hypothetical' }
    }

    // Apply temporal decay
    const decayedEvidence = this.applyTemporalDecay(evidence)

    // Resolve conflicts based on configured strategy
    let fusedProb: number
    let fusedConf: number

    switch (this.config.conflictResolution) {
      case 'dempster_shafer':
        const dsResult = this.dempsterShaferFusion(decayedEvidence)
        fusedProb = dsResult.probability
        fusedConf = dsResult.confidence
        break
      
      case 'weighted_average':
        fusedProb = this.weightedAverage(decayedEvidence)
        fusedConf = this.averageConfidence(decayedEvidence)
        break
      
      case 'max_confidence':
        const best = decayedEvidence.reduce((a, b) => 
          a.confidence > b.confidence ? a : b
        )
        fusedProb = best.probability
        fusedConf = best.confidence
        break
      
      default:
        fusedProb = this.weightedAverage(decayedEvidence)
        fusedConf = this.averageConfidence(decayedEvidence)
    }

    // Determine classification
    const classification = this.classifyEdge(decayedEvidence)

    return { probability: fusedProb, confidence: fusedConf, classification }
  }

  /**
   * Dempster-Shafer evidence combination
   * Handles conflicting evidence more gracefully than simple averaging
   */
  private dempsterShaferFusion(evidence: EdgeEvidence[]): { probability: number; confidence: number } {
    // Define frame of discernment: {Edge_Exists, Edge_Does_Not_Exist}
    // Basic probability assignments from each source
    
    let beliefExists = 0
    let beliefNotExists = 0
    let uncertainty = 1

    for (const e of evidence) {
      const sourceConf = e.confidence
      const prob = e.probability
      
      // Mass function: m(Exists) = confidence * probability
      //               m(NotExists) = confidence * (1 - probability)
      //               m(Uncertain) = 1 - confidence
      
      const mExists = sourceConf * prob
      const mNotExists = sourceConf * (1 - prob)
      const mUncertain = 1 - sourceConf

      // Dempster's combination rule
      // K = 1 - m1(Exists) * m2(NotExists) - m1(NotExists) * m2(Exists)
      const K = 1 - (beliefExists * mNotExists + beliefNotExists * mExists)
      
      if (K > 0) {
        beliefExists = (beliefExists * mExists + beliefExists * mUncertain + uncertainty * mExists) / K
        beliefNotExists = (beliefNotExists * mNotExists + beliefNotExists * mUncertain + uncertainty * mNotExists) / K
        uncertainty = (uncertainty * mUncertain) / K
      }
    }

    return {
      probability: beliefExists,
      confidence: 1 - uncertainty
    }
  }

  private weightedAverage(evidence: EdgeEvidence[]): number {
    let totalWeight = 0
    let weightedSum = 0

    for (const e of evidence) {
      const weight = e.confidence * this.getSourceWeight(e.source)
      weightedSum += e.probability * weight
      totalWeight += weight
    }

    return totalWeight > 0 ? weightedSum / totalWeight : 0.5
  }

  private averageConfidence(evidence: EdgeEvidence[]): number {
    if (evidence.length === 0) return 0
    const sum = evidence.reduce((acc, e) => acc + e.confidence, 0)
    return sum / evidence.length
  }

  private getSourceWeight(source: DataSourceType): number {
    const weights: Record<DataSourceType, number> = {
      sidescan: 1.0,
      api_discovery: 0.9,
      passive_netflow: 0.85,
      active_scan: 0.7
    }
    return weights[source]
  }

  private applyTemporalDecay(evidence: EdgeEvidence[]): EdgeEvidence[] {
    if (!this.config.temporalDecay.enabled) return evidence

    const now = Date.now()
    const halfLife = this.config.temporalDecay.halfLife

    return evidence.map(e => {
      const age = now - e.timestamp
      const decayFactor = Math.pow(0.5, age / halfLife)
      
      return {
        ...e,
        confidence: e.confidence * decayFactor
      }
    })
  }

  private classifyEdge(evidence: EdgeEvidence[]): DiscoveredEdge['classification'] {
    // Classification based on observation type and source quality
    
    // Validated: Direct observation from NetFlow or Sidescan
    const hasValidatedSource = evidence.some(e => 
      (e.source === 'passive_netflow' || e.source === 'sidescan') &&
      e.observationType === 'direct'
    )
    
    if (hasValidatedSource) return 'validated'

    // Discovered: From API Discovery or Active Scan
    const hasDiscoveredSource = evidence.some(e => 
      e.source === 'api_discovery' || e.source === 'active_scan'
    )
    
    if (hasDiscoveredSource) return 'discovered'

    // Inferred: Multiple sources agree
    if (evidence.length >= this.config.crossValidation.minSources) {
      return 'inferred'
    }

    return 'hypothetical'
  }

  /**
   * Cross-validate edges between sources
   */
  crossValidate(edges: DiscoveredEdge[]): Map<string, {
    validated: boolean
    sources: DataSourceType[]
    confidenceBoost: number
  }> {
    const results = new Map<string, {
      validated: boolean
      sources: DataSourceType[]
      confidenceBoost: number
    }>()

    for (const edge of edges) {
      const sources = new Set(edge.evidence.map(e => e.source))
      const sourceCount = sources.size
      
      // Cross-validation bonus
      let confidenceBoost = 0
      if (sourceCount >= 2) confidenceBoost = 0.1
      if (sourceCount >= 3) confidenceBoost = 0.2
      if (sourceCount >= 4) confidenceBoost = 0.3
      
      // Special bonus for Sidescan + NetFlow agreement
      if (sources.has('sidescan') && sources.has('passive_netflow')) {
        confidenceBoost += 0.15
      }

      results.set(edge.id, {
        validated: sourceCount >= this.config.crossValidation.minSources,
        sources: Array.from(sources),
        confidenceBoost
      })
    }

    return results
  }
}

// ============================================================================
// MULTI-SOURCE FUSION ORCHESTRATOR
// ============================================================================

export class MultiSourceFusionOrchestrator {
  private config: FusionConfig
  private apiDiscovery: APIDiscoverySource
  private netFlow: PassiveNetFlowSource
  private activeScan: ActiveScanSource
  private sidescan: SidescanSource
  private fusionEngine: EvidenceFusionEngine
  
  private assetRegistry: Map<string, DiscoveredAsset> = new Map()
  private edgeRegistry: Map<string, DiscoveredEdge> = new Map()

  constructor(config?: Partial<FusionConfig>) {
    this.config = this.buildDefaultConfig(config)
    
    this.apiDiscovery = new APIDiscoverySource(this.config.sources.api_discovery)
    this.netFlow = new PassiveNetFlowSource(this.config.sources.passive_netflow)
    this.activeScan = new ActiveScanSource(this.config.sources.active_scan)
    this.sidescan = new SidescanSource(this.config.sources.sidescan)
    this.fusionEngine = new EvidenceFusionEngine(this.config)
  }

  private buildDefaultConfig(partial?: Partial<FusionConfig>): FusionConfig {
    return {
      sources: {
        api_discovery: {
          enabled: true,
          confidence: 0.90,
          stalenessThreshold: 86400000, // 24 hours
          priority: 2,
          coverage: 1.0 // 100%
        },
        passive_netflow: {
          enabled: true,
          confidence: 0.85,
          stalenessThreshold: 3600000, // 1 hour
          priority: 3,
          coverage: 0.95
        },
        active_scan: {
          enabled: true,
          confidence: 0.70,
          stalenessThreshold: 604800000, // 7 days
          priority: 4,
          coverage: 0.6 // Targeted
        },
        sidescan: {
          enabled: true,
          confidence: 0.95,
          stalenessThreshold: 2592000000, // 30 days
          priority: 1,
          coverage: 0.4 // Only validated paths
        }
      },
      conflictResolution: 'dempster_shafer',
      temporalDecay: {
        enabled: true,
        halfLife: 604800000 // 7 days
      },
      crossValidation: {
        enabled: true,
        minSources: 2
      },
      ...partial
    }
  }

  /**
   * Collect from all enabled sources
   */
  async collectAll(): Promise<FusionResult> {
    const startTime = Date.now()
    const collections: Promise<SourceCollectionResult>[] = []

    // Collect from each enabled source
    if (this.config.sources.api_discovery.enabled) {
      collections.push(this.collectFromAPI())
    }
    if (this.config.sources.passive_netflow.enabled) {
      collections.push(this.collectFromNetFlow())
    }
    if (this.config.sources.active_scan.enabled) {
      collections.push(this.collectFromActiveScan())
    }
    if (this.config.sources.sidescan.enabled) {
      collections.push(this.collectFromSidescan())
    }

    // Wait for all collections
    const results = await Promise.all(collections)

    // Merge assets
    for (const result of results) {
      for (const asset of result.assets) {
        this.mergeAsset(asset)
      }
    }

    // Merge edges with evidence fusion
    for (const result of results) {
      for (const edge of result.edges) {
        this.mergeEdge(edge)
      }
    }

    // Cross-validate all edges
    const validations = this.fusionEngine.crossValidate(
      Array.from(this.edgeRegistry.values())
    )

    // Apply confidence boosts
    for (const [edgeId, validation] of validations) {
      const edge = this.edgeRegistry.get(edgeId)
      if (edge) {
        edge.fusedConfidence = Math.min(
          edge.fusedConfidence + validation.confidenceBoost,
          1.0
        )
      }
    }

    return {
      assets: Array.from(this.assetRegistry.values()),
      edges: Array.from(this.edgeRegistry.values()),
      stats: {
        totalAssets: this.assetRegistry.size,
        totalEdges: this.edgeRegistry.size,
        validatedEdges: Array.from(this.edgeRegistry.values())
          .filter(e => e.classification === 'validated').length,
        sourceCoverage: this.computeSourceCoverage(results),
        collectionTime: Date.now() - startTime
      }
    }
  }

  private async collectFromAPI(): Promise<SourceCollectionResult> {
    const result = await this.apiDiscovery.collect()
    return {
      source: 'api_discovery',
      assets: result.assets,
      edges: result.edges,
      confidence: this.config.sources.api_discovery.confidence
    }
  }

  private async collectFromNetFlow(): Promise<SourceCollectionResult> {
    const result = await this.netFlow.extractTopology()
    return {
      source: 'passive_netflow',
      assets: result.assets,
      edges: result.edges,
      confidence: this.config.sources.passive_netflow.confidence
    }
  }

  private async collectFromActiveScan(): Promise<SourceCollectionResult> {
    // Would scan configured targets
    return {
      source: 'active_scan',
      assets: [],
      edges: [],
      confidence: this.config.sources.active_scan.confidence
    }
  }

  private async collectFromSidescan(): Promise<SourceCollectionResult> {
    // Would load validated paths
    return {
      source: 'sidescan',
      assets: [],
      edges: [],
      confidence: this.config.sources.sidescan.confidence
    }
  }

  private mergeAsset(asset: DiscoveredAsset): void {
    const existing = this.assetRegistry.get(asset.id)
    
    if (!existing) {
      this.assetRegistry.set(asset.id, asset)
      return
    }

    // Merge: keep the one with higher confidence or more recent
    if (asset.confidence > existing.confidence || asset.lastSeen > existing.lastSeen) {
      // Merge services
      const mergedServices = this.mergeServices(existing.services, asset.services)
      this.assetRegistry.set(asset.id, {
        ...asset,
        services: mergedServices,
        confidence: Math.max(asset.confidence, existing.confidence)
      })
    }
  }

  private mergeServices(existing: DiscoveredService[], newServices: DiscoveredService[]): DiscoveredService[] {
    const merged = new Map<string, DiscoveredService>()
    
    for (const service of [...existing, ...newServices]) {
      const key = `${service.port}:${service.protocol}`
      merged.set(key, service)
    }
    
    return Array.from(merged.values())
  }

  private mergeEdge(edge: DiscoveredEdge): void {
    const key = `${edge.sourceAssetId}:${edge.targetAssetId}:${edge.edgeType}`
    const existing = this.edgeRegistry.get(key)
    
    if (!existing) {
      this.edgeRegistry.set(key, edge)
      return
    }

    // Merge evidence
    const allEvidence = [...existing.evidence, ...edge.evidence]
    
    // Fuse probabilities
    const fused = this.fusionEngine.fuseEvidence(allEvidence)
    
    // Update edge
    this.edgeRegistry.set(key, {
      ...existing,
      evidence: allEvidence,
      fusedConfidence: fused.confidence,
      fusedProbability: fused.probability,
      classification: fused.classification,
      firstSeen: Math.min(existing.firstSeen, edge.firstSeen),
      lastSeen: Math.max(existing.lastSeen, edge.lastSeen),
      observationCount: existing.observationCount + edge.observationCount
    })
  }

  private computeSourceCoverage(results: SourceCollectionResult[]): Record<DataSourceType, number> {
    const coverage: Record<string, number> = {}
    
    for (const result of results) {
      coverage[result.source] = result.assets.length > 0 
        ? result.assets.length / this.assetRegistry.size 
        : 0
    }
    
    return coverage as Record<DataSourceType, number>
  }

  /**
   * Get assets suitable for attack path analysis
   */
  getAssetsForAnalysis(): DiscoveredAsset[] {
    return Array.from(this.assetRegistry.values())
      .filter(a => a.confidence >= 0.5) // Filter low-confidence assets
  }

  /**
   * Get edges suitable for attack path analysis
   */
  getEdgesForAnalysis(): DiscoveredEdge[] {
    return Array.from(this.edgeRegistry.values())
      .filter(e => e.fusedConfidence >= 0.5) // Filter low-confidence edges
  }

  /**
   * Export to format compatible with EnhancedAttackGraphEngine
   */
  exportForAttackEngine(): {
    assets: FusedAsset[]
    edges: FusedEdge[]
  } {
    const assets: FusedAsset[] = []
    const edges: FusedEdge[] = []

    for (const asset of this.assetRegistry.values()) {
      assets.push({
        id: asset.id,
        name: asset.name,
        type: asset.type,
        ip: asset.ip,
        zone: asset.zone,
        criticality: asset.criticality,
        internet_facing: asset.internetFacing,
        services: asset.services.map(s => s.name),
        data_sensitivity: this.inferDataSensitivity(asset),
        misconfigurations: this.extractMisconfigurations(asset),
        evidence: this.buildEvidenceBundle(asset),
        source_confidence: asset.confidence
      })
    }

    for (const edge of this.edgeRegistry.values()) {
      edges.push({
        source_id: edge.sourceAssetId,
        target_id: edge.targetAssetId,
        edge_type: edge.edgeType,
        protocol: edge.protocol,
        port: edge.port,
        probability: edge.fusedProbability,
        confidence: edge.fusedConfidence,
        classification: edge.classification,
        evidence_count: edge.evidence.length,
        observation_count: edge.observationCount
      })
    }

    return { assets, edges }
  }

  private inferDataSensitivity(asset: DiscoveredAsset): string {
    // Infer from asset type and services
    if (asset.type === 'database_server') return 'financial'
    if (asset.type === 'domain_controller') return 'credentials'
    if (asset.type === 'file_server') return 'user_files'
    if (asset.services.some(s => s.port === 443)) return 'user_data'
    return 'business_logic'
  }

  private extractMisconfigurations(asset: DiscoveredAsset): any[] {
    const misconfigurations: any[] = []
    
    for (const service of asset.services) {
      for (const vuln of service.vulnerabilities) {
        misconfigurations.push({
          id: vuln.id,
          title: vuln.title,
          description: `Vulnerability on port ${service.port}`,
          category: 'service',
          severity: vuln.severity,
          cvss: vuln.cvss,
          exploit_available: vuln.exploitAvailable,
          epss: vuln.epss
        })
      }
    }
    
    return misconfigurations
  }

  private buildEvidenceBundle(asset: DiscoveredAsset): any {
    return {
      vulnerability_scanner: {
        confidence: asset.source === 'active_scan' ? 0.7 : 0.5,
        last_updated: asset.lastSeen,
        data: {}
      },
      siem_alerts: {
        confidence: 0.5,
        last_updated: Date.now(),
        data: {}
      },
      threat_intelligence: {
        confidence: 0.6,
        last_updated: Date.now(),
        data: {}
      },
      historical_attacks: {
        confidence: asset.source === 'sidescan' ? 0.9 : 0.3,
        last_updated: Date.now(),
        data: {}
      },
      network_flow: {
        confidence: asset.source === 'passive_netflow' ? 0.85 : 0.4,
        last_updated: asset.lastSeen,
        data: {}
      }
    }
  }
}

// ============================================================================
// EXPORT TYPES
// ============================================================================

export interface FusionResult {
  assets: DiscoveredAsset[]
  edges: DiscoveredEdge[]
  stats: {
    totalAssets: number
    totalEdges: number
    validatedEdges: number
    sourceCoverage: Record<DataSourceType, number>
    collectionTime: number
  }
}

export interface SourceCollectionResult {
  source: DataSourceType
  assets: DiscoveredAsset[]
  edges: DiscoveredEdge[]
  confidence: number
}

export interface FusedAsset {
  id: string
  name: string
  type: string
  ip: string
  zone: string
  criticality: number
  internet_facing: boolean
  services: string[]
  data_sensitivity: string
  misconfigurations: any[]
  evidence: any
  source_confidence: number
}

export interface FusedEdge {
  source_id: string
  target_id: string
  edge_type: string
  protocol: string
  port?: number
  probability: number
  confidence: number
  classification: string
  evidence_count: number
  observation_count: number
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  APIDiscoverySource,
  PassiveNetFlowSource,
  ActiveScanSource,
  SidescanSource,
  EvidenceFusionEngine
}
