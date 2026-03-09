// ============================================================================
// ZONE DETECTION MODULE
// Detects network zone (DMZ/Internal/Restricted) for assets
// ============================================================================

// ============================================================================
// TYPES
// ============================================================================

export interface NetworkZone {
  id: string
  name: string
  type: 'dmz' | 'internal' | 'restricted' | 'airgap' | 'cloud' | 'unknown'
  cidrs: string[]
  vlanIds?: number[]
  description: string
  trustLevel: number  // 1-5, lower = less trusted
  allowsInternetAccess: boolean
  allowsInternalAccess: boolean
}

export interface ZoneDetectionResult {
  assetId: string
  host: string
  detectedZone: NetworkZone['type']
  confidence: number  // 0-1
  evidence: ZoneEvidence
  metadata: Record<string, any>
}

export interface ZoneEvidence {
  ipMatch?: { ip: string; cidr: string; zone: string }
  vlanMatch?: { vlanId: number; zone: string }
  networkPath?: { path: string[]; zone: string }
  serviceName?: { service: string; zone: string }
  cloudMetadata?: { provider: string; region: string; zone: string }
}

export interface ZoneRule {
  type: 'cidr' | 'vlan' | 'hostname' | 'service' | 'cloud'
  pattern: string | RegExp
  zone: NetworkZone['type']
  confidence: number
  description: string
}

// ============================================================================
// ZONE REGISTRY
// ============================================================================

class ZoneRegistry {
  private zones: Map<string, NetworkZone> = new Map()
  private rules: ZoneRule[] = []

  constructor() {
    this.initializeDefaultZones()
    this.initializeDefaultRules()
  }

  private initializeDefaultZones(): void {
    const defaultZones: NetworkZone[] = [
      {
        id: 'dmz',
        name: 'DMZ',
        type: 'dmz',
        cidrs: ['192.168.0.0/24', '10.0.0.0/24', '172.16.0.0/24'],
        vlanIds: [10, 20, 30],
        description: 'Demilitarized Zone - Internet-facing services',
        trustLevel: 1,
        allowsInternetAccess: true,
        allowsInternalAccess: true,
      },
      {
        id: 'internal',
        name: 'Internal Network',
        type: 'internal',
        cidrs: ['10.1.0.0/16', '10.2.0.0/16', '172.20.0.0/16', '192.168.1.0/24'],
        vlanIds: [100, 101, 102, 200, 201],
        description: 'Internal network - Employee workstations and servers',
        trustLevel: 3,
        allowsInternetAccess: true,
        allowsInternalAccess: true,
      },
      {
        id: 'restricted',
        name: 'Restricted Zone',
        type: 'restricted',
        cidrs: ['10.10.0.0/16', '10.100.0.0/16', '172.30.0.0/16'],
        vlanIds: [500, 501, 502, 600],
        description: 'Restricted zone - Critical systems and data',
        trustLevel: 5,
        allowsInternetAccess: false,
        allowsInternalAccess: true,
      },
      {
        id: 'airgap',
        name: 'Air-Gapped',
        type: 'airgap',
        cidrs: ['10.255.0.0/16'],
        vlanIds: [900, 901],
        description: 'Air-gapped network - No external connectivity',
        trustLevel: 5,
        allowsInternetAccess: false,
        allowsInternalAccess: false,
      },
      {
        id: 'cloud',
        name: 'Cloud Infrastructure',
        type: 'cloud',
        cidrs: [],  // Dynamic based on cloud provider
        description: 'Cloud infrastructure (AWS, Azure, GCP)',
        trustLevel: 2,
        allowsInternetAccess: true,
        allowsInternalAccess: true,
      },
    ]

    for (const zone of defaultZones) {
      this.zones.set(zone.id, zone)
    }
  }

  private initializeDefaultRules(): void {
    this.rules = [
      // CIDR-based rules
      { type: 'cidr', pattern: '192.168.0.0/24', zone: 'dmz', confidence: 0.9, description: 'Standard DMZ range' },
      { type: 'cidr', pattern: '10.0.0.0/24', zone: 'dmz', confidence: 0.8, description: 'DMZ range in 10.x' },
      { type: 'cidr', pattern: '10.1.0.0/16', zone: 'internal', confidence: 0.9, description: 'Internal range 1' },
      { type: 'cidr', pattern: '10.2.0.0/16', zone: 'internal', confidence: 0.9, description: 'Internal range 2' },
      { type: 'cidr', pattern: '10.10.0.0/16', zone: 'restricted', confidence: 0.9, description: 'Restricted range' },
      { type: 'cidr', pattern: '10.100.0.0/16', zone: 'restricted', confidence: 0.9, description: 'Data center range' },
      { type: 'cidr', pattern: '10.255.0.0/16', zone: 'airgap', confidence: 0.95, description: 'Air-gapped range' },
      
      // Hostname patterns
      { type: 'hostname', pattern: /^dmz-/i, zone: 'dmz', confidence: 0.85, description: 'DMZ hostname prefix' },
      { type: 'hostname', pattern: /^ext-/i, zone: 'dmz', confidence: 0.8, description: 'External hostname prefix' },
      { type: 'hostname', pattern: /^web\d/i, zone: 'dmz', confidence: 0.7, description: 'Web server naming' },
      { type: 'hostname', pattern: /^dc\d/i, zone: 'restricted', confidence: 0.8, description: 'Domain controller naming' },
      { type: 'hostname', pattern: /^db\d/i, zone: 'restricted', confidence: 0.75, description: 'Database server naming' },
      { type: 'hostname', pattern: /^corp-/i, zone: 'internal', confidence: 0.8, description: 'Corporate hostname prefix' },
      { type: 'hostname', pattern: /^ws-/i, zone: 'internal', confidence: 0.7, description: 'Workstation naming' },
      
      // Service-based rules
      { type: 'service', pattern: 'iis', zone: 'dmz', confidence: 0.6, description: 'IIS web server' },
      { type: 'service', pattern: 'nginx', zone: 'dmz', confidence: 0.6, description: 'Nginx web server' },
      { type: 'service', pattern: 'apache', zone: 'dmz', confidence: 0.6, description: 'Apache web server' },
      { type: 'service', pattern: 'active-directory', zone: 'restricted', confidence: 0.7, description: 'Active Directory' },
      { type: 'service', pattern: 'sql-server', zone: 'restricted', confidence: 0.7, description: 'SQL Server' },
      
      // Cloud patterns
      { type: 'cloud', pattern: 'aws', zone: 'cloud', confidence: 0.9, description: 'AWS cloud' },
      { type: 'cloud', pattern: 'azure', zone: 'cloud', confidence: 0.9, description: 'Azure cloud' },
      { type: 'cloud', pattern: 'gcp', zone: 'cloud', confidence: 0.9, description: 'GCP cloud' },
    ]
  }

  /**
   * Add a custom zone
   */
  addZone(zone: NetworkZone): void {
    this.zones.set(zone.id, zone)
  }

  /**
   * Add a custom rule
   */
  addRule(rule: ZoneRule): void {
    this.rules.push(rule)
  }

  /**
   * Get all zones
   */
  getZones(): NetworkZone[] {
    return Array.from(this.zones.values())
  }

  /**
   * Get zone by ID
   */
  getZone(id: string): NetworkZone | undefined {
    return this.zones.get(id)
  }

  /**
   * Get all rules
   */
  getRules(): ZoneRule[] {
    return [...this.rules]
  }

  /**
   * Get rules by type
   */
  getRulesByType(type: ZoneRule['type']): ZoneRule[] {
    return this.rules.filter(r => r.type === type)
  }
}

// ============================================================================
// CIDR MATCHER
// ============================================================================

class CIDRMatcher {
  /**
   * Check if IP is in CIDR range
   */
  static match(ip: string, cidr: string): boolean {
    const [range, bits] = cidr.split('/')
    const mask = parseInt(bits, 10)
    
    const ipNum = this.ipToNumber(ip)
    const rangeNum = this.ipToNumber(range)
    
    if (ipNum === null || rangeNum === null) return false
    
    const maskNum = ~((1 << (32 - mask)) - 1)
    
    return (ipNum & maskNum) === (rangeNum & maskNum)
  }

  /**
   * Find best matching CIDR from list
   */
  static findBestMatch(ip: string, cidrs: string[]): string | null {
    let bestMatch: string | null = null
    let bestBits = -1
    
    for (const cidr of cidrs) {
      const bits = parseInt(cidr.split('/')[1], 10)
      
      if (this.match(ip, cidr) && bits > bestBits) {
        bestMatch = cidr
        bestBits = bits
      }
    }
    
    return bestMatch
  }

  private static ipToNumber(ip: string): number | null {
    const parts = ip.split('.').map(p => parseInt(p, 10))
    
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
      return null
    }
    
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
  }
}

// ============================================================================
// ZONE DETECTOR
// ============================================================================

export class ZoneDetector {
  private registry: ZoneRegistry

  constructor() {
    this.registry = new ZoneRegistry()
  }

  /**
   * Detect zone for an asset
   */
  detect(asset: {
    id: string
    host: string
    ip?: string
    hostname?: string
    vlanId?: number
    services?: string[]
    cloudMetadata?: { provider: string; region: string }
  }): ZoneDetectionResult {
    const evidences: Array<{ zone: NetworkZone['type']; confidence: number; evidence: ZoneEvidence }> = []

    // 1. CIDR-based detection (highest confidence)
    if (asset.ip) {
      const cidrMatch = this.detectByCIDR(asset.ip)
      if (cidrMatch) {
        evidences.push(cidrMatch)
      }
    }

    // 2. VLAN-based detection
    if (asset.vlanId !== undefined) {
      const vlanMatch = this.detectByVLAN(asset.vlanId)
      if (vlanMatch) {
        evidences.push(vlanMatch)
      }
    }

    // 3. Hostname-based detection
    if (asset.hostname) {
      const hostnameMatch = this.detectByHostname(asset.hostname)
      if (hostnameMatch) {
        evidences.push(hostnameMatch)
      }
    }

    // 4. Service-based detection
    if (asset.services?.length) {
      const serviceMatch = this.detectByServices(asset.services)
      if (serviceMatch) {
        evidences.push(serviceMatch)
      }
    }

    // 5. Cloud metadata detection
    if (asset.cloudMetadata) {
      const cloudMatch = this.detectByCloudMetadata(asset.cloudMetadata)
      if (cloudMatch) {
        evidences.push(cloudMatch)
      }
    }

    // Combine evidence and determine best zone
    if (evidences.length === 0) {
      return {
        assetId: asset.id,
        host: asset.host,
        detectedZone: 'unknown',
        confidence: 0,
        evidence: {},
        metadata: {},
      }
    }

    // Weight and combine
    const zoneScores: Record<string, { total: number; evidence: ZoneEvidence }> = {}
    
    for (const e of evidences) {
      const zone = e.zone
      if (!zoneScores[zone]) {
        zoneScores[zone] = { total: 0, evidence: {} }
      }
      zoneScores[zone].total += e.confidence
      zoneScores[zone].evidence = { ...zoneScores[zone].evidence, ...e.evidence }
    }

    // Find best zone
    let bestZone: NetworkZone['type'] = 'unknown'
    let bestScore = 0
    let bestEvidence: ZoneEvidence = {}

    for (const [zone, data] of Object.entries(zoneScores)) {
      if (data.total > bestScore) {
        bestScore = data.total
        bestZone = zone as NetworkZone['type']
        bestEvidence = data.evidence
      }
    }

    // Normalize confidence
    const confidence = Math.min(1, bestScore / evidences.length)

    return {
      assetId: asset.id,
      host: asset.host,
      detectedZone: bestZone,
      confidence,
      evidence: bestEvidence,
      metadata: { allEvidences: evidences },
    }
  }

  /**
   * Batch detect zones for multiple assets
   */
  detectBatch(assets: Array<Parameters<typeof this.detect>[0]>): ZoneDetectionResult[] {
    return assets.map(a => this.detect(a))
  }

  /**
   * Get zone information
   */
  getZone(zoneId: string): NetworkZone | undefined {
    return this.registry.getZone(zoneId)
  }

  /**
   * Get all zones
   */
  getZones(): NetworkZone[] {
    return this.registry.getZones()
  }

  /**
   * Add custom zone rule
   */
  addRule(rule: ZoneRule): void {
    this.registry.addRule(rule)
  }

  // Private detection methods

  private detectByCIDR(ip: string): { zone: NetworkZone['type']; confidence: number; evidence: ZoneEvidence } | null {
    const cidrRules = this.registry.getRulesByType('cidr')
    
    for (const rule of cidrRules) {
      if (CIDRMatcher.match(ip, rule.pattern as string)) {
        return {
          zone: rule.zone,
          confidence: rule.confidence,
          evidence: { ipMatch: { ip, cidr: rule.pattern as string, zone: rule.zone } },
        }
      }
    }
    
    return null
  }

  private detectByVLAN(vlanId: number): { zone: NetworkZone['type']; confidence: number; evidence: ZoneEvidence } | null {
    const zones = this.registry.getZones()
    
    for (const zone of zones) {
      if (zone.vlanIds?.includes(vlanId)) {
        return {
          zone: zone.type,
          confidence: 0.85,
          evidence: { vlanMatch: { vlanId, zone: zone.type } },
        }
      }
    }
    
    return null
  }

  private detectByHostname(hostname: string): { zone: NetworkZone['type']; confidence: number; evidence: ZoneEvidence } | null {
    const hostnameRules = this.registry.getRulesByType('hostname')
    
    for (const rule of hostnameRules) {
      const pattern = rule.pattern instanceof RegExp 
        ? rule.pattern 
        : new RegExp(rule.pattern as string, 'i')
      
      if (pattern.test(hostname)) {
        return {
          zone: rule.zone,
          confidence: rule.confidence,
          evidence: { serviceName: { service: hostname, zone: rule.zone } },
        }
      }
    }
    
    return null
  }

  private detectByServices(services: string[]): { zone: NetworkZone['type']; confidence: number; evidence: ZoneEvidence } | null {
    const serviceRules = this.registry.getRulesByType('service')
    const matches: Array<{ zone: NetworkZone['type']; confidence: number }> = []
    
    for (const service of services) {
      for (const rule of serviceRules) {
        if (service.toLowerCase().includes((rule.pattern as string).toLowerCase())) {
          matches.push({ zone: rule.zone, confidence: rule.confidence })
        }
      }
    }
    
    if (matches.length === 0) return null
    
    // Return most common zone with average confidence
    const zoneCounts: Record<string, { count: number; totalConfidence: number }> = {}
    
    for (const m of matches) {
      if (!zoneCounts[m.zone]) {
        zoneCounts[m.zone] = { count: 0, totalConfidence: 0 }
      }
      zoneCounts[m.zone].count++
      zoneCounts[m.zone].totalConfidence += m.confidence
    }
    
    let bestZone: NetworkZone['type'] = 'internal'
    let bestScore = 0
    
    for (const [zone, data] of Object.entries(zoneCounts)) {
      const score = data.count * data.totalConfidence
      if (score > bestScore) {
        bestScore = score
        bestZone = zone as NetworkZone['type']
      }
    }
    
    return {
      zone: bestZone,
      confidence: zoneCounts[bestZone].totalConfidence / zoneCounts[bestZone].count,
      evidence: { serviceName: { service: services.join(', '), zone: bestZone } },
    }
  }

  private detectByCloudMetadata(
    metadata: { provider: string; region: string }
  ): { zone: NetworkZone['type']; confidence: number; evidence: ZoneEvidence } | null {
    const cloudRules = this.registry.getRulesByType('cloud')
    
    for (const rule of cloudRules) {
      if (metadata.provider.toLowerCase().includes((rule.pattern as string).toLowerCase())) {
        return {
          zone: rule.zone,
          confidence: rule.confidence,
          evidence: { cloudMetadata: { provider: metadata.provider, region: metadata.region, zone: rule.zone } },
        }
      }
    }
    
    return null
  }
}

// ============================================================================
// ZONE REACHABILITY
// ============================================================================

export class ZoneReachability {
  /**
   * Check if source zone can reach target zone
   */
  static canReach(source: NetworkZone['type'], target: NetworkZone['type']): boolean {
    // Zone reachability matrix
    const reachability: Record<string, NetworkZone['type'][]> = {
      dmz: ['internal', 'dmz'],
      internal: ['internal', 'restricted', 'dmz'],
      restricted: ['restricted', 'internal'],
      airgap: ['airgap'],
      cloud: ['cloud', 'dmz', 'internal'],
      unknown: ['unknown', 'dmz', 'internal'],
    }
    
    return reachability[source]?.includes(target) ?? false
  }

  /**
   * Get all reachable zones from source
   */
  static getReachableZones(source: NetworkZone['type']): NetworkZone['type'][] {
    const reachability: Record<string, NetworkZone['type'][]> = {
      dmz: ['internal', 'dmz'],
      internal: ['internal', 'restricted', 'dmz'],
      restricted: ['restricted', 'internal'],
      airgap: ['airgap'],
      cloud: ['cloud', 'dmz', 'internal'],
      unknown: ['unknown', 'dmz', 'internal'],
    }
    
    return reachability[source] || []
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export { ZoneRegistry, CIDRMatcher }
