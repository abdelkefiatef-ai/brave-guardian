// ============================================================================
// NETWORK TOPOLOGY COLLECTORS
// Collects identity and access information for attack path analysis
// ============================================================================

// ============================================================================
// TYPES
// ============================================================================

export interface NetworkTopology {
  assets: TopologyAsset[]
  connections: TopologyConnection[]
  identityInfo: IdentityInformation
  accessPaths: AccessPath[]
  trustBoundaries: TrustBoundary[]
}

export interface TopologyAsset {
  id: string
  name: string
  type: AssetType
  ip: string
  zone: string
  criticality: number
  internetFacing: boolean
  services: ServiceInfo[]
  credentials: CredentialInfo[]
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
  | 'container_host'
  | 'unknown'

export interface ServiceInfo {
  name: string
  port: number
  protocol: 'tcp' | 'udp'
  version?: string
  banner?: string
  authenticated?: boolean
}

export interface CredentialInfo {
  type: 'local' | 'domain' | 'service' | 'api_key' | 'certificate'
  username: string
  scope: string[]
  lastUsed?: number
  privileged: boolean
}

export interface TopologyConnection {
  sourceId: string
  targetId: string
  type: ConnectionType
  protocol: string
  port?: number
  bidirectional: boolean
  allowedBy?: string  // Firewall rule or policy name
}

export type ConnectionType = 
  | 'network'
  | 'authentication'
  | 'trust'
  | 'replication'
  | 'backup'
  | 'management'
  | 'data_flow'

export interface IdentityInformation {
  domainName?: string
  domainControllers: string[]
  users: UserInfo[]
  groups: GroupInfo[]
  serviceAccounts: ServiceAccountInfo[]
  trusts: DomainTrust[]
  gpos: GPOInfo[]
}

export interface UserInfo {
  username: string
  domain: string
  enabled: boolean
  adminCount: boolean
  lastLogon?: number
  passwordLastSet?: number
  memberOf: string[]
  servicePrincipalNames?: string[]
  delegatedAuth?: boolean
  preAuthDisabled?: boolean
}

export interface GroupInfo {
  name: string
  domain: string
  type: 'security' | 'distribution'
  members: string[]
  adminCount: boolean
  nestedGroups: string[]
}

export interface ServiceAccountInfo {
  name: string
  domain: string
  serviceType: string
  runsAs: string
  passwordAge: number
  delegated: boolean
  spns: string[]
}

export interface DomainTrust {
  sourceDomain: string
  targetDomain: string
  type: 'parent-child' | 'tree-root' | 'external' | 'forest'
  direction: 'inbound' | 'outbound' | 'bidirectional'
  transitive: boolean
  sidFiltering: boolean
}

export interface GPOInfo {
  name: string
  guid: string
  links: string[]
  settings: Record<string, any>
  securityFiltering: string[]
}

export interface AccessPath {
  id: string
  source: string
  target: string
  path: string[]
  method: AccessMethod
  probability: number
  credentials?: string[]
}

export type AccessMethod = 
  | 'remote_desktop'
  | 'ssh'
  | 'winrm'
  | 'psremoting'
  | 'wmi'
  | 'smb'
  | 'ldap'
  | 'sql'
  | 'http'
  | 'https'

export interface TrustBoundary {
  id: string
  name: string
  type: 'network' | 'authentication' | 'data'
  assets: string[]
  controls: SecurityControl[]
}

export interface SecurityControl {
  type: string
  name: string
  enabled: boolean
  configuration: Record<string, any>
}

// ============================================================================
// IDENTITY COLLECTOR
// ============================================================================

export class IdentityCollector {
  /**
   * Collect identity information from Active Directory
   */
  async collectFromAD(
    domainController: string,
    credentials: { username: string; password: string }
  ): Promise<IdentityInformation> {
    // This would use LDAP/SAMR to query AD
    // For now, return structure
    
    return {
      domainName: 'corp.local',
      domainControllers: [domainController],
      users: [],
      groups: [],
      serviceAccounts: [],
      trusts: [],
      gpos: [],
    }
  }

  /**
   * Parse LDAP user entry
   */
  parseLDAPUser(entry: Record<string, string[]>): UserInfo {
    return {
      username: entry.sAMAccountName?.[0] || '',
      domain: entry.distinguishedName?.[0]?.split(',DC=')[1]?.replace('DC=', '') || '',
      enabled: !entry.userAccountControl?.[0]?.includes('2'),
      adminCount: entry.adminCount?.[0] === '1',
      lastLogon: entry.lastLogon ? parseInt(entry.lastLogon[0]) : undefined,
      passwordLastSet: entry.pwdLastSet ? parseInt(entry.pwdLastSet[0]) : undefined,
      memberOf: entry.memberOf || [],
      servicePrincipalNames: entry.servicePrincipalName || [],
      preAuthDisabled: entry.userAccountControl?.[0]?.includes('4194304'),
    }
  }

  /**
   * Parse LDAP group entry
   */
  parseLDAPGroup(entry: Record<string, string[]>): GroupInfo {
    return {
      name: entry.cn?.[0] || '',
      domain: entry.distinguishedName?.[0]?.split(',DC=')[1]?.replace('DC=', '') || '',
      type: entry.groupType?.[0]?.includes('2') ? 'distribution' : 'security',
      members: entry.member || [],
      adminCount: entry.adminCount?.[0] === '1',
      nestedGroups: [],
    }
  }

  /**
   * Detect privileged groups
   */
  getPrivilegedGroups(groups: GroupInfo[]): GroupInfo[] {
    const privilegedNames = [
      'Domain Admins',
      'Enterprise Admins',
      'Schema Admins',
      'Administrators',
      'Account Operators',
      'Backup Operators',
      'Server Operators',
      'Print Operators',
      'Group Policy Creator Owners',
    ]
    
    return groups.filter(g => 
      privilegedNames.some(name => g.name.toLowerCase().includes(name.toLowerCase())) ||
      g.adminCount
    )
  }

  /**
   * Find AS-REP roastable users
   */
  findASREPRoastable(users: UserInfo[]): UserInfo[] {
    return users.filter(u => u.preAuthDisabled && u.enabled)
  }

  /**
   * Find Kerberoastable users
   */
  findKerberoastable(users: UserInfo[]): UserInfo[] {
    return users.filter(u => 
      u.servicePrincipalNames && 
      u.servicePrincipalNames.length > 0 &&
      u.enabled
    )
  }

  /**
   * Find stale service accounts
   */
  findStaleServiceAccounts(
    accounts: ServiceAccountInfo[],
    maxPasswordAgeDays: number = 90
  ): ServiceAccountInfo[] {
    const maxAge = maxPasswordAgeDays * 24 * 60 * 60 * 1000
    return accounts.filter(a => a.passwordAge > maxAge)
  }
}

// ============================================================================
// ACCESS COLLECTOR
// ============================================================================

export class AccessCollector {
  /**
   * Collect network connections from a host
   */
  async collectNetworkConnections(
    host: string,
    credentials: { username: string; password: string }
  ): Promise<TopologyConnection[]> {
    // This would run netstat, lsof, or Get-NetTCPConnection
    return []
  }

  /**
   * Parse netstat output
   */
  parseNetstat(output: string, sourceId: string): TopologyConnection[] {
    const connections: TopologyConnection[] = []
    const lines = output.split('\n')
    
    for (const line of lines) {
      const match = line.match(/(TCP|UDP)\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\w+)/i)
      if (match) {
        const [, protocol, localIP, localPort, remoteIP, remotePort, state] = match
        
        if (remoteIP !== '0.0.0.0' && remoteIP !== '*' && remoteIP !== '::') {
          connections.push({
            sourceId,
            targetId: `${remoteIP}:${remotePort}`,
            type: 'network',
            protocol: protocol.toLowerCase(),
            port: parseInt(remotePort, 10),
            bidirectional: false,
          })
        }
      }
    }
    
    return connections
  }

  /**
   * Collect SMB shares and sessions
   */
  async collectSMBAccess(
    host: string,
    credentials: { username: string; password: string }
  ): Promise<Array<{ share: string; path: string; permissions: string[] }>> {
    // This would run smbclient or net share
    return []
  }

  /**
   * Collect SQL database permissions
   */
  async collectSQLAccess(
    host: string,
    credentials: { username: string; password: string }
  ): Promise<Array<{ database: string; user: string; permissions: string[] }>> {
    // This would query SQL server permissions
    return []
  }

  /**
   * Collect local group memberships
   */
  async collectLocalGroups(
    host: string,
    credentials: { username: string; password: string }
  ): Promise<Array<{ group: string; members: string[] }>> {
    // This would query local groups via WMI or /etc/group
    return []
  }

  /**
   * Analyze access paths
   */
  analyzeAccessPaths(
    assets: TopologyAsset[],
    connections: TopologyConnection[]
  ): AccessPath[] {
    const paths: AccessPath[] = []
    
    // Build adjacency list
    const adjacency = new Map<string, string[]>()
    for (const conn of connections) {
      if (!adjacency.has(conn.sourceId)) {
        adjacency.set(conn.sourceId, [])
      }
      adjacency.get(conn.sourceId)!.push(conn.targetId)
    }
    
    // Find all paths from internet-facing assets to critical assets
    const entryPoints = assets.filter(a => a.internetFacing)
    const criticalAssets = assets.filter(a => a.criticality >= 4)
    
    for (const entry of entryPoints) {
      for (const critical of criticalAssets) {
        if (entry.id === critical.id) continue
        
        const path = this.findPath(adjacency, entry.id, critical.id)
        if (path) {
          paths.push({
            id: `path-${entry.id}-${critical.id}`,
            source: entry.id,
            target: critical.id,
            path,
            method: 'ssh', // Would determine from connection type
            probability: 0.5,
          })
        }
      }
    }
    
    return paths
  }

  /**
   * Find path between two nodes (BFS)
   */
  private findPath(
    adjacency: Map<string, string[]>,
    source: string,
    target: string
  ): string[] | null {
    const visited = new Set<string>()
    const queue: Array<{ node: string; path: string[] }> = [
      { node: source, path: [source] }
    ]
    
    while (queue.length > 0) {
      const { node, path } = queue.shift()!
      
      if (node === target) {
        return path
      }
      
      if (visited.has(node)) continue
      visited.add(node)
      
      const neighbors = adjacency.get(node) || []
      for (const neighbor of neighbors) {
        if (!visited.has(neighbor)) {
          queue.push({ node: neighbor, path: [...path, neighbor] })
        }
      }
    }
    
    return null
  }
}

// ============================================================================
// NETWORK TOPOLOGY BUILDER
// ============================================================================

export class NetworkTopologyBuilder {
  private identityCollector: IdentityCollector
  private accessCollector: AccessCollector

  constructor() {
    this.identityCollector = new IdentityCollector()
    this.accessCollector = new AccessCollector()
  }

  /**
   * Build complete network topology
   */
  async buildTopology(
    targets: Array<{ host: string; credentials: { username: string; password: string } }>,
    domainController?: { host: string; credentials: { username: string; password: string } }
  ): Promise<NetworkTopology> {
    const assets: TopologyAsset[] = []
    const connections: TopologyConnection[] = []
    
    // Collect from each target
    for (const target of targets) {
      // Collect asset info
      // Collect connections
      // Collect local access info
    }
    
    // Collect identity info from AD if available
    let identityInfo: IdentityInformation = {
      domainName: undefined,
      domainControllers: [],
      users: [],
      groups: [],
      serviceAccounts: [],
      trusts: [],
      gpos: [],
    }
    
    if (domainController) {
      identityInfo = await this.identityCollector.collectFromAD(
        domainController.host,
        domainController.credentials
      )
    }
    
    // Analyze access paths
    const accessPaths = this.accessCollector.analyzeAccessPaths(assets, connections)
    
    // Identify trust boundaries
    const trustBoundaries = this.identifyTrustBoundaries(assets, connections)
    
    return {
      assets,
      connections,
      identityInfo,
      accessPaths,
      trustBoundaries,
    }
  }

  /**
   * Identify trust boundaries
   */
  private identifyTrustBoundaries(
    assets: TopologyAsset[],
    connections: TopologyConnection[]
  ): TrustBoundary[] {
    const boundaries: TrustBoundary[] = []
    
    // Group assets by zone
    const zoneAssets = new Map<string, string[]>()
    for (const asset of assets) {
      if (!zoneAssets.has(asset.zone)) {
        zoneAssets.set(asset.zone, [])
      }
      zoneAssets.get(asset.zone)!.push(asset.id)
    }
    
    // Create boundary for each zone
    for (const [zone, assetIds] of zoneAssets) {
      boundaries.push({
        id: `boundary-${zone}`,
        name: `${zone} Zone`,
        type: 'network',
        assets: assetIds,
        controls: [],
      })
    }
    
    return boundaries
  }

  /**
   * Export topology to graph format
   */
  exportToGraph(topology: NetworkTopology): { nodes: any[]; edges: any[] } {
    const nodes = topology.assets.map(a => ({
      id: a.id,
      label: a.name,
      type: a.type,
      zone: a.zone,
      criticality: a.criticality,
      internetFacing: a.internetFacing,
    }))
    
    const edges = topology.connections.map((c, i) => ({
      id: `edge-${i}`,
      source: c.sourceId,
      target: c.targetId,
      type: c.type,
      protocol: c.protocol,
    }))
    
    return { nodes, edges }
  }

  /**
   * Find critical attack paths
   */
  findCriticalPaths(topology: NetworkTopology): AccessPath[] {
    // Filter paths that lead to high-value targets
    return topology.accessPaths.filter(path => {
      const targetAsset = topology.assets.find(a => a.id === path.target)
      return targetAsset && targetAsset.criticality >= 4
    }).sort((a, b) => b.probability - a.probability)
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export { IdentityCollector, AccessCollector }
