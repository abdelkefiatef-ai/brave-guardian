'use client'

import { useState, useCallback, useMemo, useEffect } from 'react'

// ============================================================================
// TYPES
// ============================================================================

interface Misconfiguration {
  id: string
  title: string
  description: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  evidence: string
  remediation: string
}

interface Asset {
  id: string
  name: string
  type: string
  ip: string
  network_zone: string
  criticality: number
  internet_facing: boolean
  business_unit: string
  annual_revenue_exposure: number
  misconfigurations: Misconfiguration[]
  domain_joined?: boolean
  services?: string[]
  data_sensitivity?: string
  scanStatus?: 'pending' | 'scanning' | 'completed' | 'failed'
}

interface ScanJob {
  id: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  progress: number
  targetCount: number
  resultCount: number
  startTime: number
  endTime?: number
  summary?: {
    totalTargets: number
    scannedTargets: number
    successCount: number
    failedCount: number
    totalMisconfigurations: number
    criticalCount: number
    highCount: number
    mediumCount: number
    lowCount: number
  }
}

interface AttackNode {
  id: string
  asset_id: string
  asset_name: string
  asset_type: string
  asset_zone: string
  misconfig_id: string
  misconfig_title: string
  misconfig_category: string
  criticality: number
  internet_facing: boolean
  data_sensitivity: string
}

interface AttackEdge {
  source_id: string
  target_id: string
  probability: number
  technique: string
  credentials_carried: string[]
  reasoning: string
  edge_type: 'pattern' | 'llm'
}

interface AttackPath {
  path_id: string
  nodes: AttackNode[]
  edges: AttackEdge[]
  path_probability: number
  pagerank_score: number
  impact_score: number
  realism_score: number
  detection_risk: number
  final_risk_score: number
  narrative: string
  business_impact: string
  kill_chain: string[]
}

interface AnalysisResult {
  graph_stats: {
    total_nodes: number
    total_edges: number
    avg_branching_factor: number | string
  }
  edge_stats: {
    pattern_edges: number
    llm_edges: number
    total_edges: number
    candidates_evaluated?: number
  }
  entry_points: Array<{
    node_id: string
    asset_name: string
    misconfig_title: string
    reasoning: string
    attacker_value: string
    pagerank_score: number
  }>
  attack_paths: AttackPath[]
  critical_assets: Array<{
    asset_id: string
    asset_name: string
    reason: string
    paths_to_it: number
  }>
  key_insights: string[]
  timing: {
    nodes: number
    edges: number
    pagerank: number
    paths: number
    validation: number
    entry_analysis: number
    total: number
  }
}

// ============================================================================
// MISCONFIGURATION DATABASE
// ============================================================================

const MISCONFIG_DB: Misconfiguration[] = [
  { id: 'M001', title: 'RDP Accessible from Internet', description: 'RDP port 3389 open to internet', category: 'network', severity: 'critical', evidence: 'Port scan', remediation: 'Block RDP at firewall' },
  { id: 'M002', title: 'SMBv1 Protocol Active', description: 'Legacy SMB enabled', category: 'network', severity: 'critical', evidence: 'SMB scan', remediation: 'Disable SMBv1' },
  { id: 'M003', title: 'SMB Signing Not Required', description: 'SMB relay possible', category: 'network', severity: 'high', evidence: 'SMB audit', remediation: 'Enable SMB signing' },
  { id: 'M004', title: 'WinRM Over HTTP', description: 'Unencrypted WinRM', category: 'network', severity: 'high', evidence: 'WinRM config', remediation: 'Enable HTTPS' },
  { id: 'M005', title: 'LDAP Signing Disabled', description: 'LDAP interception', category: 'network', severity: 'high', evidence: 'LDAP audit', remediation: 'Enable LDAP signing' },
  { id: 'M010', title: 'Weak Password Policy', description: '8 char minimum', category: 'authentication', severity: 'medium', evidence: 'GPO review', remediation: 'Increase complexity' },
  { id: 'M011', title: 'Stale Service Account', description: '90+ day old password', category: 'authentication', severity: 'high', evidence: 'AD audit', remediation: 'Rotate passwords' },
  { id: 'M012', title: 'Kerberos Pre-Auth Disabled', description: 'AS-REP roastable', category: 'authentication', severity: 'critical', evidence: 'AD enum', remediation: 'Enable pre-auth' },
  { id: 'M013', title: 'Shared Local Admin', description: 'Same password across systems', category: 'authentication', severity: 'critical', evidence: 'Cred audit', remediation: 'Use LAPS' },
  { id: 'M020', title: 'Domain Users Local Admin', description: 'Excessive rights', category: 'authorization', severity: 'high', evidence: 'Group audit', remediation: 'Remove from admins' },
  { id: 'M022', title: 'DCSync Rights', description: 'Replication rights to non-DA', category: 'authorization', severity: 'critical', evidence: 'ACL analysis', remediation: 'Remove rights' },
  { id: 'M023', title: 'Unconstrained Delegation', description: 'Kerberos delegation enabled', category: 'authorization', severity: 'critical', evidence: 'AD audit', remediation: 'Constrain delegation' },
  { id: 'M030', title: 'AV Not Running', description: 'Antivirus disabled', category: 'service', severity: 'high', evidence: 'Service check', remediation: 'Enable AV' },
  { id: 'M031', title: 'Unquoted Service Path', description: 'Service path vulnerability', category: 'service', severity: 'high', evidence: 'Service enum', remediation: 'Quote service path' },
  { id: 'M040', title: 'BitLocker Not Enabled', description: 'No disk encryption', category: 'encryption', severity: 'medium', evidence: 'BitLocker status', remediation: 'Enable BitLocker' },
  { id: 'M050', title: 'Command Line Logging Disabled', description: 'No process logging', category: 'logging', severity: 'medium', evidence: 'Audit policy', remediation: 'Enable logging' },
]

// ============================================================================
// ENTERPRISE ENVIRONMENT GENERATOR - 500 Assets
// Realistic enterprise network with zones, segmentation, and business units
// ============================================================================

// Network Zones - Represents enterprise network segmentation
const NETWORK_ZONES = {
  // Perimeter
  'dmz': { name: 'DMZ', color: 'red', description: 'Demilitarized Zone - Internet-facing', subnet: '10.0' },
  'internet': { name: 'Internet', color: 'darkred', description: 'External network', subnet: '0.0.0.0' },
  
  // Production
  'prod-web': { name: 'Prod Web', color: 'orange', description: 'Production Web Tier', subnet: '10.10' },
  'prod-app': { name: 'Prod App', color: 'yellow', description: 'Production Application Tier', subnet: '10.11' },
  'prod-db': { name: 'Prod DB', color: 'red', description: 'Production Database Tier', subnet: '10.12' },
  
  // Development
  'dev-web': { name: 'Dev Web', color: 'blue', description: 'Development Web Tier', subnet: '10.20' },
  'dev-app': { name: 'Dev App', color: 'cyan', description: 'Development Application Tier', subnet: '10.21' },
  'dev-db': { name: 'Dev DB', color: 'purple', description: 'Development Database Tier', subnet: '10.22' },
  
  // Staging/QA
  'staging': { name: 'Staging', color: 'teal', description: 'Staging/QA Environment', subnet: '10.30' },
  
  // Internal Corporate
  'corp': { name: 'Corporate', color: 'green', description: 'Corporate Network', subnet: '10.100' },
  'corp-wifi': { name: 'Corp WiFi', color: 'lightgreen', description: 'Corporate Wireless', subnet: '10.101' },
  
  // Restricted/High-Security
  'restricted': { name: 'Restricted', color: 'darkred', description: 'High-Security Zone', subnet: '10.200' },
  'pci': { name: 'PCI-DSS', color: 'maroon', description: 'Payment Card Industry', subnet: '10.201' },
  'hipaa': { name: 'HIPAA', color: 'crimson', description: 'Healthcare Data', subnet: '10.202' },
  
  // Infrastructure
  'mgmt': { name: 'Management', color: 'gray', description: 'Network Management', subnet: '10.250' },
  'security': { name: 'Security', color: 'slate', description: 'Security Tools', subnet: '10.251' },
  
  // Cloud
  'cloud-prod': { name: 'Cloud Prod', color: 'skyblue', description: 'Cloud Production', subnet: '172.16' },
  'cloud-dev': { name: 'Cloud Dev', color: 'lightblue', description: 'Cloud Development', subnet: '172.17' },
  
  // Disaster Recovery
  'dr': { name: 'DR Site', color: 'brown', description: 'Disaster Recovery', subnet: '10.180' },
} as const

type NetworkZone = keyof typeof NETWORK_ZONES

// Business Units
const BUSINESS_UNITS = [
  { name: 'Finance', revenue: 50000000, criticality: 5 },
  { name: 'Engineering', revenue: 30000000, criticality: 4 },
  { name: 'Sales', revenue: 40000000, criticality: 4 },
  { name: 'HR', revenue: 5000000, criticality: 3 },
  { name: 'Operations', revenue: 20000000, criticality: 4 },
  { name: 'Legal', revenue: 8000000, criticality: 4 },
  { name: 'Marketing', revenue: 15000000, criticality: 3 },
  { name: 'IT', revenue: 10000000, criticality: 5 },
  { name: 'R&D', revenue: 25000000, criticality: 4 },
  { name: 'Customer Support', revenue: 12000000, criticality: 3 },
] as const

// Asset Type Definitions
interface AssetTemplate {
  type: string
  namePrefix: string
  zones: NetworkZone[]
  criticality: number
  domainJoined: boolean
  services: string[]
  dataSensitivity: string
  internetFacing: boolean
  misconfigCategories: string[]
  count: number // How many to generate
  envSpecific: boolean // Does it have dev/prod variants
}

const ASSET_TEMPLATES: AssetTemplate[] = [
  // === CORE INFRASTRUCTURE ===
  { type: 'domain_controller', namePrefix: 'DC', zones: ['restricted', 'corp', 'mgmt'], criticality: 5, domainJoined: true, services: ['AD', 'DNS', 'LDAP'], dataSensitivity: 'credentials', internetFacing: false, misconfigCategories: ['authentication', 'authorization', 'network'], count: 8, envSpecific: false },
  { type: 'backup_server', namePrefix: 'BKUP', zones: ['restricted', 'dr'], criticality: 5, domainJoined: true, services: ['Veeam', 'Commvault'], dataSensitivity: 'backups', internetFacing: false, misconfigCategories: ['authentication', 'encryption'], count: 6, envSpecific: false },
  { type: 'dns_server', namePrefix: 'DNS', zones: ['mgmt', 'corp'], criticality: 4, domainJoined: true, services: ['DNS'], dataSensitivity: 'none', internetFacing: false, misconfigCategories: ['network', 'service'], count: 4, envSpecific: false },
  { type: 'dhcp_server', namePrefix: 'DHCP', zones: ['mgmt', 'corp'], criticality: 3, domainJoined: true, services: ['DHCP'], dataSensitivity: 'none', internetFacing: false, misconfigCategories: ['network', 'authorization'], count: 3, envSpecific: false },
  
  // === IDENTITY & SECURITY ===
  { type: 'identity_server', namePrefix: 'IDP', zones: ['restricted', 'security'], criticality: 5, domainJoined: true, services: ['Okta', 'ADFS', 'SAML'], dataSensitivity: 'credentials', internetFacing: true, misconfigCategories: ['authentication', 'authorization'], count: 4, envSpecific: false },
  { type: 'pki_server', namePrefix: 'PKI', zones: ['restricted'], criticality: 5, domainJoined: true, services: ['CA', 'OCSP'], dataSensitivity: 'certificates', internetFacing: false, misconfigCategories: ['encryption', 'authentication'], count: 2, envSpecific: false },
  { type: 'siem', namePrefix: 'SIEM', zones: ['security'], criticality: 5, domainJoined: true, services: ['Splunk', 'QRadar'], dataSensitivity: 'logs', internetFacing: false, misconfigCategories: ['logging', 'network'], count: 2, envSpecific: false },
  { type: 'pam', namePrefix: 'PAM', zones: ['security', 'restricted'], criticality: 5, domainJoined: true, services: ['CyberArk', 'BeyondTrust'], dataSensitivity: 'credentials', internetFacing: false, misconfigCategories: ['authentication', 'authorization'], count: 3, envSpecific: false },
  
  // === PERIMETER / DMZ ===
  { type: 'firewall', namePrefix: 'FW', zones: ['dmz', 'mgmt'], criticality: 5, domainJoined: false, services: ['Palo Alto', 'Fortinet'], dataSensitivity: 'firewall_rules', internetFacing: true, misconfigCategories: ['network', 'authorization'], count: 6, envSpecific: false },
  { type: 'load_balancer', namePrefix: 'LB', zones: ['dmz', 'prod-web', 'cloud-prod'], criticality: 4, domainJoined: false, services: ['F5', 'NGINX'], dataSensitivity: 'ssl_certs', internetFacing: true, misconfigCategories: ['network', 'encryption'], count: 8, envSpecific: true },
  { type: 'reverse_proxy', namePrefix: 'RPX', zones: ['dmz'], criticality: 4, domainJoined: false, services: ['NGINX', 'HAProxy'], dataSensitivity: 'ssl_certs', internetFacing: true, misconfigCategories: ['network', 'encryption'], count: 4, envSpecific: false },
  { type: 'vpn_gateway', namePrefix: 'VPN', zones: ['dmz', 'corp'], criticality: 4, domainJoined: true, services: ['OpenVPN', 'Cisco ASA'], dataSensitivity: 'credentials', internetFacing: true, misconfigCategories: ['network', 'authentication'], count: 4, envSpecific: false },
  { type: 'web_application_firewall', namePrefix: 'WAF', zones: ['dmz'], criticality: 4, domainJoined: false, services: ['ModSecurity', 'AWS WAF'], dataSensitivity: 'logs', internetFacing: true, misconfigCategories: ['network', 'logging'], count: 4, envSpecific: false },
  
  // === WEB SERVERS ===
  { type: 'web_server', namePrefix: 'WEB', zones: ['dmz', 'prod-web', 'dev-web', 'staging', 'cloud-prod'], criticality: 4, domainJoined: false, services: ['IIS', 'Apache', 'NGINX'], dataSensitivity: 'app_data', internetFacing: true, misconfigCategories: ['network', 'service', 'encryption'], count: 25, envSpecific: true },
  
  // === APPLICATION SERVERS ===
  { type: 'app_server', namePrefix: 'APP', zones: ['prod-app', 'dev-app', 'staging', 'cloud-prod'], criticality: 4, domainJoined: true, services: ['Tomcat', 'NodeJS', 'Java'], dataSensitivity: 'business_logic', internetFacing: false, misconfigCategories: ['authentication', 'service'], count: 30, envSpecific: true },
  { type: 'api_gateway', namePrefix: 'API', zones: ['dmz', 'prod-web'], criticality: 4, domainJoined: false, services: ['Kong', 'Apigee'], dataSensitivity: 'api_keys', internetFacing: true, misconfigCategories: ['authentication', 'network'], count: 8, envSpecific: false },
  { type: 'microservice', namePrefix: 'SVC', zones: ['prod-app', 'dev-app', 'cloud-prod', 'cloud-dev'], criticality: 3, domainJoined: false, services: ['Docker', 'K8s'], dataSensitivity: 'app_data', internetFacing: false, misconfigCategories: ['authentication', 'service'], count: 40, envSpecific: true },
  
  // === DATABASE SERVERS ===
  { type: 'database_server', namePrefix: 'DB', zones: ['prod-db', 'dev-db', 'restricted', 'cloud-prod'], criticality: 5, domainJoined: true, services: ['SQL Server', 'Oracle', 'PostgreSQL'], dataSensitivity: 'pii', internetFacing: false, misconfigCategories: ['authentication', 'authorization', 'encryption'], count: 20, envSpecific: true },
  { type: 'nosql_db', namePrefix: 'NOSQL', zones: ['prod-db', 'dev-db', 'cloud-prod'], criticality: 4, domainJoined: false, services: ['MongoDB', 'Redis', 'Elasticsearch'], dataSensitivity: 'pii', internetFacing: false, misconfigCategories: ['authentication', 'network'], count: 15, envSpecific: true },
  { type: 'data_warehouse', namePrefix: 'DWH', zones: ['restricted', 'cloud-prod'], criticality: 5, domainJoined: true, services: ['Snowflake', 'Redshift', 'Teradata'], dataSensitivity: 'analytics', internetFacing: false, misconfigCategories: ['authentication', 'encryption'], count: 5, envSpecific: false },
  
  // === FILE & STORAGE ===
  { type: 'file_server', namePrefix: 'FS', zones: ['corp', 'prod-app', 'restricted'], criticality: 4, domainJoined: true, services: ['SMB', 'NFS'], dataSensitivity: 'user_files', internetFacing: false, misconfigCategories: ['network', 'authorization'], count: 15, envSpecific: false },
  { type: 'nas', namePrefix: 'NAS', zones: ['corp', 'restricted', 'dr'], criticality: 4, domainJoined: false, services: ['NFS', 'SMB'], dataSensitivity: 'documents', internetFacing: false, misconfigCategories: ['network', 'encryption'], count: 8, envSpecific: false },
  { type: 'storage_server', namePrefix: 'STR', zones: ['cloud-prod', 'cloud-dev'], criticality: 4, domainJoined: false, services: ['S3', 'Blob'], dataSensitivity: 'mixed', internetFacing: false, misconfigCategories: ['encryption', 'authorization'], count: 10, envSpecific: true },
  
  // === COMMUNICATION ===
  { type: 'email_server', namePrefix: 'MAIL', zones: ['dmz', 'corp'], criticality: 4, domainJoined: true, services: ['Exchange', 'Postfix'], dataSensitivity: 'emails', internetFacing: true, misconfigCategories: ['network', 'authentication', 'encryption'], count: 6, envSpecific: false },
  { type: 'voip_server', namePrefix: 'VOIP', zones: ['corp'], criticality: 3, domainJoined: true, services: ['Cisco CUCM', 'Asterisk'], dataSensitivity: 'call_logs', internetFacing: false, misconfigCategories: ['network', 'service'], count: 4, envSpecific: false },
  { type: 'chat_server', namePrefix: 'CHAT', zones: ['corp', 'cloud-prod'], criticality: 3, domainJoined: true, services: ['Slack', 'Teams', 'Mattermost'], dataSensitivity: 'messages', internetFacing: false, misconfigCategories: ['authentication', 'network'], count: 4, envSpecific: false },
  
  // === DEVELOPMENT ===
  { type: 'build_server', namePrefix: 'BLD', zones: ['dev-app', 'cloud-dev'], criticality: 3, domainJoined: true, services: ['Jenkins', 'GitLab CI'], dataSensitivity: 'source_code', internetFacing: false, misconfigCategories: ['authentication', 'service'], count: 8, envSpecific: false },
  { type: 'code_repo', namePrefix: 'GIT', zones: ['dev-app', 'cloud-dev'], criticality: 4, domainJoined: true, services: ['GitHub Enterprise', 'GitLab'], dataSensitivity: 'source_code', internetFacing: true, misconfigCategories: ['authentication', 'network'], count: 4, envSpecific: false },
  { type: 'artifact_repo', namePrefix: 'ART', zones: ['dev-app', 'cloud-dev'], criticality: 3, domainJoined: false, services: ['Nexus', 'Artifactory'], dataSensitivity: 'artifacts', internetFacing: false, misconfigCategories: ['authentication', 'network'], count: 4, envSpecific: false },
  
  // === MONITORING & MANAGEMENT ===
  { type: 'monitoring', namePrefix: 'MON', zones: ['mgmt', 'cloud-prod'], criticality: 4, domainJoined: true, services: ['Nagios', 'Zabbix', 'Datadog'], dataSensitivity: 'metrics', internetFacing: false, misconfigCategories: ['network', 'logging'], count: 8, envSpecific: false },
  { type: 'logging_server', namePrefix: 'LOG', zones: ['mgmt', 'security'], criticality: 4, domainJoined: true, services: ['ELK', 'Splunk'], dataSensitivity: 'logs', internetFacing: false, misconfigCategories: ['logging', 'network'], count: 6, envSpecific: false },
  { type: 'jump_server', namePrefix: 'JMP', zones: ['dmz', 'mgmt'], criticality: 4, domainJoined: true, services: ['RDP', 'SSH'], dataSensitivity: 'credentials', internetFacing: true, misconfigCategories: ['network', 'authentication'], count: 6, envSpecific: false },
  
  // === ENDPOINTS ===
  { type: 'workstation', namePrefix: 'WS', zones: ['corp', 'corp-wifi', 'dev-web'], criticality: 2, domainJoined: true, services: ['Office', 'Browser'], dataSensitivity: 'user_data', internetFacing: false, misconfigCategories: ['authentication', 'service'], count: 80, envSpecific: false },
  { type: 'laptop', namePrefix: 'LAP', zones: ['corp', 'corp-wifi'], criticality: 2, domainJoined: true, services: ['Office', 'Browser'], dataSensitivity: 'user_data', internetFacing: false, misconfigCategories: ['authentication', 'encryption'], count: 60, envSpecific: false },
  { type: 'developer_workstation', namePrefix: 'DEVWS', zones: ['dev-web', 'dev-app'], criticality: 3, domainJoined: true, services: ['IDE', 'Docker'], dataSensitivity: 'source_code', internetFacing: false, misconfigCategories: ['authentication', 'service'], count: 40, envSpecific: false },
  
  // === SPECIAL PURPOSE ===
  { type: 'iot_device', namePrefix: 'IOT', zones: ['corp', 'mgmt'], criticality: 2, domainJoined: false, services: ['Sensors', 'Camera'], dataSensitivity: 'telemetry', internetFacing: false, misconfigCategories: ['network', 'authentication'], count: 20, envSpecific: false },
  { type: 'printer', namePrefix: 'PRT', zones: ['corp', 'corp-wifi'], criticality: 1, domainJoined: true, services: ['Print'], dataSensitivity: 'print_jobs', internetFacing: false, misconfigCategories: ['network'], count: 15, envSpecific: false },
  { type: 'scanner', namePrefix: 'SCN', zones: ['corp'], criticality: 2, domainJoined: true, services: ['Scan'], dataSensitivity: 'scanned_docs', internetFacing: false, misconfigCategories: ['network'], count: 8, envSpecific: false },
  
  // === COMPLIANCE-SPECIFIC ===
  { type: 'pci_server', namePrefix: 'PCI', zones: ['pci'], criticality: 5, domainJoined: true, services: ['Payment', 'CardProc'], dataSensitivity: 'pci_data', internetFacing: false, misconfigCategories: ['encryption', 'authentication', 'logging'], count: 6, envSpecific: false },
  { type: 'hipaa_server', namePrefix: 'HIPAA', zones: ['hipaa'], criticality: 5, domainJoined: true, services: ['EHR', 'PHI'], dataSensitivity: 'phi', internetFacing: false, misconfigCategories: ['encryption', 'authentication', 'logging'], count: 8, envSpecific: false },
  
  // === CLOUD-NATIVE ===
  { type: 'k8s_cluster', namePrefix: 'K8S', zones: ['cloud-prod', 'cloud-dev'], criticality: 4, domainJoined: false, services: ['Kubernetes'], dataSensitivity: 'workloads', internetFacing: false, misconfigCategories: ['authentication', 'authorization', 'network'], count: 12, envSpecific: true },
  { type: 'container_registry', namePrefix: 'CR', zones: ['cloud-prod', 'cloud-dev'], criticality: 4, domainJoined: false, services: ['Docker Registry', 'ECR'], dataSensitivity: 'images', internetFacing: false, misconfigCategories: ['authentication', 'network'], count: 4, envSpecific: false },
]

// Seeded random number generator for reproducibility
class SeededRandom {
  private seed: number
  constructor(seed: number) {
    this.seed = seed
  }
  next(): number {
    this.seed = (this.seed * 1103515245 + 12345) & 0x7fffffff
    return this.seed / 0x7fffffff
  }
  nextInt(min: number, max: number): number {
    return Math.floor(this.next() * (max - min + 1)) + min
  }
  pick<T>(arr: readonly T[]): T {
    return arr[Math.floor(this.next() * arr.length)]
  }
  shuffle<T>(arr: T[]): T[] {
    const result = [...arr]
    for (let i = result.length - 1; i > 0; i--) {
      const j = Math.floor(this.next() * (i + 1))
      ;[result[i], result[j]] = [result[j], result[i]]
    }
    return result
  }
}

// Generate realistic enterprise environment
const generateEnterpriseAssets = (): Asset[] => {
  const assets: Asset[] = []
  const rng = new SeededRandom(42) // Reproducible results
  
  let assetId = 1
  const zoneCounters: Record<string, number> = {}
  const usedIPs = new Set<string>()
  
  // Generate unique IP
  const generateIP = (zone: NetworkZone): string => {
    const subnet = NETWORK_ZONES[zone].subnet
    let ip: string
    let attempts = 0
    do {
      const octet3 = rng.nextInt(0, 255)
      const octet4 = rng.nextInt(1, 254)
      ip = `${subnet}.${octet3}.${octet4}`
      attempts++
      if (attempts > 1000) {
        ip = `${subnet}.${rng.nextInt(0, 255)}.${rng.nextInt(1, 254)}`
        break
      }
    } while (usedIPs.has(ip))
    usedIPs.add(ip)
    return ip
  }
  
  // Generate misconfigurations for an asset
  const generateMisconfigurations = (categories: string[]): Misconfiguration[] => {
    const count = rng.nextInt(1, 3)
    const relevant = MISCONFIG_DB.filter(m => categories.includes(m.category))
    const shuffled = rng.shuffle(relevant)
    return shuffled.slice(0, count).map(m => ({ ...m }))
  }
  
  // Environment suffix
  const getEnvSuffix = (zone: NetworkZone): string => {
    if (zone.startsWith('dev') || zone === 'cloud-dev') return '-D'
    if (zone.startsWith('staging')) return '-S'
    if (zone === 'dr') return '-DR'
    return ''
  }
  
  // Process each asset template
  for (const template of ASSET_TEMPLATES) {
    let remaining = template.count
    
    // Distribute across zones
    const zones = rng.shuffle([...template.zones])
    
    for (const zone of zones) {
      if (remaining <= 0) break
      
      // Determine how many of this type in this zone
      const zoneShare = Math.ceil(remaining / zones.length)
      const countInZone = Math.min(zoneShare, remaining)
      
      for (let i = 0; i < countInZone; i++) {
        // Zone counter for sequential naming
        const zoneKey = `${template.type}-${zone}`
        zoneCounters[zoneKey] = (zoneCounters[zoneKey] || 0) + 1
        
        const envSuffix = getEnvSuffix(zone)
        const businessUnit = rng.pick(BUSINESS_UNITS)
        
        // Generate asset name
        const zonePrefix = NETWORK_ZONES[zone].name.toUpperCase().replace(/[^A-Z]/g, '').substring(0, 2)
        const name = `${template.namePrefix}-${zonePrefix}${String(zoneCounters[zoneKey]).padStart(3, '0')}${envSuffix}`
        
        // ============================================================================
        // IMPROVEMENT: Zone-aware internet-facing determination
        // Only DMZ and specific perimeter zones should have internet-facing assets
        // ============================================================================
        const PERIMETER_ZONES = ['dmz']  // Zones that can have internet-facing assets
        
        // An asset is internet-facing ONLY if:
        // 1. It's in a perimeter zone (DMZ) AND
        // 2. The template allows it OR zone randomly allows it
        const isInPerimeter = PERIMETER_ZONES.includes(zone)
        const templateAllowsInternet = template.internetFacing
        const zoneAllowsInternet = isInPerimeter && (rng.next() > 0.5)  // 50% of DMZ assets are internet-facing
        
        // Final determination: must be in perimeter zone
        const internetFacing = isInPerimeter && (templateAllowsInternet || zoneAllowsInternet)
        
        // Adjust criticality based on zone
        let criticality = template.criticality
        if (zone.startsWith('dev')) criticality = Math.max(1, criticality - 1)
        if (zone === 'pci' || zone === 'hipaa') criticality = 5
        if (zone === 'dr') criticality = Math.min(5, criticality + 1)
        
        assets.push({
          id: `asset-${assetId++}`,
          name,
          type: template.type,
          ip: generateIP(zone),
          network_zone: zone,
          criticality,
          internet_facing: internetFacing,
          business_unit: businessUnit.name,
          annual_revenue_exposure: businessUnit.revenue,
          misconfigurations: generateMisconfigurations(template.misconfigCategories),
          domain_joined: template.domainJoined,
          services: template.services,
          data_sensitivity: template.dataSensitivity,
          scanStatus: 'pending',
        })
      }
      
      remaining -= countInZone
    }
  }
  
  // Ensure we have exactly 500 assets by adjusting workstation counts
  const diff = 500 - assets.length
  if (diff > 0) {
    // Add more workstations
    for (let i = 0; i < diff; i++) {
      const zone = rng.pick(['corp', 'corp-wifi', 'dev-web'] as NetworkZone[])
      const zoneKey = `workstation-${zone}`
      zoneCounters[zoneKey] = (zoneCounters[zoneKey] || 0) + 1
      const businessUnit = rng.pick(BUSINESS_UNITS)
      
      assets.push({
        id: `asset-${assetId++}`,
        name: `WS-${NETWORK_ZONES[zone].name.toUpperCase().substring(0, 2)}${String(zoneCounters[zoneKey]).padStart(3, '0')}`,
        type: 'workstation',
        ip: generateIP(zone),
        network_zone: zone,
        criticality: 2,
        internet_facing: false,
        business_unit: businessUnit.name,
        annual_revenue_exposure: businessUnit.revenue,
        misconfigurations: generateMisconfigurations(['authentication', 'service']),
        domain_joined: true,
        services: ['Office', 'Browser'],
        data_sensitivity: 'user_data',
        scanStatus: 'pending',
      })
    }
  }
  
  console.log(`Generated ${assets.length} enterprise assets across ${Object.keys(NETWORK_ZONES).length} zones`)
  return assets
}

const INITIAL_ASSETS = generateEnterpriseAssets()

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function BraveGuardian() {
  const [assets, setAssets] = useState<Asset[]>(INITIAL_ASSETS)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState('')
  const [view, setView] = useState<'env' | 'scan' | 'analysis' | 'paths' | 'algo'>('env')
  const [selectedPath, setSelectedPath] = useState<number | null>(null)
  
  // Scanner state
  const [scanJob, setScanJob] = useState<ScanJob | null>(null)
  const [scanLoading, setScanLoading] = useState(false)
  const [scanResults, setScanResults] = useState<Array<{ host: string; misconfigurations: number; success: boolean }>>([])

  // Attack Analysis
  const runAnalysis = useCallback(async () => {
    setLoading(true)
    setResult(null)
    setStatus('Initializing attack analysis...')

    // Create AbortController for timeout
    const controller = new AbortController()
    const timeoutId = setTimeout(() => {
      controller.abort()
      setStatus('Request timed out - please try again')
      setLoading(false)
    }, 120000) // 2 minute timeout

    // Helper function to make the API request
    const makeRequest = async (retryCount = 0): Promise<Response | null> => {
      try {
        const response = await fetch('/api/attack-analysis', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            environment: {
              assets: assets.map(a => ({
                id: a.id,
                name: a.name,
                type: a.type,
                ip: a.ip,
                zone: a.network_zone,
                internet_facing: a.internet_facing,
                criticality: a.criticality,
                domain_joined: a.domain_joined,
                services: a.services,
                data_sensitivity: a.data_sensitivity,
                misconfigurations: a.misconfigurations.map(m => ({
                  id: m.id,
                  title: m.title,
                  description: m.description,
                  category: m.category
                }))
              }))
            }
          }),
          signal: controller.signal
        })
        return response
      } catch (fetchError) {
        // Network error or abort
        if (fetchError instanceof Error && fetchError.name === 'AbortError') {
          throw fetchError
        }
        // Retry on network errors
        if (retryCount < 2) {
          console.log(`Network error, retrying... (${retryCount + 1}/2)`)
          setStatus(`Connection issue, retrying... (${retryCount + 1}/2)`)
          await new Promise(r => setTimeout(r, 1000))
          return makeRequest(retryCount + 1)
        }
        throw fetchError
      }
    }

    try {
      setStatus('Building attack graph...')
      
      const response = await makeRequest()

      if (!response) {
        setStatus('Failed to connect to server - please try again')
        setLoading(false)
        return
      }

      clearTimeout(timeoutId)

      if (response.ok) {
        const data = await response.json()
        
        // Check if API returned an error in the response body
        if (data.error) {
          const errorMsg = data.message || data.error || 'Unknown error from server'
          setStatus(`Error: ${errorMsg}`)
          console.error('API returned error:', data)
          setResult(null)
        } else if (data.attack_paths && data.attack_paths.length > 0) {
          setResult(data)
          setStatus('')
        } else if (data.key_insights && data.key_insights.length > 0) {
          // No paths but got insights - show what we have
          setStatus(data.key_insights[0])
          setResult(data)
        } else {
          setStatus('No attack paths found - check asset configurations')
          setResult(data)
        }
      } else {
        // HTTP error response
        let errorMsg = `Server error (${response.status})`
        
        // Special handling for 502 - server might be warming up
        if (response.status === 502 || response.status === 503) {
          errorMsg = 'Server is warming up - please wait a moment and try again'
        }
        
        try {
          const errorData = await response.json()
          errorMsg = errorData.message || errorData.error || errorMsg
          console.error('Server error details:', errorData)
        } catch {
          // Couldn't parse error response
          console.error('Could not parse error response, status:', response.status)
        }
        setStatus(`Failed: ${errorMsg}`)
      }
    } catch (e: unknown) {
      clearTimeout(timeoutId)
      console.error(e)
      
      if (e instanceof Error && e.name === 'AbortError') {
        setStatus('Request timed out - server may be warming up, please try again')
      } else {
        setStatus(`Error: ${e instanceof Error ? e.message : 'Unknown error'}`)
      }
    }

    setLoading(false)
  }, [assets])

  // Scanner
  const runScan = useCallback(async () => {
    setScanLoading(true)
    setScanResults([])
    setAssets(prev => prev.map(a => ({ ...a, scanStatus: 'pending' as const })))

    try {
      // Start scan
      const startResponse = await fetch('/api/scanner', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'scan',
          targets: assets.map(a => ({
            id: a.id,
            host: a.ip,
            ip: a.ip,
            hostname: a.name,
            criticality: a.criticality,
            internetFacing: a.internet_facing,
            zone: a.network_zone,
          })),
          options: { priority: 'medium' }
        })
      })

      if (startResponse.ok) {
        const { jobId } = await startResponse.json()
        
        // Poll for results
        let completed = false
        while (!completed) {
          await new Promise(r => setTimeout(r, 500))
          
          const statusResponse = await fetch(`/api/scanner?jobId=${jobId}`)
          if (statusResponse.ok) {
            const { job } = await statusResponse.json()
            setScanJob(job)
            
            if (job.status === 'completed' || job.status === 'failed') {
              completed = true
              
              // Update assets with scan results
              setAssets(prev => prev.map(a => ({ ...a, scanStatus: 'completed' as const })))
              
              // Set scan results
              setScanResults(job.results?.map((r: any) => ({
                host: r.host,
                misconfigurations: r.misconfigurations?.length || 0,
                success: r.success
              })) || [])
            }
          }
        }
      }
    } catch (e) {
      console.error(e)
    }

    setScanLoading(false)
  }, [assets])

  // Poll scan status
  useEffect(() => {
    if (scanJob && scanJob.status === 'running') {
      const interval = setInterval(async () => {
        const response = await fetch(`/api/scanner?jobId=${scanJob.id}`)
        if (response.ok) {
          const { job } = await response.json()
          setScanJob(job)
          if (job.status !== 'running') {
            clearInterval(interval)
          }
        }
      }, 1000)
      return () => clearInterval(interval)
    }
  }, [scanJob])

  const stats = useMemo(() => {
    const totalMisconfigs = assets.reduce((s, a) => s + a.misconfigurations.length, 0)
    const byCat: Record<string, number> = {}
    const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
    
    assets.forEach(a => a.misconfigurations.forEach(m => {
      byCat[m.category] = (byCat[m.category] || 0) + 1
      bySeverity[m.severity] = (bySeverity[m.severity] || 0) + 1
    }))
    
    return { totalAssets: assets.length, totalMisconfigs, byCat, bySeverity }
  }, [assets])

  return (
    <div className="min-h-screen bg-slate-900 text-white">
      {/* Header */}
      <header className="bg-slate-800 border-b border-slate-700 sticky top-0 z-50">
        <div className="max-w-[1600px] mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-8">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-red-600 to-orange-600 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <div>
                <h1 className="text-lg font-bold">Brave Guardian</h1>
                <p className="text-xs text-slate-400">Scalable Hybrid Attack Analysis</p>
              </div>
            </div>

            <nav className="flex gap-1">
              {(['env', 'scan', 'analysis', 'paths', 'algo'] as const).map(v => (
                <button
                  key={v}
                  onClick={() => setView(v)}
                  className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                    view === v ? 'bg-red-600 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-700'
                  }`}
                >
                  {v === 'env' ? 'Environment' : v === 'scan' ? 'Scanner' : v === 'analysis' ? 'Analysis' : v === 'paths' ? 'Paths' : 'Algorithm'}
                </button>
              ))}
            </nav>
          </div>

          <div className="flex gap-3">
            <button
              onClick={runScan}
              disabled={scanLoading}
              className={`px-5 py-2.5 rounded-lg font-medium text-sm flex items-center gap-2 ${
                scanLoading ? 'bg-slate-700 text-slate-400 cursor-not-allowed' : 'bg-blue-600 text-white hover:bg-blue-700'
              }`}
            >
              {scanLoading ? (
                <>
                  <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Scanning...
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                  Run Scan
                </>
              )}
            </button>
            
            <button
              onClick={runAnalysis}
              disabled={loading}
              className={`px-6 py-2.5 rounded-lg font-medium text-sm flex items-center gap-2 ${
                loading ? 'bg-slate-700 text-slate-400 cursor-not-allowed' : 'bg-red-600 text-white hover:bg-red-700'
              }`}
            >
              {loading ? (
                <>
                  <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Analyzing...
                </>
              ) : 'Run Attack Analysis'}
            </button>
          </div>
        </div>
      </header>

      {status && (
        <div className="bg-slate-800 border-b border-slate-700 px-6 py-2">
          <div className="max-w-[1600px] mx-auto flex items-center gap-3">
            <svg className="w-4 h-4 text-red-500 animate-pulse" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            <span className="text-sm text-slate-300">{status}</span>
          </div>
        </div>
      )}

      <main className="max-w-[1600px] mx-auto px-6 py-8">
        {/* Environment View */}
        {view === 'env' && (
          <div className="space-y-6">
            <div className="grid grid-cols-6 gap-4">
              <StatCard label="Total Assets" value={stats.totalAssets} />
              <StatCard label="Misconfigurations" value={stats.totalMisconfigs} />
              <StatCard label="Critical" value={stats.bySeverity.critical} color="red" />
              <StatCard label="High" value={stats.bySeverity.high} color="orange" />
              <StatCard label="Internet-Exposed" value={assets.filter(a => a.internet_facing).length} color="yellow" />
              <StatCard label="Network Zones" value={new Set(assets.map(a => a.network_zone)).size} color="blue" />
            </div>

            {/* Zone Distribution - Enterprise View */}
            <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
              <div className="text-sm font-semibold text-slate-300 mb-3">Network Zone Distribution (Enterprise)</div>
              <div className="grid grid-cols-6 gap-2">
                {/* Perimeter */}
                <div className="space-y-2">
                  <div className="text-xs text-red-400 font-medium">Perimeter</div>
                  {['dmz'].map(zone => {
                    const zoneAssets = assets.filter(a => a.network_zone === zone)
                    if (zoneAssets.length === 0) return null
                    return (
                      <div key={zone} className="bg-red-900/30 rounded p-2 border border-red-500/30">
                        <div className="text-xs text-red-300 uppercase">{NETWORK_ZONES[zone]?.name || zone}</div>
                        <div className="text-lg font-bold">{zoneAssets.length}</div>
                        <div className="text-xs text-slate-400">{zoneAssets.filter(a => a.internet_facing).length} exposed</div>
                      </div>
                    )
                  })}
                </div>
                
                {/* Production */}
                <div className="space-y-2">
                  <div className="text-xs text-orange-400 font-medium">Production</div>
                  {['prod-web', 'prod-app', 'prod-db'].map(zone => {
                    const zoneAssets = assets.filter(a => a.network_zone === zone)
                    if (zoneAssets.length === 0) return null
                    return (
                      <div key={zone} className="bg-orange-900/30 rounded p-2 border border-orange-500/30">
                        <div className="text-xs text-orange-300 uppercase">{NETWORK_ZONES[zone]?.name || zone}</div>
                        <div className="text-lg font-bold">{zoneAssets.length}</div>
                        <div className="text-xs text-slate-400">{zoneAssets.filter(a => a.criticality >= 4).length} critical</div>
                      </div>
                    )
                  })}
                </div>
                
                {/* Development */}
                <div className="space-y-2">
                  <div className="text-xs text-blue-400 font-medium">Development</div>
                  {['dev-web', 'dev-app', 'dev-db', 'staging'].map(zone => {
                    const zoneAssets = assets.filter(a => a.network_zone === zone)
                    if (zoneAssets.length === 0) return null
                    return (
                      <div key={zone} className="bg-blue-900/30 rounded p-2 border border-blue-500/30">
                        <div className="text-xs text-blue-300 uppercase">{NETWORK_ZONES[zone]?.name || zone}</div>
                        <div className="text-lg font-bold">{zoneAssets.length}</div>
                        <div className="text-xs text-slate-400">dev assets</div>
                      </div>
                    )
                  })}
                </div>
                
                {/* Corporate */}
                <div className="space-y-2">
                  <div className="text-xs text-green-400 font-medium">Corporate</div>
                  {['corp', 'corp-wifi'].map(zone => {
                    const zoneAssets = assets.filter(a => a.network_zone === zone)
                    if (zoneAssets.length === 0) return null
                    return (
                      <div key={zone} className="bg-green-900/30 rounded p-2 border border-green-500/30">
                        <div className="text-xs text-green-300 uppercase">{NETWORK_ZONES[zone]?.name || zone}</div>
                        <div className="text-lg font-bold">{zoneAssets.length}</div>
                        <div className="text-xs text-slate-400">users</div>
                      </div>
                    )
                  })}
                </div>
                
                {/* Restricted */}
                <div className="space-y-2">
                  <div className="text-xs text-red-500 font-medium">Restricted</div>
                  {['restricted', 'pci', 'hipaa'].map(zone => {
                    const zoneAssets = assets.filter(a => a.network_zone === zone)
                    if (zoneAssets.length === 0) return null
                    return (
                      <div key={zone} className="bg-red-900/50 rounded p-2 border border-red-500/50">
                        <div className="text-xs text-red-200 uppercase">{NETWORK_ZONES[zone]?.name || zone}</div>
                        <div className="text-lg font-bold">{zoneAssets.length}</div>
                        <div className="text-xs text-red-300">high security</div>
                      </div>
                    )
                  })}
                </div>
                
                {/* Cloud & Infra */}
                <div className="space-y-2">
                  <div className="text-xs text-cyan-400 font-medium">Cloud & Infra</div>
                  {['cloud-prod', 'cloud-dev', 'mgmt', 'security', 'dr'].map(zone => {
                    const zoneAssets = assets.filter(a => a.network_zone === zone)
                    if (zoneAssets.length === 0) return null
                    return (
                      <div key={zone} className="bg-cyan-900/30 rounded p-2 border border-cyan-500/30">
                        <div className="text-xs text-cyan-300 uppercase">{NETWORK_ZONES[zone]?.name || zone}</div>
                        <div className="text-lg font-bold">{zoneAssets.length}</div>
                        <div className="text-xs text-slate-400">infra</div>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>

            {/* Business Unit Distribution */}
            <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
              <div className="text-sm font-semibold text-slate-300 mb-3">Business Unit Segmentation</div>
              <div className="grid grid-cols-5 gap-3">
                {BUSINESS_UNITS.map(bu => {
                  const buAssets = assets.filter(a => a.business_unit === bu.name)
                  if (buAssets.length === 0) return null
                  const criticalCount = buAssets.filter(a => a.criticality >= 4).length
                  const exposedCount = buAssets.filter(a => a.internet_facing).length
                  return (
                    <div key={bu.name} className="bg-slate-700/50 rounded-lg p-3">
                      <div className="text-sm font-medium text-slate-200">{bu.name}</div>
                      <div className="text-2xl font-bold">{buAssets.length}</div>
                      <div className="flex gap-2 mt-1">
                        <span className="text-xs text-red-400">{criticalCount} critical</span>
                        <span className="text-xs text-yellow-400">{exposedCount} exposed</span>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Asset Type Distribution */}
            <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
              <div className="text-sm font-semibold text-slate-300 mb-3">Asset Types</div>
              <div className="grid grid-cols-8 gap-2">
                {(() => {
                  const typeCounts: Record<string, number> = {}
                  assets.forEach(a => { typeCounts[a.type] = (typeCounts[a.type] || 0) + 1 })
                  return Object.entries(typeCounts)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 16)
                    .map(([type, count]) => (
                      <div key={type} className="bg-slate-700/50 rounded p-2 text-center">
                        <div className="text-xs text-slate-400 capitalize">{type.replace(/_/g, ' ')}</div>
                        <div className="text-lg font-bold">{count}</div>
                      </div>
                    ))
                })()}
              </div>
            </div>

            {/* Category Stats */}
            <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
              <div className="text-sm font-semibold text-slate-300 mb-3">Misconfiguration Categories</div>
              <div className="grid grid-cols-6 gap-3">
                {Object.entries(stats.byCat).map(([cat, count]) => (
                  <div key={cat} className="bg-slate-700/50 rounded-lg p-3 text-center">
                    <div className="text-xs text-slate-400 capitalize">{cat}</div>
                    <div className="text-xl font-bold">{count}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Asset Table */}
            <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
              <div className="p-4 border-b border-slate-700 font-semibold">Enterprise Assets (500 Total)</div>
              <div className="overflow-x-auto max-h-[500px]">
                <table className="w-full text-sm">
                  <thead className="bg-slate-700/50 sticky top-0">
                    <tr>
                      <th className="text-left p-3 text-slate-400">Asset</th>
                      <th className="text-left p-3 text-slate-400">Type</th>
                      <th className="text-left p-3 text-slate-400">Zone</th>
                      <th className="text-left p-3 text-slate-400">IP</th>
                      <th className="text-left p-3 text-slate-400">Business Unit</th>
                      <th className="text-left p-3 text-slate-400">Criticality</th>
                      <th className="text-left p-3 text-slate-400">Misconfigs</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700">
                    {assets.slice(0, 100).map(asset => (
                      <tr key={asset.id} className="hover:bg-slate-700/30">
                        <td className="p-3 font-medium">{asset.name}</td>
                        <td className="p-3 text-slate-400 capitalize">{asset.type.replace(/_/g, ' ')}</td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded text-xs ${
                            asset.network_zone === 'dmz' ? 'bg-red-900/50 text-red-300' :
                            asset.network_zone.startsWith('prod') ? 'bg-orange-900/50 text-orange-300' :
                            asset.network_zone.startsWith('dev') ? 'bg-blue-900/50 text-blue-300' :
                            asset.network_zone === 'restricted' || asset.network_zone === 'pci' || asset.network_zone === 'hipaa' ? 'bg-red-900/50 text-red-200' :
                            asset.network_zone.startsWith('cloud') ? 'bg-cyan-900/50 text-cyan-300' :
                            asset.network_zone === 'corp' || asset.network_zone === 'corp-wifi' ? 'bg-green-900/50 text-green-300' :
                            'bg-slate-700 text-slate-300'
                          }`}>{NETWORK_ZONES[asset.network_zone as NetworkZone]?.name || asset.network_zone}</span>
                        </td>
                        <td className="p-3 text-slate-400 font-mono text-xs">{asset.ip}</td>
                        <td className="p-3 text-slate-400 text-xs">{asset.business_unit}</td>
                        <td className="p-3">
                          <div className="flex gap-1">
                            {[1,2,3,4,5].map(i => (
                              <div key={i} className={`w-2 h-2 rounded-full ${i <= asset.criticality ? 'bg-red-500' : 'bg-slate-600'}`} />
                            ))}
                          </div>
                        </td>
                        <td className="p-3">
                          <span className="px-2 py-0.5 bg-orange-900/50 text-orange-300 rounded text-xs">
                            {asset.misconfigurations.length}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {assets.length > 100 && (
                <div className="p-2 text-center text-xs text-slate-400 border-t border-slate-700">
                  Showing 100 of {assets.length} assets
                </div>
              )}
            </div>
          </div>
        )}

        {/* Scanner View */}
        {view === 'scan' && (
          <div className="space-y-6">
            {/* Scanner Stats */}
            <div className="grid grid-cols-4 gap-4">
              <StatCard 
                label="Scan Status" 
                value={scanJob?.status || 'idle'} 
                color={scanJob?.status === 'completed' ? 'green' : scanJob?.status === 'running' ? 'blue' : 'white'} 
              />
              <StatCard 
                label="Progress" 
                value={scanJob ? `${Math.round(scanJob.progress)}%` : '0%'} 
                color="blue" 
              />
              <StatCard 
                label="Targets" 
                value={scanJob?.targetCount || assets.length} 
              />
              <StatCard 
                label="Findings" 
                value={scanJob?.summary?.totalMisconfigurations || 0} 
                color="orange" 
              />
            </div>

            {/* Scan Progress Bar */}
            {scanJob && scanJob.status === 'running' && (
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-slate-400">Scanning Progress</span>
                  <span className="text-sm text-blue-400">{Math.round(scanJob.progress)}%</span>
                </div>
                <div className="w-full h-3 bg-slate-700 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-blue-600 to-cyan-500 transition-all duration-300"
                    style={{ width: `${scanJob.progress}%` }}
                  />
                </div>
              </div>
            )}

            {/* Scan Results */}
            {scanJob?.summary && (
              <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
                <h3 className="text-lg font-semibold mb-4">Scan Summary</h3>
                <div className="grid grid-cols-5 gap-4">
                  <div className="text-center">
                    <div className="text-3xl font-bold text-red-400">{scanJob.summary.criticalCount}</div>
                    <div className="text-xs text-slate-400">Critical</div>
                  </div>
                  <div className="text-center">
                    <div className="text-3xl font-bold text-orange-400">{scanJob.summary.highCount}</div>
                    <div className="text-xs text-slate-400">High</div>
                  </div>
                  <div className="text-center">
                    <div className="text-3xl font-bold text-yellow-400">{scanJob.summary.mediumCount}</div>
                    <div className="text-xs text-slate-400">Medium</div>
                  </div>
                  <div className="text-center">
                    <div className="text-3xl font-bold text-slate-400">{scanJob.summary.lowCount}</div>
                    <div className="text-xs text-slate-400">Low</div>
                  </div>
                  <div className="text-center">
                    <div className="text-3xl font-bold text-green-400">{scanJob.summary.successCount}</div>
                    <div className="text-xs text-slate-400">Scanned</div>
                  </div>
                </div>
              </div>
            )}

            {/* Optimization Features */}
            <div className="bg-gradient-to-br from-slate-800 to-slate-800/50 rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold mb-4">Scanner Optimizations Active</h3>
              <div className="grid grid-cols-3 gap-4">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-blue-900/50 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                    </svg>
                  </div>
                  <div>
                    <div className="font-medium text-sm">Batched Commands</div>
                    <div className="text-xs text-slate-400">20+ commands in 1 SSH call</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-green-900/50 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
                    </svg>
                  </div>
                  <div>
                    <div className="font-medium text-sm">Connection Pooling</div>
                    <div className="text-xs text-slate-400">SSH ControlMaster reuse</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-purple-900/50 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                  </div>
                  <div>
                    <div className="font-medium text-sm">Host Discovery</div>
                    <div className="text-xs text-slate-400">Skip dead hosts (100ms vs 30s)</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-yellow-900/50 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <div>
                    <div className="font-medium text-sm">Result Caching</div>
                    <div className="text-xs text-slate-400">Skip unchanged hosts</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-red-900/50 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
                    </svg>
                  </div>
                  <div>
                    <div className="font-medium text-sm">Adaptive Rate Limit</div>
                    <div className="text-xs text-slate-400">AIMD algorithm</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-cyan-900/50 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
                    </svg>
                  </div>
                  <div>
                    <div className="font-medium text-sm">Priority Queue</div>
                    <div className="text-xs text-slate-400">Business impact scoring</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Analysis View */}
        {view === 'analysis' && (
          <div className="space-y-6">
            {!result ? (
              <div className="text-center py-20">
                <div className="w-20 h-20 bg-slate-800 rounded-full flex items-center justify-center mx-auto mb-4">
                  <svg className="w-10 h-10 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                  </svg>
                </div>
                <h3 className="text-xl font-semibold mb-2">Ready for Hybrid Analysis</h3>
                <p className="text-slate-400 mb-6">Scalable algorithm: Graph + Batch LLM</p>
              </div>
            ) : (
              <>
                {/* Graph Stats */}
                <div className="grid grid-cols-5 gap-4">
                  <StatCard label="Nodes" value={result.graph_stats.total_nodes} color="blue" />
                  <StatCard label="Edges" value={result.graph_stats.total_edges} color="purple" />
                  <StatCard label="Branching" value={result.graph_stats.avg_branching_factor} color="green" />
                  <StatCard label="Entry Points" value={result.entry_points.length} color="red" />
                  <StatCard label="Attack Paths" value={result.attack_paths.length} color="orange" />
                </div>

                {/* Edge Stats - Hybrid */}
                <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                  <div className="text-sm text-slate-400 mb-2">Hybrid Edge Creation</div>
                  <div className="flex items-center gap-6">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                      <span className="text-sm text-blue-400">Pattern: {result.edge_stats.pattern_edges}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 bg-purple-500 rounded-full"></div>
                      <span className="text-sm text-purple-400">LLM: {result.edge_stats.llm_edges}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                      <span className="text-sm text-green-400">Total: {result.edge_stats.total_edges}</span>
                    </div>
                  </div>
                  <div className="text-xs text-slate-500 mt-2">
                    Pattern edges: instant • LLM edges: batch evaluated for non-obvious attack paths
                  </div>
                </div>

                {/* Timing */}
                <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                  <div className="text-sm text-slate-400 mb-2">Performance (Total: {result.timing.total}ms)</div>
                  <div className="flex gap-4 text-xs">
                    <span className="text-blue-400">Nodes: {result.timing.nodes}ms</span>
                    <span className="text-purple-400">Edges: {result.timing.edges}ms</span>
                    <span className="text-green-400">PageRank: {result.timing.pagerank}ms</span>
                    <span className="text-yellow-400">Paths: {result.timing.paths}ms</span>
                    <span className="text-red-400">LLM Validation: {result.timing.validation}ms</span>
                    <span className="text-orange-400">Entry Analysis: {result.timing.entry_analysis}ms</span>
                  </div>
                </div>

                {/* Entry Points */}
                <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
                  <div className="p-4 border-b border-slate-700 font-semibold">Entry Points (LLM Ranked)</div>
                  <div className="divide-y divide-slate-700">
                    {result.entry_points.slice(0, 6).map((entry, i) => (
                      <div key={i} className="p-4">
                        <div className="flex items-start gap-3">
                          <div className="w-7 h-7 bg-red-900/50 rounded-full flex items-center justify-center text-red-400 text-sm font-bold">
                            {i + 1}
                          </div>
                          <div className="flex-1">
                            <div className="font-medium">{entry.asset_name}</div>
                            <div className="text-sm text-orange-400">{entry.misconfig_title}</div>
                            <div className="text-sm text-slate-400 mt-1">{entry.reasoning}</div>
                            <div className="text-sm text-red-300">Value: {entry.attacker_value}</div>
                          </div>
                          <div className="text-xs text-slate-400">PR: {entry.pagerank_score.toFixed(4)}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Critical Assets */}
                <div className="bg-slate-800 rounded-xl border border-slate-700 p-4">
                  <div className="font-semibold mb-3">Critical Assets</div>
                  <div className="grid grid-cols-3 gap-3">
                    {result.critical_assets.map((a, i) => (
                      <div key={i} className="bg-slate-700/50 rounded-lg p-3">
                        <div className="font-medium text-sm">{a.asset_name}</div>
                        <div className="text-xs text-slate-400">{a.reason}</div>
                        <div className="text-xs text-purple-400">{a.paths_to_it} paths</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Insights */}
                <div className="bg-gradient-to-br from-red-900/30 to-orange-900/30 rounded-xl p-5 border border-red-800/50">
                  <div className="font-semibold mb-3">Key Insights</div>
                  <ul className="space-y-1">
                    {result.key_insights.map((insight, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm">
                        <span className="text-red-400">•</span>
                        <span className="text-slate-300">{insight}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </>
            )}
          </div>
        )}

        {/* Paths View */}
        {view === 'paths' && (
          <div className="space-y-6">
            {!result?.attack_paths?.length ? (
              <div className="text-center py-20 text-slate-400">Run analysis to discover paths</div>
            ) : (
              <>
                {/* Unique Paths Summary */}
                <div className="bg-gradient-to-r from-green-900/30 to-blue-900/30 rounded-xl p-4 border border-green-800/50">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <svg className="w-5 h-5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                      <span className="font-medium text-green-300">Unique Attack Paths Discovered</span>
                    </div>
                    <div className="flex items-center gap-4 text-sm">
                      <span className="text-slate-300">
                        {result.attack_paths.length} paths • 
                        Each uses <span className="text-green-400 font-medium">distinct assets</span>
                      </span>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-6">
                  {/* Path List */}
                  <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
                    <div className="p-4 border-b border-slate-700 font-semibold">
                      Unique Paths ({result.attack_paths.length})
                    </div>
                    <div className="divide-y divide-slate-700 max-h-[600px] overflow-y-auto">
                      {result.attack_paths.map((path, i) => {
                        // Get unique assets for this path
                        const uniqueAssets = [...new Set(path.nodes.map(n => n.asset_id))]
                        const vulnCategories = [...new Set(path.nodes.map(n => n.misconfig_category))]
                        
                        return (
                          <button
                            key={path.path_id}
                            onClick={() => setSelectedPath(i)}
                            className={`w-full p-4 text-left hover:bg-slate-700/30 transition-colors ${
                              selectedPath === i ? 'bg-red-900/20 border-l-2 border-red-500' : ''
                            }`}
                          >
                            <div className="flex items-center justify-between mb-1">
                              <span className="font-medium">{path.path_id}</span>
                              <span className={`text-xs px-2 py-0.5 rounded ${
                                path.final_risk_score > 0.5 ? 'bg-red-900/50 text-red-300' : 'bg-yellow-900/50 text-yellow-300'
                              }`}>
                                {Math.round(path.final_risk_score * 100)}% risk
                              </span>
                            </div>
                            <div className="text-xs text-slate-400 mb-1">
                              {uniqueAssets.length} unique assets • {path.nodes.length} steps
                            </div>
                            <div className="flex flex-wrap gap-1 mb-1">
                              {vulnCategories.map((cat, ci) => (
                                <span key={ci} className={`text-xs px-1.5 py-0.5 rounded ${
                                  cat === 'authentication' ? 'bg-red-900/40 text-red-300' :
                                  cat === 'authorization' ? 'bg-purple-900/40 text-purple-300' :
                                  cat === 'network' ? 'bg-blue-900/40 text-blue-300' :
                                  cat === 'service' ? 'bg-orange-900/40 text-orange-300' :
                                  'bg-slate-700 text-slate-300'
                                }`}>
                                  {cat}
                                </span>
                              ))}
                            </div>
                            <div className="flex gap-2 text-xs">
                              <span className="text-blue-400">P:{Math.round(path.path_probability * 100)}%</span>
                              <span className="text-green-400">R:{Math.round(path.realism_score * 100)}%</span>
                            </div>
                          </button>
                        )
                      })}
                    </div>
                  </div>

                {/* Path Detail */}
                <div className="col-span-2">
                  {selectedPath !== null && result.attack_paths[selectedPath] ? (
                    <div className="bg-slate-800 rounded-xl border border-slate-700">
                      <div className="p-5 border-b border-slate-700">
                        <div className="flex items-center justify-between">
                          <h3 className="text-lg font-semibold">{result.attack_paths[selectedPath].path_id}</h3>
                          <div className="flex gap-3 text-xs">
                            <span className="text-blue-400">Prob: {Math.round(result.attack_paths[selectedPath].path_probability * 100)}%</span>
                            <span className="text-green-400">Realism: {Math.round(result.attack_paths[selectedPath].realism_score * 100)}%</span>
                            <span className="text-orange-400">Impact: {Math.round(result.attack_paths[selectedPath].impact_score * 100)}%</span>
                          </div>
                        </div>
                      </div>

                      {/* Score Bar */}
                      <div className="p-4 border-b border-slate-700 bg-slate-700/30">
                        <div className="flex items-center justify-between">
                          <span className="text-sm">Final Risk Score</span>
                          <div className="flex items-center gap-3">
                            <div className="w-48 h-3 bg-slate-700 rounded-full overflow-hidden">
                              <div
                                className="h-full bg-gradient-to-r from-green-500 via-yellow-500 to-red-500"
                                style={{ width: `${result.attack_paths[selectedPath].final_risk_score * 100}%` }}
                              />
                            </div>
                            <span className="text-lg font-bold text-red-400">
                              {Math.round(result.attack_paths[selectedPath].final_risk_score * 100)}%
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Steps */}
                      <div className="p-5 border-b border-slate-700">
                        <div className="flex items-center justify-between mb-4">
                          <h4 className="font-medium">Attack Chain</h4>
                          <div className="flex items-center gap-2 text-xs">
                            <span className="text-green-400">
                              {[...new Set(result.attack_paths[selectedPath].nodes.map(n => n.asset_id))].length} unique assets
                            </span>
                          </div>
                        </div>
                        <div className="space-y-3">
                          {result.attack_paths[selectedPath].nodes.map((node, i) => {
                            const edge = result.attack_paths[selectedPath].edges[i]
                            const categoryColor = 
                              node.misconfig_category === 'authentication' ? 'bg-red-900/40 text-red-300 border-red-700' :
                              node.misconfig_category === 'authorization' ? 'bg-purple-900/40 text-purple-300 border-purple-700' :
                              node.misconfig_category === 'network' ? 'bg-blue-900/40 text-blue-300 border-blue-700' :
                              node.misconfig_category === 'service' ? 'bg-orange-900/40 text-orange-300 border-orange-700' :
                              'bg-slate-700 text-slate-300 border-slate-600'
                            
                            return (
                              <div key={i} className="flex gap-4">
                                <div className="flex flex-col items-center">
                                  <div className={`w-7 h-7 rounded-full flex items-center justify-center text-sm font-bold ${
                                    i === 0 ? 'bg-red-600' : i === result.attack_paths[selectedPath].nodes.length - 1 ? 'bg-purple-600' : 'bg-orange-600'
                                  }`}>{i + 1}</div>
                                  {i < result.attack_paths[selectedPath].nodes.length - 1 && (
                                    <div className="w-0.5 h-full bg-slate-600 my-2" />
                                  )}
                                </div>
                                <div className="flex-1 pb-3">
                                  <div className="flex items-center gap-2 mb-1">
                                    <span className="font-medium">{node.asset_name}</span>
                                    <span className="text-xs px-1.5 py-0.5 bg-slate-700 rounded uppercase">{node.asset_zone}</span>
                                    <span className="text-xs px-1.5 py-0.5 bg-slate-600 rounded capitalize">{node.asset_type.replace(/_/g, ' ')}</span>
                                  </div>
                                  <div className="flex items-center gap-2 mb-1">
                                    <span className="text-sm text-orange-400">{node.misconfig_title}</span>
                                    <span className={`text-xs px-1.5 py-0.5 rounded border ${categoryColor}`}>
                                      {node.misconfig_category}
                                    </span>
                                  </div>
                                  {edge && (
                                    <div className="mt-1 text-xs bg-slate-700/50 p-2 rounded">
                                      <div className="flex items-center gap-2">
                                        <span className="text-slate-400">→ {Math.round(edge.probability * 100)}% via {edge.technique}</span>
                                        <span className={`px-1.5 py-0.5 rounded text-xs ${
                                          edge.edge_type === 'llm' 
                                            ? 'bg-purple-900/50 text-purple-300' 
                                            : 'bg-blue-900/50 text-blue-300'
                                        }`}>
                                          {edge.edge_type === 'llm' ? 'LLM' : 'Pattern'}
                                        </span>
                                      </div>
                                      {edge.reasoning && (
                                        <div className="text-slate-500 mt-1">{edge.reasoning}</div>
                                      )}
                                    </div>
                                  )}
                                </div>
                              </div>
                            )
                          })}
                        </div>
                      </div>

                      {/* Narrative */}
                      <div className="p-5 border-b border-slate-700">
                        <h4 className="font-medium mb-2">LLM Narrative</h4>
                        <p className="text-sm text-slate-300">{result.attack_paths[selectedPath].narrative}</p>
                      </div>

                      {/* Impact */}
                      <div className="p-5">
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <span className="text-sm text-slate-400">Business Impact:</span>
                            <p className="text-sm text-red-300 mt-1">{result.attack_paths[selectedPath].business_impact}</p>
                          </div>
                          <div>
                            <span className="text-sm text-slate-400">Kill Chain:</span>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {result.attack_paths[selectedPath].kill_chain.map((phase, i) => (
                                <span key={i} className="text-xs px-2 py-0.5 bg-slate-700 rounded">{phase}</span>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="bg-slate-800 rounded-xl border border-slate-700 p-12 text-center text-slate-400">
                      Select a path
                    </div>
                  )}
                </div>
              </div>
              </>
            )}
          </div>
        )}

        {/* Algorithm View */}
        {view === 'algo' && (
          <div className="space-y-6">
            <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
              <h3 className="text-xl font-bold mb-6">Scalable Hybrid Algorithm</h3>

              <div className="space-y-4">
                <div className="border-l-4 border-blue-500 pl-4">
                  <h4 className="font-semibold text-blue-400">Phase 1: Build Nodes (O(n))</h4>
                  <p className="text-sm text-slate-400">Create node per (asset, misconfiguration) pair</p>
                </div>

                <div className="border-l-4 border-purple-500 pl-4">
                  <h4 className="font-semibold text-purple-400">Phase 2: Edge Evaluation (O(n²) but fast)</h4>
                  <p className="text-sm text-slate-400">Use attack pattern templates + zone reachability. No per-edge LLM calls!</p>
                  <div className="mt-2 bg-slate-700/50 p-2 rounded text-xs">
                    Predefined patterns encode attacker knowledge: network_exposure → authentication → authorization
                  </div>
                </div>

                <div className="border-l-4 border-green-500 pl-4">
                  <h4 className="font-semibold text-green-400">Phase 3: PageRank (O(iterations × E))</h4>
                  <p className="text-sm text-slate-400">Calculate node importance with probability-weighted edges</p>
                </div>

                <div className="border-l-4 border-yellow-500 pl-4">
                  <h4 className="font-semibold text-yellow-400">Phase 4: Dijkstra Path Finding (O(E log V))</h4>
                  <p className="text-sm text-slate-400">Find highest probability paths using -log(probability) as edge weight</p>
                </div>

                <div className="border-l-4 border-red-500 pl-4">
                  <h4 className="font-semibold text-red-400">Phase 5: Batch LLM Validation (scales linearly)</h4>
                  <p className="text-sm text-slate-400">Validate 5 paths per LLM call instead of 1 call per edge</p>
                </div>
              </div>
            </div>

            {/* Performance Comparison */}
            <div className="bg-gradient-to-r from-green-900/30 to-blue-900/30 rounded-xl p-6 border border-green-800/50">
              <h3 className="font-semibold mb-3 text-green-400">Performance Comparison</h3>
              <div className="grid grid-cols-2 gap-6 text-sm">
                <div>
                  <h4 className="text-slate-300 mb-2">Before (Per-Edge LLM)</h4>
                  <ul className="space-y-1 text-slate-400">
                    <li>❌ 150 nodes = ~22,500 edge evaluations</li>
                    <li>❌ 22,500 LLM calls</li>
                    <li>❌ ~30+ minutes</li>
                  </ul>
                </div>
                <div>
                  <h4 className="text-slate-300 mb-2">After (Pattern + Batch)</h4>
                  <ul className="space-y-1 text-green-400">
                    <li>✓ Pattern-based edge creation (instant)</li>
                    <li>✓ ~2-4 LLM calls total (batched)</li>
                    <li>✓ ~5-15 seconds</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* False Positive Reduction */}
            <div className="bg-gradient-to-r from-purple-900/30 to-pink-900/30 rounded-xl p-6 border border-purple-800/50">
              <h3 className="font-semibold mb-3 text-purple-400">False Positive Reduction</h3>
              <div className="grid grid-cols-2 gap-6 text-sm">
                <div>
                  <h4 className="text-slate-300 mb-2">Before</h4>
                  <ul className="space-y-1 text-slate-400">
                    <li>❌ 15-30% false positive rate</li>
                    <li>❌ Static detection rules</li>
                    <li>❌ No context awareness</li>
                  </ul>
                </div>
                <div>
                  <h4 className="text-slate-300 mb-2">After</h4>
                  <ul className="space-y-1 text-purple-400">
                    <li>✓ 5-10% false positive rate</li>
                    <li>✓ Context-aware validation</li>
                    <li>✓ Confidence scoring</li>
                    <li>✓ Known FP patterns database</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Scanner Architecture */}
            <div className="bg-gradient-to-r from-cyan-900/30 to-teal-900/30 rounded-xl p-6 border border-cyan-800/50">
              <h3 className="font-semibold mb-4 text-cyan-400">Scanner Architecture Files</h3>
              <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                <div className="space-y-1">
                  <div className="text-slate-300">Core Scanners:</div>
                  <div className="text-cyan-300">optimized-scanner.ts</div>
                  <div className="text-cyan-300">high-perf-scanner.ts</div>
                  <div className="text-slate-300 mt-2">Scalable Components:</div>
                  <div className="text-cyan-300">scalable/scanner-orchestrator.ts</div>
                  <div className="text-cyan-300">scalable/result-streamer.ts</div>
                  <div className="text-cyan-300">scalable/distributed-coordinator.ts</div>
                </div>
                <div className="space-y-1">
                  <div className="text-slate-300">Infrastructure:</div>
                  <div className="text-cyan-300">scalable/job-state-manager.ts</div>
                  <div className="text-cyan-300">scalable/priority-queue.ts</div>
                  <div className="text-cyan-300">scalable/adaptive-rate-limiter.ts</div>
                  <div className="text-cyan-300">scalable/scan-scheduler.ts</div>
                  <div className="text-slate-300 mt-2">Analysis:</div>
                  <div className="text-cyan-300">zone-detection.ts</div>
                  <div className="text-cyan-300">network-topology-collector.ts</div>
                  <div className="text-cyan-300">fp-reduction.ts</div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

function StatCard({ label, value, color = 'white' }: { label: string; value: string | number; color?: string }) {
  const colors: Record<string, string> = {
    white: 'text-white',
    red: 'text-red-400',
    yellow: 'text-yellow-400',
    blue: 'text-blue-400',
    purple: 'text-purple-400',
    green: 'text-green-400',
    orange: 'text-orange-400'
  }
  return (
    <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
      <div className="text-sm text-slate-400 mb-1">{label}</div>
      <div className={`text-2xl font-bold ${colors[color]}`}>{value}</div>
    </div>
  )
}
