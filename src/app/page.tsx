'use client'

import { useState, useCallback, useMemo } from 'react'

// ─── TYPES ───────────────────────────────────────────────────────────────────

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
  edge_type: 'pattern' | 'llm' | 'gnn_bayesian'
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
  graph_stats: { total_nodes: number; total_edges: number; avg_branching_factor: number | string }
  edge_stats: { pattern_edges: number; llm_edges: number; total_edges: number }
  entry_points: Array<{ node_id: string; asset_name: string; misconfig_title: string; reasoning: string; attacker_value: string; pagerank_score: number }>
  attack_paths: AttackPath[]
  critical_assets: Array<{ asset_id: string; asset_name: string; reason: string; paths_to_it: number }>
  key_insights: string[]
  timing: { nodes: number; edges: number; pagerank: number; paths: number; validation: number; entry_analysis: number; total: number }
}

// ─── STATIC DATA ─────────────────────────────────────────────────────────────

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

const NETWORK_ZONES = {
  'dmz':        { name: 'DMZ',        subnet: '10.0' },
  'prod-web':   { name: 'Prod Web',   subnet: '10.10' },
  'prod-app':   { name: 'Prod App',   subnet: '10.11' },
  'prod-db':    { name: 'Prod DB',    subnet: '10.12' },
  'dev-web':    { name: 'Dev Web',    subnet: '10.20' },
  'dev-app':    { name: 'Dev App',    subnet: '10.21' },
  'dev-db':     { name: 'Dev DB',     subnet: '10.22' },
  'staging':    { name: 'Staging',    subnet: '10.30' },
  'corp':       { name: 'Corporate',  subnet: '10.100' },
  'corp-wifi':  { name: 'Corp WiFi',  subnet: '10.101' },
  'restricted': { name: 'Restricted', subnet: '10.200' },
  'pci':        { name: 'PCI-DSS',    subnet: '10.201' },
  'hipaa':      { name: 'HIPAA',      subnet: '10.202' },
  'mgmt':       { name: 'Management', subnet: '10.250' },
  'security':   { name: 'Security',   subnet: '10.251' },
  'cloud-prod': { name: 'Cloud Prod', subnet: '172.16' },
  'cloud-dev':  { name: 'Cloud Dev',  subnet: '172.17' },
  'dr':         { name: 'DR Site',    subnet: '10.180' },
} as const

type NetworkZone = keyof typeof NETWORK_ZONES

const BUSINESS_UNITS = [
  { name: 'Finance', revenue: 50000000 },
  { name: 'Engineering', revenue: 30000000 },
  { name: 'Sales', revenue: 40000000 },
  { name: 'HR', revenue: 5000000 },
  { name: 'Operations', revenue: 20000000 },
  { name: 'Legal', revenue: 8000000 },
  { name: 'Marketing', revenue: 15000000 },
  { name: 'IT', revenue: 10000000 },
  { name: 'R&D', revenue: 25000000 },
  { name: 'Customer Support', revenue: 12000000 },
] as const

// ─── SEEDED RNG ───────────────────────────────────────────────────────────────

class SeededRandom {
  private seed: number
  constructor(seed: number) { this.seed = seed }
  next(): number { this.seed = (this.seed * 1103515245 + 12345) & 0x7fffffff; return this.seed / 0x7fffffff }
  nextInt(min: number, max: number): number { return Math.floor(this.next() * (max - min + 1)) + min }
  pick<T>(arr: readonly T[]): T { return arr[Math.floor(this.next() * arr.length)] }
  shuffle<T>(arr: T[]): T[] {
    const r = [...arr]
    for (let i = r.length - 1; i > 0; i--) { const j = Math.floor(this.next() * (i + 1));[r[i], r[j]] = [r[j], r[i]] }
    return r
  }
}

// ─── ASSET GENERATOR ─────────────────────────────────────────────────────────

const ASSET_TEMPLATES = [
  { type: 'domain_controller', namePrefix: 'DC', zones: ['restricted', 'corp', 'mgmt'] as NetworkZone[], criticality: 5, domainJoined: true, services: ['AD', 'DNS', 'LDAP'], dataSensitivity: 'credentials', internetFacing: false, misconfigCategories: ['authentication', 'authorization', 'network'], count: 8 },
  { type: 'backup_server', namePrefix: 'BKUP', zones: ['restricted', 'dr'] as NetworkZone[], criticality: 5, domainJoined: true, services: ['Veeam', 'Commvault'], dataSensitivity: 'backups', internetFacing: false, misconfigCategories: ['authentication', 'encryption'], count: 6 },
  { type: 'dns_server', namePrefix: 'DNS', zones: ['mgmt', 'corp'] as NetworkZone[], criticality: 4, domainJoined: true, services: ['DNS'], dataSensitivity: 'none', internetFacing: false, misconfigCategories: ['network', 'service'], count: 4 },
  { type: 'dhcp_server', namePrefix: 'DHCP', zones: ['mgmt', 'corp'] as NetworkZone[], criticality: 3, domainJoined: true, services: ['DHCP'], dataSensitivity: 'none', internetFacing: false, misconfigCategories: ['network', 'authorization'], count: 3 },
  { type: 'identity_server', namePrefix: 'IDP', zones: ['restricted', 'security'] as NetworkZone[], criticality: 5, domainJoined: true, services: ['Okta', 'ADFS', 'SAML'], dataSensitivity: 'credentials', internetFacing: true, misconfigCategories: ['authentication', 'authorization'], count: 4 },
  { type: 'pki_server', namePrefix: 'PKI', zones: ['restricted'] as NetworkZone[], criticality: 5, domainJoined: true, services: ['CA', 'OCSP'], dataSensitivity: 'certificates', internetFacing: false, misconfigCategories: ['encryption', 'authentication'], count: 2 },
  { type: 'siem', namePrefix: 'SIEM', zones: ['security'] as NetworkZone[], criticality: 5, domainJoined: true, services: ['Splunk', 'QRadar'], dataSensitivity: 'logs', internetFacing: false, misconfigCategories: ['logging', 'network'], count: 2 },
  { type: 'pam', namePrefix: 'PAM', zones: ['security', 'restricted'] as NetworkZone[], criticality: 5, domainJoined: true, services: ['CyberArk', 'BeyondTrust'], dataSensitivity: 'credentials', internetFacing: false, misconfigCategories: ['authentication', 'authorization'], count: 3 },
  { type: 'firewall', namePrefix: 'FW', zones: ['dmz', 'mgmt'] as NetworkZone[], criticality: 5, domainJoined: false, services: ['Palo Alto', 'Fortinet'], dataSensitivity: 'firewall_rules', internetFacing: true, misconfigCategories: ['network', 'authorization'], count: 6 },
  { type: 'load_balancer', namePrefix: 'LB', zones: ['dmz', 'prod-web', 'cloud-prod'] as NetworkZone[], criticality: 4, domainJoined: false, services: ['F5', 'NGINX'], dataSensitivity: 'ssl_certs', internetFacing: true, misconfigCategories: ['network', 'encryption'], count: 8 },
  { type: 'reverse_proxy', namePrefix: 'RPX', zones: ['dmz'] as NetworkZone[], criticality: 4, domainJoined: false, services: ['NGINX', 'HAProxy'], dataSensitivity: 'ssl_certs', internetFacing: true, misconfigCategories: ['network', 'encryption'], count: 4 },
  { type: 'vpn_gateway', namePrefix: 'VPN', zones: ['dmz', 'corp'] as NetworkZone[], criticality: 4, domainJoined: true, services: ['OpenVPN', 'Cisco ASA'], dataSensitivity: 'credentials', internetFacing: true, misconfigCategories: ['network', 'authentication'], count: 4 },
  { type: 'web_application_firewall', namePrefix: 'WAF', zones: ['dmz'] as NetworkZone[], criticality: 4, domainJoined: false, services: ['ModSecurity', 'AWS WAF'], dataSensitivity: 'logs', internetFacing: true, misconfigCategories: ['network', 'logging'], count: 4 },
  { type: 'web_server', namePrefix: 'WEB', zones: ['dmz', 'prod-web', 'dev-web', 'staging', 'cloud-prod'] as NetworkZone[], criticality: 4, domainJoined: false, services: ['IIS', 'Apache', 'NGINX'], dataSensitivity: 'app_data', internetFacing: true, misconfigCategories: ['network', 'service', 'encryption'], count: 25 },
  { type: 'app_server', namePrefix: 'APP', zones: ['prod-app', 'dev-app', 'staging', 'cloud-prod'] as NetworkZone[], criticality: 4, domainJoined: true, services: ['Tomcat', 'NodeJS', 'Java'], dataSensitivity: 'business_logic', internetFacing: false, misconfigCategories: ['authentication', 'service'], count: 30 },
  { type: 'api_gateway', namePrefix: 'API', zones: ['dmz', 'prod-web'] as NetworkZone[], criticality: 4, domainJoined: false, services: ['Kong', 'Apigee'], dataSensitivity: 'api_keys', internetFacing: true, misconfigCategories: ['authentication', 'network'], count: 8 },
  { type: 'microservice', namePrefix: 'SVC', zones: ['prod-app', 'dev-app', 'cloud-prod', 'cloud-dev'] as NetworkZone[], criticality: 3, domainJoined: false, services: ['Docker', 'K8s'], dataSensitivity: 'app_data', internetFacing: false, misconfigCategories: ['authentication', 'service'], count: 40 },
  { type: 'database_server', namePrefix: 'DB', zones: ['prod-db', 'dev-db', 'restricted', 'cloud-prod'] as NetworkZone[], criticality: 5, domainJoined: true, services: ['SQL Server', 'Oracle', 'PostgreSQL'], dataSensitivity: 'pii', internetFacing: false, misconfigCategories: ['authentication', 'authorization', 'encryption'], count: 20 },
  { type: 'nosql_db', namePrefix: 'NOSQL', zones: ['prod-db', 'dev-db', 'cloud-prod'] as NetworkZone[], criticality: 4, domainJoined: false, services: ['MongoDB', 'Redis', 'Elasticsearch'], dataSensitivity: 'pii', internetFacing: false, misconfigCategories: ['authentication', 'network'], count: 15 },
  { type: 'data_warehouse', namePrefix: 'DWH', zones: ['restricted', 'cloud-prod'] as NetworkZone[], criticality: 5, domainJoined: true, services: ['Snowflake', 'Redshift', 'Teradata'], dataSensitivity: 'analytics', internetFacing: false, misconfigCategories: ['authentication', 'encryption'], count: 5 },
  { type: 'file_server', namePrefix: 'FS', zones: ['corp', 'prod-app', 'restricted'] as NetworkZone[], criticality: 4, domainJoined: true, services: ['SMB', 'NFS'], dataSensitivity: 'user_files', internetFacing: false, misconfigCategories: ['network', 'authorization'], count: 15 },
  { type: 'nas', namePrefix: 'NAS', zones: ['corp', 'restricted', 'dr'] as NetworkZone[], criticality: 4, domainJoined: false, services: ['NFS', 'SMB'], dataSensitivity: 'documents', internetFacing: false, misconfigCategories: ['network', 'encryption'], count: 8 },
  { type: 'storage_server', namePrefix: 'STR', zones: ['cloud-prod', 'cloud-dev'] as NetworkZone[], criticality: 4, domainJoined: false, services: ['S3', 'Blob'], dataSensitivity: 'mixed', internetFacing: false, misconfigCategories: ['encryption', 'authorization'], count: 10 },
  { type: 'email_server', namePrefix: 'MAIL', zones: ['dmz', 'corp'] as NetworkZone[], criticality: 4, domainJoined: true, services: ['Exchange', 'Postfix'], dataSensitivity: 'emails', internetFacing: true, misconfigCategories: ['network', 'authentication', 'encryption'], count: 6 },
  { type: 'voip_server', namePrefix: 'VOIP', zones: ['corp'] as NetworkZone[], criticality: 3, domainJoined: true, services: ['Cisco CUCM', 'Asterisk'], dataSensitivity: 'call_logs', internetFacing: false, misconfigCategories: ['network', 'service'], count: 4 },
  { type: 'chat_server', namePrefix: 'CHAT', zones: ['corp', 'cloud-prod'] as NetworkZone[], criticality: 3, domainJoined: true, services: ['Slack', 'Teams', 'Mattermost'], dataSensitivity: 'messages', internetFacing: false, misconfigCategories: ['authentication', 'network'], count: 4 },
  { type: 'build_server', namePrefix: 'BLD', zones: ['dev-app', 'cloud-dev'] as NetworkZone[], criticality: 3, domainJoined: true, services: ['Jenkins', 'GitLab CI'], dataSensitivity: 'source_code', internetFacing: false, misconfigCategories: ['authentication', 'service'], count: 8 },
  { type: 'code_repo', namePrefix: 'GIT', zones: ['dev-app', 'cloud-dev'] as NetworkZone[], criticality: 4, domainJoined: true, services: ['GitHub Enterprise', 'GitLab'], dataSensitivity: 'source_code', internetFacing: true, misconfigCategories: ['authentication', 'network'], count: 4 },
  { type: 'artifact_repo', namePrefix: 'ART', zones: ['dev-app', 'cloud-dev'] as NetworkZone[], criticality: 3, domainJoined: false, services: ['Nexus', 'Artifactory'], dataSensitivity: 'artifacts', internetFacing: false, misconfigCategories: ['authentication', 'network'], count: 4 },
  { type: 'monitoring', namePrefix: 'MON', zones: ['mgmt', 'cloud-prod'] as NetworkZone[], criticality: 4, domainJoined: true, services: ['Nagios', 'Zabbix', 'Datadog'], dataSensitivity: 'metrics', internetFacing: false, misconfigCategories: ['network', 'logging'], count: 8 },
  { type: 'logging_server', namePrefix: 'LOG', zones: ['mgmt', 'security'] as NetworkZone[], criticality: 4, domainJoined: true, services: ['ELK', 'Splunk'], dataSensitivity: 'logs', internetFacing: false, misconfigCategories: ['logging', 'network'], count: 6 },
  { type: 'jump_server', namePrefix: 'JMP', zones: ['dmz', 'mgmt'] as NetworkZone[], criticality: 4, domainJoined: true, services: ['RDP', 'SSH'], dataSensitivity: 'credentials', internetFacing: true, misconfigCategories: ['network', 'authentication'], count: 6 },
  { type: 'workstation', namePrefix: 'WS', zones: ['corp', 'corp-wifi', 'dev-web'] as NetworkZone[], criticality: 2, domainJoined: true, services: ['Office', 'Browser'], dataSensitivity: 'user_data', internetFacing: false, misconfigCategories: ['authentication', 'service'], count: 80 },
  { type: 'laptop', namePrefix: 'LAP', zones: ['corp', 'corp-wifi'] as NetworkZone[], criticality: 2, domainJoined: true, services: ['Office', 'Browser'], dataSensitivity: 'user_data', internetFacing: false, misconfigCategories: ['authentication', 'encryption'], count: 60 },
  { type: 'developer_workstation', namePrefix: 'DEVWS', zones: ['dev-web', 'dev-app'] as NetworkZone[], criticality: 3, domainJoined: true, services: ['IDE', 'Docker'], dataSensitivity: 'source_code', internetFacing: false, misconfigCategories: ['authentication', 'service'], count: 40 },
  { type: 'iot_device', namePrefix: 'IOT', zones: ['corp', 'mgmt'] as NetworkZone[], criticality: 2, domainJoined: false, services: ['Sensors', 'Camera'], dataSensitivity: 'telemetry', internetFacing: false, misconfigCategories: ['network', 'authentication'], count: 20 },
  { type: 'printer', namePrefix: 'PRT', zones: ['corp', 'corp-wifi'] as NetworkZone[], criticality: 1, domainJoined: true, services: ['Print'], dataSensitivity: 'print_jobs', internetFacing: false, misconfigCategories: ['network'], count: 15 },
  { type: 'scanner_device', namePrefix: 'SCN', zones: ['corp'] as NetworkZone[], criticality: 2, domainJoined: true, services: ['Scan'], dataSensitivity: 'scanned_docs', internetFacing: false, misconfigCategories: ['network'], count: 8 },
  { type: 'pci_server', namePrefix: 'PCI', zones: ['pci'] as NetworkZone[], criticality: 5, domainJoined: true, services: ['Payment', 'CardProc'], dataSensitivity: 'pci_data', internetFacing: false, misconfigCategories: ['encryption', 'authentication', 'logging'], count: 6 },
  { type: 'hipaa_server', namePrefix: 'HIPAA', zones: ['hipaa'] as NetworkZone[], criticality: 5, domainJoined: true, services: ['EHR', 'PHI'], dataSensitivity: 'phi', internetFacing: false, misconfigCategories: ['encryption', 'authentication', 'logging'], count: 8 },
  { type: 'k8s_cluster', namePrefix: 'K8S', zones: ['cloud-prod', 'cloud-dev'] as NetworkZone[], criticality: 4, domainJoined: false, services: ['Kubernetes'], dataSensitivity: 'workloads', internetFacing: false, misconfigCategories: ['authentication', 'authorization', 'network'], count: 12 },
  { type: 'container_registry', namePrefix: 'CR', zones: ['cloud-prod', 'cloud-dev'] as NetworkZone[], criticality: 4, domainJoined: false, services: ['Docker Registry', 'ECR'], dataSensitivity: 'images', internetFacing: false, misconfigCategories: ['authentication', 'network'], count: 4 },
]

function generateEnterpriseAssets(): Asset[] {
  const assets: Asset[] = []
  const rng = new SeededRandom(42)
  let assetId = 1
  const zoneCounters: Record<string, number> = {}
  const usedIPs = new Set<string>()

  const generateIP = (zone: NetworkZone): string => {
    const subnet = NETWORK_ZONES[zone].subnet
    let ip = `${subnet}.0.1`
    let attempts = 0
    do {
      ip = `${subnet}.${rng.nextInt(0, 255)}.${rng.nextInt(1, 254)}`
      attempts++
    } while (usedIPs.has(ip) && attempts < 1000)
    usedIPs.add(ip)
    return ip
  }

  const genMisconfigs = (cats: string[]): Misconfiguration[] => {
    const relevant = MISCONFIG_DB.filter(m => cats.includes(m.category))
    return rng.shuffle(relevant).slice(0, rng.nextInt(1, 3)).map(m => ({ ...m }))
  }

  const getEnvSuffix = (zone: NetworkZone): string => {
    if (zone.startsWith('dev') || zone === 'cloud-dev') return '-D'
    if (zone.startsWith('staging')) return '-S'
    if (zone === 'dr') return '-DR'
    return ''
  }

  for (const t of ASSET_TEMPLATES) {
    let remaining = t.count
    const zones = rng.shuffle([...t.zones])
    for (const zone of zones) {
      if (remaining <= 0) break
      const countInZone = Math.min(Math.ceil(remaining / zones.length), remaining)
      for (let i = 0; i < countInZone; i++) {
        const zk = `${t.type}-${zone}`
        zoneCounters[zk] = (zoneCounters[zk] || 0) + 1
        const zp = NETWORK_ZONES[zone].name.toUpperCase().replace(/[^A-Z]/g, '').substring(0, 2)
        const name = `${t.namePrefix}-${zp}${String(zoneCounters[zk]).padStart(3, '0')}${getEnvSuffix(zone)}`
        const internetFacing = zone === 'dmz' && (t.internetFacing || rng.next() > 0.5)
        let criticality = t.criticality
        if (zone.startsWith('dev')) criticality = Math.max(1, criticality - 1)
        if (zone === 'pci' || zone === 'hipaa') criticality = 5
        if (zone === 'dr') criticality = Math.min(5, criticality + 1)
        const bu = rng.pick(BUSINESS_UNITS)
        assets.push({
          id: `asset-${assetId++}`, name, type: t.type,
          ip: generateIP(zone), network_zone: zone, criticality, internet_facing: internetFacing,
          business_unit: bu.name, annual_revenue_exposure: bu.revenue,
          misconfigurations: genMisconfigs(t.misconfigCategories),
          domain_joined: t.domainJoined, services: t.services as string[],
          data_sensitivity: t.dataSensitivity, scanStatus: 'pending',
        })
      }
      remaining -= countInZone
    }
  }

  while (assets.length < 500) {
    const zone = rng.pick(['corp', 'corp-wifi', 'dev-web'] as NetworkZone[])
    const zk = `ws-pad-${zone}`
    zoneCounters[zk] = (zoneCounters[zk] || 0) + 1
    const bu = rng.pick(BUSINESS_UNITS)
    assets.push({
      id: `asset-${assetId++}`,
      name: `WS-${NETWORK_ZONES[zone].name.toUpperCase().substring(0, 2)}${String(zoneCounters[zk]).padStart(3, '0')}`,
      type: 'workstation', ip: generateIP(zone), network_zone: zone, criticality: 2,
      internet_facing: false, business_unit: bu.name, annual_revenue_exposure: bu.revenue,
      misconfigurations: genMisconfigs(['authentication', 'service']),
      domain_joined: true, services: ['Office', 'Browser'], data_sensitivity: 'user_data', scanStatus: 'pending',
    })
  }

  return assets
}

// ─── UI HELPERS ───────────────────────────────────────────────────────────────

const ZONE_PILL: Record<string, string> = {
  'dmz':        'text-red-300 bg-red-950/60 border-red-800',
  'prod-web':   'text-orange-300 bg-orange-950/60 border-orange-800',
  'prod-app':   'text-amber-300 bg-amber-950/60 border-amber-800',
  'prod-db':    'text-red-200 bg-red-950/80 border-red-700',
  'dev-web':    'text-blue-300 bg-blue-950/60 border-blue-800',
  'dev-app':    'text-blue-300 bg-blue-950/60 border-blue-800',
  'dev-db':     'text-violet-300 bg-violet-950/60 border-violet-800',
  'staging':    'text-teal-300 bg-teal-950/60 border-teal-800',
  'corp':       'text-emerald-300 bg-emerald-950/60 border-emerald-800',
  'corp-wifi':  'text-emerald-300 bg-emerald-950/60 border-emerald-800',
  'restricted': 'text-red-200 bg-red-950/80 border-red-700',
  'pci':        'text-rose-200 bg-rose-950/80 border-rose-700',
  'hipaa':      'text-rose-200 bg-rose-950/80 border-rose-700',
  'mgmt':       'text-slate-300 bg-slate-800 border-slate-700',
  'security':   'text-slate-300 bg-slate-800 border-slate-700',
  'cloud-prod': 'text-cyan-300 bg-cyan-950/60 border-cyan-800',
  'cloud-dev':  'text-sky-300 bg-sky-950/60 border-sky-800',
  'dr':         'text-stone-300 bg-stone-900 border-stone-700',
}

const SEV_PILL: Record<string, string> = {
  critical: 'text-red-400 bg-red-950/60 border-red-800',
  high:     'text-orange-400 bg-orange-950/60 border-orange-800',
  medium:   'text-amber-400 bg-amber-950/60 border-amber-800',
  low:      'text-slate-400 bg-slate-800 border-slate-700',
}

function zoneName(z: string) { return (NETWORK_ZONES as Record<string, { name: string }>)[z]?.name ?? z }

function ZonePill({ zone }: { zone: string }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs border font-mono ${ZONE_PILL[zone] ?? 'text-slate-400 bg-slate-800 border-slate-700'}`}>
      {zoneName(zone)}
    </span>
  )
}

function SevPill({ sev }: { sev: string }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs border font-mono uppercase tracking-wider ${SEV_PILL[sev] ?? SEV_PILL.low}`}>
      {sev}
    </span>
  )
}

function Kpi({ label, value, sub, red }: { label: string; value: string | number; sub?: string; red?: boolean }) {
  return (
    <div className={`rounded-xl border p-4 ${red ? 'bg-red-950/20 border-red-900/60' : 'bg-[#0d1117] border-[#21262d]'}`}>
      <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-1">{label}</div>
      <div className={`text-2xl font-bold font-mono ${red ? 'text-red-400' : 'text-slate-100'}`}>{value}</div>
      {sub && <div className="text-xs text-slate-600 mt-0.5">{sub}</div>}
    </div>
  )
}

function Spin() {
  return (
    <svg className="w-3.5 h-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
      <circle className="opacity-20" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  )
}

function Bar({ pct, color = 'bg-slate-500' }: { pct: number; color?: string }) {
  return (
    <div className="h-1.5 bg-[#21262d] rounded-full overflow-hidden">
      <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${Math.min(100, Math.max(0, pct))}%` }} />
    </div>
  )
}

function RiskBar({ value }: { value: number }) {
  const pct = Math.min(1, Math.max(0, value)) * 100
  const color = pct > 66 ? 'bg-gradient-to-r from-red-600 to-red-400' : pct > 33 ? 'bg-gradient-to-r from-orange-600 to-amber-400' : 'bg-gradient-to-r from-emerald-700 to-emerald-500'
  return <Bar pct={pct} color={color} />
}

// ─── ENV VIEW ─────────────────────────────────────────────────────────────────

function EnvView({ assets }: { assets: Asset[] }) {
  const [q, setQ] = useState('')
  const [zf, setZf] = useState('all')

  const stats = useMemo(() => {
    const sev = { critical: 0, high: 0, medium: 0, low: 0 }
    const cat: Record<string, number> = {}
    assets.forEach(a => a.misconfigurations.forEach(m => {
      sev[m.severity as keyof typeof sev]++
      cat[m.category] = (cat[m.category] || 0) + 1
    }))
    return { sev, cat, total: assets.reduce((s, a) => s + a.misconfigurations.length, 0) }
  }, [assets])

  const zones = useMemo(() => {
    const m: Record<string, number> = {}
    assets.forEach(a => { m[a.network_zone] = (m[a.network_zone] || 0) + 1 })
    return m
  }, [assets])

  const visible = useMemo(() =>
    assets
      .filter(a => zf === 'all' || a.network_zone === zf)
      .filter(a => !q || a.name.toLowerCase().includes(q) || a.type.includes(q) || a.ip.includes(q))
      .slice(0, 200)
  , [assets, q, zf])

  const GROUPS = [
    { label: 'Perimeter', zones: ['dmz'], col: 'text-red-400' },
    { label: 'Production', zones: ['prod-web', 'prod-app', 'prod-db'], col: 'text-orange-400' },
    { label: 'Development', zones: ['dev-web', 'dev-app', 'dev-db', 'staging'], col: 'text-blue-400' },
    { label: 'Corporate', zones: ['corp', 'corp-wifi'], col: 'text-emerald-400' },
    { label: 'Restricted', zones: ['restricted', 'pci', 'hipaa'], col: 'text-red-300' },
    { label: 'Infra & Cloud', zones: ['mgmt', 'security', 'cloud-prod', 'cloud-dev', 'dr'], col: 'text-cyan-400' },
  ]

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-6 gap-3">
        <Kpi label="Assets" value={assets.length} />
        <Kpi label="Misconfigs" value={stats.total} />
        <Kpi label="Critical" value={stats.sev.critical} red />
        <Kpi label="High" value={stats.sev.high} />
        <Kpi label="Internet-Exposed" value={assets.filter(a => a.internet_facing).length} />
        <Kpi label="Active Zones" value={Object.keys(zones).length} />
      </div>

      {/* Zone heatmap */}
      <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-5">
        <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-4">Network Zone Distribution</div>
        <div className="grid grid-cols-6 gap-3">
          {GROUPS.map(g => (
            <div key={g.label} className="space-y-2">
              <div className={`text-xs font-mono font-semibold ${g.col}`}>{g.label}</div>
              {g.zones.map(z => {
                const cnt = zones[z] || 0
                if (!cnt) return null
                const exposed = assets.filter(a => a.network_zone === z && a.internet_facing).length
                const crit = assets.filter(a => a.network_zone === z && a.criticality >= 4).length
                return (
                  <button key={z} onClick={() => setZf(zf === z ? 'all' : z)}
                    className={`w-full text-left p-3 rounded-lg border transition-all ${zf === z ? 'border-slate-500 bg-[#21262d]' : 'border-[#21262d] bg-[#161b22] hover:border-slate-600'}`}>
                    <div className={`text-xs font-mono mb-1 ${ZONE_PILL[z]?.split(' ')[0] ?? 'text-slate-400'}`}>{zoneName(z)}</div>
                    <div className="text-xl font-bold font-mono text-slate-100">{cnt}</div>
                    <div className="text-xs mt-1 space-x-1">
                      {exposed > 0 && <span className="text-red-500">{exposed} exp</span>}
                      {crit > 0 && <span className="text-orange-500">{crit} crit</span>}
                    </div>
                  </button>
                )
              })}
            </div>
          ))}
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 gap-3">
        <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-5">
          <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-3">Severity</div>
          <div className="space-y-2">
            {(['critical', 'high', 'medium', 'low'] as const).map(s => (
              <div key={s} className="flex items-center gap-3">
                <div className="w-14 text-xs font-mono text-slate-500">{s}</div>
                <div className="flex-1">
                  <Bar pct={(stats.sev[s] / stats.total) * 100}
                    color={s === 'critical' ? 'bg-red-500' : s === 'high' ? 'bg-orange-500' : s === 'medium' ? 'bg-amber-500' : 'bg-slate-600'} />
                </div>
                <div className="w-7 text-xs font-mono text-right text-slate-400">{stats.sev[s]}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-5">
          <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-3">Categories</div>
          <div className="space-y-2">
            {Object.entries(stats.cat).sort((a, b) => b[1] - a[1]).map(([cat, n]) => (
              <div key={cat} className="flex items-center gap-3">
                <div className="w-20 text-xs font-mono capitalize text-slate-500">{cat}</div>
                <div className="flex-1"><Bar pct={(n / stats.total) * 100} /></div>
                <div className="w-7 text-xs font-mono text-right text-slate-400">{n}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-[#0d1117] border border-[#21262d] rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-3 border-b border-[#21262d]">
          <span className="text-xs font-mono text-slate-600">
            {zf !== 'all' && <><span className="text-slate-300">{zoneName(zf)}</span> · </>}
            {visible.length} assets shown
          </span>
          <div className="flex items-center gap-2">
            {zf !== 'all' && (
              <button onClick={() => setZf('all')} className="text-xs font-mono text-slate-500 hover:text-slate-300">✕ clear</button>
            )}
            <input value={q} onChange={e => setQ(e.target.value.toLowerCase())} placeholder="filter…"
              className="bg-[#161b22] border border-[#21262d] rounded-lg px-3 py-1.5 text-xs font-mono text-slate-300 placeholder-slate-700 focus:outline-none focus:border-slate-600 w-40" />
          </div>
        </div>
        <div className="overflow-auto max-h-96">
          <table className="w-full text-xs font-mono">
            <thead className="bg-[#161b22] sticky top-0">
              <tr>
                {['Asset', 'Type', 'Zone', 'IP', 'BU', 'Crit', 'Findings'].map(h => (
                  <th key={h} className="text-left px-4 py-2 text-slate-600 font-normal">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.map(a => (
                <tr key={a.id} className="border-t border-[#21262d] hover:bg-[#161b22]">
                  <td className="px-4 py-2 text-slate-200 font-semibold">{a.name}</td>
                  <td className="px-4 py-2 text-slate-500 capitalize">{a.type.replace(/_/g, ' ')}</td>
                  <td className="px-4 py-2"><ZonePill zone={a.network_zone} /></td>
                  <td className="px-4 py-2 text-slate-500">{a.ip}</td>
                  <td className="px-4 py-2 text-slate-500">{a.business_unit}</td>
                  <td className="px-4 py-2">
                    <div className="flex gap-0.5 items-center">
                      {[1,2,3,4,5].map(n => (
                        <div key={n} className={`w-1.5 h-3 rounded-sm ${n <= a.criticality ? 'bg-red-500' : 'bg-[#21262d]'}`} />
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <div className="flex gap-1">
                      {a.misconfigurations.map(m => (
                        <span key={m.id} title={m.title}
                          className={`w-2 h-2 rounded-full ${m.severity === 'critical' ? 'bg-red-500' : m.severity === 'high' ? 'bg-orange-500' : m.severity === 'medium' ? 'bg-amber-500' : 'bg-slate-600'}`} />
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ─── SCAN VIEW ────────────────────────────────────────────────────────────────

function ScanView({ scanJob, scanLoading, onScan }: { scanJob: ScanJob | null; scanLoading: boolean; onScan: () => void }) {
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-4 gap-3">
        <Kpi label="Status" value={scanJob?.status ?? 'idle'} />
        <Kpi label="Progress" value={`${Math.round(scanJob?.progress ?? 0)}%`} />
        <Kpi label="Targets" value={scanJob?.targetCount ?? 0} />
        <Kpi label="Findings" value={scanJob?.summary?.totalMisconfigurations ?? 0} red />
      </div>

      {scanJob?.status === 'running' && (
        <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-5">
          <div className="flex justify-between mb-2">
            <span className="text-xs font-mono text-slate-600">Scanning {scanJob.targetCount} targets</span>
            <span className="text-xs font-mono text-blue-400">{Math.round(scanJob.progress)}%</span>
          </div>
          <div className="h-2 bg-[#21262d] rounded-full overflow-hidden">
            <div className="h-full bg-gradient-to-r from-blue-600 to-cyan-400 rounded-full transition-all" style={{ width: `${scanJob.progress}%` }} />
          </div>
        </div>
      )}

      {scanJob?.summary && (
        <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-5">
          <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-4">Scan Results</div>
          <div className="grid grid-cols-5 gap-4 text-center">
            {[
              { label: 'Critical', v: scanJob.summary.criticalCount, c: 'text-red-400' },
              { label: 'High', v: scanJob.summary.highCount, c: 'text-orange-400' },
              { label: 'Medium', v: scanJob.summary.mediumCount, c: 'text-amber-400' },
              { label: 'Low', v: scanJob.summary.lowCount, c: 'text-slate-400' },
              { label: 'Scanned', v: scanJob.summary.successCount, c: 'text-emerald-400' },
            ].map(({ label, v, c }) => (
              <div key={label}>
                <div className={`text-3xl font-bold font-mono ${c}`}>{v}</div>
                <div className="text-xs text-slate-600 font-mono mt-1">{label}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-5">
        <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-4">Scanner Optimizations</div>
        <div className="grid grid-cols-3 gap-3">
          {[
            { icon: '⚡', title: 'Batched SSH Commands', sub: '20+ cmds per connection' },
            { icon: '🔄', title: 'Connection Pooling', sub: 'ControlMaster multiplexing' },
            { icon: '🎯', title: 'Host Discovery', sub: '100ms vs 30s dead-host skip' },
            { icon: '💾', title: 'Result Caching', sub: 'Skip unchanged hosts' },
            { icon: '📊', title: 'Adaptive Rate Limit', sub: 'AIMD congestion control' },
            { icon: '🏆', title: 'Priority Queue', sub: 'Business-impact ordering' },
          ].map(({ icon, title, sub }) => (
            <div key={title} className="flex items-start gap-3 p-3 bg-[#161b22] border border-[#21262d] rounded-lg">
              <span className="text-lg">{icon}</span>
              <div>
                <div className="text-xs font-mono text-slate-300">{title}</div>
                <div className="text-xs text-slate-600 mt-0.5">{sub}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <button onClick={onScan} disabled={scanLoading}
        className={`w-full py-3 rounded-xl font-mono text-sm border transition-all flex items-center justify-center gap-2 ${scanLoading ? 'border-[#21262d] text-slate-600 cursor-not-allowed bg-transparent' : 'border-blue-800 text-blue-400 bg-blue-950/20 hover:bg-blue-950/40'}`}>
        {scanLoading ? <><Spin />Scanning…</> : '▶  Run Network Scan'}
      </button>
    </div>
  )
}

// ─── ANALYSIS VIEW ────────────────────────────────────────────────────────────

function AnalysisView({ result, loading, status, onAnalyze }: { result: AnalysisResult | null; loading: boolean; status: string; onAnalyze: () => void }) {
  if (!result) {
    return (
      <div className="space-y-5">
        <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-12 text-center">
          <div className="text-5xl mb-4">{loading ? '⚙️' : '🕸️'}</div>
          <div className="text-slate-300 font-mono mb-1">GNN + Bayesian + MCTS Analysis Engine</div>
          <div className="text-xs text-slate-600 font-mono mb-6">Graph Neural Networks · Bayesian Inference · Monte Carlo Tree Search · Qwen3 Validation</div>
          {loading && (
            <div className="mb-5 space-y-2">
              <div className="inline-flex items-center gap-2 text-xs font-mono text-amber-400 bg-amber-950/30 border border-amber-900/60 rounded-lg px-4 py-2">
                <Spin />{status || 'Initializing…'}
              </div>
              <div className="text-xs text-slate-600 font-mono">Crown jewel evaluation · MCTS search · Qwen3 narrative generation</div>
            </div>
          )}
          {!loading && status && (
            <div className="mb-5 inline-block text-xs font-mono text-red-400 bg-red-950/30 border border-red-900/60 rounded-lg px-4 py-2">{status}</div>
          )}
          <div>
            <button onClick={onAnalyze} disabled={loading}
              className={`px-8 py-3 rounded-xl font-mono text-sm border transition-all flex items-center gap-2 mx-auto ${loading ? 'border-[#21262d] text-slate-600 cursor-not-allowed' : 'border-red-800 text-red-400 bg-red-950/20 hover:bg-red-950/40'}`}>
              {loading ? <><Spin />Analyzing…</> : '▶  Run Attack Analysis'}
            </button>
          </div>
        </div>
        <div className="grid grid-cols-4 gap-3">
          {[
            { n: '01', col: 'border-l-blue-600 text-blue-400', label: 'GNN Embedding', desc: 'O(N×d) graph attention — node feature extraction' },
            { n: '02', col: 'border-l-violet-600 text-violet-400', label: 'Bayesian Inference', desc: 'Multi-source evidence fusion for edge probabilities' },
            { n: '03', col: 'border-l-emerald-600 text-emerald-400', label: 'MCTS Path Discovery', desc: 'UCB1-guided search — O(E log V) optimal paths' },
            { n: '04', col: 'border-l-red-600 text-red-400', label: 'LLM Validation', desc: 'Batch narrative — 5 paths per API call' },
          ].map(({ n, col, label, desc }) => (
            <div key={n} className={`bg-[#0d1117] border border-[#21262d] border-l-2 ${col} rounded-xl p-4 flex gap-3`}>
              <div className="text-2xl font-black font-mono text-[#21262d]">{n}</div>
              <div>
                <div className={`text-xs font-mono font-bold ${col.split(' ')[1]}`}>{label}</div>
                <div className="text-xs text-slate-600 mt-1">{desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-5 gap-3">
        <Kpi label="Nodes" value={result.graph_stats.total_nodes} />
        <Kpi label="Edges" value={result.graph_stats.total_edges} />
        <Kpi label="Branching Factor" value={result.graph_stats.avg_branching_factor} />
        <Kpi label="Entry Points" value={result.entry_points.length} />
        <Kpi label="Attack Paths" value={result.attack_paths.length} red />
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-5">
          <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-3">Timing — {result.timing.total}ms</div>
          <div className="space-y-2">
            {[
              { label: 'Node Build', v: result.timing.nodes, c: 'bg-blue-500' },
              { label: 'Edge Eval', v: result.timing.edges, c: 'bg-violet-500' },
              { label: 'PageRank', v: result.timing.pagerank, c: 'bg-emerald-500' },
              { label: 'Path Find', v: result.timing.paths, c: 'bg-amber-500' },
              { label: 'LLM Narr', v: result.timing.validation, c: 'bg-red-500' },
            ].map(({ label, v, c }) => (
              <div key={label} className="flex items-center gap-3">
                <div className="w-16 text-xs font-mono text-slate-500">{label}</div>
                <div className="flex-1"><Bar pct={(v / result.timing.total) * 100} color={c} /></div>
                <div className="w-14 text-xs font-mono text-right text-slate-400">{v}ms</div>
              </div>
            ))}
          </div>
        </div>
        <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-5">
          <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-3">Hybrid Edges</div>
          <div className="space-y-3">
            {[
              { label: 'Pattern', v: result.edge_stats.pattern_edges, c: 'text-blue-400' },
              { label: 'LLM', v: result.edge_stats.llm_edges, c: 'text-violet-400' },
              { label: 'Total', v: result.edge_stats.total_edges, c: 'text-slate-100' },
            ].map(({ label, v, c }) => (
              <div key={label} className="flex justify-between items-center">
                <span className={`text-xs font-mono ${c}`}>{label}</span>
                <span className={`text-sm font-mono font-bold ${c}`}>{v}</span>
              </div>
            ))}
            <div className="h-2 bg-[#21262d] rounded-full overflow-hidden mt-2">
              <div className="h-full bg-gradient-to-r from-blue-600 to-violet-500 rounded-full"
                style={{ width: `${(result.edge_stats.pattern_edges / Math.max(result.edge_stats.total_edges, 1)) * 100}%` }} />
            </div>
          </div>
        </div>
      </div>

      <div className="bg-[#0d1117] border border-[#21262d] rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-[#21262d] text-xs font-mono text-slate-600 uppercase tracking-widest">Entry Points — LLM Ranked</div>
        <div className="divide-y divide-[#21262d]">
          {result.entry_points.slice(0, 6).map((ep, i) => (
            <div key={ep.node_id} className="px-5 py-3 flex items-start gap-4">
              <div className="w-6 h-6 bg-red-950/60 border border-red-800 rounded flex items-center justify-center text-xs font-mono font-bold text-red-400 shrink-0">{i + 1}</div>
              <div className="flex-1 min-w-0">
                <div className="flex flex-wrap items-center gap-2 mb-0.5">
                  <span className="text-sm font-mono font-semibold text-slate-200">{ep.asset_name}</span>
                  <span className="text-xs font-mono text-orange-400">{ep.misconfig_title}</span>
                </div>
                <div className="text-xs text-slate-500">{ep.reasoning}</div>
                <div className="text-xs text-red-300 mt-0.5">Value: {ep.attacker_value}</div>
              </div>
              <div className="text-xs font-mono text-slate-600 shrink-0 whitespace-nowrap">PR {ep.pagerank_score.toFixed(4)}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-5">
          <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-3">Critical Assets</div>
          <div className="space-y-2">
            {result.critical_assets.map((ca, i) => (
              <div key={ca.asset_id} className="flex items-center gap-3 p-2.5 bg-[#161b22] border border-[#21262d] rounded-lg">
                <span className="text-xs font-mono text-slate-600 w-4">{i + 1}</span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-mono text-slate-300 truncate">{ca.asset_name}</div>
                  <div className="text-xs text-slate-600 truncate">{ca.reason}</div>
                </div>
                <span className="text-xs font-mono text-violet-400 shrink-0">{ca.paths_to_it} paths</span>
              </div>
            ))}
          </div>
        </div>
        <div className="bg-[#0d1117] border border-red-900/30 rounded-xl p-5">
          <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-3">Key Insights</div>
          <ul className="space-y-2">
            {result.key_insights.map((ins, i) => (
              <li key={i} className="flex gap-2 text-xs">
                <span className="text-red-600 shrink-0 mt-0.5">▸</span>
                <span className="text-slate-400">{ins}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}

// ─── PATHS VIEW ───────────────────────────────────────────────────────────────

function PathsView({ result }: { result: AnalysisResult | null }) {
  const [sel, setSel] = useState<number | null>(result?.attack_paths?.length ? 0 : null)

  if (!result?.attack_paths?.length) {
    return (
      <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-20 text-center">
        <div className="text-3xl mb-3">🔍</div>
        <div className="text-slate-600 font-mono">Run analysis first to discover attack paths</div>
      </div>
    )
  }

  const path = sel !== null ? result.attack_paths[sel] : null

  return (
    <div className="grid grid-cols-3 gap-4" style={{ minHeight: 600 }}>
      {/* List */}
      <div className="bg-[#0d1117] border border-[#21262d] rounded-xl overflow-hidden flex flex-col">
        <div className="px-4 py-3 border-b border-[#21262d] text-xs font-mono text-slate-600 shrink-0">
          {result.attack_paths.length} unique paths discovered
        </div>
        <div className="overflow-y-auto flex-1 divide-y divide-[#21262d]">
          {result.attack_paths.map((p, i) => {
            const risk = Math.min(1, Math.max(0, p.final_risk_score))
            const cats = [...new Set(p.nodes.map(n => n.misconfig_category))]
            return (
              <button key={p.path_id} onClick={() => setSel(i)}
                className={`w-full text-left p-4 hover:bg-[#161b22] transition-colors ${sel === i ? 'bg-red-950/10 border-l-2 border-red-600 pl-[14px]' : ''}`}>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-mono font-bold text-slate-300">PATH-{String(i+1).padStart(2,"0")}</span>
                  <span className={`text-xs font-mono px-2 py-0.5 rounded border ${risk > 0.5 ? 'text-red-400 border-red-900 bg-red-950/30' : 'text-amber-400 border-amber-900 bg-amber-950/30'}`}>
                    {Math.round(risk * 100)}%
                  </span>
                </div>
                <div className="text-xs text-slate-600 font-mono mb-2">{p.nodes.length} steps · {[...new Set(p.nodes.map(n => n.asset_id))].length} assets</div>
                <RiskBar value={risk} />
                <div className="flex flex-wrap gap-1 mt-2">
                  {cats.map(c => (
                    <span key={c} className={`text-xs px-1.5 py-0.5 rounded border font-mono ${
                      c === 'authentication' ? 'text-red-400 border-red-900 bg-red-950/20' :
                      c === 'authorization'  ? 'text-violet-400 border-violet-900 bg-violet-950/20' :
                      c === 'network'        ? 'text-blue-400 border-blue-900 bg-blue-950/20' :
                      'text-slate-400 border-[#21262d]'
                    }`}>{c}</span>
                  ))}
                </div>
              </button>
            )
          })}
        </div>
      </div>

      {/* Detail */}
      <div className="col-span-2">
        {!path ? (
          <div className="bg-[#0d1117] border border-[#21262d] rounded-xl h-full flex items-center justify-center">
            <div className="text-slate-700 font-mono text-sm">← Select a path</div>
          </div>
        ) : (
          <div className="bg-[#0d1117] border border-[#21262d] rounded-xl overflow-hidden flex flex-col">
            {/* Header */}
            <div className="px-5 py-4 border-b border-[#21262d] flex items-center justify-between shrink-0">
              <div>
                <div className="font-mono font-bold text-slate-100">PATH-{String(sel !== null ? sel + 1 : 1).padStart(2, "0")} — {path.nodes[0]?.asset_name} → {path.nodes[path.nodes.length-1]?.asset_name}</div>
                <div className="text-xs text-slate-600 font-mono mt-0.5">
                  {path.nodes.length} steps · {[...new Set(path.nodes.map(n => n.asset_id))].length} unique assets
                </div>
              </div>
              <div className="flex gap-5 text-xs font-mono text-right">
                <div><div className="text-slate-600">Prob</div><div className="text-blue-400">{Math.round(path.path_probability * 100)}%</div></div>
                <div><div className="text-slate-600">Realism</div><div className="text-emerald-400">{Math.round(path.realism_score * 100)}%</div></div>
                <div><div className="text-slate-600">Risk</div><div className="text-red-400 font-bold">{Math.round(Math.min(1, path.final_risk_score) * 100)}%</div></div>
              </div>
            </div>

            {/* Risk bar */}
            <div className="px-5 py-2 border-b border-[#21262d] bg-[#0a0f14] shrink-0">
              <RiskBar value={Math.min(1, path.final_risk_score)} />
            </div>

            {/* Kill chain */}
            <div className="px-5 py-3 border-b border-[#21262d] flex gap-2 flex-wrap shrink-0">
              {path.kill_chain.map((phase, i) => (
                <span key={i} className="text-xs font-mono px-2 py-0.5 bg-[#161b22] border border-[#21262d] rounded text-slate-400">
                  {i + 1}. {phase}
                </span>
              ))}
            </div>

            {/* Chain */}
            <div className="p-5 border-b border-[#21262d] overflow-y-auto flex-1 space-y-3 max-h-64">
              {path.nodes.map((node, i) => {
                const edge = path.edges[i]
                const isFirst = i === 0
                const isLast = i === path.nodes.length - 1
                return (
                  <div key={i} className="flex gap-3">
                    <div className="flex flex-col items-center shrink-0">
                      <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-mono font-bold border ${
                        isFirst ? 'bg-red-950/60 border-red-700 text-red-300' :
                        isLast  ? 'bg-violet-950/60 border-violet-700 text-violet-300' :
                        'bg-[#161b22] border-[#21262d] text-slate-500'
                      }`}>{i + 1}</div>
                      {!isLast && <div className="w-px flex-1 bg-[#21262d] my-1 min-h-3" />}
                    </div>
                    <div className="flex-1 pb-2">
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        <span className="text-sm font-mono font-semibold text-slate-200">{node.asset_name}</span>
                        <ZonePill zone={node.asset_zone} />
                        <span className="text-xs font-mono text-slate-600 capitalize">{node.asset_type.replace(/_/g, ' ')}</span>
                      </div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs text-orange-400 font-mono">{node.misconfig_title}</span>
                        <span className={`px-2 py-0.5 rounded text-xs border font-mono uppercase tracking-wider ${
                          node.misconfig_category === 'authentication' ? 'text-red-400 bg-red-950/60 border-red-800' :
                          node.misconfig_category === 'authorization'  ? 'text-violet-400 bg-violet-950/60 border-violet-800' :
                          node.misconfig_category === 'network'        ? 'text-blue-400 bg-blue-950/60 border-blue-800' :
                          node.misconfig_category === 'service'        ? 'text-amber-400 bg-amber-950/60 border-amber-800' :
                          node.misconfig_category === 'encryption'     ? 'text-cyan-400 bg-cyan-950/60 border-cyan-800' :
                          'text-slate-400 bg-slate-800 border-slate-700'
                        }`}>{node.misconfig_category}</span>
                      </div>
                      {edge && (
                        <div className="text-xs font-mono bg-[#161b22] border border-[#21262d] rounded px-3 py-2 text-slate-500 space-y-0.5">
                          <div className="flex items-center gap-2">
                            <span className="text-emerald-500">→</span>
                            <span className="text-slate-300 font-semibold">{edge.technique}</span>
                            <span className="text-blue-400">{Math.round(edge.probability * 100)}% success</span>
                            <span className={`ml-auto px-1.5 py-0.5 rounded border text-xs ${edge.edge_type === 'llm' || edge.edge_type === 'gnn_bayesian' ? 'text-violet-400 border-violet-900' : 'text-blue-400 border-blue-900'}`}>
                              {edge.edge_type === 'gnn_bayesian' ? 'Bayesian' : edge.edge_type === 'llm' ? 'LLM' : 'Pattern'}
                            </span>
                          </div>
                          <div className="text-slate-600 truncate">{edge.reasoning}</div>
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>

            {/* Narrative + impact */}
            <div className="grid grid-cols-2 divide-x divide-[#21262d] shrink-0">
              <div className="p-4">
                <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-2">Narrative</div>
                <p className="text-xs text-slate-400 leading-relaxed">{path.narrative || '—'}</p>
              </div>
              <div className="p-4">
                <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-2">Business Impact</div>
                <p className="text-xs text-red-300 leading-relaxed">{path.business_impact || '—'}</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── ALGO VIEW ────────────────────────────────────────────────────────────────

function AlgoView() {
  return (
    <div className="space-y-4">
      <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-6">
        <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-6">Scalable Hybrid Algorithm — 5-Phase Pipeline</div>
        <div className="space-y-4">
          {[
            { n: '01', col: 'border-blue-600 text-blue-400', label: 'Build Nodes — O(n)', desc: 'One node per (asset, misconfiguration) pair. GNN feature extraction on graph structure.' },
            { n: '02', col: 'border-violet-600 text-violet-400', label: 'Edge Evaluation — O(n²) fast', desc: 'Pattern templates + zone reachability matrix. No per-edge LLM calls. Bayesian priors applied immediately.' },
            { n: '03', col: 'border-emerald-600 text-emerald-400', label: 'PageRank — O(iterations × E)', desc: 'Node importance via probability-weighted adjacency. GNN attention weights refine scores.' },
            { n: '04', col: 'border-amber-600 text-amber-400', label: 'MCTS Discovery — O(E log V)', desc: 'UCB1-guided Monte Carlo tree search. −log(prob) as edge cost. Explores high-value paths first.' },
            { n: '05', col: 'border-red-600 text-red-400', label: 'Batch LLM Validation — O(paths / 5)', desc: '5 attack paths validated per LLM API call. Generates narrative, scores realism, assesses business impact.' },
          ].map(({ n, col, label, desc }) => (
            <div key={n} className={`border-l-2 pl-4 ${col}`}>
              <div className="flex items-center gap-3 mb-1">
                <span className="text-xs font-mono text-slate-600">{n}</span>
                <span className={`text-sm font-mono font-bold ${col.split(' ')[1]}`}>{label}</span>
              </div>
              <p className="text-xs text-slate-500">{desc}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-5">
          <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-3">Before — Per-Edge LLM</div>
          <div className="space-y-1.5 text-xs font-mono">
            <div className="text-red-400">✕ 150 nodes → 22,500 edge evals</div>
            <div className="text-red-400">✕ 22,500 LLM API calls</div>
            <div className="text-red-400">✕ 30+ minutes per run</div>
            <div className="text-red-400">✕ 15–30% false positive rate</div>
          </div>
        </div>
        <div className="bg-[#0d1117] border border-emerald-900/40 rounded-xl p-5">
          <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-3">After — Pattern + Batch</div>
          <div className="space-y-1.5 text-xs font-mono">
            <div className="text-emerald-400">✓ Pattern edges — instant</div>
            <div className="text-emerald-400">✓ 2–4 LLM calls total (batched)</div>
            <div className="text-emerald-400">✓ 5–15 seconds per run</div>
            <div className="text-emerald-400">✓ 5–10% false positive rate</div>
          </div>
        </div>
      </div>

      <div className="bg-[#0d1117] border border-[#21262d] rounded-xl p-5">
        <div className="text-xs font-mono text-slate-600 uppercase tracking-widest mb-3">Module Map</div>
        <div className="grid grid-cols-3 gap-5 text-xs font-mono">
          {[
            { g: 'Core Scanners', f: ['optimized-scanner.ts', 'high-perf-scanner.ts', 'zone-detection.ts', 'fp-reduction.ts'] },
            { g: 'Scalable Architecture', f: ['scanner-orchestrator.ts', 'result-streamer.ts', 'distributed-coordinator.ts', 'adaptive-rate-limiter.ts', 'scan-scheduler.ts'] },
            { g: 'Analysis Engine', f: ['enhanced-attack-engine.ts', 'llm-realism-engine.ts', 'complete-hybrid-engine.ts', 'network-topology-collector.ts'] },
          ].map(({ g, f }) => (
            <div key={g}>
              <div className="text-slate-500 mb-2">{g}</div>
              {f.map(file => <div key={file} className="text-cyan-700 py-0.5">{file}</div>)}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── MAIN ─────────────────────────────────────────────────────────────────────

type View = 'env' | 'scan' | 'analysis' | 'paths' | 'algo'

export default function BraveGuardian() {
  const [assets] = useState<Asset[]>(() => generateEnterpriseAssets())
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState('')
  const [view, setView] = useState<View>('env')
  const [scanJob, setScanJob] = useState<ScanJob | null>(null)
  const [scanLoading, setScanLoading] = useState(false)

  const runAnalysis = useCallback(async () => {
    setLoading(true)
    setResult(null)
    setStatus('Building attack graph…')

    const ctrl = new AbortController()
    const timer = setTimeout(() => { ctrl.abort(); setStatus('Timed out — please retry'); setLoading(false) }, 120000)

    try {
      setStatus('Running GNN + Bayesian + MCTS…')
      const res = await fetch('/api/attack-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          environment: {
            assets: assets.map(a => ({
              id: a.id, name: a.name, type: a.type, ip: a.ip,
              zone: a.network_zone, internet_facing: a.internet_facing,
              criticality: a.criticality, domain_joined: a.domain_joined,
              services: a.services, data_sensitivity: a.data_sensitivity,
              misconfigurations: a.misconfigurations.map(m => ({
                id: m.id, title: m.title, description: m.description,
                category: m.category, severity: m.severity,
              }))
            }))
          }
        }),
        signal: ctrl.signal,
      })

      clearTimeout(timer)
      if (res.ok) {
        const data = await res.json()
        if (data.error) { setStatus(`Error: ${data.message ?? data.error}`) }
        else { setResult(data); setStatus(''); setView('analysis') }
      } else {
        const err = await res.json().catch(() => ({}))
        setStatus(`Server error ${res.status}: ${err.message ?? 'unknown'}`)
      }
    } catch (e: unknown) {
      clearTimeout(timer)
      if (e instanceof Error && e.name === 'AbortError') setStatus('Request timed out — retry')
      else setStatus(`Error: ${e instanceof Error ? e.message : 'unknown'}`)
    }

    setLoading(false)
  }, [assets])

  const runScan = useCallback(async () => {
    setScanLoading(true)
    const targets = [...assets].sort((a, b) => b.criticality - a.criticality).slice(0, 100)

    try {
      const res = await fetch('/api/scanner', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'scan',
          targets: targets.map(a => ({
            id: a.id, host: a.ip, ip: a.ip, hostname: a.name,
            criticality: a.criticality, internetFacing: a.internet_facing, zone: a.network_zone,
          })),
          options: { priority: 'medium' },
        }),
      })

      if (res.ok) {
        const { jobId } = await res.json()
        let done = false
        while (!done) {
          await new Promise(r => setTimeout(r, 600))
          const poll = await fetch(`/api/scanner?jobId=${jobId}`)
          if (poll.ok) {
            const { job } = await poll.json()
            setScanJob(job)
            if (job.status === 'completed' || job.status === 'failed') done = true
          }
        }
      }
    } catch (e) { console.error(e) }

    setScanLoading(false)
  }, [assets])

  const NAV: { id: View; label: string }[] = [
    { id: 'env', label: 'Environment' },
    { id: 'scan', label: 'Scanner' },
    { id: 'analysis', label: 'Analysis' },
    { id: 'paths', label: 'Attack Paths' },
    { id: 'algo', label: 'Algorithm' },
  ]

  return (
    <div className="min-h-screen bg-[#010409] text-slate-100" style={{ fontFamily: 'ui-monospace, "JetBrains Mono", "Fira Code", monospace' }}>
      {/* ── Header ── */}
      <header className="bg-[#0d1117] border-b border-[#21262d] sticky top-0 z-50">
        <div className="max-w-[1600px] mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-8">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-gradient-to-br from-red-700 to-red-500 rounded-lg flex items-center justify-center shrink-0">
                <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <div>
                <div className="text-sm font-bold tracking-tight text-slate-100">BRAVE GUARDIAN</div>
                <div className="text-xs text-slate-600">v3.0 · GNN+Bayesian+MCTS</div>
              </div>
            </div>

            <nav className="flex gap-0.5">
              {NAV.map(n => (
                <button key={n.id} onClick={() => setView(n.id)}
                  className={`px-3 py-1.5 text-xs rounded-md transition-colors relative ${view === n.id ? 'bg-[#21262d] text-slate-100' : 'text-slate-500 hover:text-slate-300 hover:bg-[#161b22]'}`}>
                  {n.label}
                  {n.id === 'paths' && result?.attack_paths?.length ? (
                    <span className="ml-1.5 px-1.5 py-0.5 rounded bg-red-950 text-red-400 text-xs">{result.attack_paths.length}</span>
                  ) : null}
                </button>
              ))}
            </nav>
          </div>

          <div className="flex gap-2">
            <button onClick={runScan} disabled={scanLoading}
              className={`flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs border transition-all ${scanLoading ? 'border-[#21262d] text-slate-600 cursor-not-allowed' : 'border-blue-800/60 text-blue-400 hover:bg-blue-950/30'}`}>
              {scanLoading ? <><Spin />Scanning…</> : '⟳ Run Scan'}
            </button>
            <button onClick={runAnalysis} disabled={loading}
              className={`flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs border transition-all ${loading ? 'border-[#21262d] text-slate-600 cursor-not-allowed' : 'border-red-800/60 text-red-400 hover:bg-red-950/30'}`}>
              {loading ? <><Spin />Analyzing…</> : '▶ Run Analysis'}
            </button>
          </div>
        </div>

        {(status || loading) && (
          <div className="border-t border-[#21262d] px-6 py-1.5 flex items-center gap-2 bg-[#0a0f14]">
            <div className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse shrink-0" />
            <span className="text-xs font-mono text-slate-400">{status || 'Processing…'}</span>
          </div>
        )}
      </header>

      {/* ── Main ── */}
      <main className="max-w-[1600px] mx-auto px-6 py-6">
        {view === 'env'      && <EnvView assets={assets} />}
        {view === 'scan'     && <ScanView scanJob={scanJob} scanLoading={scanLoading} onScan={runScan} />}
        {view === 'analysis' && <AnalysisView result={result} loading={loading} status={status} onAnalyze={runAnalysis} />}
        {view === 'paths'    && <PathsView result={result} />}
        {view === 'algo'     && <AlgoView />}
      </main>
    </div>
  )
}
