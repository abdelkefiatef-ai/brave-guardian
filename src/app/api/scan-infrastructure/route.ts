import { NextRequest, NextResponse } from 'next/server'

// Vulnerability database for mapping discovered issues
const VULN_DB: Record<string, any> = {
  'ssh-weak-crypto': { id: 'SSH-WEAK-CRYPTO', title: 'SSH Weak Cryptography', severity: 'medium', cvss: 5.0, epss: 0.3, attack_complexity: 0.4, privileges_required: 'low', cisa_kev: false, ransomware: false, kill_chain_phase: 'initial_access', mitre_techniques: ['T1021.004'] },
  'rdp-exposed': { id: 'RDP-EXPOSED', title: 'RDP Exposed to Network', severity: 'high', cvss: 8.0, epss: 0.7, attack_complexity: 0.2, privileges_required: 'none', cisa_kev: true, ransomware: true, kill_chain_phase: 'initial_access', mitre_techniques: ['T1021.001'] },
  'smb-exposed': { id: 'SMB-EXPOSED', title: 'SMB Exposed to Network', severity: 'high', cvss: 8.5, epss: 0.75, attack_complexity: 0.15, privileges_required: 'none', cisa_kev: true, ransomware: true, kill_chain_phase: 'initial_access', mitre_techniques: ['T1021.002'] },
  'telnet-enabled': { id: 'TELNET-ENABLED', title: 'Telnet Service Enabled', severity: 'high', cvss: 7.5, epss: 0.6, attack_complexity: 0.25, privileges_required: 'none', cisa_kev: false, ransomware: false, kill_chain_phase: 'initial_access', mitre_techniques: ['T1021.003'] },
  'ftp-anonymous': { id: 'FTP-ANONYMOUS', title: 'FTP Anonymous Access', severity: 'medium', cvss: 5.5, epss: 0.4, attack_complexity: 0.3, privileges_required: 'none', cisa_kev: false, ransomware: false, kill_chain_phase: 'initial_access', mitre_techniques: ['T1078'] },
  'http-clear-text': { id: 'HTTP-CLEARTEXT', title: 'HTTP Clear Text', severity: 'medium', cvss: 4.5, epss: 0.3, attack_complexity: 0.35, privileges_required: 'none', cisa_kev: false, ransomware: false, kill_chain_phase: 'initial_access', mitre_techniques: ['T1071.001'] },
  'mysql-exposed': { id: 'MYSQL-EXPOSED', title: 'MySQL Exposed to Network', severity: 'high', cvss: 7.0, epss: 0.5, attack_complexity: 0.3, privileges_required: 'none', cisa_kev: false, ransomware: false, kill_chain_phase: 'initial_access', mitre_techniques: ['T1021.005'] },
  'ssh-root-login': { id: 'SSH-ROOT-LOGIN', title: 'SSH Root Login Enabled', severity: 'critical', cvss: 9.0, epss: 0.8, attack_complexity: 0.15, privileges_required: 'none', cisa_kev: true, ransomware: true, kill_chain_phase: 'initial_access', mitre_techniques: ['T1021.004'] },
  'snmp-default': { id: 'SNMP-DEFAULT', title: 'SNMP Default Community', severity: 'high', cvss: 7.5, epss: 0.65, attack_complexity: 0.2, privileges_required: 'none', cisa_kev: false, ransomware: false, kill_chain_phase: 'discovery', mitre_techniques: ['T1046'] },
  'outdated-os': { id: 'OUTDATED-OS', title: 'Outdated Operating System', severity: 'high', cvss: 7.0, epss: 0.55, attack_complexity: 0.25, privileges_required: 'none', cisa_kev: false, ransomware: false, kill_chain_phase: 'initial_access', mitre_techniques: ['T1190'] },
  'missing-patches': { id: 'MISSING-PATCHES', title: 'Missing Security Patches', severity: 'critical', cvss: 9.0, epss: 0.82, attack_complexity: 0.2, privileges_required: 'none', cisa_kev: true, ransomware: true, kill_chain_phase: 'privilege_escalation', mitre_techniques: ['T1068'] },
  'firewall-misconfig': { id: 'FW-MISCONFIG', title: 'Firewall Misconfiguration', severity: 'high', cvss: 7.5, epss: 0.45, attack_complexity: 0.3, privileges_required: 'low', cisa_kev: false, ransomware: false, kill_chain_phase: 'initial_access', mitre_techniques: ['T1562.004'] },
}

// Service to vulnerability mapping
const SERVICE_VULNS: Record<string, string[]> = {
  '22': ['ssh-weak-crypto', 'ssh-root-login'],
  '23': ['telnet-enabled'],
  '21': ['ftp-anonymous'],
  '80': ['http-clear-text'],
  '3389': ['rdp-exposed'],
  '445': ['smb-exposed'],
  '3306': ['mysql-exposed'],
  '161': ['snmp-default'],
}

// Simulate network scan (in production, this would use actual network tools)
async function simulateScan(config: any): Promise<any[]> {
  const assets: any[] = []
  
  // Parse network range if provided
  const baseIP = config.networkRange ? 
    config.networkRange.split('/')[0].split('.').slice(0, 3).join('.') : 
    '192.168.1'
  
  // Simulate discovering hosts
  const numHosts = Math.floor(Math.random() * 10) + 5
  
  const hostTypes = ['vm', 'server', 'firewall', 'cloud_resource']
  const osTypes = ['Windows Server 2019', 'Ubuntu 22.04', 'CentOS 8', 'Cisco IOS', 'FortiOS']
  const zones = ['dmz', 'internal', 'restricted']
  
  for (let i = 0; i < numHosts; i++) {
    const hostIP = `${baseIP}.${i + 1}`
    const hostType = hostTypes[Math.floor(Math.random() * hostTypes.length)]
    const isFirewall = hostType === 'firewall'
    
    // Generate open ports based on type
    const commonPorts = [22, 80, 443]
    const firewallPorts = [22, 443, 161, 500]
    const windowsPorts = [22, 80, 443, 3389, 445]
    const dbPorts = [22, 3306, 5432]
    
    let openPorts = commonPorts
    if (isFirewall) openPorts = firewallPorts
    else if (hostType === 'vm') openPorts = windowsPorts
    else if (Math.random() > 0.7) openPorts = [...commonPorts, ...dbPorts]
    
    // Map ports to vulnerabilities
    const vulnerabilities: any[] = []
    openPorts.forEach(port => {
      const vulnIds = SERVICE_VULNS[port.toString()] || []
      vulnIds.forEach(vid => {
        if (Math.random() > 0.3 && VULN_DB[vid]) {
          vulnerabilities.push({ ...VULN_DB[vid] })
        }
      })
    })
    
    // Add some random vulnerabilities
    if (Math.random() > 0.5) {
      vulnerabilities.push({ ...VULN_DB['outdated-os'] })
    }
    if (Math.random() > 0.6) {
      vulnerabilities.push({ ...VULN_DB['missing-patches'] })
    }
    if (isFirewall && Math.random() > 0.4) {
      vulnerabilities.push({ ...VULN_DB['firewall-misconfig'] })
    }
    
    const zone = zones[Math.floor(Math.random() * zones.length)]
    const isInternetFacing = zone === 'dmz' || (Math.random() > 0.9)
    
    assets.push({
      host: hostIP,
      hostname: isFirewall ? 
        `FW-${['Cisco', 'PaloAlto', 'Fortinet'][Math.floor(Math.random() * 3)]}-${i + 1}` :
        `${hostType === 'vm' ? 'WIN' : 'LNX'}-SRV-${String(i + 1).padStart(4, '0')}`,
      type: hostType,
      os: isFirewall ? 'FortiOS 7.2' : osTypes[Math.floor(Math.random() * osTypes.length)],
      openPorts,
      networkZone: zone,
      criticality: Math.floor(Math.random() * 5) + 1,
      internetFacing: isInternetFacing,
      businessUnit: ['Finance', 'Engineering', 'IT', 'Operations'][Math.floor(Math.random() * 4)],
      revenueExposure: Math.floor(Math.random() * 5000000) + 100000,
      vulnerabilities: vulnerabilities.length > 0 ? vulnerabilities : [{ ...VULN_DB['missing-patches'] }]
    })
  }
  
  return assets
}

export async function POST(request: NextRequest) {
  try {
    const config = await request.json()
    
    console.log('Scan request:', config.type, config.host || config.networkRange)
    
    // Validate config
    if (!config.type) {
      return NextResponse.json({ error: 'Connection type required' }, { status: 400 })
    }
    
    // Perform scan
    const assets = await simulateScan(config)
    
    return NextResponse.json({
      success: true,
      assets,
      scanTime: new Date().toISOString(),
      config: {
        type: config.type,
        target: config.host || config.networkRange || 'network'
      }
    })
    
  } catch (error) {
    console.error('Scan error:', error)
    return NextResponse.json({
      error: true,
      message: error instanceof Error ? error.message : 'Scan failed',
      assets: []
    }, { status: 500 })
  }
}
