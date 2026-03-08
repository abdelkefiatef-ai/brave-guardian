// Run the hybrid analysis and output results

// Import the asset generation logic
const MISCONFIG_DB = [
  { id: 'M001', title: 'RDP Accessible from Internet', description: 'Remote Desktop Protocol port 3389 is open to the internet', category: 'network' },
  { id: 'M002', title: 'SMBv1 Protocol Active', description: 'Legacy SMB version 1 protocol is enabled', category: 'network' },
  { id: 'M003', title: 'SMB Signing Not Required', description: 'SMB traffic can be intercepted', category: 'network' },
  { id: 'M004', title: 'WinRM Over HTTP', description: 'Windows Remote Management accepting unencrypted connections', category: 'network' },
  { id: 'M005', title: 'LDAP Signing Disabled', description: 'LDAP traffic can be intercepted', category: 'network' },
  { id: 'M006', title: 'Web Server Directory Listing Enabled', description: 'Directory contents exposed', category: 'network' },
  { id: 'M007', title: 'Database Port Exposed', description: 'SQL Server/MySQL port accessible', category: 'network' },
  { id: 'M010', title: 'Password Policy Allows 8 Characters', description: 'Minimum password length only 8 characters', category: 'authentication' },
  { id: 'M011', title: 'Service Account with 90-Day Password Age', description: 'Service account password not changed', category: 'authentication' },
  { id: 'M012', title: 'Kerberos Pre-Auth Disabled', description: 'User account does not require Kerberos pre-auth', category: 'authentication' },
  { id: 'M013', title: 'Same Local Admin Password', description: 'Multiple systems share identical local admin password', category: 'authentication' },
  { id: 'M014', title: 'Credential Guard Disabled', description: 'Windows Defender Credential Guard not enabled', category: 'authentication' },
  { id: 'M015', title: 'No MFA on Admin Accounts', description: 'Administrative accounts lack MFA', category: 'authentication' },
  { id: 'M016', title: 'Password in GPP', description: 'Group Policy Preferences contains encrypted password', category: 'authentication' },
  { id: 'M020', title: 'Domain Users in Local Admins', description: 'Domain Users group added to local administrators', category: 'authorization' },
  { id: 'M021', title: 'Excessive Local Admin Rights', description: 'Non-IT users have local administrator', category: 'authorization' },
  { id: 'M022', title: 'DCSync Rights to Service Account', description: 'Non-DA account has DS-Replication rights', category: 'authorization' },
  { id: 'M023', title: 'Unconstrained Delegation', description: 'Computer account trusted for unconstrained delegation', category: 'authorization' },
  { id: 'M024', title: 'WriteDACL on Domain Root', description: 'Account can modify domain ACLs', category: 'authorization' },
  { id: 'M025', title: 'GenericAll on Computer Objects', description: 'Account has full control over computer objects', category: 'authorization' },
  { id: 'M026', title: 'AdminSDHolder Backdoor Possible', description: 'Account in AdminSDHolder can persist privileges', category: 'authorization' },
  { id: 'M030', title: 'Antivirus Not Running', description: 'Windows Defender stopped/disabled', category: 'service' },
  { id: 'M031', title: 'Unquoted Service Path', description: 'Service executable path contains spaces without quotes', category: 'service' },
  { id: 'M032', title: 'Service with Weak Permissions', description: 'Service binary path writable by non-admin', category: 'service' },
  { id: 'M033', title: 'AlwaysInstallElevated Enabled', description: 'MSI packages install with SYSTEM privileges', category: 'service' },
  { id: 'M034', title: 'PowerShell ExecutionPolicy Bypass', description: 'Execution policy can be bypassed', category: 'service' },
  { id: 'M035', title: 'Scheduled Task with Weak Permissions', description: 'Task runs as SYSTEM with writable action', category: 'service' },
  { id: 'M040', title: 'BitLocker Not Enabled', description: 'Disk encryption not active', category: 'encryption' },
  { id: 'M041', title: 'LM Hashes Stored', description: 'LAN Manager hashes stored in AD', category: 'encryption' },
  { id: 'M042', title: 'TLS 1.0 Still Active', description: 'Deprecated TLS 1.0 protocol still accepted', category: 'encryption' },
  { id: 'M043', title: 'SMB Encryption Disabled', description: 'SMB3 encryption not required', category: 'encryption' },
  { id: 'M050', title: 'Command Line Logging Disabled', description: 'Process command line arguments not logged', category: 'logging' },
  { id: 'M051', title: 'Security Log Size Too Small', description: 'Security event log only retains 20MB', category: 'logging' },
  { id: 'M052', title: 'No 4688 Process Creation Logging', description: 'Process creation events not captured', category: 'logging' },
  { id: 'M053', title: 'PowerShell Logging Disabled', description: 'Module and script block logging not enabled', category: 'logging' },
];

function generateAssets() {
  const assetTypes = [
    { type: 'domain_controller', zone: 'restricted', criticality: 5, domain_joined: true, services: ['Active Directory', 'DNS', 'Kerberos'], data_sensitivity: 'credentials' },
    { type: 'file_server', zone: 'internal', criticality: 4, domain_joined: true, services: ['SMB', 'DFS'], data_sensitivity: 'user_files' },
    { type: 'web_server', zone: 'dmz', criticality: 4, domain_joined: false, services: ['IIS', 'HTTP'], data_sensitivity: 'application_data' },
    { type: 'database_server', zone: 'restricted', criticality: 5, domain_joined: true, services: ['SQL Server'], data_sensitivity: 'pii' },
    { type: 'app_server', zone: 'internal', criticality: 3, domain_joined: true, services: ['Application Services'], data_sensitivity: 'business_logic' },
    { type: 'workstation', zone: 'internal', criticality: 2, domain_joined: true, services: ['Office', 'Browser'], data_sensitivity: 'user_data' },
    { type: 'jump_server', zone: 'dmz', criticality: 4, domain_joined: true, services: ['RDP Gateway'], data_sensitivity: 'access_credentials' },
    { type: 'email_server', zone: 'internal', criticality: 4, domain_joined: true, services: ['Exchange'], data_sensitivity: 'emails' },
    { type: 'backup_server', zone: 'restricted', criticality: 5, domain_joined: true, services: ['Backup Agent'], data_sensitivity: 'backups' },
    { type: 'firewall', zone: 'dmz', criticality: 4, domain_joined: false, services: ['Firewall', 'VPN'], data_sensitivity: 'network_rules' },
  ];

  const businessUnits = ['Finance', 'Engineering', 'Operations', 'HR', 'Legal', 'IT', 'Sales'];
  let seed = 12345;
  const random = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff };

  const assets = [];
  for (let i = 0; i < 50; i++) {
    const template = assetTypes[Math.floor(random() * assetTypes.length)];
    const internetFacing = template.zone === 'dmz' || (template.zone === 'internal' && random() > 0.95);
    
    const relevantCategories = template.type === 'domain_controller'
      ? ['authentication', 'authorization', 'network', 'logging']
      : template.type === 'web_server'
      ? ['network', 'service', 'encryption']
      : ['authentication', 'authorization', 'service', 'network'];
    
    const relevantMisconfigs = MISCONFIG_DB.filter(m => relevantCategories.includes(m.category));
    const numMisconfigs = Math.floor(random() * 3) + 2;
    const selectedMisconfigs = [];
    
    for (let j = 0; j < numMisconfigs; j++) {
      const misconfig = relevantMisconfigs[Math.floor(random() * relevantMisconfigs.length)];
      if (!selectedMisconfigs.find(m => m.id === misconfig.id)) {
        selectedMisconfigs.push({ ...misconfig });
      }
    }

    assets.push({
      id: `asset-${i + 1}`,
      name: `${template.type.toUpperCase().substring(0, 3)}-${String(i + 1).padStart(3, '0')}`,
      type: template.type,
      ip: `10.${Math.floor(random() * 3) + 1}.${Math.floor(random() * 255)}.${Math.floor(random() * 255)}`,
      zone: template.zone,
      internet_facing: internetFacing,
      criticality: template.criticality,
      domain_joined: template.domain_joined,
      services: template.services,
      data_sensitivity: template.data_sensitivity,
      misconfigurations: selectedMisconfigs.map(m => ({ id: m.id, title: m.title, description: m.description, category: m.category }))
    });
  }
  return assets;
}

async function main() {
  console.log('╔══════════════════════════════════════════════════════════════════════════╗');
  console.log('║        BRAVE GUARDIAN - Hybrid Attack Path Analysis                      ║');
  console.log('║        Graph Theory + LLM Intelligence                                   ║');
  console.log('╚══════════════════════════════════════════════════════════════════════════╝\n');

  const assets = generateAssets();
  console.log(`📊 Environment: ${assets.length} assets generated\n`);
  console.log('🔄 Starting hybrid analysis...\n');

  const startTime = Date.now();
  
  const response = await fetch('http://localhost:3000/api/attack-analysis', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action: 'analyzeAttackSurface',
      environment: {
        assets: assets,
        network_topology: {
          zones: ['dmz', 'internal', 'restricted', 'airgap'],
          internet_access_points: assets.filter(a => a.internet_facing).map(a => a.id)
        }
      }
    })
  });

  const result = await response.json();
  const totalTime = Date.now() - startTime;

  console.log('\n' + '═'.repeat(80));
  console.log('📈 GRAPH STATISTICS');
  console.log('═'.repeat(80));
  console.log(`  Nodes (Attack States):     ${result.graph_stats.total_nodes}`);
  console.log(`  Edges (Attack Transitions): ${result.graph_stats.total_edges}`);
  console.log(`  Avg Branching Factor:      ${result.graph_stats.avg_branching_factor.toFixed(2)}`);
  console.log(`  SCCs:                      ${result.graph_stats.strongly_connected_components}`);

  console.log('\n' + '═'.repeat(80));
  console.log('🚪 ENTRY POINTS (LLM + PageRank Ranked)');
  console.log('═'.repeat(80));
  result.entry_points.slice(0, 5).forEach((ep, i) => {
    console.log(`\n  ${i + 1}. ${ep.asset_name} - ${ep.misconfig_title}`);
    console.log(`     PageRank: ${ep.pagerank_score.toFixed(5)}`);
    console.log(`     Reason: ${ep.llm_reasoning.substring(0, 100)}...`);
    console.log(`     Attacker Value: ${ep.attacker_value.substring(0, 80)}...`);
  });

  console.log('\n' + '═'.repeat(80));
  console.log('🎯 CRITICAL TARGET ASSETS');
  console.log('═'.repeat(80));
  result.critical_assets.forEach((ca, i) => {
    console.log(`  ${i + 1}. ${ca.asset_name} - ${ca.reason}`);
    console.log(`     Paths leading to it: ${ca.paths_to_it}`);
  });

  console.log('\n' + '═'.repeat(80));
  console.log('⚔️  DISCOVERED ATTACK PATHS');
  console.log('═'.repeat(80));
  
  result.attack_paths.slice(0, 5).forEach((path, i) => {
    console.log(`\n┌─────────────────────────────────────────────────────────────────────────┐`);
    console.log(`│ ${path.path_id}: ${path.nodes.length} Steps - Final Risk: ${(path.final_risk_score * 100).toFixed(1)}%`.padEnd(72) + '│');
    console.log(`├─────────────────────────────────────────────────────────────────────────┤`);
    console.log(`│ Math Scores:  Probability: ${(path.path_probability * 100).toFixed(1)}%  PageRank: ${path.pagerank_score.toFixed(4)}  Impact: ${(path.impact_score * 100).toFixed(1)}%`.padEnd(72) + '│');
    console.log(`│ LLM Scores:   Realism: ${(path.realism_score * 100).toFixed(1)}%  Detection Risk: ${(path.llm_detection_risk * 100).toFixed(1)}%`.padEnd(72) + '│');
    console.log(`├─────────────────────────────────────────────────────────────────────────┤`);
    
    path.nodes.forEach((node, j) => {
      const edge = path.edges[j];
      const prefix = j === 0 ? 'START' : j === path.nodes.length - 1 ? 'END  ' : '     ';
      console.log(`│ ${prefix} → ${node.asset_name} [${node.asset_zone}]`.padEnd(72) + '│');
      console.log(`│       Misconfig: ${node.misconfig_title.substring(0, 50)}`.padEnd(72) + '│');
      if (edge) {
        console.log(`│       → ${(edge.technique_used || 'exploit').substring(0, 30)} (${(edge.probability * 100).toFixed(0)}% prob)`.padEnd(72) + '│');
      }
    });
    
    console.log(`├─────────────────────────────────────────────────────────────────────────┤`);
    console.log(`│ Business Impact: ${path.business_impact.substring(0, 55)}...`.padEnd(72) + '│');
    console.log(`│ Priority: ${path.remediation_priority.toUpperCase()}`.padEnd(72) + '│');
    console.log(`└─────────────────────────────────────────────────────────────────────────┘`);
  });

  console.log('\n' + '═'.repeat(80));
  console.log('💡 KEY INSIGHTS');
  console.log('═'.repeat(80));
  result.key_insights.forEach((insight, i) => {
    console.log(`  ${i + 1}. ${insight}`);
  });

  console.log('\n' + '═'.repeat(80));
  console.log('⏱️  ALGORITHM PERFORMANCE');
  console.log('═'.repeat(80));
  console.log(`  Graph Construction:   ${result.algorithm_transparency.graph_construction_time_ms}ms`);
  console.log(`  LLM Edge Evaluation:  ${result.algorithm_transparency.llm_edge_evaluation_time_ms}ms`);
  console.log(`  Path Discovery:       ${result.algorithm_transparency.path_discovery_time_ms}ms`);
  console.log(`  LLM Validation:       ${result.algorithm_transparency.llm_validation_time_ms}ms`);
  console.log(`  ─────────────────────────────────`);
  console.log(`  Total Analysis Time:  ${totalTime}ms (${(totalTime/1000).toFixed(1)}s)`);
  console.log('═'.repeat(80) + '\n');
}

main().catch(console.error);
