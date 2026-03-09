// Debug script to understand why restricted zone paths aren't found

const SAMPLE_ASSETS = [
  {
    id: 'web-server-01',
    name: 'Public Web Server',
    type: 'web_server',
    ip: '203.0.113.10',
    zone: 'dmz',
    internet_facing: true,
    criticality: 3,
    domain_joined: true,
    services: ['http', 'https', 'ssh'],
    data_sensitivity: 'standard',
    misconfigurations: [
      { id: 'm1', title: 'SQL Injection Vulnerability', description: 'User input not sanitized', category: 'network' },
    ]
  },
  {
    id: 'app-server-01',
    name: 'Application Server',
    type: 'application_server',
    ip: '10.0.1.50',
    zone: 'internal',
    internet_facing: false,
    criticality: 4,
    domain_joined: true,
    services: ['tomcat'],
    data_sensitivity: 'confidential',
    misconfigurations: [
      { id: 'm5', title: 'Default Admin Credentials', description: 'Admin panel uses default credentials', category: 'authentication' },
    ]
  },
  {
    id: 'dc-01',
    name: 'Primary Domain Controller',
    type: 'domain_controller',
    ip: '10.0.2.10',
    zone: 'restricted',
    internet_facing: false,
    criticality: 5,
    domain_joined: false,
    services: ['ldap', 'kerberos'],
    data_sensitivity: 'restricted',
    misconfigurations: [
      { id: 'm9', title: 'Kerberoasting Vulnerable SPNs', description: 'Service accounts with weak passwords', category: 'authentication' },
      { id: 'm10', title: 'DCSync Rights Misconfiguration', description: 'Backup account has DCSync privileges', category: 'authorization' }
    ]
  }
];

// Simulate the key parts of the algorithm

const ZONE_REACH: Record<string, string[]> = {
  dmz: ['internal', 'dmz'],
  internal: ['restricted', 'internal', 'dmz'],
  restricted: ['restricted', 'internal'],
  airgap: ['airgap', 'restricted']
};

const ATTACK_PATTERNS: Record<string, { provides: string[]; techniques: string[]; to_categories: string[] }> = {
  network: {
    provides: ['initial_access', 'remote_access', 'network_position'],
    techniques: ['T1133', 'T1190', 'T1021'],
    to_categories: ['authentication', 'authorization', 'service', 'network', 'encryption', 'logging']
  },
  authentication: {
    provides: ['credentials', 'session_tokens', 'kerberos_tickets', 'user_access'],
    techniques: ['T1110', 'T1558', 'T1208', 'T1550'],
    to_categories: ['authorization', 'network', 'service', 'authentication']
  },
  authorization: {
    provides: ['elevated_privileges', 'domain_admin', 'dc_sync', 'admin_access'],
    techniques: ['T1078', 'T1098', 'T1482', 'T1068'],
    to_categories: ['network', 'service', 'encryption', 'logging', 'authorization']
  }
};

console.log('=== DEBUG: Zone Reachability Analysis ===\n');

console.log('Zone Reachability Matrix:');
for (const [from, toList] of Object.entries(ZONE_REACH)) {
  console.log(`  ${from} → ${toList.join(', ')}`);
}

console.log('\n=== DEBUG: Asset Analysis ===\n');

for (const asset of SAMPLE_ASSETS) {
  console.log(`${asset.name} (${asset.zone}, criticality: ${asset.criticality})`);
  console.log(`  Internet-facing: ${asset.internet_facing}`);
  console.log(`  Misconfigurations:`);
  for (const m of asset.misconfigurations) {
    console.log(`    - ${m.title} [${m.category}]`);
    const pattern = ATTACK_PATTERNS[m.category];
    if (pattern) {
      console.log(`      Can transition to: ${pattern.to_categories.join(', ')}`);
    }
  }
  console.log();
}

console.log('=== DEBUG: Edge Analysis ===\n');

const nodes: Array<{ id: string; asset: typeof SAMPLE_ASSETS[0]; misconfig: typeof SAMPLE_ASSETS[0]['misconfigurations'][0] }> = [];
for (const asset of SAMPLE_ASSETS) {
  for (const m of asset.misconfigurations) {
    nodes.push({ id: `${asset.id}::${m.id}`, asset, misconfig: m });
  }
}

console.log('Nodes created:');
nodes.forEach(n => console.log(`  ${n.id} (${n.asset.zone})`));

console.log('\nPossible Edges:');

for (const source of nodes) {
  for (const target of nodes) {
    if (source.id === target.id) continue;

    const canReachZone = ZONE_REACH[source.asset.zone]?.includes(target.asset.zone);
    const sameAsset = source.asset.id === target.asset.id;
    
    if (!canReachZone && !sameAsset) continue;

    const sourcePattern = ATTACK_PATTERNS[source.misconfig.category];
    if (!sourcePattern) continue;

    if (!sourcePattern.to_categories.includes(target.misconfig.category)) continue;

    console.log(`  ${source.asset.name} [${source.misconfig.category}] → ${target.asset.name} [${target.misconfig.category}]`);
    console.log(`    Zone: ${source.asset.zone} → ${target.asset.zone} (valid: ${canReachZone})`);
    console.log(`    Pattern: ${source.misconfig.category} → ${target.misconfig.category} (valid)`);
  }
}

console.log('\n=== DEBUG: Expected Paths ===\n');

console.log('Expected multi-hop path:');
console.log('  1. web-server-01 (dmz, network) → app-server-01 (internal, authentication)');
console.log('     - Zone: dmz → internal ✓');
console.log('     - Pattern: network → authentication ✓');
console.log('  2. app-server-01 (internal, authentication) → dc-01 (restricted, authorization)');
console.log('     - Zone: internal → restricted ✓');
console.log('     - Pattern: authentication → authorization ✓');
console.log('');
console.log('This should create a 3-node path: DMZ → internal → restricted');
