// Simple test with 5 assets
async function test() {
  const assets = [
    { id: 'asset-1', name: 'WEB-DMZ-001', type: 'web_server', ip: '10.0.1.10', zone: 'dmz', internet_facing: true, criticality: 4, domain_joined: false, services: ['HTTP'], data_sensitivity: 'app_data', misconfigurations: [{ id: 'M001', title: 'RDP Accessible from Internet', description: 'RDP open', category: 'network' }] },
    { id: 'asset-2', name: 'APP-PROD-001', type: 'app_server', ip: '10.10.1.10', zone: 'prod-web', internet_facing: false, criticality: 4, domain_joined: true, services: ['HTTP'], data_sensitivity: 'app_data', misconfigurations: [{ id: 'M010', title: 'Weak Password Policy', description: '8 chars', category: 'authentication' }] },
    { id: 'asset-3', name: 'DB-PROD-001', type: 'database_server', ip: '10.11.1.10', zone: 'prod-app', internet_facing: false, criticality: 5, domain_joined: true, services: ['SQL'], data_sensitivity: 'pii', misconfigurations: [{ id: 'M020', title: 'Domain Users Local Admin', description: 'Excessive rights', category: 'authorization' }] },
    { id: 'asset-4', name: 'DC-RESTRICTED-001', type: 'domain_controller', ip: '10.200.1.10', zone: 'restricted', internet_facing: false, criticality: 5, domain_joined: true, services: ['AD', 'DNS'], data_sensitivity: 'credentials', misconfigurations: [{ id: 'M022', title: 'DCSync Rights', description: 'Replication rights', category: 'authorization' }] },
    { id: 'asset-5', name: 'VPN-DMZ-001', type: 'vpn_gateway', ip: '10.0.1.1', zone: 'dmz', internet_facing: true, criticality: 4, domain_joined: true, services: ['VPN'], data_sensitivity: 'credentials', misconfigurations: [{ id: 'M011', title: 'Stale Service Account', description: 'Old password', category: 'authentication' }] }
  ];

  console.log('Testing with 5 assets...');
  console.log('Asset zones:', assets.map(a => `${a.name}(${a.zone})`).join(', '));
  
  const response = await fetch('http://localhost:3000/api/attack-analysis', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ environment: { assets } })
  });
  
  const data = await response.json();
  
  console.log('\nGraph Stats:', data.graph_stats);
  console.log('Edge Stats:', data.edge_stats);
  console.log('Paths found:', data.attack_paths?.length || 0);
  
  if (data.attack_paths?.length > 0) {
    console.log('\nTop path:');
    const p = data.attack_paths[0];
    console.log('  Nodes:', p.nodes.map(n => n.asset_name).join(' → '));
    console.log('  Probability:', (p.path_probability * 100).toFixed(1) + '%');
    console.log('  Realism:', (p.realism_score * 100).toFixed(1) + '%');
  }
  
  if (data.key_insights) {
    console.log('\nKey insights:', data.key_insights);
  }
}

test().catch(console.error);
