// Quick 50-asset test with proper zones
const ASSET_TEMPLATES = [
  { type: 'web_server', zones: ['dmz', 'prod-web'], crit: 4, internet: true },
  { type: 'app_server', zones: ['prod-web', 'prod-app'], crit: 4, internet: false },
  { type: 'database_server', zones: ['prod-app', 'prod-db'], crit: 5, internet: false },
  { type: 'domain_controller', zones: ['restricted'], crit: 5, internet: false },
  { type: 'identity_server', zones: ['restricted', 'security'], crit: 5, internet: false },
  { type: 'backup_server', zones: ['restricted', 'dr'], crit: 5, internet: false },
  { type: 'vpn_gateway', zones: ['dmz', 'corp'], crit: 4, internet: true },
  { type: 'firewall', zones: ['dmz', 'mgmt'], crit: 5, internet: true },
  { type: 'email_server', zones: ['dmz', 'corp'], crit: 4, internet: true },
  { type: 'jump_server', zones: ['dmz', 'mgmt'], crit: 4, internet: true },
  { type: 'siem', zones: ['security'], crit: 5, internet: false },
  { type: 'file_server', zones: ['corp', 'prod-app'], crit: 4, internet: false },
  { type: 'workstation', zones: ['corp', 'corp-wifi'], crit: 2, internet: false },
  { type: 'load_balancer', zones: ['dmz', 'prod-web'], crit: 4, internet: true },
  { type: 'api_gateway', zones: ['dmz', 'prod-web'], crit: 4, internet: true },
];

const MISCONFIGS = [
  { id: 'M001', title: 'RDP Exposed', description: 'RDP port open', category: 'network' },
  { id: 'M002', title: 'SMBv1 Active', description: 'SMBv1 enabled', category: 'network' },
  { id: 'M003', title: 'Weak Password', description: 'Weak password policy', category: 'authentication' },
  { id: 'M004', title: 'Domain Users Admin', description: 'Domain Users in local admin', category: 'authorization' },
  { id: 'M005', title: 'Unconstrained Delegation', description: 'Kerberos delegation enabled', category: 'authorization' },
  { id: 'M006', title: 'DCSync Rights', description: 'DCSync rights to non-DA', category: 'authorization' },
  { id: 'M007', title: 'AS-REP Roastable', description: 'Pre-auth disabled', category: 'authentication' },
  { id: 'M008', title: 'Service Account Stale', description: 'Old password', category: 'authentication' },
];

function generateAssets(count = 50) {
  const assets = [];
  const rng = (s) => { let h = 0; for (let i = 0; i < s.length; i++) h = Math.imul(31, h) + s.charCodeAt(i) | 0; return (h & 0xffffff) / 0xffffff; };
  
  for (let i = 1; i <= count; i++) {
    const t = ASSET_TEMPLATES[(i - 1) % ASSET_TEMPLATES.length];
    const zone = t.zones[Math.floor(rng(`zone-${i}`) * t.zones.length)];
    const mIdx = Math.floor(rng(`misc-${i}`) * MISCONFIGS.length);
    
    assets.push({
      id: `asset-${i}`,
      name: `${t.type.toUpperCase().replace(/_/g, '-')}-${String(i).padStart(3, '0')}`,
      type: t.type,
      ip: `10.${(i % 255)}.${(i * 7) % 255}.${(i * 13) % 254 + 1}`,
      zone,
      internet_facing: t.internet || zone === 'dmz',
      criticality: t.crit,
      domain_joined: t.type !== 'workstation' && t.type !== 'load_balancer',
      services: ['HTTP', 'SSH'],
      data_sensitivity: t.crit >= 5 ? 'credentials' : 'app',
      misconfigurations: [{ ...MISCONFIGS[mIdx] }]
    });
  }
  return assets;
}

async function main() {
  const assets = generateAssets(50);
  
  console.log('=== 50-Asset Attack Path Analysis ===\n');
  console.log(`Assets by zone:`);
  const byZone = {};
  assets.forEach(a => { byZone[a.zone] = (byZone[a.zone] || 0) + 1; });
  console.log(Object.entries(byZone).map(([z, c]) => `  ${z}: ${c}`).join('\n'));
  
  console.log('\nRunning analysis...');
  const start = Date.now();
  
  const res = await fetch('http://localhost:3000/api/attack-analysis', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ environment: { assets } })
  });
  
  const elapsed = Date.now() - start;
  const data = await res.json();
  
  console.log(`\n=== RESULTS (${(elapsed/1000).toFixed(1)}s) ===\n`);
  console.log('Graph:', data.graph_stats);
  console.log('Edges:', data.edge_stats);
  console.log(`Paths: ${data.attack_paths?.length || 0}`);
  
  if (data.attack_paths?.length > 0) {
    console.log('\n=== TOP 3 PATHS ===');
    for (let i = 0; i < Math.min(3, data.attack_paths.length); i++) {
      const p = data.attack_paths[i];
      console.log(`\nPath ${i + 1}:`);
      console.log(`  Chain: ${p.nodes.map(n => n.asset_name).join(' → ')}`);
      console.log(`  Zones: ${p.nodes.map(n => n.asset_zone).join(' → ')}`);
      console.log(`  Probability: ${(p.path_probability * 100).toFixed(1)}%`);
      console.log(`  Realism: ${(p.realism_score * 100).toFixed(1)}%`);
      console.log(`  Detection: ${(p.detection_risk * 100).toFixed(1)}%`);
      console.log(`  Impact: ${(p.impact_score * 100).toFixed(1)}%`);
    }
  }
}

main().catch(console.error);
