// Quick test with 10 assets
async function quickTest() {
  const assets = []
  const types = ['web_server', 'app_server', 'database_server', 'domain_controller', 'vpn_gateway']
  const zones = ['dmz', 'prod-web', 'prod-app', 'restricted', 'corp']
  
  for (let i = 1; i <= 10; i++) {
    const type = types[i % types.length]
    const zone = zones[i % zones.length]
    assets.push({
      id: `asset-${i}`,
      name: `${type.toUpperCase()}-${i}`,
      type,
      ip: `10.${i}.1.1`,
      zone,
      internet_facing: zone === 'dmz',
      criticality: type === 'domain_controller' ? 5 : 4,
      domain_joined: true,
      services: ['HTTP'],
      data_sensitivity: 'standard',
      misconfigurations: [
        { id: 'M001', title: 'RDP Accessible', description: 'RDP open', category: 'network' }
      ]
    })
  }

  console.log(`Testing with ${assets.length} assets...`)
  console.time('API call')
  
  const response = await fetch('http://localhost:3000/api/attack-analysis', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ environment: { assets } })
  })
  
  console.timeEnd('API call')
  
  const data = await response.json()
  
  console.log('\nGraph:', data.graph_stats)
  console.log('Edges:', data.edge_stats)
  console.log('Paths:', data.attack_paths?.length || 0)
  
  if (data.attack_paths?.length > 0) {
    console.log('\nTop path realism:', data.attack_paths[0].realism_score)
  }
  
  if (data.key_insights) {
    console.log('Insights:', data.key_insights)
  }
}

quickTest().catch(console.error)
