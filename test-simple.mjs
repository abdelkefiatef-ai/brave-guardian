// Simpler test with fewer assets

async function runTest() {
  const MISCONFIG_DB = [
    { id: 'M001', title: 'RDP Accessible from Internet', description: 'RDP open', category: 'network' },
    { id: 'M011', title: 'Kerberos Pre-Auth Disabled', description: 'AS-REP Roasting', category: 'authentication' },
    { id: 'M022', title: 'DCSync Rights to Service Account', description: 'Domain replication', category: 'authorization' },
  ];

  const assets = [
    {
      id: 'asset-1',
      name: 'WEB-001',
      type: 'web_server',
      ip: '10.1.1.10',
      zone: 'dmz',
      internet_facing: true,
      criticality: 4,
      domain_joined: false,
      services: ['IIS'],
      data_sensitivity: 'application_data',
      misconfigurations: [{ ...MISCONFIG_DB[0] }]
    },
    {
      id: 'asset-2',
      name: 'DC-002',
      type: 'domain_controller',
      ip: '10.2.1.10',
      zone: 'restricted',
      internet_facing: false,
      criticality: 5,
      domain_joined: true,
      services: ['AD', 'DNS'],
      data_sensitivity: 'credentials',
      misconfigurations: [{ ...MISCONFIG_DB[1] }, { ...MISCONFIG_DB[2] }]
    },
    {
      id: 'asset-3',
      name: 'WS-003',
      type: 'workstation',
      ip: '10.1.5.50',
      zone: 'internal',
      internet_facing: false,
      criticality: 2,
      domain_joined: true,
      services: ['Office'],
      data_sensitivity: 'user_data',
      misconfigurations: [{ ...MISCONFIG_DB[0] }]
    }
  ];

  console.log('='.repeat(80));
  console.log('HYBRID ATTACK PATH ANALYSIS - SIMPLIFIED TEST');
  console.log('='.repeat(80));
  console.log(`\n📊 Assets: ${assets.length}`);
  console.log(`📊 Misconfigurations: ${assets.reduce((s, a) => s + a.misconfigurations.length, 0)}`);

  console.log('\n📡 Calling API...');
  const startTime = Date.now();
  
  const response = await fetch('http://localhost:3000/api/attack-analysis', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      action: 'analyzeAttackSurface',
      environment: {
        assets,
        network_topology: {
          zones: ['dmz', 'internal', 'restricted'],
          internet_access_points: ['asset-1']
        }
      }
    })
  });

  const elapsed = Date.now() - startTime;
  console.log(`⏱️  Response time: ${elapsed}ms`);

  if (!response.ok) {
    console.error('❌ API Error:', response.status);
    const text = await response.text();
    console.error(text.substring(0, 500));
    return;
  }

  const result = await response.json();

  console.log('\n' + '='.repeat(80));
  console.log('ANALYSIS RESULTS');
  console.log('='.repeat(80));

  console.log('\n📈 Graph Statistics:');
  console.log(`   Nodes: ${result.graph_stats.total_nodes}`);
  console.log(`   Edges: ${result.graph_stats.total_edges}`);
  console.log(`   Branching Factor: ${result.graph_stats.avg_branching_factor.toFixed(3)}`);

  console.log('\n⏱️  Performance Breakdown:');
  console.log(`   Graph Construction: ${result.algorithm_transparency.graph_construction_time_ms}ms`);
  console.log(`   LLM Edge Evaluation: ${result.algorithm_transparency.llm_edge_evaluation_time_ms}ms`);
  console.log(`   Path Discovery: ${result.algorithm_transparency.path_discovery_time_ms}ms`);
  console.log(`   LLM Validation: ${result.algorithm_transparency.llm_validation_time_ms}ms`);

  console.log('\n🚪 Entry Points:');
  result.entry_points.forEach((entry, i) => {
    console.log(`   ${i + 1}. ${entry.asset_name} - ${entry.misconfig_title}`);
    console.log(`      PageRank: ${entry.pagerank_score.toFixed(5)}`);
    console.log(`      LLM Reasoning: ${entry.llm_reasoning?.substring(0, 60)}...`);
  });

  console.log('\n⚔️  Attack Paths Found: ' + result.attack_paths.length);
  
  result.attack_paths.slice(0, 3).forEach((path, i) => {
    console.log(`\n   ┌─ ${path.path_id} ─────────────────────────────────────────`);
    console.log(`   │ Risk: ${(path.final_risk_score * 100).toFixed(1)}% | Steps: ${path.nodes.length}`);
    console.log(`   │ Prob: ${(path.path_probability * 100).toFixed(0)}% | Realism: ${(path.realism_score * 100).toFixed(0)}%`);
    path.nodes.forEach((node, j) => {
      const edge = path.edges[j];
      console.log(`   │ ${j + 1}. ${node.asset_name} [${node.asset_zone}] - ${node.misconfig_title}`);
      if (edge) {
        console.log(`   │    → ${edge.technique_used} (${(edge.probability * 100).toFixed(0)}%)`);
      }
    });
    console.log(`   │ Impact: ${path.business_impact?.substring(0, 50)}...`);
    console.log(`   └──────────────────────────────────────────────────────────`);
  });

  console.log('\n💡 Key Insights:');
  result.key_insights.forEach((insight, i) => {
    console.log(`   ${i + 1}. ${insight}`);
  });

  console.log('\n' + '='.repeat(80));
  console.log('✅ Complete');
}

runTest().catch(console.error);
