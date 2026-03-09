async function main() {
  console.log('╔══════════════════════════════════════════════════════════════════════════╗');
  console.log('║        BRAVE GUARDIAN - Hybrid Attack Path Analysis                      ║');
  console.log('║        Graph Theory + LLM Intelligence                                   ║');
  console.log('╚══════════════════════════════════════════════════════════════════════════╝\n');

  const assets = [
    {"id": "asset-1", "name": "WEB-001", "type": "web_server", "ip": "10.1.1.1", "zone": "dmz", "internet_facing": true, "criticality": 4, "domain_joined": false, "services": ["IIS"], "data_sensitivity": "application_data", "misconfigurations": [{"id": "M001", "title": "RDP Accessible from Internet", "description": "RDP port 3389 open to internet", "category": "network"}]},
    {"id": "asset-2", "name": "JUM-002", "type": "jump_server", "ip": "10.1.1.2", "zone": "dmz", "internet_facing": true, "criticality": 4, "domain_joined": true, "services": ["RDP Gateway"], "data_sensitivity": "access_credentials", "misconfigurations": [{"id": "M003", "title": "SMB Signing Not Required", "description": "SMB relay possible", "category": "network"}, {"id": "M013", "title": "Same Local Admin Password", "description": "Shared local admin", "category": "authentication"}]},
    {"id": "asset-3", "name": "FIL-003", "type": "file_server", "ip": "10.2.1.1", "zone": "internal", "internet_facing": false, "criticality": 4, "domain_joined": true, "services": ["SMB"], "data_sensitivity": "user_files", "misconfigurations": [{"id": "M014", "title": "Credential Guard Disabled", "description": "LSASS vulnerable", "category": "authentication"}]},
    {"id": "asset-4", "name": "DOM-004", "type": "domain_controller", "ip": "10.3.1.1", "zone": "restricted", "internet_facing": false, "criticality": 5, "domain_joined": true, "services": ["AD", "DNS"], "data_sensitivity": "credentials", "misconfigurations": [{"id": "M022", "title": "DCSync Rights to Service Account", "description": "Non-DA has replication rights", "category": "authorization"}, {"id": "M023", "title": "Unconstrained Delegation", "description": "Computer trusted for delegation", "category": "authorization"}]},
    {"id": "asset-5", "name": "DAT-005", "type": "database_server", "ip": "10.3.1.2", "zone": "restricted", "internet_facing": false, "criticality": 5, "domain_joined": true, "services": ["SQL Server"], "data_sensitivity": "pii", "misconfigurations": [{"id": "M007", "title": "Database Port Exposed", "description": "SQL port accessible", "category": "network"}, {"id": "M020", "title": "Domain Users in Local Admins", "description": "Excessive rights", "category": "authorization"}]},
    {"id": "asset-6", "name": "WRK-006", "type": "workstation", "ip": "10.2.2.1", "zone": "internal", "internet_facing": false, "criticality": 2, "domain_joined": true, "services": ["Office"], "data_sensitivity": "user_data", "misconfigurations": [{"id": "M012", "title": "Kerberos Pre-Auth Disabled", "description": "AS-REP Roasting possible", "category": "authentication"}]}
  ];

  console.log(`📊 Environment: ${assets.length} assets loaded`);
  console.log(`   - DMZ: ${assets.filter(a => a.zone === 'dmz').length} (Internet-facing)`);
  console.log(`   - Internal: ${assets.filter(a => a.zone === 'internal').length}`);
  console.log(`   - Restricted: ${assets.filter(a => a.zone === 'restricted').length}\n`);
  
  console.log('🔄 Running Hybrid Analysis...\n');
  console.log('   Phase 1: Building attack graph nodes...');
  console.log('   Phase 2: LLM evaluating attack transitions...');
  console.log('   Phase 3: Calculating PageRank & discovering paths...');
  console.log('   Phase 4: LLM validating discovered paths...\n');

  const startTime = Date.now();
  
  try {
    const response = await fetch('http://localhost:3000/api/attack-analysis', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'analyzeAttackSurface',
        environment: {
          assets: assets,
          network_topology: {
            zones: ['dmz', 'internal', 'restricted'],
            internet_access_points: assets.filter(a => a.internet_facing).map(a => a.id)
          }
        }
      })
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const result = await response.json();
    const totalTime = Date.now() - startTime;

    console.log('═'.repeat(80));
    console.log('📈 GRAPH STATISTICS');
    console.log('═'.repeat(80));
    console.log(`  Nodes (Attack States):     ${result.graph_stats.total_nodes}`);
    console.log(`  Edges (Attack Transitions): ${result.graph_stats.total_edges}`);
    console.log(`  Avg Branching Factor:      ${result.graph_stats.avg_branching_factor.toFixed(2)}`);
    console.log(`  Strongly Connected:        ${result.graph_stats.strongly_connected_components}`);

    console.log('\n' + '═'.repeat(80));
    console.log('🚪 ENTRY POINTS (LLM + PageRank Ranked)');
    console.log('═'.repeat(80));
    result.entry_points.forEach((ep, i) => {
      console.log(`\n  ${i + 1}. ${ep.asset_name} - ${ep.misconfig_title}`);
      console.log(`     PageRank Score: ${ep.pagerank_score.toFixed(5)}`);
      console.log(`     LLM Reasoning: ${ep.llm_reasoning.substring(0, 100)}`);
      console.log(`     Attacker Value: ${ep.attacker_value.substring(0, 80)}`);
    });

    console.log('\n' + '═'.repeat(80));
    console.log('🎯 CRITICAL TARGET ASSETS');
    console.log('═'.repeat(80));
    result.critical_assets.forEach((ca, i) => {
      console.log(`  ${i + 1}. ${ca.asset_name} - ${ca.reason}`);
      console.log(`     Attack paths leading here: ${ca.paths_to_it}`);
    });

    console.log('\n' + '═'.repeat(80));
    console.log('⚔️  DISCOVERED ATTACK PATHS');
    console.log('═'.repeat(80));
    
    result.attack_paths.forEach((path, i) => {
      console.log(`\n┌${'─'.repeat(78)}┐`);
      console.log(`│ ${path.path_id}: ${path.nodes.length} Steps - FINAL RISK SCORE: ${(path.final_risk_score * 100).toFixed(1)}%`.padEnd(79) + '│');
      console.log(`├${'─'.repeat(78)}┤`);
      console.log(`│ HYBRID SCORES:`.padEnd(79) + '│');
      console.log(`│   Mathematical:  Probability ${(path.path_probability * 100).toFixed(1)}% | PageRank ${path.pagerank_score.toFixed(4)} | Impact ${(path.impact_score * 100).toFixed(1)}%`.padEnd(79) + '│');
      console.log(`│   LLM:           Realism ${(path.realism_score * 100).toFixed(1)}% | Detection Risk ${(path.llm_detection_risk * 100).toFixed(1)}%`.padEnd(79) + '│');
      console.log(`├${'─'.repeat(78)}┤`);
      console.log(`│ ATTACK CHAIN:`.padEnd(79) + '│');
      
      path.nodes.forEach((node, j) => {
        const edge = path.edges[j];
        const label = j === 0 ? '  START →' : j === path.nodes.length - 1 ? '  END   →' : '         →';
        console.log(`│${label} ${node.asset_name} [${node.asset_zone.toUpperCase()}]`.padEnd(79) + '│');
        console.log(`│           Misconfig: ${node.misconfig_title}`.padEnd(79) + '│');
        if (edge) {
          console.log(`│           Technique: ${edge.technique_used} (${(edge.probability * 100).toFixed(0)}% success)`.padEnd(79) + '│');
          if (edge.credentials_carried && edge.credentials_carried.length > 0) {
            console.log(`│           Credentials: ${edge.credentials_carried.join(', ')}`.padEnd(79) + '│');
          }
        }
      });
      
      console.log(`├${'─'.repeat(78)}┤`);
      console.log(`│ BUSINESS IMPACT: ${path.business_impact.substring(0, 60)}`.padEnd(79) + '│');
      console.log(`│ REMEDIATION: ${path.remediation_priority.toUpperCase()}`.padEnd(79) + '│');
      console.log(`└${'─'.repeat(78)}┘`);
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
    console.log(`  Graph Construction:    ${result.algorithm_transparency.graph_construction_time_ms}ms`);
    console.log(`  LLM Edge Evaluation:   ${result.algorithm_transparency.llm_edge_evaluation_time_ms}ms`);
    console.log(`  Path Discovery:        ${result.algorithm_transparency.path_discovery_time_ms}ms`);
    console.log(`  LLM Path Validation:   ${result.algorithm_transparency.llm_validation_time_ms}ms`);
    console.log(`  ${'─'.repeat(40)}`);
    console.log(`  TOTAL ANALYSIS TIME:   ${totalTime}ms (${(totalTime/1000).toFixed(1)} seconds)`);
    console.log('═'.repeat(80) + '\n');

  } catch (error) {
    console.error('Error:', error.message);
  }
}

main();
