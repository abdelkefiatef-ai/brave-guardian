// Comprehensive Coherence Check for Attack Paths

interface AttackNode {
  id: string;
  asset_name: string;
  asset_zone: string;
  asset_type: string;
  misconfig_title: string;
  misconfig_category: string;
  criticality: number;
  internet_facing: boolean;
  domain_joined: boolean;
}

interface AttackEdge {
  source_id: string;
  target_id: string;
  probability: number;
  technique: string;
  edge_type: 'pattern' | 'llm';
  reasoning: string;
}

interface AttackPath {
  path_id: string;
  nodes: AttackNode[];
  edges: AttackEdge[];
  path_probability: number;
  realism_score: number;
  detection_risk: number;
  final_risk_score: number;
  narrative: string;
  business_impact: string;
  kill_chain: string[];
}

// Zone reachability rules
const ZONE_REACH: Record<string, string[]> = {
  dmz: ['internal', 'dmz'],
  internal: ['restricted', 'internal', 'dmz'],
  restricted: ['restricted', 'internal'],
  airgap: ['airgap', 'restricted']
};

// Pattern compatibility rules
const PATTERN_COMPAT: Record<string, string[]> = {
  network: ['authentication', 'authorization', 'service', 'network', 'encryption', 'logging'],
  authentication: ['authorization', 'network', 'service', 'authentication'],
  authorization: ['network', 'service', 'encryption', 'logging', 'authorization'],
  service: ['authentication', 'authorization', 'network', 'service'],
  encryption: ['authentication', 'network', 'service'],
  logging: ['service', 'network', 'authentication', 'authorization']
};

function validatePath(path: AttackPath): { valid: boolean; issues: string[] } {
  const issues: string[] = [];
  
  // 1. Check entry point is internet-facing
  const entry = path.nodes[0];
  if (!entry.internet_facing) {
    issues.push(`Entry point ${entry.asset_name} is not internet-facing`);
  }
  
  // 2. Check target is high-criticality
  const target = path.nodes[path.nodes.length - 1];
  if (target.criticality < 4) {
    issues.push(`Target ${target.asset_name} has criticality ${target.criticality} < 4`);
  }
  
  // 3. Check zone progression
  for (let i = 0; i < path.nodes.length - 1; i++) {
    const from = path.nodes[i].asset_zone;
    const to = path.nodes[i + 1].asset_zone;
    const allowed = ZONE_REACH[from] || [];
    if (!allowed.includes(to)) {
      issues.push(`Invalid zone transition: ${from} → ${to}`);
    }
  }
  
  // 4. Check pattern compatibility for each edge
  for (const edge of path.edges) {
    const sourceNode = path.nodes.find(n => n.id === edge.source_id);
    const targetNode = path.nodes.find(n => n.id === edge.target_id);
    if (!sourceNode || !targetNode) continue;
    
    const allowedCategories = PATTERN_COMPAT[sourceNode.misconfig_category] || [];
    if (!allowedCategories.includes(targetNode.misconfig_category)) {
      issues.push(`Pattern incompatibility: ${sourceNode.misconfig_category} → ${targetNode.misconfig_category}`);
    }
  }
  
  // 5. Check probability calculation
  let calculatedProb = 1;
  for (const edge of path.edges) {
    calculatedProb *= edge.probability;
  }
  if (Math.abs(calculatedProb - path.path_probability) > 0.01) {
    issues.push(`Probability mismatch: calculated ${calculatedProb.toFixed(4)} vs reported ${path.path_probability.toFixed(4)}`);
  }
  
  // 6. Check path length
  if (path.nodes.length < 2 || path.nodes.length > 6) {
    issues.push(`Path length ${path.nodes.length} is outside valid range [2-6]`);
  }
  
  return { valid: issues.length === 0, issues };
}

// Test with real API data
async function main() {
  console.log('═'.repeat(80));
  console.log('ATTACK PATH COHERENCE VALIDATION');
  console.log('═'.repeat(80));
  
  const response = await fetch('http://localhost:3000/api/attack-analysis', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      assets: [
        {
          id: 'web-01', name: 'WEB-DMZ-01', type: 'web_server', ip: '203.0.113.10',
          zone: 'dmz', internet_facing: true, criticality: 3, domain_joined: true,
          services: ['http'], data_sensitivity: 'standard',
          misconfigurations: [
            { id: 'm1', title: 'SQL Injection', description: 'SQL injection', category: 'network' }
          ]
        },
        {
          id: 'jump-01', name: 'JUMP-INTERNAL-01', type: 'jump_server', ip: '10.0.1.5',
          zone: 'internal', internet_facing: false, criticality: 4, domain_joined: true,
          services: ['rdp'], data_sensitivity: 'credentials',
          misconfigurations: [
            { id: 'm2', title: 'Weak Password', description: 'Weak password', category: 'authentication' },
            { id: 'm3', title: 'Domain Admin', description: 'DA rights', category: 'authorization' }
          ]
        },
        {
          id: 'dc-01', name: 'DC-RESTRICTED-01', type: 'domain_controller', ip: '10.0.2.10',
          zone: 'restricted', internet_facing: false, criticality: 5, domain_joined: false,
          services: ['ldap'], data_sensitivity: 'credentials',
          misconfigurations: [
            { id: 'm4', title: 'Kerberoasting', description: 'Weak SPN', category: 'authentication' },
            { id: 'm5', title: 'DCSync', description: 'DCSync rights', category: 'authorization' }
          ]
        }
      ]
    })
  });
  
  const data = await response.json();
  
  console.log(`\n📊 STATISTICS:`);
  console.log(`   Total Nodes: ${data.graph_stats.total_nodes}`);
  console.log(`   Total Edges: ${data.graph_stats.total_edges}`);
  console.log(`   Pattern Edges: ${data.edge_stats.pattern_edges}`);
  console.log(`   LLM Edges: ${data.edge_stats.llm_edges}`);
  console.log(`   Execution Time: ${data.timing.total}ms`);
  
  console.log(`\n🔬 PATH VALIDATION:`);
  
  let allValid = true;
  for (const path of data.attack_paths) {
    const validation = validatePath(path);
    
    console.log(`\n   ${path.path_id}:`);
    console.log(`   Chain: ${path.nodes.map(n => `${n.asset_name}(${n.asset_zone[0].toUpperCase()})`).join(' → ')}`);
    console.log(`   Length: ${path.nodes.length} steps`);
    console.log(`   Probability: ${(path.path_probability * 100).toFixed(1)}%`);
    console.log(`   Risk Score: ${(path.final_risk_score * 100).toFixed(1)}%`);
    
    if (validation.valid) {
      console.log(`   ✅ COHERENT - All checks passed`);
    } else {
      allValid = false;
      console.log(`   ❌ ISSUES FOUND:`);
      validation.issues.forEach(issue => console.log(`      - ${issue}`));
    }
  }
  
  console.log('\n' + '═'.repeat(80));
  console.log('FINAL VERDICT');
  console.log('═'.repeat(80));
  
  if (allValid) {
    console.log('✅ ALL PATHS ARE COHERENT');
    console.log('   • Zone transitions follow network segmentation rules');
    console.log('   • Pattern transitions follow attack logic');
    console.log('   • Entry points are internet-facing');
    console.log('   • Targets are high-criticality assets');
    console.log('   • Probabilities are correctly calculated');
  } else {
    console.log('❌ SOME PATHS HAVE COHERENCE ISSUES');
  }
  
  console.log('\n📋 ALGORITHM SUMMARY:');
  console.log('   Phase 1: Build Nodes - O(n)');
  console.log('   Phase 2: Hybrid Edges - Pattern + Batch LLM');
  console.log('   Phase 3: PageRank - O(iterations × E)');
  console.log('   Phase 4: Dijkstra - O(E log V)');
  console.log('   Phase 5: LLM Validation - Batch');
  console.log('   Phase 6: Final Scoring');
}

main().catch(console.error);
