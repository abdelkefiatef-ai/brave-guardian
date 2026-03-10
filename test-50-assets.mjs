#!/usr/bin/env node
/**
 * Test script: Simulate 50 assets and get top-3 attack paths
 * Measures timing and reports coherence/realism scores
 */

const MISCONFIG_DB = [
  { id: 'M001', title: 'RDP Accessible from Internet', description: 'RDP port 3389 open to internet', category: 'network' },
  { id: 'M002', title: 'SMBv1 Protocol Active', description: 'Legacy SMB enabled', category: 'network' },
  { id: 'M003', title: 'SMB Signing Not Required', description: 'SMB relay possible', category: 'network' },
  { id: 'M010', title: 'Weak Password Policy', description: '8 char minimum', category: 'authentication' },
  { id: 'M011', title: 'Stale Service Account', description: '90+ day old password', category: 'authentication' },
  { id: 'M012', title: 'Kerberos Pre-Auth Disabled', description: 'AS-REP roastable', category: 'authentication' },
  { id: 'M013', title: 'Shared Local Admin', description: 'Same password across systems', category: 'authentication' },
  { id: 'M020', title: 'Domain Users Local Admin', description: 'Excessive rights', category: 'authorization' },
  { id: 'M022', title: 'DCSync Rights', description: 'Replication rights to non-DA', category: 'authorization' },
  { id: 'M023', title: 'Unconstrained Delegation', description: 'Kerberos delegation enabled', category: 'authorization' },
  { id: 'M030', title: 'AV Not Running', description: 'Antivirus disabled', category: 'service' },
  { id: 'M040', title: 'BitLocker Not Enabled', description: 'No disk encryption', category: 'encryption' },
  { id: 'M050', title: 'Command Line Logging Disabled', description: 'No process logging', category: 'logging' },
];

const ZONES = ['dmz', 'prod-web', 'prod-app', 'prod-db', 'corp', 'restricted', 'mgmt', 'dev-web', 'cloud-prod'];

const ASSET_TYPES = [
  { type: 'web_server', criticality: 4, internetFacing: true, domainJoined: false, categories: ['network', 'service'] },
  { type: 'app_server', criticality: 4, internetFacing: false, domainJoined: true, categories: ['authentication', 'service'] },
  { type: 'database_server', criticality: 5, internetFacing: false, domainJoined: true, categories: ['authentication', 'authorization', 'encryption'] },
  { type: 'domain_controller', criticality: 5, internetFacing: false, domainJoined: true, categories: ['authentication', 'authorization'] },
  { type: 'file_server', criticality: 4, internetFacing: false, domainJoined: true, categories: ['network', 'authorization'] },
  { type: 'workstation', criticality: 2, internetFacing: false, domainJoined: true, categories: ['authentication', 'service'] },
  { type: 'firewall', criticality: 5, internetFacing: true, domainJoined: false, categories: ['network', 'authorization'] },
  { type: 'vpn_gateway', criticality: 4, internetFacing: true, domainJoined: true, categories: ['network', 'authentication'] },
  { type: 'backup_server', criticality: 5, internetFacing: false, domainJoined: true, categories: ['authentication', 'encryption'] },
  { type: 'email_server', criticality: 4, internetFacing: true, domainJoined: true, categories: ['network', 'authentication'] },
  { type: 'jump_server', criticality: 4, internetFacing: true, domainJoined: true, categories: ['network', 'authentication'] },
  { type: 'identity_server', criticality: 5, internetFacing: true, domainJoined: true, categories: ['authentication', 'authorization'] },
  { type: 'load_balancer', criticality: 4, internetFacing: true, domainJoined: false, categories: ['network', 'encryption'] },
  { type: 'api_gateway', criticality: 4, internetFacing: true, domainJoined: false, categories: ['authentication', 'network'] },
  { type: 'siem', criticality: 5, internetFacing: false, domainJoined: true, categories: ['logging', 'network'] },
];

// Seeded random for reproducibility
class SeededRandom {
  constructor(seed) { this.seed = seed; }
  next() {
    this.seed = (this.seed * 1103515245 + 12345) & 0x7fffffff;
    return this.seed / 0x7fffffff;
  }
  nextInt(min, max) { return Math.floor(this.next() * (max - min + 1)) + min; }
  pick(arr) { return arr[Math.floor(this.next() * arr.length)]; }
}

function generateAssets(count = 50) {
  const rng = new SeededRandom(42);
  const assets = [];
  
  for (let i = 1; i <= count; i++) {
    const template = rng.pick(ASSET_TYPES);
    const zone = rng.pick(ZONES);
    const numMisconfigs = rng.nextInt(1, 3);
    
    // Pick relevant misconfigurations
    const relevantMisconfigs = MISCONFIG_DB.filter(m => template.categories.includes(m.category));
    const shuffled = relevantMisconfigs.sort(() => rng.next() - 0.5);
    const misconfigs = shuffled.slice(0, numMisconfigs).map(m => ({ ...m }));
    
    // Generate IP
    const ip = `10.${rng.nextInt(0, 255)}.${rng.nextInt(0, 255)}.${rng.nextInt(1, 254)}`;
    
    assets.push({
      id: `asset-${i}`,
      name: `${template.type.toUpperCase().replace(/_/g, '-')}-${String(i).padStart(3, '0')}`,
      type: template.type,
      ip,
      zone,
      internet_facing: template.internetFacing,
      criticality: template.criticality,
      domain_joined: template.domainJoined,
      services: ['SSH', 'HTTP', 'HTTPS'],
      data_sensitivity: template.criticality >= 5 ? 'pii' : 'standard',
      misconfigurations: misconfigs
    });
  }
  
  return assets;
}

async function runTest() {
  console.log('='.repeat(70));
  console.log('BRAVE GUARDIAN - Attack Path Analysis Test (50 Assets)');
  console.log('='.repeat(70));
  console.log();
  
  // Generate 50 assets
  console.log('[1/3] Generating 50 assets...');
  const assets = generateAssets(50);
  
  // Count by type
  const byType = {};
  assets.forEach(a => { byType[a.type] = (byType[a.type] || 0) + 1; });
  console.log('      Asset distribution:', Object.entries(byType).map(([k, v]) => `${k}=${v}`).join(', '));
  
  // Count internet-facing
  const internetFacing = assets.filter(a => a.internet_facing).length;
  console.log(`      Internet-facing: ${internetFacing}`);
  console.log();
  
  // Prepare request
  const requestBody = {
    environment: {
      assets: assets.map(a => ({
        id: a.id,
        name: a.name,
        type: a.type,
        ip: a.ip,
        zone: a.zone,
        internet_facing: a.internet_facing,
        criticality: a.criticality,
        domain_joined: a.domain_joined,
        services: a.services,
        data_sensitivity: a.data_sensitivity,
        misconfigurations: a.misconfigurations
      }))
    }
  };
  
  // Call API with timing
  console.log('[2/3] Running attack analysis (this may take a minute)...');
  const startTime = Date.now();
  
  try {
    const response = await fetch('http://localhost:3000/api/attack-analysis', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody)
    });
    
    const elapsed = Date.now() - startTime;
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error(`\n[ERROR] API returned ${response.status}: ${errorText}`);
      return;
    }
    
    const data = await response.json();
    
    console.log();
    console.log('[3/3] Analysis complete!');
    console.log();
    console.log('='.repeat(70));
    console.log(`TOTAL TIME: ${(elapsed / 1000).toFixed(2)} seconds`);
    console.log('='.repeat(70));
    console.log();
    
    // Print timing breakdown
    if (data.timing) {
      console.log('TIMING BREAKDOWN:');
      console.log(`  Node building:    ${data.timing.nodes}ms`);
      console.log(`  Edge creation:    ${data.timing.edges}ms`);
      console.log(`  PageRank:         ${data.timing.pagerank}ms`);
      console.log(`  Path discovery:   ${data.timing.paths}ms`);
      console.log(`  Path validation:  ${data.timing.validation}ms`);
      console.log(`  Entry analysis:   ${data.timing.entry_analysis}ms`);
      console.log(`  Total (server):   ${data.timing.total}ms`);
      console.log();
    }
    
    // Print graph stats
    if (data.graph_stats) {
      console.log('GRAPH STATISTICS:');
      console.log(`  Total nodes:      ${data.graph_stats.total_nodes}`);
      console.log(`  Total edges:      ${data.graph_stats.total_edges}`);
      console.log(`  Avg branching:    ${data.graph_stats.avg_branching_factor}`);
      console.log();
    }
    
    // Print edge stats
    if (data.edge_stats) {
      console.log('EDGE STATISTICS:');
      console.log(`  Pattern edges:    ${data.edge_stats.pattern_edges}`);
      console.log(`  LLM edges:        ${data.edge_stats.llm_edges}`);
      console.log(`  Candidates:       ${data.edge_stats.candidates_evaluated || 'N/A'}`);
      console.log();
    }
    
    // Print top-3 attack paths
    const paths = data.attack_paths || [];
    console.log('='.repeat(70));
    console.log('TOP-3 ATTACK PATHS');
    console.log('='.repeat(70));
    
    for (let i = 0; i < Math.min(3, paths.length); i++) {
      const path = paths[i];
      console.log();
      console.log(`--- PATH ${i + 1}: ${path.path_id} ---`);
      console.log();
      
      // Attack chain
      console.log('ATTACK CHAIN:');
      path.nodes.forEach((node, idx) => {
        const arrow = idx < path.nodes.length - 1 ? ' ──▶ ' : '';
        process.stdout.write(`  [${idx + 1}] ${node.asset_name} (${node.asset_type})${arrow}`);
        if (idx === path.nodes.length - 1) process.stdout.write('\n');
      });
      console.log();
      
      // Vulnerabilities exploited
      console.log('VULNERABILITIES:');
      path.nodes.forEach((node, idx) => {
        console.log(`  [${idx + 1}] ${node.misconfig_title} (${node.misconfig_category})`);
      });
      console.log();
      
      // Techniques used
      console.log('TECHNIQUES:');
      path.edges.forEach((edge, idx) => {
        console.log(`  ${edge.technique}: ${edge.reasoning.substring(0, 60)}...`);
      });
      console.log();
      
      // Scores
      console.log('SCORES:');
      console.log(`  Path Probability:  ${(path.path_probability * 100).toFixed(1)}%`);
      console.log(`  Coherence/Realism: ${(path.realism_score * 100).toFixed(1)}%`);
      console.log(`  Detection Risk:    ${(path.detection_risk * 100).toFixed(1)}%`);
      console.log(`  Impact Score:      ${(path.impact_score * 100).toFixed(1)}%`);
      console.log(`  Final Risk Score:  ${(path.final_risk_score * 100).toFixed(1)}%`);
      console.log();
      
      // Narrative
      if (path.narrative) {
        console.log('NARRATIVE:');
        console.log(`  ${path.narrative}`);
        console.log();
      }
      
      // Business impact
      if (path.business_impact) {
        console.log('BUSINESS IMPACT:');
        console.log(`  ${path.business_impact}`);
        console.log();
      }
      
      // Kill chain
      if (path.kill_chain && path.kill_chain.length > 0) {
        console.log('KILL CHAIN:');
        console.log(`  ${path.kill_chain.join(' → ')}`);
        console.log();
      }
    }
    
    // Summary
    console.log('='.repeat(70));
    console.log('SUMMARY');
    console.log('='.repeat(70));
    console.log();
    console.log(`Assets analyzed:       50`);
    console.log(`Total attack paths:    ${paths.length}`);
    console.log(`Analysis time:         ${(elapsed / 1000).toFixed(2)} seconds`);
    console.log();
    
    if (paths.length >= 3) {
      console.log('TOP-3 COHERENCE/REALISM SCORES:');
      for (let i = 0; i < 3; i++) {
        console.log(`  Path ${i + 1}: ${(paths[i].realism_score * 100).toFixed(1)}% realism, ${(paths[i].path_probability * 100).toFixed(1)}% probability`);
      }
    }
    
  } catch (error) {
    const elapsed = Date.now() - startTime;
    console.error(`\n[ERROR] Request failed after ${elapsed}ms:`, error.message);
    
    if (error.cause?.code === 'ECONNREFUSED') {
      console.error('\nThe development server is not running. Please start it with: bun run dev');
    }
  }
}

runTest();
