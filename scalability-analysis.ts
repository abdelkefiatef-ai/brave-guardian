// Scalability Analysis for 10,000 Assets

console.log('═'.repeat(80));
console.log('SCALABILITY ANALYSIS: 10,000 Assets');
console.log('═'.repeat(80));

const ASSET_COUNT = 10000;
const MISCONFIGS_PER_ASSET = 2;
const TOTAL_NODES = ASSET_COUNT * MISCONFIGS_PER_ASSET;

console.log(`\n📊 INPUT SIZE:`);
console.log(`   Assets: ${ASSET_COUNT.toLocaleString()}`);
console.log(`   Misconfigs per asset: ${MISCONFIGS_PER_ASSET}`);
console.log(`   Total attack nodes: ${TOTAL_NODES.toLocaleString()}`);

// Simulate zone distribution (typical enterprise)
const zoneDistribution = {
  dmz: 0.05,       // 5% - internet-facing
  internal: 0.70,  // 70% - internal network
  restricted: 0.20, // 20% - restricted zone
  airgap: 0.05     // 5% - air-gapped
};

const nodesByZone = {
  dmz: Math.floor(TOTAL_NODES * zoneDistribution.dmz),
  internal: Math.floor(TOTAL_NODES * zoneDistribution.internal),
  restricted: Math.floor(TOTAL_NODES * zoneDistribution.restricted),
  airgap: Math.floor(TOTAL_NODES * zoneDistribution.airgap)
};

console.log(`\n📁 ZONE DISTRIBUTION:`);
Object.entries(nodesByZone).forEach(([zone, count]) => {
  console.log(`   ${zone}: ${count.toLocaleString()} nodes`);
});

// Calculate edge comparisons
console.log('\n' + '─'.repeat(80));
console.log('EDGE CREATION COMPLEXITY');
console.log('─'.repeat(80));

// OLD APPROACH: O(n²)
const oldComparisons = TOTAL_NODES * TOTAL_NODES;
console.log(`\n❌ OLD APPROACH (O(n²)):`);
console.log(`   Comparisons: ${oldComparisons.toLocaleString()}`);
console.log(`   At 1μs per comparison: ${(oldComparisons / 1_000_000).toFixed(1)} seconds`);
console.log(`   At 0.1μs per comparison: ${(oldComparisons / 10_000_000).toFixed(1)} seconds`);

// NEW APPROACH: Zone-indexed
// Edges only between reachable zones
const ZONE_REACH: Record<string, string[]> = {
  dmz: ['internal', 'dmz'],
  internal: ['restricted', 'internal', 'dmz'],
  restricted: ['restricted', 'internal'],
  airgap: ['airgap', 'restricted']
};

let newComparisons = 0;

// DMZ → Internal edges
newComparisons += nodesByZone.dmz * nodesByZone.internal;
// Internal → Restricted edges
newComparisons += nodesByZone.internal * nodesByZone.restricted;
// Internal → DMZ edges (reverse)
newComparisons += nodesByZone.internal * nodesByZone.dmz;
// Same-asset edges (approx 20% have 2+ misconfigs)
newComparisons += ASSET_COUNT * 2;
// Restricted → Restricted (lateral)
newComparisons += nodesByZone.restricted * 0.1 * nodesByZone.restricted; // Only 10% connect

console.log(`\n✅ NEW APPROACH (Zone-indexed):`);
console.log(`   Comparisons: ${newComparisons.toLocaleString()}`);
console.log(`   At 1μs per comparison: ${(newComparisons / 1_000_000).toFixed(2)} seconds`);
console.log(`   Improvement: ${(oldComparisons / newComparisons).toFixed(0)}× faster`);

// Estimated edges
const avgEdgesPerNode = 3; // Conservative estimate after filtering
const estimatedEdges = TOTAL_NODES * avgEdgesPerNode;
console.log(`\n   Estimated edges: ${estimatedEdges.toLocaleString()}`);

// PageRank complexity
console.log('\n' + '─'.repeat(80));
console.log('PAGERANK COMPLEXITY');
console.log('─'.repeat(80));

const pagerankIterations = 15;
const pagerankOps = pagerankIterations * estimatedEdges;
console.log(`\n   Iterations: ${pagerankIterations}`);
console.log(`   Operations: ${pagerankOps.toLocaleString()}`);
console.log(`   Estimated time: ${(pagerankOps / 10_000_000).toFixed(2)} seconds`);

// Path finding complexity
console.log('\n' + '─'.repeat(80));
console.log('PATH FINDING COMPLEXITY');
console.log('─'.repeat(80));

const entryPoints = Math.floor(TOTAL_NODES * 0.05 * zoneDistribution.dmz); // 5% of DMZ
const allTargets = Math.floor(TOTAL_NODES * 0.2); // 20% are critical

// OLD: All pairs
const oldPathSearches = entryPoints * allTargets;
console.log(`\n❌ OLD APPROACH (all pairs):`);
console.log(`   Entry points: ${entryPoints}`);
console.log(`   Targets: ${allTargets}`);
console.log(`   Dijkstra runs: ${oldPathSearches.toLocaleString()}`);
console.log(`   Time (1ms per Dijkstra): ${(oldPathSearches / 1000).toFixed(1)} seconds`);

// NEW: Limited pairs
const maxEntries = 50;
const maxTargets = 30;
const newPathSearches = maxEntries * maxTargets;
console.log(`\n✅ NEW APPROACH (bounded):`);
console.log(`   Limited entries: ${maxEntries}`);
console.log(`   Limited targets: ${maxTargets}`);
console.log(`   Dijkstra runs: ${newPathSearches.toLocaleString()}`);
console.log(`   Time (1ms per Dijkstra): ${(newPathSearches / 1000).toFixed(2)} seconds`);
console.log(`   Improvement: ${(oldPathSearches / newPathSearches).toFixed(0)}× faster`);

// LLM calls
console.log('\n' + '─'.repeat(80));
console.log('LLM EVALUATION (bounded)');
console.log('─'.repeat(80));

const maxLLMCandidates = 500;
const batchSize = 30;
const llmCalls = Math.ceil(maxLLMCandidates / batchSize);
const parallelLlmTime = 3; // seconds for parallel execution

console.log(`\n   Max candidates: ${maxLLMCandidates}`);
console.log(`   Batch size: ${batchSize}`);
console.log(`   LLM calls: ${llmCalls} (parallel)`);
console.log(`   Estimated time: ${parallelLlmTime} seconds`);

// Total time estimation
console.log('\n' + '═'.repeat(80));
console.log('TOTAL TIME ESTIMATION');
console.log('═'.repeat(80));

const nodeBuildTime = TOTAL_NODES / 100_000; // Very fast
const edgeCreateTime = newComparisons / 1_000_000;
const pagerankTime = pagerankOps / 10_000_000;
const pathTime = newPathSearches / 1000;
const llmTime = parallelLlmTime;
const totalTime = nodeBuildTime + edgeCreateTime + pagerankTime + pathTime + llmTime;

console.log(`\n⏱️ BREAKDOWN:`);
console.log(`   Node building: ${nodeBuildTime.toFixed(3)}s`);
console.log(`   Edge creation: ${edgeCreateTime.toFixed(2)}s`);
console.log(`   PageRank: ${pagerankTime.toFixed(2)}s`);
console.log(`   Path finding: ${pathTime.toFixed(2)}s`);
console.log(`   LLM evaluation: ${llmTime.toFixed(1)}s`);
console.log(`   ─────────────────────`);
console.log(`   TOTAL: ${totalTime.toFixed(1)} seconds`);

// Memory estimation
console.log('\n' + '─'.repeat(80));
console.log('MEMORY ESTIMATION');
console.log('─'.repeat(80));

const nodeSize = 500; // bytes per node
const edgeSize = 200; // bytes per edge
const nodeMemory = TOTAL_NODES * nodeSize;
const edgeMemory = estimatedEdges * edgeSize;
const totalMemory = nodeMemory + edgeMemory;

console.log(`\n   Nodes: ${(nodeMemory / 1_000_000).toFixed(1)} MB`);
console.log(`   Edges: ${(edgeMemory / 1_000_000).toFixed(1)} MB`);
console.log(`   Indices: ~${(TOTAL_NODES * 100 / 1_000_000).toFixed(1)} MB`);
console.log(`   Total: ${(totalMemory / 1_000_000).toFixed(1)} MB`);

// Final verdict
console.log('\n' + '═'.repeat(80));
console.log('SCALABILITY VERDICT');
console.log('═'.repeat(80));

if (totalTime < 60) {
  console.log(`\n✅ YES - Scales to 10,000 assets`);
  console.log(`   Estimated time: ${totalTime.toFixed(1)} seconds`);
  console.log(`   Memory: ${(totalMemory / 1_000_000).toFixed(0)} MB`);
} else {
  console.log(`\n⚠️ MARGINAL - May need optimization`);
  console.log(`   Estimated time: ${(totalTime / 60).toFixed(1)} minutes`);
}

console.log(`\n📋 KEY SCALABILITY IMPROVEMENTS:`);
console.log(`   1. Zone indexing: O(n²) → O(n × zone_size)`);
console.log(`   2. Bounded Dijkstra: unlimited → 1,500 pairs max`);
console.log(`   3. LLM batching: unbounded → 500 candidates / 17 calls`);
console.log(`   4. Memory-efficient indices: Map-based O(1) lookups`);
