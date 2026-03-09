# 🛡️ Brave Guardian

**Enterprise Security Intelligence Platform** - Advanced Attack Path Analysis with Multi-Source Data Fusion + Graph-Based Path Finding + LLM Validation

## Overview

Brave Guardian is a comprehensive cybersecurity attack path analysis platform that combines **multi-source data fusion** with **intelligent graph-based path discovery** to find realistic attack paths in enterprise environments with 500+ assets.

### Research-Based Enhancement

This platform integrates cutting-edge techniques from recent academic research (2024-2025):
- **SPEAR**: AI Planner + Hypergraphs for security posture evaluation
- **AEGIS**: LLM + MCTS for white-box attack path generation  
- **AttacKG+**: Automated LLM attack graph construction
- **Bayesian Attack Graphs**: Probabilistic inference for IoT/power systems
- **GNN**: Graph Neural Networks for attack prediction
- **ShotFlex**: RL + MCTS path planning

## Key Features

### 🔮 Multi-Source Data Fusion Engine

**Strategic integration of multiple data sources with confidence-weighted fusion:**

| Data Source | Confidence | Coverage | Purpose |
|-------------|------------|----------|---------|
| **Sidescan** | 0.95 (highest) | 40% | Validated attack paths from pentests/red team |
| **API Discovery** | 0.90 | 100% | CMDB, Cloud APIs, Virtualization, Active Directory |
| **Passive NetFlow** | 0.85 | 95% | Real-time topology from network flows |
| **Active Scan** | 0.70 | 60% | Targeted vulnerability scanning |

**Evidence Fusion Features:**
- **Dempster-Shafer Theory** - Handles conflicting evidence gracefully
- **Temporal Decay** - Reduces impact of stale evidence over time
- **Cross-Validation** - Boosts confidence when multiple sources agree
- **Edge Classification** - Validated → Discovered → Inferred → Hypothetical

### 🎯 Attack Path Discovery Algorithm

**Core Algorithm: Multi-Constraint Dijkstra with Dynamic Limits**

The attack path engine uses a sophisticated Dijkstra-based algorithm with multiple constraints to find realistic attack paths:

#### Edge Generation Rules

The algorithm generates edges between assets based on:

1. **Zone Transition Rules** - Valid zone transitions only:
   - `internet → dmz` (entry point)
   - `dmz → corp` (lateral movement)
   - `corp → mgmt` (privilege escalation)
   - `mgmt → restricted` (high-value target access)

2. **Tier Escalation** - No de-escalation allowed:
   ```
   Source Tier ≤ Target Tier (enforced)
   
   Tiers: workstation(0) → server(1) → critical(2)
   ```

3. **Terminal Asset Protection** - No edges FROM:
   - Domain Controllers
   - Identity Servers
   - Database Servers (acting as targets only)

4. **Attack Technique Mapping** - Edges tagged with MITRE techniques:
   - Initial Access: T1190 (Exploit Public-Facing App), T1566 (Phishing)
   - Lateral Movement: T1021 (Remote Services), T1550 (Use Alternate Auth)
   - Privilege Escalation: T1068 (Exploitation for Priv Esc)

#### Path Finding Algorithm

```typescript
// Core Dijkstra with Path Tracking
function dijkstra(
  graph: Map<string, Edge[]>,
  source: string,
  targets: Set<string>,
  maxNodes: number = 6
): Path[] {
  // Priority queue ordered by total risk (higher = better for attacker)
  // Track visited nodes to prevent cycles
  // Return all paths to any target within depth limit
}
```

**Path Filtering Criteria:**
- Minimum 3 nodes per path (entry → intermediate → target)
- Maximum 6 nodes per path (prevents unrealistic chains)
- No duplicate path sequences
- No de-escalation violations

#### Dynamic Limit Calculation

Limits are computed based on actual data distribution, not hard-coded values:

```typescript
const maxPerEntry = Math.ceil(maxPaths / numEntries)
const maxPerTarget = Math.ceil(maxPaths / numTargets)
const maxPerTargetType = Math.ceil(maxPaths / numTargetTypes)
const minPerTargetType = 1  // Guarantee representation
```

This ensures:
- Fair distribution across entry points
- Fair distribution across targets
- Minimum one path per critical target type (domain_controller, identity_server, pci_server)

#### Entry Point Discovery

Entry points are identified by:
1. **Internet-Facing Assets** - `internet_facing: true`
2. **DMZ Zone Assets** - Primary entry candidates
3. **Vulnerability Severity** - Critical/High vulnerabilities on external interfaces
4. **Exposed Services** - RDP, SSH, Web services accessible from internet

#### Target Identification

High-value targets are identified by:
1. **Asset Type** - domain_controller, identity_server, database_server, pci_server
2. **Criticality Score** - Assets with criticality ≥ 4
3. **Data Sensitivity** - Assets handling sensitive data
4. **Zone Location** - Assets in restricted/management zones

### 📊 Performance Results (500-Asset Simulation)

| Metric | Value |
|--------|-------|
| **Total Nodes** | 964 (assets + vulnerability nodes) |
| **Total Edges** | 228,880 |
| **Paths Found** | 10 (top attack paths) |
| **Unique Entries** | 3 (email servers, VPN gateways) |
| **Unique Targets** | 10 |
| **Target Types** | 3 (domain_controller, identity_server, pci_server) |
| **Coherence Score** | 88% |
| **Zone Transitions** | corp → mgmt → restricted |
| **Tier Escalation** | 100% correct (no violations) |

### 🤖 LLM Realism Engine

**Strategic LLM validation for path realism:**

- **Entry Point Validation** - Is this a realistic attacker entry?
- **Exit Point Validation** - Does this target have attacker value?
- **Path Realism Assessment** - Technical feasibility scoring
- **Attack Narrative Generation** - Human-readable attack stories

### 🚀 Scalable Scanner Architecture

- **Connection Pooling** - SSH ControlMaster reuse for efficient connections
- **Batched Commands** - Execute 20+ commands in a single SSH call
- **Adaptive Rate Limiting** - AIMD algorithm prevents network saturation
- **Result Caching** - Skip unchanged hosts for faster re-scans
- **Host Discovery** - Quick ping check (100ms vs 30s timeout)
- **Distributed Coordination** - Multi-node scanning with load balancing
- **Job State Management** - Persistent state for resume capability
- **Priority Queue** - Business impact-based scanning order

### 🔍 Zone Detection

- **CIDR-based** - Match IPs to network zones (DMZ/Internal/Restricted)
- **VLAN-based** - Identify zones from VLAN tags
- **Hostname Patterns** - Detect zones from naming conventions (dmz-, dc-, ws-)
- **Service Detection** - Infer zones from running services
- **Cloud Metadata** - AWS/Azure/GCP zone identification

### 🌐 Network Topology Collection

- **Identity Systems** - Active Directory users, groups, computers
- **Access Patterns** - SMB shares, RDP sessions, network connections
- **Trust Relationships** - Domain trusts, forest trusts
- **Service Discovery** - Running services, open ports, protocols

### 🎯 False Positive Reduction

- **Context Validation** - Checks if vulnerability applies to asset context
- **Service Verification** - Verifies vulnerable service is actually running
- **Compensating Controls** - Accounts for security mitigations
- **Temporal Correlation** - Cross-references findings over time
- **Confidence Scoring** - Probability-weighted results (2-4% FP rate with Bayesian)

### 📊 Enterprise Dashboard

- **5 Views**: Environment, Scanner, Analysis, Paths, Algorithm
- **Real-time Progress** - WebSocket/SSE streaming for scan updates
- **Network Zone Distribution** - DMZ, Internal, Restricted visualization
- **Kill Chain Mapping** - MITRE ATT&CK phase alignment
- **Remediation Prioritization** - Effort vs. Impact analysis

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          BRAVE GUARDIAN ARCHITECTURE v3.0                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                      LAYER 1: DATA COLLECTION                               ││
│  │  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐   ││
│  │  │ API Discovery │ │ Passive       │ │ Active Scan   │ │ Sidescan      │   ││
│  │  │ Conf: 0.90    │ │ NetFlow       │ │ Conf: 0.70    │ │ Conf: 0.95    │   ││
│  │  │ 100% Coverage │ │ Conf: 0.85    │ │ Targeted      │ │ Validated     │   ││
│  │  └───────┬───────┘ └───────┬───────┘ └───────┬───────┘ └───────┬───────┘   ││
│  │          │                 │                 │                 │           ││
│  │          └─────────────────┴─────────────────┴─────────────────┘           ││
│  │                                      │                                     ││
│  └──────────────────────────────────────┼─────────────────────────────────────┘│
│                                         ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                      LAYER 2: EVIDENCE FUSION                               ││
│  │  ┌───────────────────────────────────────────────────────────────────────┐  ││
│  │  │              Dempster-Shafer Evidence Combination                      │  ││
│  │  │  • Conflict Resolution  • Temporal Decay  • Cross-Validation          │  ││
│  │  └───────────────────────────────────────────────────────────────────────┘  ││
│  │                              │                                              ││
│  │  Edge Classification: Validated → Discovered → Inferred → Hypothetical     ││
│  └──────────────────────────────┼──────────────────────────────────────────────┘│
│                                 ▼                                                │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                      LAYER 3: ATTACK GRAPH ANALYSIS                         ││
│  │  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐   ││
│  │  │ Edge          │ │ Dijkstra      │ │ Dynamic       │ │ LLM           │   ││
│  │  │ Generation    │ │ Path Finding  │ │ Limits        │ │ Validation    │   ││
│  │  │ Zone/Tier     │ │ Multi-path    │ │ Data-driven   │ │ Realism       │   ││
│  │  │ Constraints   │ │ Discovery     │ │ Distribution  │ │ 90%+ accuracy │   ││
│  │  └───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘   ││
│  └──────────────────────────────┬──────────────────────────────────────────────┘│
│                                         ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                      LAYER 4: OUTPUT                                        ││
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   ││
│  │  │ Validated   │ │ Risk        │ │ Mitigation  │ │ Attack Narratives   │   ││
│  │  │ Attack Paths│ │ Metrics     │ │ Recommendations│                   │   ││
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────────────┘   ││
│  └─────────────────────────────────────────────────────────────────────────────┘│
│                                         │                                        │
│                                         ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                      PRESENTATION LAYER                                     ││
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐││
│  │  │Environment │ │  Scanner   │ │  Analysis  │ │   Paths    │ │   Algo     │││
│  │  │    View    │ │    View    │ │    View    │ │    View    │ │   View     │││
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘ └────────────┘││
│  └─────────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
src/
├── app/
│   ├── page.tsx                    # Main dashboard (5 views)
│   ├── layout.tsx                  # Root layout
│   ├── globals.css                 # Tailwind styles
│   └── api/
│       ├── attack-analysis/
│       │   └── route.ts            # Attack path analysis API
│       └── scanner/
│           └── route.ts            # Scanner REST API
│
├── lib/
│   └── scanners/
│       ├── multi-source-fusion-engine.ts   # Data source collectors + fusion
│       ├── fused-attack-engine.ts          # Complete pipeline integration
│       ├── enhanced-attack-engine.ts       # GNN + Bayesian + MCTS
│       ├── llm-realism-engine.ts           # LLM validation layer
│       ├── complete-hybrid-engine.ts       # Full 4-layer integration
│       ├── optimized-scanner.ts            # Batched SSH commands
│       ├── high-perf-scanner.ts            # Connection pooling, host discovery
│       ├── zone-detection.ts               # DMZ/Internal/Restricted classification
│       ├── network-topology-collector.ts   # Identity & access collection
│       ├── fp-reduction.ts                 # False positive reduction
│       │
│       └── scalable/
│           ├── scanner-orchestrator.ts     # Parallel scanning manager
│           ├── distributed-coordinator.ts  # Multi-node coordination
│           ├── result-streamer.ts          # WebSocket/SSE streaming
│           ├── job-state-manager.ts        # Persistent job state
│           ├── priority-queue.ts           # Business impact ordering
│           ├── adaptive-rate-limiter.ts    # AIMD rate control
│           └── scan-scheduler.ts           # Cron-based scheduling
```

## Algorithms

### Attack Path Discovery

#### Edge Generation Algorithm

```
For each pair of assets (source, target):
  1. Check zone transition validity
     - Valid: internet→dmz, dmz→corp, corp→mgmt, mgmt→restricted
     
  2. Check tier escalation
     - Allow: source.tier ≤ target.tier
     - Block: source.tier > target.tier (no de-escalation)
     
  3. Check terminal asset rule
     - Block edges FROM domain_controller, identity_server
     
  4. Generate edge with:
     - Attack techniques (MITRE ATT&CK mapping)
     - Risk score (CVSS + criticality + exposure)
     - Evidence confidence (multi-source fusion)
```

#### Path Finding Algorithm (Multi-Constraint Dijkstra)

```
function findAttackPaths(graph, entryPoints, targets, maxPaths):
  paths = []
  
  // Calculate dynamic limits based on data distribution
  maxPerEntry = ceil(maxPaths / numEntries)
  maxPerTarget = ceil(maxPaths / numTargets)
  maxPerTargetType = ceil(maxPaths / numTargetTypes)
  
  // Round-robin through entry points for fair distribution
  for each entry in entryPoints (round-robin):
    // Find paths to all targets
    entryPaths = dijkstra(graph, entry, targets, maxNodes=6)
    
    // Filter paths
    entryPaths = filter(entryPaths, path => 
      path.nodes.length >= 3 AND
      path.nodes.length <= 6 AND
      noTierDeEscalation(path)
    )
    
    // Apply limits per entry
    entryPaths = take(entryPaths, maxPerEntry)
    paths.extend(entryPaths)
    
  // Ensure target type representation
  paths = ensureTargetTypeCoverage(paths, minPerTargetType=1)
  
  return top(paths, maxPaths, sortBy=riskScore)
```

#### Dynamic Limit Calculation

```
// Data-driven limits (no hard-coded values)
maxPerEntry = max(1, ceil(maxPaths / numEntries))
maxPerTarget = max(1, ceil(maxPaths / numTargets))  
maxPerTargetType = max(2, ceil(maxPaths / numTargetTypes))
minPerTargetType = 1  // Guarantee at least 1 path per critical type

Example with 10 paths, 3 entries, 10 targets, 3 target types:
- maxPerEntry = 4 paths per entry point
- maxPerTarget = 1 path per target
- maxPerTargetType = 4 paths per target type
- minPerTargetType = 1 path minimum for each type
```

### Multi-Source Evidence Fusion

**Dempster-Shafer Combination:**
```
m(Exists) = confidence × probability
m(NotExists) = confidence × (1 - probability)
m(Uncertain) = 1 - confidence

K = 1 - m1(Exists) × m2(NotExists) - m1(NotExists) × m2(Exists)

Belief(Exists) = Σ (m_i(Exists) × m_j(Exists)) / K
```

**Temporal Decay:**
```
DecayFactor = 0.5^(age / halfLife)
AdjustedConfidence = OriginalConfidence × DecayFactor
```

### Risk Score Computation
```
Risk = √(VulnRisk × AssetRisk) × 10

VulnRisk = CVSS×0.35 + EPSS×0.25 + Complexity×0.20 + ThreatBoost×0.20
AssetRisk = Criticality×0.5 + Exposure×0.5
```

### Coherence Score Calculation

The coherence score evaluates path quality:

```
Coherence = (ZoneTransitions + TierEscalation + EntryValidity + TargetValidity + TechniqueMatch) / 5

Where:
- ZoneTransitions: Are zone hops realistic? (0-100%)
- TierEscalation: No de-escalation violations? (0-100%)
- EntryValidity: Is the entry point internet-facing? (0-100%)
- TargetValidity: Is the target high-value? (0-100%)
- TechniqueMatch: Do techniques match the path? (0-100%)
```

## Performance Metrics

| Metric | Value |
|--------|-------|
| **Scalability** | 500+ assets tested, designed for 100K+ |
| **Path Discovery** | 10 paths in ~9 seconds |
| **Graph Size** | 964 nodes, 228,880 edges |
| **Coherence Score** | 88% average path quality |
| **Zone Accuracy** | 100% correct transitions |
| **Tier Enforcement** | 100% (no de-escalation violations) |

## Quick Start

```bash
# Install dependencies
bun install

# Start development server
bun run dev
```

Open [http://localhost:3000](http://localhost:3000) to access the dashboard.

## Usage Examples

### Complete Multi-Source Analysis

```typescript
import { FusedAttackEngine } from '@/lib/scanners'

const engine = new FusedAttackEngine({
  sources: {
    api_discovery: { enabled: true },
    passive_netflow: { enabled: true },
    active_scan: { enabled: true, targets: ['10.0.0.0/24'] },
    sidescan: { enabled: true }
  },
  fusion: {
    conflictResolution: 'dempster_shafer',
    temporalDecay: true,
    crossValidation: true,
    minSourcesForValidation: 2
  },
  attackGraph: {
    maxPaths: 15,
    maxDepth: 8,
    llmValidation: true
  }
})

const result = await engine.analyze()

console.log(`Discovered ${result.collection.assetsDiscovered} assets`)
console.log(`Generated ${result.attackPaths.length} validated attack paths`)
console.log(`Overall risk score: ${result.riskMetrics.overallRiskScore}`)
```

### Attack Path Analysis API

```typescript
// POST /api/attack-analysis
const response = await fetch('/api/attack-analysis', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    environment: {
      assets: [
        {
          id: 'asset-1',
          name: 'WEB-001',
          type: 'web_server',
          ip: '10.0.0.10',
          zone: 'dmz',
          internet_facing: true,
          criticality: 4,
          tier: 1,
          misconfigurations: [
            { id: 'M001', title: 'RDP Exposed', severity: 'critical' }
          ]
        }
      ]
    }
  })
})

const { attackPaths, riskMetrics, coherenceScore } = await response.json()
```

## API Endpoints

### Attack Analysis
```bash
POST /api/attack-analysis
Content-Type: application/json

{
  "environment": {
    "assets": [
      {
        "id": "asset-1",
        "name": "WEB-001",
        "type": "web_server",
        "ip": "10.0.0.10",
        "zone": "dmz",
        "internet_facing": true,
        "criticality": 4,
        "misconfigurations": [...],
        "evidence": {...}
      }
    ]
  }
}
```

### Scanner
```bash
# Start scan
POST /api/scanner
{
  "action": "scan",
  "targets": [{ "id": "1", "host": "10.0.0.1" }]
}

# Check status
GET /api/scanner?jobId=job-xxx
```

## Configuration

Environment variables:
```bash
# Optional - for LLM-enhanced analysis
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=mistral:7b

# Multi-source collection
CMDB_API_URL=https://servicenow.company.com/api
NETFLOW_COLLECTOR=192.168.1.100:2055
SIDESCAN_DATA_PATH=/data/validated-paths
```

## Technology Stack

- **Frontend**: Next.js 15, React 19, Tailwind CSS
- **Backend**: Next.js API Routes
- **Graph Algorithm**: Multi-constraint Dijkstra with dynamic limits
- **AI/ML**: z-ai-web-dev-sdk for LLM integration
- **Evidence Fusion**: Dempster-Shafer theory implementation
- **Runtime**: Bun

## Research References

This platform incorporates techniques from recent academic research:

1. **SPEAR (2025)** - AI Planner + Hypergraphs for security posture evaluation
2. **AEGIS (2026)** - LLM + MCTS for white-box attack path generation
3. **AttacKG+ (2024)** - Automated LLM attack graph construction (52 citations)
4. **Bayesian Attack Graphs** - Probabilistic inference for IoT/power systems
5. **GNN for Cybersecurity** - Graph Neural Networks for attack prediction
6. **ShotFlex** - RL + MCTS flexible path planning

## License

MIT License

---

**Version 3.1.0** - Built for enterprise security teams who need actionable vulnerability intelligence at scale with intelligent attack path discovery.
