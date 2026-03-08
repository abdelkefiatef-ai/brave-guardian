# 🛡️ Brave Guardian

**Enterprise Security Intelligence Platform** - Scalable Hybrid Attack Path Analysis with Graph Theory + AI

## Overview

Brave Guardian is a comprehensive cybersecurity infrastructure scanning and attack path analysis platform. It combines **scalable multi-threaded scanning** with **hybrid Graph + AI analysis** to discover attack paths, prioritize vulnerabilities, and provide actionable remediation recommendations.

## Key Features

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

### 🔬 Hybrid Attack Graph Analysis
- **Pattern-Based Edges** - Instant edge creation from known attack patterns
- **LLM-Enhanced Edges** - AI analysis for non-obvious attack paths
- **PageRank Computation** - Identifies critical nodes in attack paths
- **Risk Propagation** - Dynamic risk diffusion across the graph
- **Path Discovery** - Weighted random walk for realistic attack scenarios

### 🎯 False Positive Reduction
- **Context Validation** - Checks if vulnerability applies to asset context
- **Service Verification** - Verifies vulnerable service is actually running
- **Compensating Controls** - Accounts for security mitigations
- **Temporal Correlation** - Cross-references findings over time
- **Confidence Scoring** - Probability-weighted results (5-10% FP rate)

### 📊 Enterprise Dashboard
- **5 Views**: Environment, Scanner, Analysis, Paths, Algorithm
- **Real-time Progress** - WebSocket/SSE streaming for scan updates
- **Network Zone Distribution** - DMZ, Internal, Restricted visualization
- **Kill Chain Mapping** - MITRE ATT&CK phase alignment
- **Remediation Prioritization** - Effort vs. Impact analysis

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           BRAVE GUARDIAN ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐    ┌─────────────────────────────────────────────────────┐ │
│  │   Target    │───▶│              SCANNER LAYER                          │ │
│  │   Assets    │    │  ┌───────────┐ ┌───────────┐ ┌───────────────────┐  │ │
│  │  (10K+)     │    │  │ Optimized │ │ High-Perf │ │  Distributed      │  │ │
│  └─────────────┘    │  │ Scanner   │ │ Scanner   │ │  Coordinator      │  │ │
│                     │  └─────┬─────┘ └─────┬─────┘ └─────────┬─────────┘  │ │
│                     │        │             │                 │             │ │
│                     │        └─────────────┴─────────────────┘             │ │
│                     │                      │                               │ │
│                     └──────────────────────┼───────────────────────────────┘ │
│                                            ▼                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                    ANALYSIS LAYER                                        ││
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ ││
│  │  │    Zone      │  │  Network     │  │     FP       │  │   Attack    │ ││
│  │  │  Detection   │  │  Topology    │  │  Reduction   │  │   Graph     │ ││
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ ││
│  │         │                 │                 │                 │        ││
│  │         └─────────────────┴─────────────────┴─────────────────┘        ││
│  │                                    │                                   ││
│  │                                    ▼                                   ││
│  │  ┌──────────────────────────────────────────────────────────────────┐  ││
│  │  │              HYBRID ATTACK GRAPH ENGINE                           │  ││
│  │  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐  │  ││
│  │  │  │ Pattern Edges  │  │   LLM Edges    │  │  Risk Computation  │  │  ││
│  │  │  │   (Instant)    │  │ (Batch/Async)  │  │ PageRank + Prop.   │  │  ││
│  │  │  └────────────────┘  └────────────────┘  └────────────────────┘  │  ││
│  │  └──────────────────────────────────────────────────────────────────┘  ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                            │                                 │
│                                            ▼                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                         PRESENTATION LAYER                               ││
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────┐││
│  │  │Environment │ │  Scanner   │ │  Analysis  │ │   Paths    │ │  Algo  │││
│  │  │    View    │ │    View    │ │    View    │ │    View    │ │  View  │││
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘ └────────┘││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
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
│       │   └── route.ts            # Hybrid attack graph API
│       └── scanner/
│           └── route.ts            # Scanner REST API
│
├── lib/
│   └── scanners/
│       ├── optimized-scanner.ts    # Batched SSH commands
│       ├── high-perf-scanner.ts    # Connection pooling, host discovery
│       ├── zone-detection.ts       # DMZ/Internal/Restricted classification
│       ├── network-topology-collector.ts  # Identity & access collection
│       ├── fp-reduction.ts         # False positive reduction
│       │
│       └── scalable/
│           ├── scanner-orchestrator.ts    # Parallel scanning manager
│           ├── distributed-coordinator.ts  # Multi-node coordination
│           ├── result-streamer.ts          # WebSocket/SSE streaming
│           ├── job-state-manager.ts        # Persistent job state
│           ├── priority-queue.ts           # Business impact ordering
│           ├── adaptive-rate-limiter.ts    # AIMD rate control
│           └── scan-scheduler.ts           # Cron-based scheduling
```

## Algorithms

### Risk Score Computation
```
Risk = √(VulnRisk × AssetRisk) × 10

VulnRisk = CVSS×0.35 + EPSS×0.25 + Complexity×0.20 + ThreatBoost×0.20
AssetRisk = Criticality×0.5 + Exposure×0.5
```

### PageRank (Node Importance)
- Power iteration with d=0.85 damping factor
- 20 iterations for convergence
- Weighted by attack graph edges

### Risk Propagation
- 5 iterations of diffusion
- 70% inherent risk + 30% propagated from predecessors
- Amplifies risk along attack chains

### Attack Path Discovery
- Entry points: Internet-facing vulnerabilities
- Targets: High-criticality assets
- Weighted random walk (max 6 steps)
- Returns top 10 paths by risk score

### Hybrid Edge Creation
1. **Pattern Edges** - Instant creation from known attack patterns:
   - Lateral movement via SMB/RDP
   - Credential theft (Mimikatz, LSASS)
   - Privilege escalation paths
   - Domain dominance techniques

2. **LLM Edges** - AI analysis for non-obvious paths:
   - Multi-hop reasoning
   - Context-aware probability
   - Novel attack vectors

## Performance

| Metric | Value |
|--------|-------|
| Scanning Rate | 50-100 hosts/second |
| Graph Construction | 1000 nodes/second |
| Path Discovery | 10 paths in <500ms |
| Memory Efficiency | O(E) sparse adjacency |
| False Positive Rate | 5-10% |

## Quick Start

```bash
# Install dependencies
bun install

# Start development server
bun run dev
```

Open [http://localhost:3000](http://localhost:3000) to access the dashboard.

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
        "misconfigurations": [...]
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

## Misconfiguration Database

Includes real-world CVEs and configuration issues:
- **CVE-2017-0144** (EternalBlue) - SMBv1 RCE
- **CVE-2019-0708** (BlueKeep) - RDS RCE
- **CVE-2021-44228** (Log4Shell) - JNDI RCE
- **Network** - RDP/SMB exposed, weak firewall rules
- **Authentication** - Weak passwords, Kerberos issues
- **Authorization** - Excessive rights, delegation issues
- **Service** - AV disabled, unquoted service paths

## Configuration

Environment variables:
```bash
# Optional - for LLM-enhanced analysis
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=mistral:7b
```

## Technology Stack

- **Frontend**: Next.js 15, React 19, Tailwind CSS
- **Backend**: Next.js API Routes
- **Graph**: Custom sparse adjacency implementation
- **AI**: z-ai-web-dev-sdk for LLM integration
- **Runtime**: Bun

## License

MIT License

---

Built for enterprise security teams who need actionable vulnerability intelligence at scale.
