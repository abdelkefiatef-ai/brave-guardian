# 🛡️ Brave Guardian

**Enterprise Security Intelligence Platform** - Graph + AI Powered Vulnerability Analysis

## Overview

Brave Guardian is a cybersecurity infrastructure scanning platform that combines **Graph Theory** algorithms with **AI-powered analysis** to discover attack paths, prioritize vulnerabilities, and provide actionable remediation recommendations.

## Features

### 🔍 Graph-Based Analysis
- **Attack Graph Construction** - Sparse adjacency list representation (O(E) memory efficiency)
- **PageRank Computation** - Identifies central/important nodes in attack paths
- **Risk Propagation** - Dynamic risk diffusion across the attack graph
- **Attack Path Discovery** - Weighted random walk algorithm for realistic path finding

### 🤖 AI Intelligence
- **mistral:7b LLM Integration** - Local AI analysis (no cloud dependencies)
- **Per-Path Analysis** - Attack scenarios, business impact, and remediation for each path
- **Correlation Detection** - Identifies threat patterns across assets
- **Strategic Insights** - CISO-level security recommendations

### 📊 Enterprise Dashboard
- **Network Zone Distribution** - DMZ, Internal, Restricted, Airgap visibility
- **Kill Chain Mapping** - MITRE ATT&CK phase alignment
- **Risk Scoring** - CVSS + EPSS + KEV + Business Context
- **Remediation Prioritization** - Effort vs. Impact analysis

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

## Quick Start

```bash
# Install dependencies
bun install

# Start development server
bun run dev

# Build for production
bun run build
```

Open [http://localhost:3000](http://localhost:3000) to access the dashboard.

## Requirements

- **Ollama** with mistral:7b model for AI analysis
- **Bun** or **Node.js** runtime

### Setting up Ollama

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull mistral:7b model
ollama pull mistral:7b

# Start Ollama server
ollama serve
```

## Project Structure

```
src/
├── app/
│   ├── page.tsx                    # Main dashboard component
│   ├── layout.tsx                  # Root layout
│   ├── globals.css                 # Tailwind styles
│   └── api/
│       └── analyze-correlations/
│           └── route.ts            # LLM analysis API
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Asset Data     │────▶│  Graph Engine   │────▶│  Risk Engine    │
│  (50 assets)    │     │  (Sparse Adj.)  │     │  (PageRank +    │
│                 │     │                 │     │   Propagation)  │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                                                         ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    Dashboard    │◀────│  LLM Analysis   │◀────│  Attack Paths   │
│    (React)      │     │  (mistral:7b)   │     │  Discovery      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Vulnerability Database

Includes real-world CVEs:
- **CVE-2017-0144** (EternalBlue) - SMBv1 RCE
- **CVE-2019-0708** (BlueKeep) - RDS RCE
- **CVE-2021-44228** (Log4Shell) - JNDI RCE
- Plus configuration issues (RDP/SMB exposed, Pass-the-Hash, etc.)

## Configuration

Set environment variables:
```bash
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=mistral:7b
```

## License

MIT License

---

Built for enterprise security teams who need actionable vulnerability intelligence.
