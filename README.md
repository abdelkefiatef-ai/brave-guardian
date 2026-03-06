# 🛡️ Brave Guardian

**Enterprise Security Intelligence Platform** - Graph + AI Powered Vulnerability Analysis

## Overview

Brave Guardian is a cybersecurity infrastructure scanning platform that combines advanced **Graph Theory** algorithms with **intelligent security analysis** to discover attack paths, prioritize vulnerabilities, and provide actionable remediation recommendations.

## Features

### 🔍 Graph-Based Analysis
- **Multiplicative Bayesian Risk Scoring** - Non-linear combination of CVSS, EPSS, KEV, zone exposure
- **Privilege-Gated Graph Construction** - Probabilistic transition model with zone reachability matrix
- **Personalized PageRank (PPR)** - Forward PPR for attacker reachability, Reverse PPR for blast radius
- **Max-Product Belief Propagation** - Adversarial best-path modeling
- **Yen's K-Shortest Paths** - Deterministic optimal attack path discovery

### 🤖 Intelligent Security Analysis
- **Correlation Detection** - Identifies threat patterns across assets
- **Path Risk Scoring** - Multi-factor non-linear combination
- **Strategic Insights** - Prioritized remediation recommendations
- **Business Impact Analysis** - Revenue exposure and criticality weighting

### 📊 Enterprise Dashboard
- **Network Zone Distribution** - DMZ, Internal, Restricted, Airgap visibility
- **Kill Chain Mapping** - MITRE ATT&CK phase alignment
- **Risk Scoring** - Differentiated scores (0.5 - 10.0 scale)
- **Remediation Prioritization** - Effort vs. Impact analysis

## Algorithms

### Risk Score Computation (Multi-Factor)
```
Base Risk = Bayesian multiplicative model with:
  - CVSS^0.6 (diminishing returns at high end)
  - EPSS × (1-complexity) = true P(exploited)
  - KEV/ransomware multipliers (2.0×/1.5×)
  - Zone exposure (DMZ=1.8×, airgap=0.1×)

Final Risk = Entropy-weighted combination of:
  - Base Risk (~50%)
  - Forward PPR reachability (~15%)
  - Reverse PPR blast radius (~18%)
  - Belief propagation probability (~17%)
  + Cross-factor interaction terms
```

### Personalized PageRank
- Forward PPR: Seeds at internet-facing nodes → "Can attacker reach this?"
- Reverse PPR: Seeds at high-criticality targets → "How many paths converge here?"
- α = 0.15 teleportation, 100 iterations

### Belief Propagation
- Max-product algorithm for adversarial path modeling
- Attacker chooses best path, not average
- Damping factor 0.6 for stability

### Attack Path Discovery
- Yen's K-Shortest Paths algorithm
- Operates in -log(probability) space
- Wilson score confidence intervals
- Chain probability with FAIR retry model

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

## Project Structure

```
src/
├── app/
│   ├── page.tsx                    # Main dashboard with all algorithms
│   ├── layout.tsx                  # Root layout
│   ├── globals.css                 # Tailwind styles
│   └── api/
│       └── analyze-correlations/
│           └── route.ts            # Security analysis API
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Asset Data     │────▶│  Graph Engine   │────▶│  Risk Engine    │
│  (50 assets)    │     │  (Sparse Adj.)  │     │  (PPR + Belief  │
│                 │     │                 │     │   Propagation)  │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                                                         ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    Dashboard    │◀────│  Security       │◀────│  Attack Paths   │
│    (React)      │     │  Analysis       │     │  (Yen's K-Shortest)
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Vulnerability Database

Includes real-world CVEs:
- **CVE-2017-0144** (EternalBlue) - SMBv1 RCE, EPSS 0.97, KEV
- **CVE-2019-0708** (BlueKeep) - RDS RCE, EPSS 0.92, KEV
- **CVE-2021-44228** (Log4Shell) - JNDI RCE, EPSS 0.96, KEV
- Plus configuration issues (RDP/SMB exposed, Pass-the-Hash, Kerberoasting, etc.)

## Risk Score Differentiation

The sophisticated multi-factor algorithm produces differentiated scores:

| Path Type | Score Range |
|-----------|-------------|
| Critical (KEV + ransomware + internet-facing) | 8.0 - 9.0 |
| High (KEV + high blast radius) | 7.0 - 8.5 |
| Medium (non-KEV, DMZ) | 4.5 - 6.5 |
| Low (internal, no KEV) | 2.5 - 4.0 |

## Tech Stack

- **Next.js 16** with App Router
- **React 19** with TypeScript
- **Tailwind CSS 4** for styling
- **Bun** runtime

## License

MIT License

---

Built for enterprise security teams who need actionable vulnerability intelligence.
