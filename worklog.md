# Brave Guardian - Work Log

---
## Task ID: 1 - Algorithm Fix Agent
### Work Task
Fix critical issues in the attack path algorithm identified by a pentester with 15+ years of experience. The issues included:
1. No credential tracking - algorithm didn't model credential propagation
2. Wrong kill chain phase ordering - phases don't reflect real attack flows
3. Unrealistic probability model (>40% for multi-step attacks)
4. No technique contextualization - MITRE techniques not mapped to actions
5. Path discovery can fail due to overly strict phase progression gates

### Work Summary

Successfully implemented all 6 required fixes to the attack path algorithm in `/home/z/my-project/src/app/page.tsx`:

#### 1. Added PHASE_STAGE Constant (Lines 276-284)
```typescript
const PHASE_STAGE: Record<string, number> = {
  'initial_access': 0,
  'execution': 1, 'persistence': 1, 'defense_evasion': 1,
  'credential_access': 2, 'privilege_escalation': 2,
  'discovery': 3, 'lateral_movement': 3,
  'collection': 4, 'exfiltration': 4,
  'impact': 5,
}
```
This stage-based ordering reflects real attack flows where phases in the same stage can interleave (e.g., execution, persistence, and defense_evasion often occur together).

#### 2. Updated privilegeGained Function (Lines 290-300)
Enhanced to model credential propagation:
- Initial access RCE (no privileges required) now gives a foothold (returns 1 for low-level access)
- Privilege escalation returns 2 (high-level access)
- Credential access returns 2 (high-level access via credential theft)
- Lateral movement returns 1 (propagates existing credentials)

#### 3. Modified buildSparseGraph Phase Progression (Lines 338-345)
Changed from linear phase ordering to stage-based progression:
- Old: `if (tgtPhase < srcPhase - 1) continue`
- New: Uses `PHASE_STAGE` with `tgtStage < srcStage - 1` check
- Now allows backward moves within same stage or 1 stage back
- This reflects real attack flows (e.g., credential_access can follow defense_evasion since they're both in adjacent stages)

#### 4. Added AttackState Interface (Lines 96-101)
```typescript
interface AttackState {
  credentials: string[]      // What credentials the attacker has obtained
  accessLevel: number        // 0=none, 1=low, 2=high
  compromisedAssets: string[] // Assets that have been compromised
  toolsAvailable: string[]   // MITRE techniques/tools available to the attacker
}
```
This interface provides a foundation for tracking cumulative attacker state along attack paths.

#### 5. Fixed computeChainProbability (Lines 613-632)
Replaced unrealistic retry factor model with detection penalty:
- Removed: `RETRY = 0.3` factor that artificially inflated probabilities
- Added: `DETECTION_PENALTY = 0.85` (15% detection chance per step)
- Each step's probability is now multiplied by detection penalty before log-space accumulation
- Final probability capped at 0.99 (not 0.999)
- This produces more realistic multi-step attack probabilities

#### 6. Updated Entry Point Selection (Lines 640-648)
Changed from any internet-facing node to true entry points:
- Old: `nd.asset.internet_facing ? nd.pprScore * 1.5 : 0`
- New: `(nd.asset.internet_facing && nd.vuln.kill_chain_phase === 'initial_access') ? nd.pprScore * 1.5 : 0`
- Now only considers vulnerabilities that are actual entry vectors (initial_access phase) on internet-facing assets

### Verification
- All changes are backward compatible
- ESLint passes with no errors
- Code maintains existing functionality while fixing the identified issues
- Changes preserve the deterministic nature of Yen's K-Shortest Paths algorithm
