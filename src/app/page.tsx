'use client'

import { useState, useCallback, useMemo, useEffect } from 'react'

// ============================================================================
// TYPES
// ============================================================================

interface Misconfiguration {
  id: string
  title: string
  description: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  evidence: string
  remediation: string
}

interface Asset {
  id: string
  name: string
  type: string
  ip: string
  network_zone: string
  criticality: number
  internet_facing: boolean
  business_unit: string
  annual_revenue_exposure: number
  misconfigurations: Misconfiguration[]
  domain_joined?: boolean
  services?: string[]
  data_sensitivity?: string
  scanStatus?: 'pending' | 'scanning' | 'completed' | 'failed'
}

interface ScanJob {
  id: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  progress: number
  targetCount: number
  resultCount: number
  startTime: number
  endTime?: number
  summary?: {
    totalTargets: number
    scannedTargets: number
    successCount: number
    failedCount: number
    totalMisconfigurations: number
    criticalCount: number
    highCount: number
    mediumCount: number
    lowCount: number
  }
}

interface AttackNode {
  id: string
  asset_id: string
  asset_name: string
  asset_type: string
  asset_zone: string
  misconfig_id: string
  misconfig_title: string
  misconfig_category: string
  criticality: number
  internet_facing: boolean
  data_sensitivity: string
}

interface AttackEdge {
  source_id: string
  target_id: string
  probability: number
  technique: string
  credentials_carried: string[]
  reasoning: string
  edge_type: 'pattern' | 'llm'
}

interface AttackPath {
  path_id: string
  nodes: AttackNode[]
  edges: AttackEdge[]
  path_probability: number
  pagerank_score: number
  impact_score: number
  realism_score: number
  detection_risk: number
  final_risk_score: number
  narrative: string
  business_impact: string
  kill_chain: string[]
}

interface AnalysisResult {
  graph_stats: {
    total_nodes: number
    total_edges: number
    avg_branching_factor: number | string
  }
  edge_stats: {
    pattern_edges: number
    llm_edges: number
    total_edges: number
    candidates_evaluated?: number
  }
  entry_points: Array<{
    node_id: string
    asset_name: string
    misconfig_title: string
    reasoning: string
    attacker_value: string
    pagerank_score: number
  }>
  attack_paths: AttackPath[]
  critical_assets: Array<{
    asset_id: string
    asset_name: string
    reason: string
    paths_to_it: number
  }>
  key_insights: string[]
  timing: {
    nodes: number
    edges: number
    pagerank: number
    paths: number
    validation: number
    entry_analysis: number
    total: number
  }
}

// ============================================================================
// MISCONFIGURATION DATABASE
// ============================================================================

const MISCONFIG_DB: Misconfiguration[] = [
  { id: 'M001', title: 'RDP Accessible from Internet', description: 'RDP port 3389 open to internet', category: 'network', severity: 'critical', evidence: 'Port scan', remediation: 'Block RDP at firewall' },
  { id: 'M002', title: 'SMBv1 Protocol Active', description: 'Legacy SMB enabled', category: 'network', severity: 'critical', evidence: 'SMB scan', remediation: 'Disable SMBv1' },
  { id: 'M003', title: 'SMB Signing Not Required', description: 'SMB relay possible', category: 'network', severity: 'high', evidence: 'SMB audit', remediation: 'Enable SMB signing' },
  { id: 'M004', title: 'WinRM Over HTTP', description: 'Unencrypted WinRM', category: 'network', severity: 'high', evidence: 'WinRM config', remediation: 'Enable HTTPS' },
  { id: 'M005', title: 'LDAP Signing Disabled', description: 'LDAP interception', category: 'network', severity: 'high', evidence: 'LDAP audit', remediation: 'Enable LDAP signing' },
  { id: 'M010', title: 'Weak Password Policy', description: '8 char minimum', category: 'authentication', severity: 'medium', evidence: 'GPO review', remediation: 'Increase complexity' },
  { id: 'M011', title: 'Stale Service Account', description: '90+ day old password', category: 'authentication', severity: 'high', evidence: 'AD audit', remediation: 'Rotate passwords' },
  { id: 'M012', title: 'Kerberos Pre-Auth Disabled', description: 'AS-REP roastable', category: 'authentication', severity: 'critical', evidence: 'AD enum', remediation: 'Enable pre-auth' },
  { id: 'M013', title: 'Shared Local Admin', description: 'Same password across systems', category: 'authentication', severity: 'critical', evidence: 'Cred audit', remediation: 'Use LAPS' },
  { id: 'M020', title: 'Domain Users Local Admin', description: 'Excessive rights', category: 'authorization', severity: 'high', evidence: 'Group audit', remediation: 'Remove from admins' },
  { id: 'M022', title: 'DCSync Rights', description: 'Replication rights to non-DA', category: 'authorization', severity: 'critical', evidence: 'ACL analysis', remediation: 'Remove rights' },
  { id: 'M023', title: 'Unconstrained Delegation', description: 'Kerberos delegation enabled', category: 'authorization', severity: 'critical', evidence: 'AD audit', remediation: 'Constrain delegation' },
  { id: 'M030', title: 'AV Not Running', description: 'Antivirus disabled', category: 'service', severity: 'high', evidence: 'Service check', remediation: 'Enable AV' },
  { id: 'M031', title: 'Unquoted Service Path', description: 'Service path vulnerability', category: 'service', severity: 'high', evidence: 'Service enum', remediation: 'Quote service path' },
  { id: 'M040', title: 'BitLocker Not Enabled', description: 'No disk encryption', category: 'encryption', severity: 'medium', evidence: 'BitLocker status', remediation: 'Enable BitLocker' },
  { id: 'M050', title: 'Command Line Logging Disabled', description: 'No process logging', category: 'logging', severity: 'medium', evidence: 'Audit policy', remediation: 'Enable logging' },
]

// ============================================================================
// ASSET GENERATION
// ============================================================================

const generateAssets = (): Asset[] => {
  const assetTypes = [
    { type: 'domain_controller', zone: 'restricted', criticality: 5, domain_joined: true, services: ['AD', 'DNS'], data_sensitivity: 'credentials' },
    { type: 'file_server', zone: 'internal', criticality: 4, domain_joined: true, services: ['SMB'], data_sensitivity: 'user_files' },
    { type: 'web_server', zone: 'dmz', criticality: 4, domain_joined: false, services: ['IIS'], data_sensitivity: 'app_data' },
    { type: 'database_server', zone: 'restricted', criticality: 5, domain_joined: true, services: ['SQL'], data_sensitivity: 'pii' },
    { type: 'app_server', zone: 'internal', criticality: 3, domain_joined: true, services: ['App'], data_sensitivity: 'business_logic' },
    { type: 'workstation', zone: 'internal', criticality: 2, domain_joined: true, services: ['Office'], data_sensitivity: 'user_data' },
    { type: 'jump_server', zone: 'dmz', criticality: 4, domain_joined: true, services: ['RDP'], data_sensitivity: 'credentials' },
    { type: 'email_server', zone: 'internal', criticality: 4, domain_joined: true, services: ['Exchange'], data_sensitivity: 'emails' },
    { type: 'backup_server', zone: 'restricted', criticality: 5, domain_joined: true, services: ['Backup'], data_sensitivity: 'backups' },
  ]

  const businessUnits = ['Finance', 'Engineering', 'Operations', 'HR', 'IT', 'Sales']
  let seed = 12345
  const random = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff }

  const assets: Asset[] = []
  for (let i = 0; i < 50; i++) {
    const template = assetTypes[Math.floor(random() * assetTypes.length)]
    const internetFacing = template.zone === 'dmz' || (template.zone === 'internal' && random() > 0.92)

    const relevantCats = template.type === 'domain_controller' ? ['authentication', 'authorization', 'network'] :
      template.type === 'web_server' ? ['network', 'service'] :
      template.type === 'database_server' ? ['authentication', 'authorization'] :
      ['authentication', 'service', 'network']

    const relevant = MISCONFIG_DB.filter(m => relevantCats.includes(m.category))
    const numMisconfigs = Math.floor(random() * 2) + 1
    const selected: Misconfiguration[] = []

    for (let j = 0; j < numMisconfigs; j++) {
      const m = relevant[Math.floor(random() * relevant.length)]
      if (!selected.find(s => s.id === m.id)) selected.push({ ...m })
    }

    assets.push({
      id: `asset-${i + 1}`,
      name: `${template.type.substring(0, 3).toUpperCase()}-${String(i + 1).padStart(3, '0')}`,
      type: template.type,
      ip: `10.${Math.floor(random() * 3) + 1}.${Math.floor(random() * 255)}.${Math.floor(random() * 255)}`,
      network_zone: template.zone,
      criticality: template.criticality,
      internet_facing: internetFacing,
      business_unit: businessUnits[Math.floor(random() * businessUnits.length)],
      annual_revenue_exposure: Math.floor(random() * 10000000) + 100000,
      misconfigurations: selected,
      domain_joined: template.domain_joined,
      services: template.services,
      data_sensitivity: template.data_sensitivity,
      scanStatus: 'pending',
    })
  }

  return assets
}

const INITIAL_ASSETS = generateAssets()

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function BraveGuardian() {
  const [assets, setAssets] = useState<Asset[]>(INITIAL_ASSETS)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState('')
  const [view, setView] = useState<'env' | 'scan' | 'analysis' | 'paths' | 'algo'>('env')
  const [selectedPath, setSelectedPath] = useState<number | null>(null)
  
  // Scanner state
  const [scanJob, setScanJob] = useState<ScanJob | null>(null)
  const [scanLoading, setScanLoading] = useState(false)
  const [scanResults, setScanResults] = useState<Array<{ host: string; misconfigurations: number; success: boolean }>>([])

  // Attack Analysis
  const runAnalysis = useCallback(async () => {
    setLoading(true)
    setResult(null)
    setStatus('Building attack graph...')

    try {
      const response = await fetch('/api/attack-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          environment: {
            assets: assets.map(a => ({
              id: a.id,
              name: a.name,
              type: a.type,
              ip: a.ip,
              zone: a.network_zone,
              internet_facing: a.internet_facing,
              criticality: a.criticality,
              domain_joined: a.domain_joined,
              services: a.services,
              data_sensitivity: a.data_sensitivity,
              misconfigurations: a.misconfigurations.map(m => ({
                id: m.id,
                title: m.title,
                description: m.description,
                category: m.category
              }))
            }))
          }
        })
      })

      if (response.ok) {
        const data = await response.json()
        setResult(data)
      } else {
        setStatus('Analysis failed')
      }
    } catch (e) {
      console.error(e)
      setStatus('Error during analysis')
    }

    setLoading(false)
    setStatus('')
  }, [assets])

  // Scanner
  const runScan = useCallback(async () => {
    setScanLoading(true)
    setScanResults([])
    setAssets(prev => prev.map(a => ({ ...a, scanStatus: 'pending' as const })))

    try {
      // Start scan
      const startResponse = await fetch('/api/scanner', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'scan',
          targets: assets.map(a => ({
            id: a.id,
            host: a.ip,
            ip: a.ip,
            hostname: a.name,
            criticality: a.criticality,
            internetFacing: a.internet_facing,
            zone: a.network_zone,
          })),
          options: { priority: 'medium' }
        })
      })

      if (startResponse.ok) {
        const { jobId } = await startResponse.json()
        
        // Poll for results
        let completed = false
        while (!completed) {
          await new Promise(r => setTimeout(r, 500))
          
          const statusResponse = await fetch(`/api/scanner?jobId=${jobId}`)
          if (statusResponse.ok) {
            const { job } = await statusResponse.json()
            setScanJob(job)
            
            if (job.status === 'completed' || job.status === 'failed') {
              completed = true
              
              // Update assets with scan results
              setAssets(prev => prev.map(a => ({ ...a, scanStatus: 'completed' as const })))
              
              // Set scan results
              setScanResults(job.results?.map((r: any) => ({
                host: r.host,
                misconfigurations: r.misconfigurations?.length || 0,
                success: r.success
              })) || [])
            }
          }
        }
      }
    } catch (e) {
      console.error(e)
    }

    setScanLoading(false)
  }, [assets])

  // Poll scan status
  useEffect(() => {
    if (scanJob && scanJob.status === 'running') {
      const interval = setInterval(async () => {
        const response = await fetch(`/api/scanner?jobId=${scanJob.id}`)
        if (response.ok) {
          const { job } = await response.json()
          setScanJob(job)
          if (job.status !== 'running') {
            clearInterval(interval)
          }
        }
      }, 1000)
      return () => clearInterval(interval)
    }
  }, [scanJob])

  const stats = useMemo(() => {
    const totalMisconfigs = assets.reduce((s, a) => s + a.misconfigurations.length, 0)
    const byCat: Record<string, number> = {}
    const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
    
    assets.forEach(a => a.misconfigurations.forEach(m => {
      byCat[m.category] = (byCat[m.category] || 0) + 1
      bySeverity[m.severity] = (bySeverity[m.severity] || 0) + 1
    }))
    
    return { totalAssets: assets.length, totalMisconfigs, byCat, bySeverity }
  }, [assets])

  return (
    <div className="min-h-screen bg-slate-900 text-white">
      {/* Header */}
      <header className="bg-slate-800 border-b border-slate-700 sticky top-0 z-50">
        <div className="max-w-[1600px] mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-8">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-red-600 to-orange-600 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <div>
                <h1 className="text-lg font-bold">Brave Guardian</h1>
                <p className="text-xs text-slate-400">Scalable Hybrid Attack Analysis</p>
              </div>
            </div>

            <nav className="flex gap-1">
              {(['env', 'scan', 'analysis', 'paths', 'algo'] as const).map(v => (
                <button
                  key={v}
                  onClick={() => setView(v)}
                  className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                    view === v ? 'bg-red-600 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-700'
                  }`}
                >
                  {v === 'env' ? 'Environment' : v === 'scan' ? 'Scanner' : v === 'analysis' ? 'Analysis' : v === 'paths' ? 'Paths' : 'Algorithm'}
                </button>
              ))}
            </nav>
          </div>

          <div className="flex gap-3">
            <button
              onClick={runScan}
              disabled={scanLoading}
              className={`px-5 py-2.5 rounded-lg font-medium text-sm flex items-center gap-2 ${
                scanLoading ? 'bg-slate-700 text-slate-400 cursor-not-allowed' : 'bg-blue-600 text-white hover:bg-blue-700'
              }`}
            >
              {scanLoading ? (
                <>
                  <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Scanning...
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                  Run Scan
                </>
              )}
            </button>
            
            <button
              onClick={runAnalysis}
              disabled={loading}
              className={`px-6 py-2.5 rounded-lg font-medium text-sm flex items-center gap-2 ${
                loading ? 'bg-slate-700 text-slate-400 cursor-not-allowed' : 'bg-red-600 text-white hover:bg-red-700'
              }`}
            >
              {loading ? (
                <>
                  <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Analyzing...
                </>
              ) : 'Run Attack Analysis'}
            </button>
          </div>
        </div>
      </header>

      {status && (
        <div className="bg-slate-800 border-b border-slate-700 px-6 py-2">
          <div className="max-w-[1600px] mx-auto flex items-center gap-3">
            <svg className="w-4 h-4 text-red-500 animate-pulse" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            <span className="text-sm text-slate-300">{status}</span>
          </div>
        </div>
      )}

      <main className="max-w-[1600px] mx-auto px-6 py-8">
        {/* Environment View */}
        {view === 'env' && (
          <div className="space-y-6">
            <div className="grid grid-cols-5 gap-4">
              <StatCard label="Total Assets" value={stats.totalAssets} />
              <StatCard label="Misconfigurations" value={stats.totalMisconfigs} />
              <StatCard label="Critical" value={stats.bySeverity.critical} color="red" />
              <StatCard label="High" value={stats.bySeverity.high} color="orange" />
              <StatCard label="Internet-Exposed" value={assets.filter(a => a.internet_facing).length} color="yellow" />
            </div>

            {/* Zone Distribution */}
            <div className="grid grid-cols-4 gap-4">
              {['dmz', 'internal', 'restricted'].map(zone => {
                const zoneAssets = assets.filter(a => a.network_zone === zone)
                return (
                  <div key={zone} className={`bg-slate-800 rounded-xl p-4 border ${
                    zone === 'dmz' ? 'border-red-500/50' :
                    zone === 'restricted' ? 'border-yellow-500/50' :
                    'border-slate-700'
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-slate-400 uppercase">{zone} Zone</span>
                      <span className="text-xs px-2 py-0.5 bg-slate-700 rounded">{zoneAssets.length} assets</span>
                    </div>
                    <div className="text-2xl font-bold">
                      {zoneAssets.reduce((s, a) => s + a.misconfigurations.length, 0)}
                    </div>
                    <div className="text-xs text-slate-400">misconfigurations</div>
                  </div>
                )
              })}
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <div className="text-sm text-slate-400 mb-2">By Category</div>
                <div className="space-y-1">
                  {Object.entries(stats.byCat).map(([cat, count]) => (
                    <div key={cat} className="flex justify-between text-xs">
                      <span className="text-slate-400 capitalize">{cat}</span>
                      <span className="text-white">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Asset Table */}
            <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
              <div className="p-4 border-b border-slate-700 font-semibold">Environment Assets</div>
              <div className="overflow-x-auto max-h-[500px]">
                <table className="w-full text-sm">
                  <thead className="bg-slate-700/50 sticky top-0">
                    <tr>
                      <th className="text-left p-3 text-slate-400">Asset</th>
                      <th className="text-left p-3 text-slate-400">Type</th>
                      <th className="text-left p-3 text-slate-400">Zone</th>
                      <th className="text-left p-3 text-slate-400">IP</th>
                      <th className="text-left p-3 text-slate-400">Criticality</th>
                      <th className="text-left p-3 text-slate-400">Misconfigs</th>
                      <th className="text-left p-3 text-slate-400">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700">
                    {assets.map(asset => (
                      <tr key={asset.id} className="hover:bg-slate-700/30">
                        <td className="p-3 font-medium">{asset.name}</td>
                        <td className="p-3 text-slate-400 capitalize">{asset.type.replace(/_/g, ' ')}</td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded text-xs ${
                            asset.network_zone === 'dmz' ? 'bg-red-900/50 text-red-300' :
                            asset.network_zone === 'restricted' ? 'bg-yellow-900/50 text-yellow-300' :
                            'bg-slate-700 text-slate-300'
                          }`}>{asset.network_zone}</span>
                        </td>
                        <td className="p-3 text-slate-400 font-mono text-xs">{asset.ip}</td>
                        <td className="p-3">
                          <div className="flex gap-1">
                            {[1,2,3,4,5].map(i => (
                              <div key={i} className={`w-2 h-2 rounded-full ${i <= asset.criticality ? 'bg-red-500' : 'bg-slate-600'}`} />
                            ))}
                          </div>
                        </td>
                        <td className="p-3">
                          <span className="px-2 py-0.5 bg-orange-900/50 text-orange-300 rounded text-xs">
                            {asset.misconfigurations.length}
                          </span>
                        </td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded text-xs ${
                            asset.scanStatus === 'completed' ? 'bg-green-900/50 text-green-300' :
                            asset.scanStatus === 'scanning' ? 'bg-blue-900/50 text-blue-300' :
                            'bg-slate-700 text-slate-400'
                          }`}>
                            {asset.scanStatus || 'pending'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* Scanner View */}
        {view === 'scan' && (
          <div className="space-y-6">
            {/* Scanner Stats */}
            <div className="grid grid-cols-4 gap-4">
              <StatCard 
                label="Scan Status" 
                value={scanJob?.status || 'idle'} 
                color={scanJob?.status === 'completed' ? 'green' : scanJob?.status === 'running' ? 'blue' : 'white'} 
              />
              <StatCard 
                label="Progress" 
                value={scanJob ? `${Math.round(scanJob.progress)}%` : '0%'} 
                color="blue" 
              />
              <StatCard 
                label="Targets" 
                value={scanJob?.targetCount || assets.length} 
              />
              <StatCard 
                label="Findings" 
                value={scanJob?.summary?.totalMisconfigurations || 0} 
                color="orange" 
              />
            </div>

            {/* Scan Progress Bar */}
            {scanJob && scanJob.status === 'running' && (
              <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-slate-400">Scanning Progress</span>
                  <span className="text-sm text-blue-400">{Math.round(scanJob.progress)}%</span>
                </div>
                <div className="w-full h-3 bg-slate-700 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-blue-600 to-cyan-500 transition-all duration-300"
                    style={{ width: `${scanJob.progress}%` }}
                  />
                </div>
              </div>
            )}

            {/* Scan Results */}
            {scanJob?.summary && (
              <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
                <h3 className="text-lg font-semibold mb-4">Scan Summary</h3>
                <div className="grid grid-cols-5 gap-4">
                  <div className="text-center">
                    <div className="text-3xl font-bold text-red-400">{scanJob.summary.criticalCount}</div>
                    <div className="text-xs text-slate-400">Critical</div>
                  </div>
                  <div className="text-center">
                    <div className="text-3xl font-bold text-orange-400">{scanJob.summary.highCount}</div>
                    <div className="text-xs text-slate-400">High</div>
                  </div>
                  <div className="text-center">
                    <div className="text-3xl font-bold text-yellow-400">{scanJob.summary.mediumCount}</div>
                    <div className="text-xs text-slate-400">Medium</div>
                  </div>
                  <div className="text-center">
                    <div className="text-3xl font-bold text-slate-400">{scanJob.summary.lowCount}</div>
                    <div className="text-xs text-slate-400">Low</div>
                  </div>
                  <div className="text-center">
                    <div className="text-3xl font-bold text-green-400">{scanJob.summary.successCount}</div>
                    <div className="text-xs text-slate-400">Scanned</div>
                  </div>
                </div>
              </div>
            )}

            {/* Optimization Features */}
            <div className="bg-gradient-to-br from-slate-800 to-slate-800/50 rounded-xl p-6 border border-slate-700">
              <h3 className="text-lg font-semibold mb-4">Scanner Optimizations Active</h3>
              <div className="grid grid-cols-3 gap-4">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-blue-900/50 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                    </svg>
                  </div>
                  <div>
                    <div className="font-medium text-sm">Batched Commands</div>
                    <div className="text-xs text-slate-400">20+ commands in 1 SSH call</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-green-900/50 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
                    </svg>
                  </div>
                  <div>
                    <div className="font-medium text-sm">Connection Pooling</div>
                    <div className="text-xs text-slate-400">SSH ControlMaster reuse</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-purple-900/50 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                  </div>
                  <div>
                    <div className="font-medium text-sm">Host Discovery</div>
                    <div className="text-xs text-slate-400">Skip dead hosts (100ms vs 30s)</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-yellow-900/50 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </div>
                  <div>
                    <div className="font-medium text-sm">Result Caching</div>
                    <div className="text-xs text-slate-400">Skip unchanged hosts</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-red-900/50 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
                    </svg>
                  </div>
                  <div>
                    <div className="font-medium text-sm">Adaptive Rate Limit</div>
                    <div className="text-xs text-slate-400">AIMD algorithm</div>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 bg-cyan-900/50 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
                    </svg>
                  </div>
                  <div>
                    <div className="font-medium text-sm">Priority Queue</div>
                    <div className="text-xs text-slate-400">Business impact scoring</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Analysis View */}
        {view === 'analysis' && (
          <div className="space-y-6">
            {!result ? (
              <div className="text-center py-20">
                <div className="w-20 h-20 bg-slate-800 rounded-full flex items-center justify-center mx-auto mb-4">
                  <svg className="w-10 h-10 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                  </svg>
                </div>
                <h3 className="text-xl font-semibold mb-2">Ready for Hybrid Analysis</h3>
                <p className="text-slate-400 mb-6">Scalable algorithm: Graph + Batch LLM</p>
              </div>
            ) : (
              <>
                {/* Graph Stats */}
                <div className="grid grid-cols-5 gap-4">
                  <StatCard label="Nodes" value={result.graph_stats.total_nodes} color="blue" />
                  <StatCard label="Edges" value={result.graph_stats.total_edges} color="purple" />
                  <StatCard label="Branching" value={result.graph_stats.avg_branching_factor} color="green" />
                  <StatCard label="Entry Points" value={result.entry_points.length} color="red" />
                  <StatCard label="Attack Paths" value={result.attack_paths.length} color="orange" />
                </div>

                {/* Edge Stats - Hybrid */}
                <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                  <div className="text-sm text-slate-400 mb-2">Hybrid Edge Creation</div>
                  <div className="flex items-center gap-6">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                      <span className="text-sm text-blue-400">Pattern: {result.edge_stats.pattern_edges}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 bg-purple-500 rounded-full"></div>
                      <span className="text-sm text-purple-400">LLM: {result.edge_stats.llm_edges}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 bg-green-500 rounded-full"></div>
                      <span className="text-sm text-green-400">Total: {result.edge_stats.total_edges}</span>
                    </div>
                  </div>
                  <div className="text-xs text-slate-500 mt-2">
                    Pattern edges: instant • LLM edges: batch evaluated for non-obvious attack paths
                  </div>
                </div>

                {/* Timing */}
                <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
                  <div className="text-sm text-slate-400 mb-2">Performance (Total: {result.timing.total}ms)</div>
                  <div className="flex gap-4 text-xs">
                    <span className="text-blue-400">Nodes: {result.timing.nodes}ms</span>
                    <span className="text-purple-400">Edges: {result.timing.edges}ms</span>
                    <span className="text-green-400">PageRank: {result.timing.pagerank}ms</span>
                    <span className="text-yellow-400">Paths: {result.timing.paths}ms</span>
                    <span className="text-red-400">LLM Validation: {result.timing.validation}ms</span>
                    <span className="text-orange-400">Entry Analysis: {result.timing.entry_analysis}ms</span>
                  </div>
                </div>

                {/* Entry Points */}
                <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
                  <div className="p-4 border-b border-slate-700 font-semibold">Entry Points (LLM Ranked)</div>
                  <div className="divide-y divide-slate-700">
                    {result.entry_points.slice(0, 6).map((entry, i) => (
                      <div key={i} className="p-4">
                        <div className="flex items-start gap-3">
                          <div className="w-7 h-7 bg-red-900/50 rounded-full flex items-center justify-center text-red-400 text-sm font-bold">
                            {i + 1}
                          </div>
                          <div className="flex-1">
                            <div className="font-medium">{entry.asset_name}</div>
                            <div className="text-sm text-orange-400">{entry.misconfig_title}</div>
                            <div className="text-sm text-slate-400 mt-1">{entry.reasoning}</div>
                            <div className="text-sm text-red-300">Value: {entry.attacker_value}</div>
                          </div>
                          <div className="text-xs text-slate-400">PR: {entry.pagerank_score.toFixed(4)}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Critical Assets */}
                <div className="bg-slate-800 rounded-xl border border-slate-700 p-4">
                  <div className="font-semibold mb-3">Critical Assets</div>
                  <div className="grid grid-cols-3 gap-3">
                    {result.critical_assets.map((a, i) => (
                      <div key={i} className="bg-slate-700/50 rounded-lg p-3">
                        <div className="font-medium text-sm">{a.asset_name}</div>
                        <div className="text-xs text-slate-400">{a.reason}</div>
                        <div className="text-xs text-purple-400">{a.paths_to_it} paths</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Insights */}
                <div className="bg-gradient-to-br from-red-900/30 to-orange-900/30 rounded-xl p-5 border border-red-800/50">
                  <div className="font-semibold mb-3">Key Insights</div>
                  <ul className="space-y-1">
                    {result.key_insights.map((insight, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm">
                        <span className="text-red-400">•</span>
                        <span className="text-slate-300">{insight}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </>
            )}
          </div>
        )}

        {/* Paths View */}
        {view === 'paths' && (
          <div className="space-y-6">
            {!result?.attack_paths?.length ? (
              <div className="text-center py-20 text-slate-400">Run analysis to discover paths</div>
            ) : (
              <div className="grid grid-cols-3 gap-6">
                {/* Path List */}
                <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
                  <div className="p-4 border-b border-slate-700 font-semibold">
                    Paths ({result.attack_paths.length})
                  </div>
                  <div className="divide-y divide-slate-700 max-h-[600px] overflow-y-auto">
                    {result.attack_paths.map((path, i) => (
                      <button
                        key={path.path_id}
                        onClick={() => setSelectedPath(i)}
                        className={`w-full p-4 text-left hover:bg-slate-700/30 transition-colors ${
                          selectedPath === i ? 'bg-red-900/20 border-l-2 border-red-500' : ''
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-medium">{path.path_id}</span>
                          <span className={`text-xs px-2 py-0.5 rounded ${
                            path.final_risk_score > 0.5 ? 'bg-red-900/50 text-red-300' : 'bg-yellow-900/50 text-yellow-300'
                          }`}>
                            {Math.round(path.final_risk_score * 100)}% risk
                          </span>
                        </div>
                        <div className="text-xs text-slate-400">{path.nodes.length} steps</div>
                        <div className="flex gap-2 mt-1 text-xs">
                          <span className="text-blue-400">P:{Math.round(path.path_probability * 100)}%</span>
                          <span className="text-green-400">R:{Math.round(path.realism_score * 100)}%</span>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Path Detail */}
                <div className="col-span-2">
                  {selectedPath !== null && result.attack_paths[selectedPath] ? (
                    <div className="bg-slate-800 rounded-xl border border-slate-700">
                      <div className="p-5 border-b border-slate-700">
                        <div className="flex items-center justify-between">
                          <h3 className="text-lg font-semibold">{result.attack_paths[selectedPath].path_id}</h3>
                          <div className="flex gap-3 text-xs">
                            <span className="text-blue-400">Prob: {Math.round(result.attack_paths[selectedPath].path_probability * 100)}%</span>
                            <span className="text-green-400">Realism: {Math.round(result.attack_paths[selectedPath].realism_score * 100)}%</span>
                            <span className="text-orange-400">Impact: {Math.round(result.attack_paths[selectedPath].impact_score * 100)}%</span>
                          </div>
                        </div>
                      </div>

                      {/* Score Bar */}
                      <div className="p-4 border-b border-slate-700 bg-slate-700/30">
                        <div className="flex items-center justify-between">
                          <span className="text-sm">Final Risk Score</span>
                          <div className="flex items-center gap-3">
                            <div className="w-48 h-3 bg-slate-700 rounded-full overflow-hidden">
                              <div
                                className="h-full bg-gradient-to-r from-green-500 via-yellow-500 to-red-500"
                                style={{ width: `${result.attack_paths[selectedPath].final_risk_score * 100}%` }}
                              />
                            </div>
                            <span className="text-lg font-bold text-red-400">
                              {Math.round(result.attack_paths[selectedPath].final_risk_score * 100)}%
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Steps */}
                      <div className="p-5 border-b border-slate-700">
                        <h4 className="font-medium mb-4">Attack Chain</h4>
                        <div className="space-y-3">
                          {result.attack_paths[selectedPath].nodes.map((node, i) => {
                            const edge = result.attack_paths[selectedPath].edges[i]
                            return (
                              <div key={i} className="flex gap-4">
                                <div className="flex flex-col items-center">
                                  <div className={`w-7 h-7 rounded-full flex items-center justify-center text-sm font-bold ${
                                    i === 0 ? 'bg-red-600' : i === result.attack_paths[selectedPath].nodes.length - 1 ? 'bg-purple-600' : 'bg-orange-600'
                                  }`}>{i + 1}</div>
                                  {i < result.attack_paths[selectedPath].nodes.length - 1 && (
                                    <div className="w-0.5 h-full bg-slate-600 my-2" />
                                  )}
                                </div>
                                <div className="flex-1 pb-3">
                                  <div className="flex items-center gap-2 mb-1">
                                    <span className="font-medium">{node.asset_name}</span>
                                    <span className="text-xs px-1.5 py-0.5 bg-slate-700 rounded uppercase">{node.asset_zone}</span>
                                  </div>
                                  <div className="text-sm text-orange-400">{node.misconfig_title}</div>
                                  {edge && (
                                    <div className="mt-1 text-xs bg-slate-700/50 p-2 rounded">
                                      <div className="flex items-center gap-2">
                                        <span className="text-slate-400">→ {Math.round(edge.probability * 100)}% via {edge.technique}</span>
                                        <span className={`px-1.5 py-0.5 rounded text-xs ${
                                          edge.edge_type === 'llm' 
                                            ? 'bg-purple-900/50 text-purple-300' 
                                            : 'bg-blue-900/50 text-blue-300'
                                        }`}>
                                          {edge.edge_type === 'llm' ? 'LLM' : 'Pattern'}
                                        </span>
                                      </div>
                                      {edge.reasoning && (
                                        <div className="text-slate-500 mt-1">{edge.reasoning}</div>
                                      )}
                                    </div>
                                  )}
                                </div>
                              </div>
                            )
                          })}
                        </div>
                      </div>

                      {/* Narrative */}
                      <div className="p-5 border-b border-slate-700">
                        <h4 className="font-medium mb-2">LLM Narrative</h4>
                        <p className="text-sm text-slate-300">{result.attack_paths[selectedPath].narrative}</p>
                      </div>

                      {/* Impact */}
                      <div className="p-5">
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <span className="text-sm text-slate-400">Business Impact:</span>
                            <p className="text-sm text-red-300 mt-1">{result.attack_paths[selectedPath].business_impact}</p>
                          </div>
                          <div>
                            <span className="text-sm text-slate-400">Kill Chain:</span>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {result.attack_paths[selectedPath].kill_chain.map((phase, i) => (
                                <span key={i} className="text-xs px-2 py-0.5 bg-slate-700 rounded">{phase}</span>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="bg-slate-800 rounded-xl border border-slate-700 p-12 text-center text-slate-400">
                      Select a path
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Algorithm View */}
        {view === 'algo' && (
          <div className="space-y-6">
            <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
              <h3 className="text-xl font-bold mb-6">Scalable Hybrid Algorithm</h3>

              <div className="space-y-4">
                <div className="border-l-4 border-blue-500 pl-4">
                  <h4 className="font-semibold text-blue-400">Phase 1: Build Nodes (O(n))</h4>
                  <p className="text-sm text-slate-400">Create node per (asset, misconfiguration) pair</p>
                </div>

                <div className="border-l-4 border-purple-500 pl-4">
                  <h4 className="font-semibold text-purple-400">Phase 2: Edge Evaluation (O(n²) but fast)</h4>
                  <p className="text-sm text-slate-400">Use attack pattern templates + zone reachability. No per-edge LLM calls!</p>
                  <div className="mt-2 bg-slate-700/50 p-2 rounded text-xs">
                    Predefined patterns encode attacker knowledge: network_exposure → authentication → authorization
                  </div>
                </div>

                <div className="border-l-4 border-green-500 pl-4">
                  <h4 className="font-semibold text-green-400">Phase 3: PageRank (O(iterations × E))</h4>
                  <p className="text-sm text-slate-400">Calculate node importance with probability-weighted edges</p>
                </div>

                <div className="border-l-4 border-yellow-500 pl-4">
                  <h4 className="font-semibold text-yellow-400">Phase 4: Dijkstra Path Finding (O(E log V))</h4>
                  <p className="text-sm text-slate-400">Find highest probability paths using -log(probability) as edge weight</p>
                </div>

                <div className="border-l-4 border-red-500 pl-4">
                  <h4 className="font-semibold text-red-400">Phase 5: Batch LLM Validation (scales linearly)</h4>
                  <p className="text-sm text-slate-400">Validate 5 paths per LLM call instead of 1 call per edge</p>
                </div>
              </div>
            </div>

            {/* Performance Comparison */}
            <div className="bg-gradient-to-r from-green-900/30 to-blue-900/30 rounded-xl p-6 border border-green-800/50">
              <h3 className="font-semibold mb-3 text-green-400">Performance Comparison</h3>
              <div className="grid grid-cols-2 gap-6 text-sm">
                <div>
                  <h4 className="text-slate-300 mb-2">Before (Per-Edge LLM)</h4>
                  <ul className="space-y-1 text-slate-400">
                    <li>❌ 150 nodes = ~22,500 edge evaluations</li>
                    <li>❌ 22,500 LLM calls</li>
                    <li>❌ ~30+ minutes</li>
                  </ul>
                </div>
                <div>
                  <h4 className="text-slate-300 mb-2">After (Pattern + Batch)</h4>
                  <ul className="space-y-1 text-green-400">
                    <li>✓ Pattern-based edge creation (instant)</li>
                    <li>✓ ~2-4 LLM calls total (batched)</li>
                    <li>✓ ~5-15 seconds</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* False Positive Reduction */}
            <div className="bg-gradient-to-r from-purple-900/30 to-pink-900/30 rounded-xl p-6 border border-purple-800/50">
              <h3 className="font-semibold mb-3 text-purple-400">False Positive Reduction</h3>
              <div className="grid grid-cols-2 gap-6 text-sm">
                <div>
                  <h4 className="text-slate-300 mb-2">Before</h4>
                  <ul className="space-y-1 text-slate-400">
                    <li>❌ 15-30% false positive rate</li>
                    <li>❌ Static detection rules</li>
                    <li>❌ No context awareness</li>
                  </ul>
                </div>
                <div>
                  <h4 className="text-slate-300 mb-2">After</h4>
                  <ul className="space-y-1 text-purple-400">
                    <li>✓ 5-10% false positive rate</li>
                    <li>✓ Context-aware validation</li>
                    <li>✓ Confidence scoring</li>
                    <li>✓ Known FP patterns database</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Scanner Architecture */}
            <div className="bg-gradient-to-r from-cyan-900/30 to-teal-900/30 rounded-xl p-6 border border-cyan-800/50">
              <h3 className="font-semibold mb-4 text-cyan-400">Scanner Architecture Files</h3>
              <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                <div className="space-y-1">
                  <div className="text-slate-300">Core Scanners:</div>
                  <div className="text-cyan-300">optimized-scanner.ts</div>
                  <div className="text-cyan-300">high-perf-scanner.ts</div>
                  <div className="text-slate-300 mt-2">Scalable Components:</div>
                  <div className="text-cyan-300">scalable/scanner-orchestrator.ts</div>
                  <div className="text-cyan-300">scalable/result-streamer.ts</div>
                  <div className="text-cyan-300">scalable/distributed-coordinator.ts</div>
                </div>
                <div className="space-y-1">
                  <div className="text-slate-300">Infrastructure:</div>
                  <div className="text-cyan-300">scalable/job-state-manager.ts</div>
                  <div className="text-cyan-300">scalable/priority-queue.ts</div>
                  <div className="text-cyan-300">scalable/adaptive-rate-limiter.ts</div>
                  <div className="text-cyan-300">scalable/scan-scheduler.ts</div>
                  <div className="text-slate-300 mt-2">Analysis:</div>
                  <div className="text-cyan-300">zone-detection.ts</div>
                  <div className="text-cyan-300">network-topology-collector.ts</div>
                  <div className="text-cyan-300">fp-reduction.ts</div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

function StatCard({ label, value, color = 'white' }: { label: string; value: string | number; color?: string }) {
  const colors: Record<string, string> = {
    white: 'text-white',
    red: 'text-red-400',
    yellow: 'text-yellow-400',
    blue: 'text-blue-400',
    purple: 'text-purple-400',
    green: 'text-green-400',
    orange: 'text-orange-400'
  }
  return (
    <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
      <div className="text-sm text-slate-400 mb-1">{label}</div>
      <div className={`text-2xl font-bold ${colors[color]}`}>{value}</div>
    </div>
  )
}
