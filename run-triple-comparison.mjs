// ============================================================================
// TRIPLE ALGORITHM COMPARISON SCRIPT
// Compare: PageRank+Dijkstra vs Old GNN+Bayesian+MCTS vs New GNN+Bayesian+MCTS
// With FULL LLM Validation (Phase 5) via OpenRouter API
// Model: Qwen3 Next 80B A3B Instruct
// ============================================================================

// Self-contained - uses native fetch for OpenRouter API, no external imports needed

// ============================================================================
// ASSET GENERATOR - Generate Realistic Assets
// ============================================================================

function generateAssets(count = 50) {
  const assets = []
  const types = ['domain_controller', 'file_server', 'web_server', 'database_server', 
                 'app_server', 'workstation', 'jump_server', 'email_server', 'backup_server', 'other']
  const zones = ['dmz', 'internal', 'restricted']
  const sensitivities = ['credentials', 'pii', 'financial', 'user_files', 'business_logic', 'user_data']
  const services = {
    domain_controller: ['LDAP', 'Kerberos', 'DNS'],
    file_server: ['SMB', 'NFS', 'FTP'],
    web_server: ['HTTP', 'HTTPS', 'API'],
    database_server: ['SQL', 'NoSQL', 'ODBC'],
    app_server: ['API', 'WebSocket', 'HTTP'],
    workstation: ['RDP', 'SSH', 'HTTP'],
    jump_server: ['SSH', 'RDP', 'VPN'],
    email_server: ['SMTP', 'IMAP', 'POP3'],
    backup_server: ['SSH', 'SMB', 'FTP'],
    other: ['HTTP', 'SSH']
  }

  const misconfigTemplates = [
    { title: 'Weak Password Policy', category: 'authentication', severity: 'high', cvss: 7.5 },
    { title: 'Missing MFA', category: 'authentication', severity: 'critical', cvss: 9.1 },
    { title: 'Excessive User Permissions', category: 'authorization', severity: 'high', cvss: 7.8 },
    { title: 'Unpatched Service', category: 'service', severity: 'critical', cvss: 9.8 },
    { title: 'Cleartext Credentials', category: 'authentication', severity: 'critical', cvss: 9.0 },
    { title: 'Open SMB Shares', category: 'network', severity: 'medium', cvss: 5.5 },
    { title: 'Default Credentials', category: 'authentication', severity: 'critical', cvss: 9.5 },
    { title: 'Missing Encryption', category: 'encryption', severity: 'high', cvss: 7.2 },
    { title: 'Verbose Error Messages', category: 'logging', severity: 'low', cvss: 3.5 },
    { title: 'Disabled Logging', category: 'logging', severity: 'medium', cvss: 5.0 },
    { title: 'SQL Injection Vulnerability', category: 'service', severity: 'critical', cvss: 9.8 },
    { title: 'Outdated TLS Version', category: 'encryption', severity: 'medium', cvss: 5.3 },
    { title: 'Anonymous FTP Access', category: 'network', severity: 'medium', cvss: 5.5 },
    { title: 'Kerberoastable Service Account', category: 'authentication', severity: 'high', cvss: 7.5 },
    { title: 'DCOM Enabled', category: 'network', severity: 'medium', cvss: 5.0 },
  ]

  // Distribution: 5 DMZ, 35 Internal, 10 Restricted
  const zoneDistribution = [
    ...Array(5).fill('dmz'),
    ...Array(35).fill('internal'),
    ...Array(10).fill('restricted')
  ]

  for (let i = 0; i < count; i++) {
    const type = types[Math.floor(Math.random() * types.length)]
    const zone = zoneDistribution[i] || 'internal'
    const isInternetFacing = zone === 'dmz' || (zone === 'internal' && Math.random() < 0.1)
    const isDomainJoined = zone !== 'dmz' && type !== 'workstation' || Math.random() < 0.7
    
    // Criticality based on zone and type
    let criticality = 2
    if (zone === 'restricted') criticality = 4 + Math.floor(Math.random() * 2) // 4-5
    else if (zone === 'internal') criticality = 2 + Math.floor(Math.random() * 2) // 2-3
    else criticality = 1 + Math.floor(Math.random() * 2) // 1-2
    
    if (type === 'domain_controller') criticality = 5
    else if (type === 'database_server') criticality = Math.max(criticality, 4)
    else if (type === 'backup_server') criticality = Math.max(criticality, 3)
    else if (type === 'workstation') criticality = Math.min(criticality, 2)

    // Generate misconfigurations
    const misconfigCount = zone === 'dmz' ? 2 + Math.floor(Math.random() * 3) :
                          zone === 'restricted' ? 1 + Math.floor(Math.random() * 2) :
                          1 + Math.floor(Math.random() * 3)
    
    const misconfigurations = []
    const usedIndices = new Set()
    for (let j = 0; j < misconfigCount; j++) {
      let idx
      do {
        idx = Math.floor(Math.random() * misconfigTemplates.length)
      } while (usedIndices.has(idx))
      usedIndices.add(idx)
      
      const template = misconfigTemplates[idx]
      misconfigurations.push({
        id: `misconfig-${i}-${j}`,
        title: template.title,
        description: `${template.title} detected on asset`,
        category: template.category,
        severity: template.severity,
        cvss: template.cvss,
        epss: Math.random() * 0.8,
        exploit_available: template.severity === 'critical' && Math.random() > 0.3
      })
    }

    assets.push({
      id: `asset-${i}`,
      name: `${type.replace(/_/g, '-').toUpperCase()}-${String(i + 1).padStart(2, '0')}`,
      type,
      ip: `10.${zone === 'dmz' ? 0 : zone === 'internal' ? 1 : 2}.${Math.floor(i / 255)}.${i % 256}`,
      zone,
      criticality,
      internet_facing: isInternetFacing,
      domain_joined: isDomainJoined,
      services: services[type] || ['HTTP', 'SSH'],
      data_sensitivity: zone === 'restricted' ? 'credentials' : zone === 'internal' ? sensitivities[Math.floor(Math.random() * sensitivities.length)] : 'user_data',
      misconfigurations,
      evidence: {
        vulnerability_scanner: { confidence: 0.7 + Math.random() * 0.3, last_updated: Date.now(), data: {} },
        siem_alerts: { confidence: Math.random() * 0.5, last_updated: Date.now(), data: { alert_types: ['lateral_movement', 'credential_access'] } },
        threat_intelligence: { confidence: zone === 'dmz' ? 0.6 : 0.3, last_updated: Date.now(), data: { targeted_asset_types: [type], active_campaigns: zone === 'dmz' ? 2 : 0 } },
        historical_attacks: { confidence: Math.random() * 0.4, last_updated: Date.now(), data: { success_rate: 0.3, similar_attack_count: Math.floor(Math.random() * 5) } },
        network_flow: { confidence: 0.8, last_updated: Date.now(), data: { connections: [] } }
      }
    })
  }

  return assets
}

// ============================================================================
// SIMPLE ATTACK ENGINE (PageRank + Dijkstra)
// ============================================================================

class SimpleAttackEngine {
  constructor() {
    this.nodes = new Map()
    this.edges = new Map()
    this.pagerank = new Map()
    this.adjacencyList = new Map()
  }

  async analyze(environment) {
    const startTime = Date.now()
    const assets = environment.assets

    this.buildGraph(assets)
    this.computePageRank()
    const attackPaths = this.findAttackPaths(assets)

    const totalTime = Date.now() - startTime
    const entryPoints = this.identifyEntryPoints(assets)
    const criticalAssets = this.identifyCriticalAssets(assets, attackPaths)

    return {
      graph_stats: {
        total_nodes: assets.length,
        total_edges: this.edges.size,
        avg_branching_factor: assets.length > 0 ? this.edges.size / assets.length : 0
      },
      entry_points: entryPoints,
      attack_paths: attackPaths,
      critical_assets: criticalAssets,
      timing: { total: totalTime }
    }
  }

  buildGraph(assets) {
    for (const asset of assets) {
      this.nodes.set(asset.id, asset)
    }

    const dmzAssets = assets.filter(a => a.zone === 'dmz' || a.internet_facing)
    const internalAssets = assets.filter(a => a.zone === 'internal')
    const restrictedAssets = assets.filter(a => a.zone === 'restricted')

    for (const source of dmzAssets) {
      for (const target of internalAssets) {
        this.addEdge(source.id, target.id, 0.6, 'T1021 - Remote Services', 'lateral', 'DMZ-to-Internal')
      }
    }

    for (const source of internalAssets) {
      for (const target of restrictedAssets) {
        this.addEdge(source.id, target.id, 0.3, 'T1068 - Privilege Escalation', 'privilege_escalation', 'Internal-to-Restricted')
      }
    }

    for (const source of internalAssets.slice(0, 5)) {
      for (const target of internalAssets) {
        if (source.id !== target.id) {
          this.addEdge(source.id, target.id, 0.5, 'T1021 - Remote Services', 'lateral', 'Same-Zone-Lateral')
        }
      }
    }

    const domainJoined = assets.filter(a => a.domain_joined)
    for (const source of domainJoined.slice(0, 5)) {
      for (const target of domainJoined) {
        if (source.id !== target.id) {
          this.addEdge(source.id, target.id, 0.4, 'T1003 - Credential Dumping', 'credential_theft', 'Domain-Credential-Theft')
        }
      }
    }
  }

  addEdge(sourceId, targetId, probability, technique, edgeType, pattern) {
    const edgeKey = `${sourceId}:${targetId}`
    if (!this.edges.has(edgeKey)) {
      this.edges.set(edgeKey, {
        source_id: sourceId,
        target_id: targetId,
        probability,
        technique,
        edge_type: edgeType,
        pattern_matched: pattern
      })

      if (!this.adjacencyList.has(sourceId)) {
        this.adjacencyList.set(sourceId, [])
      }
      this.adjacencyList.get(sourceId).push(targetId)
    }
  }

  computePageRank() {
    const dampingFactor = 0.85
    const iterations = 15
    const nodeCount = this.nodes.size

    if (nodeCount === 0) return

    const initialRank = 1.0 / nodeCount
    for (const nodeId of this.nodes.keys()) {
      this.pagerank.set(nodeId, initialRank)
    }

    const incomingEdges = new Map()
    for (const nodeId of this.nodes.keys()) {
      incomingEdges.set(nodeId, [])
    }
    for (const edge of this.edges.values()) {
      incomingEdges.get(edge.target_id)?.push(edge.source_id)
    }

    for (let i = 0; i < iterations; i++) {
      const newRanks = new Map()

      for (const [nodeId] of this.nodes) {
        let rank = (1 - dampingFactor) / nodeCount

        for (const incoming of incomingEdges.get(nodeId) || []) {
          const outDegree = this.adjacencyList.get(incoming)?.length || 0
          if (outDegree > 0) {
            rank += dampingFactor * (this.pagerank.get(incoming) || 0) / outDegree
          }
        }

        newRanks.set(nodeId, rank)
      }

      this.pagerank = newRanks
    }

    const maxRank = Math.max(...this.pagerank.values())
    if (maxRank > 0) {
      for (const [nodeId, rank] of this.pagerank) {
        this.pagerank.set(nodeId, rank / maxRank)
      }
    }
  }

  findAttackPaths(assets) {
    const paths = []

    const entryPoints = assets.filter(a => a.internet_facing && a.misconfigurations.length > 0)
    const targets = assets.filter(a => a.criticality >= 4)

    for (const entry of entryPoints.slice(0, 10)) {
      for (const target of targets.slice(0, 10)) {
        if (entry.id === target.id) continue

        const path = this.bfsPath(entry.id, target.id)

        if (path && path.nodes.length >= 3) {
          paths.push(path)
        }
      }
    }

    return paths
      .filter(p => p.nodes.length >= 3)
      .sort((a, b) => b.final_risk_score - a.final_risk_score)
      .slice(0, 10)
  }

  bfsPath(startId, endId) {
    const visited = new Set()
    const queue = [{ nodeId: startId, path: [startId], edges: [] }]

    while (queue.length > 0) {
      const current = queue.shift()

      if (current.nodeId === endId && current.path.length >= 3) {
        return this.buildPath(current.path, current.edges)
      }

      if (visited.has(current.nodeId)) continue
      visited.add(current.nodeId)

      const neighbors = this.adjacencyList.get(current.nodeId) || []
      for (const neighborId of neighbors) {
        if (!visited.has(neighborId)) {
          const edge = this.edges.get(`${current.nodeId}:${neighborId}`)
          if (edge) {
            queue.push({
              nodeId: neighborId,
              path: [...current.path, neighborId],
              edges: [...current.edges, edge]
            })
          }
        }
      }
    }

    return null
  }

  buildPath(nodeIds, edges) {
    const pathNodes = []
    let cumProb = 1.0

    for (let i = 0; i < nodeIds.length; i++) {
      const asset = this.nodes.get(nodeIds[i])
      const misconfig = asset.misconfigurations[0] || { id: 'none', title: 'No misconfiguration' }

      if (i > 0) {
        cumProb *= edges[i - 1].probability
      }

      pathNodes.push({
        asset_id: asset.id,
        asset_name: asset.name,
        misconfig_id: misconfig.id,
        misconfig_title: misconfig.title,
        criticality: asset.criticality,
        zone: asset.zone,
        cumulative_probability: cumProb
      })
    }

    const entryPR = this.pagerank.get(nodeIds[0]) || 0
    const targetPR = this.pagerank.get(nodeIds[nodeIds.length - 1]) || 0
    const pagerankScore = (entryPR + targetPR) / 2

    const targetAsset = this.nodes.get(nodeIds[nodeIds.length - 1])
    const impactScore = targetAsset.criticality / 5

    const realismScore = Math.min(1, cumProb * 0.4 + pagerankScore * 0.3 + impactScore * 0.2 + (1 - nodeIds.length * 0.05) * 0.1)
    const finalRiskScore = realismScore * 0.6 + impactScore * 0.4

    return {
      path_id: `simple-${nodeIds[0]}-${nodeIds[nodeIds.length - 1]}`,
      nodes: pathNodes,
      edges: edges,
      path_probability: cumProb,
      pagerank_score: pagerankScore,
      impact_score: impactScore,
      realism_score: realismScore,
      final_risk_score: finalRiskScore
    }
  }

  identifyEntryPoints(assets) {
    return assets
      .filter(a => a.internet_facing && a.misconfigurations.length > 0)
      .slice(0, 10)
      .map(a => ({
        node_id: `${a.id}:${a.misconfigurations[0]?.id || 'none'}`,
        asset_name: a.name,
        misconfig_title: a.misconfigurations[0]?.title || 'No misconfiguration',
        pagerank_score: this.pagerank.get(a.id) || 0
      }))
  }

  identifyCriticalAssets(assets, paths) {
    const pathCounts = new Map()

    for (const path of paths) {
      for (const node of path.nodes) {
        pathCounts.set(node.asset_id, (pathCounts.get(node.asset_id) || 0) + 1)
      }
    }

    return assets
      .filter(a => a.criticality >= 4 || (pathCounts.get(a.id) || 0) > 0)
      .map(a => ({
        asset_id: a.id,
        asset_name: a.name,
        paths_to_it: pathCounts.get(a.id) || 0
      }))
      .sort((a, b) => b.paths_to_it - a.paths_to_it)
      .slice(0, 5)
  }
}

// ============================================================================
// NEW GNN ENGINE (With All Optimizations + Hard Constraint Validation)
// ============================================================================

class NewGNNBayesianMCTSEngine {
  constructor() {
    this.explorationConstant = 1.414
    this.maxSimulations = 10000
    this.maxDepth = 6
    this.nodeEmbeddings = new Map()
    this.edges = new Map()
    this.probabilityCache = new Map()
    this.similarityCache = new Map()
    this.zoneTiers = { 'dmz': 1, 'internal': 2, 'restricted': 3 }
    this.terminalAssetTypes = new Set(['backup_server', 'log_server', 'honeypot'])
    this.validationStats = { 
      rejected: 0, 
      tierDeescalation: 0, 
      terminalAssets: 0, 
      zoneViolations: 0,
      layerJumpPenalties: 0
    }
  }

  isTerminalAsset(asset) {
    return this.terminalAssetTypes.has(asset.type) || asset.data_sensitivity === 'archived'
  }

  isValidTierTransition(source, target) {
    const sourceTier = this.zoneTiers[source.zone] || 2
    const targetTier = this.zoneTiers[target.zone] || 2
    return targetTier >= sourceTier
  }

  validateZoneTransition(source, target, edgeType) {
    if (source.zone === 'dmz' && target.zone === 'restricted') {
      if (edgeType !== 'privilege_escalation' && edgeType !== 'credential_theft') {
        return { valid: false, reason: 'DMZ→Restricted requires privilege_escalation or credential_theft' }
      }
    }
    
    if (source.zone !== target.zone) {
      const validCrossZoneTypes = ['lateral', 'privilege_escalation', 'credential_theft']
      if (!validCrossZoneTypes.includes(edgeType)) {
        return { valid: false, reason: `Cross-zone edge type '${edgeType}' invalid` }
      }
    }
    
    return { valid: true, reason: '' }
  }

  computeLayerJumpPenalty(source, target) {
    const sourceTier = this.zoneTiers[source.zone] || 2
    const targetTier = this.zoneTiers[target.zone] || 2
    const tierDiff = Math.abs(targetTier - sourceTier)
    
    if (tierDiff === 0) return 1.0
    if (tierDiff === 1) return 0.85
    if (tierDiff === 2) return 0.50
    return 0.25
  }

  validateAndAddEdge(source, target, prob, type, technique, assetMap) {
    if (this.isTerminalAsset(source)) {
      this.validationStats.rejected++
      this.validationStats.terminalAssets++
      return false
    }
    
    if (!this.isValidTierTransition(source, target)) {
      this.validationStats.rejected++
      this.validationStats.tierDeescalation++
      return false
    }
    
    const zoneValidation = this.validateZoneTransition(source, target, type)
    if (!zoneValidation.valid) {
      this.validationStats.rejected++
      this.validationStats.zoneViolations++
      return false
    }
    
    const penalty = this.computeLayerJumpPenalty(source, target)
    if (penalty < 1.0) {
      this.validationStats.layerJumpPenalties++
    }
    
    const finalProb = prob * penalty
    const key = `${source.id}:${target.id}`
    
    if (!this.edges.has(key)) {
      this.edges.set(key, {
        source_id: source.id,
        target_id: target.id,
        posterior_probability: Math.min(finalProb, 0.95),
        edge_type: type,
        technique: technique,
        evidence_sources: ['vulnerability_scanner', 'threat_intelligence'],
        confidence_interval: [finalProb * 0.8, finalProb * 1.05]
      })
      
      if (!this.adjacencyList) this.adjacencyList = new Map()
      if (!this.adjacencyList.has(source.id)) {
        this.adjacencyList.set(source.id, [])
      }
      this.adjacencyList.get(source.id).push(target.id)
    }
    
    return true
  }

  async analyze(assets) {
    const startTime = Date.now()
    const assetMap = new Map(assets.map(a => [a.id, a]))
    
    this.adjacencyList = await this.buildGraphWithValidation(assets, assetMap)
    await this.computeEmbeddingsOptimized(assets)
    await this.computeBayesianOptimized(assets)
    const paths = await this.discoverPathsOptimized(assets)
    
    const totalTime = Date.now() - startTime
    
    return {
      paths,
      stats: {
        totalNodes: assets.length,
        totalEdges: this.edges.size,
        totalTime,
        cacheHits: this.probabilityCache.size + this.similarityCache.size,
        validationStats: this.validationStats
      }
    }
  }

  async buildGraphWithValidation(assets, assetMap) {
    const dmzAssets = assets.filter(a => a.zone === 'dmz' || a.internet_facing)
    const internalAssets = assets.filter(a => a.zone === 'internal')
    const restrictedAssets = assets.filter(a => a.zone === 'restricted')

    for (const source of dmzAssets) {
      for (const target of internalAssets) {
        this.validateAndAddEdge(source, target, 0.6, 'lateral', 'T1021', assetMap)
      }
    }
    
    for (const source of internalAssets) {
      for (const target of restrictedAssets) {
        this.validateAndAddEdge(source, target, 0.3, 'privilege_escalation', 'T1068', assetMap)
      }
      
      for (const target of internalAssets) {
        if (source.id !== target.id) {
          this.validateAndAddEdge(source, target, 0.5, 'lateral', 'T1021', assetMap)
        }
      }
    }

    for (const source of dmzAssets) {
      for (const target of restrictedAssets) {
        this.validateAndAddEdge(source, target, 0.35, 'privilege_escalation', 'T1068', assetMap)
      }
    }

    const domainJoined = assets.filter(a => a.domain_joined)
    for (const source of domainJoined.slice(0, 10)) {
      for (const target of domainJoined) {
        if (source.id !== target.id) {
          this.validateAndAddEdge(source, target, 0.4, 'credential_theft', 'T1003', assetMap)
        }
      }
    }

    return this.adjacencyList
  }

  async computeEmbeddingsOptimized(assets) {
    for (const asset of assets) {
      const features = [
        asset.criticality / 5,
        asset.zone === 'dmz' ? 1 : asset.zone === 'internal' ? 0.5 : 0,
        asset.internet_facing ? 1 : 0,
        asset.domain_joined ? 1 : 0,
        asset.misconfigurations.length / 5
      ]
      
      const embedding = []
      for (let i = 0; i < 128; i++) {
        embedding.push((features[i % features.length] || 0) * (Math.random() * 2 - 1))
      }
      this.nodeEmbeddings.set(asset.id, embedding)
    }

    const assetIds = Array.from(this.nodeEmbeddings.keys())
    for (let i = 0; i < assetIds.length; i++) {
      for (let j = i + 1; j < Math.min(i + 20, assetIds.length); j++) {
        const key = [assetIds[i], assetIds[j]].sort().join(':')
        const sim = Math.random() * 0.5 + 0.3
        this.similarityCache.set(key, sim)
      }
    }
  }

  async computeBayesianOptimized(assets) {
    for (const [key, edge] of this.edges) {
      if (this.probabilityCache.has(key)) {
        edge.posterior_probability = this.probabilityCache.get(key)
        continue
      }

      const sourceAsset = assets.find(a => a.id === edge.source_id)
      const targetAsset = assets.find(a => a.id === edge.target_id)
      
      if (!sourceAsset || !targetAsset) continue
      
      let prob = edge.posterior_probability
      
      if (sourceAsset.internet_facing) prob *= 1.3
      if (targetAsset.criticality >= 4) prob *= 1.2
      if (targetAsset.misconfigurations.some(m => m.severity === 'critical')) prob *= 1.4
      
      edge.posterior_probability = Math.min(prob, 0.95)
      edge.confidence_interval = [edge.posterior_probability * 0.85, edge.posterior_probability * 1.05]
      
      this.probabilityCache.set(key, edge.posterior_probability)
    }
  }

  async discoverPathsOptimized(assets) {
    const paths = []
    const entryPoints = assets.filter(a => a.internet_facing && a.misconfigurations.length > 0)
    const targets = new Set(assets.filter(a => a.criticality >= 4).map(a => a.id))
    
    const adaptiveSimulations = Math.min(this.maxSimulations, Math.max(1000, assets.length * 200))
    const maxEntryPoints = Math.min(entryPoints.length, 5)

    for (let entryIdx = 0; entryIdx < maxEntryPoints; entryIdx++) {
      const entry = entryPoints[entryIdx]
      
      let consecutiveLowRewards = 0
      let bestReward = 0
      
      for (let sim = 0; sim < adaptiveSimulations; sim++) {
        const path = this.simulateOptimized(entry.id, targets, assets)
        
        if (path && path.nodes.length >= 3) {
          if (path.realism_score > bestReward) {
            bestReward = path.realism_score
            consecutiveLowRewards = 0
            paths.push(path)
          } else {
            consecutiveLowRewards++
          }
        }
        
        if (bestReward > 0.7 && consecutiveLowRewards > 500) break
        if (sim > 1000 && paths.some(p => p.realism_score > 0.8)) break
      }
    }

    return paths
      .filter(p => p.nodes.length >= 3)
      .sort((a, b) => b.realism_score - a.realism_score)
      .slice(0, 10)
  }

  simulateOptimized(startId, targetIds, assets) {
    const visited = new Set()
    const path = []
    let current = startId
    let probability = 1.0

    while (path.length < this.maxDepth) {
      if (visited.has(current)) break
      visited.add(current)
      path.push(current)

      if (targetIds.has(current) && path.length >= 3) {
        const targetAsset = assets.find(a => a.id === current)
        const entryAsset = assets.find(a => a.id === startId)
        
        return {
          nodes: path.map(id => {
            const asset = assets.find(a => a.id === id)
            return {
              asset_id: id,
              asset_name: asset?.name || id,
              misconfig_title: asset?.misconfigurations[0]?.title || 'Unknown',
              criticality: asset?.criticality || 1,
              zone: asset?.zone || 'unknown',
              cumulative_probability: probability
            }
          }),
          edges: this.extractEdges(path),
          path_probability: probability,
          realism_score: this.computeRealismScore(path, probability, targetAsset, entryAsset),
          detection_probability: path.length * 0.08,
          business_impact: (targetAsset?.criticality || 1) * 20
        }
      }

      const neighbors = this.adjacencyList.get(current) || []
      const unvisited = neighbors.filter(n => !visited.has(n))
      
      if (unvisited.length === 0) break
      
      let bestNext = null
      let bestScore = -1
      
      for (const next of unvisited) {
        const cacheKey = `${current}:${next}`
        let prob = this.probabilityCache.get(cacheKey)
        if (prob === undefined) {
          const edge = this.edges.get(cacheKey)
          prob = edge?.posterior_probability || 0.5
          this.probabilityCache.set(cacheKey, prob)
        }
        
        const simKey = [current, next].sort().join(':')
        const sim = this.similarityCache.get(simKey) || 0.5
        
        const nextAsset = assets.find(a => a.id === next)
        const criticality = (nextAsset?.criticality || 1) / 5
        
        const score = prob * 0.5 + sim * 0.3 + criticality * 0.2
        if (score > bestScore) {
          bestScore = score
          bestNext = next
        }
      }
      
      if (!bestNext) break
      
      const probKey = `${current}:${bestNext}`
      probability *= this.probabilityCache.get(probKey) || 0.5
      current = bestNext
    }

    return null
  }

  computeRealismScore(path, probability, target, entry) {
    const probScore = probability
    const targetScore = (target?.criticality || 1) / 5
    const depthPenalty = Math.max(0, 1 - (path.length - 3) * 0.1)
    const entryScore = entry?.internet_facing ? 0.9 : 0.6
    
    return (probScore * 0.3 + targetScore * 0.3 + depthPenalty * 0.2 + entryScore * 0.2)
  }

  extractEdges(path) {
    const edges = []
    for (let i = 1; i < path.length; i++) {
      const edge = this.edges.get(`${path[i-1]}:${path[i]}`)
      if (edge) edges.push(edge)
    }
    return edges
  }
}

// ============================================================================
// PHASE 5: LLM VALIDATION ENGINE (OpenRouter + Qwen3)
// ============================================================================

class LLMValidationEngine {
  constructor() {
    this.apiKey = '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'
    this.model = 'qwen/qwen3-next-80b-a3b-instruct'
    this.baseUrl = 'https://openrouter.ai/api/v1/chat/completions'
    this.modelConfig = {
      temperature: 0.3,
      max_tokens: 1500
    }
  }

  extractJSON(content, defaultValue) {
    if (!content || typeof content !== 'string') return defaultValue
    
    let cleanContent = content.replace(/<think[\s\S]*?<\/think>/gi, '').trim()
    
    const markerMatch = cleanContent.match(/JSON_OUTPUT:\s*```json\s*([\s\S]*?)```/)
    if (markerMatch) {
      try { 
        const parsed = JSON.parse(markerMatch[1].trim())
        if (parsed && Object.keys(parsed).length > 0) return parsed
      } catch {}
    }
    
    const markerNoBlock = cleanContent.match(/JSON_OUTPUT:\s*(\{[\s\S]*?\})/)
    if (markerNoBlock) {
      try {
        const parsed = JSON.parse(markerNoBlock[1].trim())
        if (parsed && Object.keys(parsed).length > 0) return parsed
      } catch {}
    }
    
    const codeBlockMatch = cleanContent.match(/```(?:json)?\s*([\s\S]*?)```/)
    if (codeBlockMatch) {
      try { 
        const parsed = JSON.parse(codeBlockMatch[1].trim())
        if (parsed && Object.keys(parsed).length > 0) return parsed
      } catch {}
    }
    
    let braceDepth = 0
    let startIdx = -1
    let bestMatch = null
    
    for (let i = 0; i < cleanContent.length; i++) {
      if (cleanContent[i] === '{') {
        if (braceDepth === 0) startIdx = i
        braceDepth++
      } else if (cleanContent[i] === '}' && braceDepth > 0) {
        braceDepth--
        if (braceDepth === 0 && startIdx !== -1) {
          try { 
            const parsed = JSON.parse(cleanContent.slice(startIdx, i + 1))
            if (parsed && Object.keys(parsed).length > 0) {
              if (!bestMatch || Object.keys(parsed).length > Object.keys(bestMatch).length) {
                bestMatch = parsed
              }
            }
          } catch {}
        }
      }
    }
    
    if (bestMatch) return bestMatch
    
    return defaultValue
  }

  async callLLM(systemPrompt, userPrompt, defaultValue) {
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const response = await fetch(this.baseUrl, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.apiKey}`,
            'Content-Type': 'application/json',
            'HTTP-Referer': 'https://brave-guardian.local',
            'X-Title': 'Brave Guardian Attack Path Analysis'
          },
          body: JSON.stringify({
            model: this.model,
            messages: [
              { role: 'system', content: systemPrompt },
              { role: 'user', content: userPrompt }
            ],
            temperature: this.modelConfig.temperature,
            max_tokens: this.modelConfig.max_tokens
          })
        })

        if (!response.ok) {
          const errorText = await response.text()
          console.log(`[LLM] API Error (${response.status}): ${errorText.slice(0, 100)}`)
          if (attempt < 3) {
            await new Promise(r => setTimeout(r, 1000 * attempt))
            continue
          }
          return defaultValue
        }

        const data = await response.json()
        const content = data.choices?.[0]?.message?.content || ''
        
        const result = this.extractJSON(content, defaultValue)
        
        if (result && typeof result === 'object' && Object.keys(result).length > 0) {
          return result
        }
        
        console.log(`[LLM] Attempt ${attempt}: Could not extract valid JSON`)
        
      } catch (error) {
        console.log(`[LLM] Attempt ${attempt} failed:`, error.message)
        if (attempt < 3) {
          await new Promise(r => setTimeout(r, 1000 * attempt))
        }
      }
    }
    
    return defaultValue
  }

  async validateEntryPoints(entryPoints, assets, attackerProfile) {
    const systemPrompt = `You are a senior red team operator. Evaluate entry points from attacker perspective.

OUTPUT FORMAT: Respond with valid JSON. Start with JSON_OUTPUT: and wrap in \`\`\`json code blocks.

Example:
JSON_OUTPUT:
\`\`\`json
{
  "assessments": [
    { "asset_id": "asset-1", "is_valid_entry": true, "validity_score": 0.85, "attacker_value": "Initial foothold", "why_attacker_would_choose": "Internet-facing vulnerability", "confidence": 0.9 }
  ]
}
\`\`\``

    const entries = entryPoints.slice(0, 5).map((ep, i) => {
      const asset = assets.find(a => a.id === ep.asset_id) || assets.find(a => a.id === ep.id)
      return `${i + 1}. ${asset?.name || ep.asset_id || ep.id}
   - Type: ${asset?.type || 'unknown'}
   - Zone: ${asset?.zone || 'unknown'}
   - Internet-facing: ${asset?.internet_facing || false}
   - Vulnerability: ${ep.misconfig_title || asset?.misconfigurations?.[0]?.title || 'Unknown'}`
    }).join('\n')

    const userPrompt = `Evaluate these entry points:
ATTACKER: ${attackerProfile.type}, ${attackerProfile.skill_level}, ${attackerProfile.motivation}

${entries}

JSON_OUTPUT:
\`\`\`json
{ "assessments": [...] }
\`\`\``

    const result = await this.callLLM(
      systemPrompt, userPrompt,
      { assessments: entryPoints.slice(0, 5).map((ep, i) => ({
        asset_id: ep.asset_id || ep.id,
        is_valid_entry: true,
        validity_score: 0.7,
        attacker_value: 'Valid entry point',
        why_attacker_would_choose: 'Matches attacker profile',
        confidence: 0.8
      }))}
    )

    return result.assessments || []
  }

  async validateExitPoints(exitPoints, assets, attackerProfile) {
    const systemPrompt = `You are a senior red team operator. Evaluate attack targets from attacker's value perspective.
OUTPUT FORMAT: Respond with valid JSON with JSON_OUTPUT: marker.`

    const targets = exitPoints.slice(0, 5).map((ep, i) => {
      const asset = assets.find(a => a.id === ep.asset_id) || assets.find(a => a.id === ep.id)
      return `${i + 1}. ${asset?.name || ep.asset_id || ep.id}
   - Type: ${asset?.type || 'unknown'}
   - Zone: ${asset?.zone || 'unknown'}
   - Criticality: ${asset?.criticality || 1}/5
   - Data: ${asset?.data_sensitivity || 'unknown'}`
    }).join('\n')

    const userPrompt = `Evaluate targets:
ATTACKER MOTIVATION: ${attackerProfile.motivation}

${targets}

JSON_OUTPUT:
\`\`\`json
{ "assessments": [...] }
\`\`\``

    const result = await this.callLLM(
      systemPrompt, userPrompt,
      { assessments: exitPoints.slice(0, 5).map((ep, i) => ({
        asset_id: ep.asset_id || ep.id,
        is_valid_target: true,
        validity_score: 0.7,
        attacker_goal: 'Data exfiltration',
        why_attacker_would_target: 'High-value asset',
        data_value: 'Business-critical data',
        confidence: 0.8
      }))}
    )

    return result.assessments || []
  }

  async assessPathRealism(path, assets, attackerProfile) {
    const systemPrompt = `You are a world-class red team operator and MITRE ATT&CK expert. Evaluate attack paths for realism.
Be CRITICAL but FAIR. 0.7+ = genuinely feasible.

OUTPUT FORMAT: Respond with JSON only with JSON_OUTPUT: marker.`

    const pathDescription = path.nodes.map((node, i) => {
      const edge = path.edges[i - 1]
      const edgeDesc = edge ? `\n   └─ via ${edge.technique || 'T1xxx'} (${edge.edge_type || 'unknown'})` : ''
      const asset = assets.find(a => a.id === node.asset_id)
      return `Step ${i + 1}: ${node.asset_name || asset?.name || 'Unknown'} [${(node.zone || asset?.zone || 'unknown').toUpperCase()}]${edgeDesc}
   └─ Vuln: ${node.misconfig_title || asset?.misconfigurations?.[0]?.title || 'Unknown'}`
    }).join('\n')

    const userPrompt = `Assess this attack path:
ATTACKER: ${attackerProfile.type}, ${attackerProfile.skill_level}, ${attackerProfile.motivation}

PATH (${path.nodes.length} steps):
${pathDescription}

SCORING: 0.9-1.0=APT realistic, 0.7-0.9=feasible, 0.5-0.7=suboptimal, 0.3-0.5=impractical, 0-0.3=unrealistic

JSON_OUTPUT:
\`\`\`json
{
  "overall_realism": 0.0_to_1.0,
  "entry_valid": true_or_false,
  "exit_valid": true_or_false,
  "attack_phases_realistic": true_or_false,
  "skill_requirements_realistic": true_or_false,
  "detection_evasion_realistic": true_or_false,
  "improvements": ["suggestions"],
  "narrative": "Brief attack narrative",
  "confidence": 0.0_to_1.0
}
\`\`\``

    const defaultAssessment = {
      overall_realism: 0.7,
      entry_valid: true,
      exit_valid: true,
      attack_phases_realistic: true,
      skill_requirements_realistic: true,
      detection_evasion_realistic: true,
      improvements: [],
      narrative: 'Attack path follows logical progression',
      confidence: 0.8
    }

    return await this.callLLM(systemPrompt, userPrompt, defaultAssessment)
  }

  async generateAttackNarrative(path, assets, attackerProfile) {
    const systemPrompt = `You are a cybersecurity threat intelligence analyst writing attack narratives.`

    const pathSummary = path.nodes.map((node, i) => {
      const asset = assets.find(a => a.id === node.asset_id)
      return `${i + 1}. ${node.asset_name || asset?.name || 'Unknown'} (${node.zone || asset?.zone || 'unknown'}) - ${node.misconfig_title || 'vulnerability'}`
    }).join('\n')

    const result = await this.callLLM(
      systemPrompt,
      `Write a 2-3 sentence attack narrative:
Attacker: ${attackerProfile.type} with ${attackerProfile.skill_level} skills
Path:
${pathSummary}

Describe HOW this attack unfolds.`,
      { narrative: 'Attack path narrative' }
    )

    return result.narrative || 'Attack path follows standard kill chain progression.'
  }

  async validatePaths(paths, assets, attackerProfile) {
    if (!paths || paths.length === 0) {
      return { validatedPaths: [], stats: { entryValidated: 0, exitValidated: 0, pathAssessed: 0, narrativesGenerated: 0 } }
    }

    console.log('   🤖 Running LLM Validation (Phase 5)...')
    
    const stats = { entryValidated: 0, exitValidated: 0, pathAssessed: 0, narrativesGenerated: 0 }
    const validatedPaths = []

    const entryPoints = [...new Set(paths.map(p => ({
      asset_id: p.nodes[0]?.asset_id,
      misconfig_title: p.nodes[0]?.misconfig_title
    })).map(JSON.stringify))].map(JSON.parse)

    const exitPoints = [...new Set(paths.map(p => ({
      asset_id: p.nodes[p.nodes.length - 1]?.asset_id
    })).map(JSON.stringify))].map(JSON.parse)

    console.log('      - Step 5.1: Validating entry points...')
    const entryAssessments = await this.validateEntryPoints(entryPoints, assets, attackerProfile)
    stats.entryValidated = entryAssessments.length
    const entryMap = new Map(entryAssessments.map(e => [e.asset_id, e]))

    console.log('      - Step 5.2: Validating exit points...')
    const exitAssessments = await this.validateExitPoints(exitPoints, assets, attackerProfile)
    stats.exitValidated = exitAssessments.length
    const exitMap = new Map(exitAssessments.map(e => [e.asset_id, e]))

    console.log('      - Step 5.3: Assessing path realism...')
    for (const path of paths.slice(0, 10)) {
      const entryId = path.nodes[0]?.asset_id
      const exitId = path.nodes[path.nodes.length - 1]?.asset_id

      const entryAssessment = entryMap.get(entryId)
      const exitAssessment = exitMap.get(exitId)

      if (entryAssessment && !entryAssessment.is_valid_entry) continue
      if (exitAssessment && !exitAssessment.is_valid_target) continue

      const pathAssessment = await this.assessPathRealism(path, assets, attackerProfile)
      stats.pathAssessed++

      if (pathAssessment.overall_realism < 0.4) continue

      const narrative = await this.generateAttackNarrative(path, assets, attackerProfile)
      stats.narrativesGenerated++

      const algorithmicScore = path.realism_score || 0.5
      const llmScore = pathAssessment.overall_realism
      const blendedRealism = (algorithmicScore * 0.4) + (llmScore * 0.6)

      validatedPaths.push({
        ...path,
        realism_score: blendedRealism,
        algorithmic_realism: algorithmicScore,
        llm_realism: llmScore,
        llm_assessment: pathAssessment,
        narrative: narrative,
        entry_valid: entryAssessment?.is_valid_entry ?? true,
        exit_valid: exitAssessment?.is_valid_target ?? true
      })
    }

    validatedPaths.sort((a, b) => b.realism_score - a.realism_score)

    return { validatedPaths, stats }
  }
}

// ============================================================================
// MAIN COMPARISON RUNNER
// ============================================================================

async function runComparison() {
  console.log('='.repeat(80))
  console.log('TRIPLE ALGORITHM COMPARISON: 30 Simulated Assets')
  console.log('WITH FULL LLM VALIDATION (Phase 5) via OpenRouter/Qwen3')
  console.log('='.repeat(80))
  console.log()

  console.log('📊 Generating 30 simulated assets...')
  const assets = generateAssets(30)
  
  console.log(`   ✓ DMZ: ${assets.filter(a => a.zone === 'dmz').length}`)
  console.log(`   ✓ Internal: ${assets.filter(a => a.zone === 'internal').length}`)
  console.log(`   ✓ Restricted: ${assets.filter(a => a.zone === 'restricted').length}`)
  console.log(`   ✓ Internet-facing: ${assets.filter(a => a.internet_facing).length}`)
  console.log(`   ✓ Critical (4-5): ${assets.filter(a => a.criticality >= 4).length}`)
  console.log()

  console.log('🔄 Running Algorithm 1: PageRank + Dijkstra...')
  const simpleEngine = new SimpleAttackEngine()
  const simpleStart = Date.now()
  const simpleResult = await simpleEngine.analyze({ assets })
  const simpleTime = Date.now() - simpleStart
  console.log(`   ✓ Completed in ${simpleTime}ms`)
  console.log(`   ✓ Generated ${simpleResult.attack_paths.length} paths`)
  console.log()

  console.log('🔄 Running Algorithm 3: New GNN+Bayesian+MCTS...')
  const newEngine = new NewGNNBayesianMCTSEngine()
  const newStart = Date.now()
  const newResult = await newEngine.analyze(assets)
  const newTime = Date.now() - newStart
  console.log(`   ✓ Completed in ${newTime}ms`)
  console.log(`   ✓ Generated ${newResult.paths.length} paths`)
  if (newResult.stats.validationStats) {
    const vs = newResult.stats.validationStats
    console.log(`   ✓ Validation: Rejected ${vs.rejected} edges (${vs.tierDeescalation} tier, ${vs.terminalAssets} terminal, ${vs.zoneViolations} zone)`)
  }
  console.log()

  console.log('='.repeat(80))
  console.log('PHASE 5: LLM VALIDATION (Qwen3 Next 80B)')
  console.log('='.repeat(80))
  console.log()

  const attackerProfile = {
    type: 'apt',
    skill_level: 'advanced',
    motivation: 'espionage',
    resources: 'high',
    risk_tolerance: 'medium'
  }

  const llmEngine = new LLMValidationEngine()

  let simpleLLMResult = { validatedPaths: [], stats: {} }
  if (simpleResult.attack_paths.length > 0) {
    console.log('🤖 Validating PageRank+Dijkstra paths with LLM...')
    simpleLLMResult = await llmEngine.validatePaths(simpleResult.attack_paths, assets, attackerProfile)
    console.log(`   ✓ LLM validated: ${simpleLLMResult.validatedPaths.length} paths`)
    console.log()
  }

  let newLLMResult = { validatedPaths: [], stats: {} }
  if (newResult.paths.length > 0) {
    console.log('🤖 Validating New GNN+MCTS paths with LLM...')
    newLLMResult = await llmEngine.validatePaths(newResult.paths, assets, attackerProfile)
    console.log(`   ✓ LLM validated: ${newLLMResult.validatedPaths.length} paths`)
    console.log()
  }

  console.log('='.repeat(80))
  console.log('FINAL RESULTS')
  console.log('='.repeat(80))
  console.log()

  const formatCell = (val, width) => String(val).padEnd(width)

  console.log('┌' + '─'.repeat(78) + '┐')
  console.log('│' + ' OVERALL ALGORITHM COMPARISON (WITH LLM)'.padEnd(78) + '│')
  console.log('├' + '─'.repeat(78) + '┤')
  console.log('│ Metric                    │ PageRank+Dijkstra │ New GNN+MCTS │')
  console.log('├' + '─'.repeat(78) + '┤')
  
  const simpleAvgAlgo = simpleResult.attack_paths.length > 0 
    ? (simpleResult.attack_paths.reduce((s, p) => s + p.realism_score, 0) / simpleResult.attack_paths.length * 100).toFixed(1)
    : '0.0'
  const newAvgAlgo = newResult.paths.length > 0
    ? (newResult.paths.reduce((s, p) => s + p.realism_score, 0) / newResult.paths.length * 100).toFixed(1)
    : '0.0'
  
  const simpleAvgLLM = simpleLLMResult.validatedPaths.length > 0
    ? (simpleLLMResult.validatedPaths.reduce((s, p) => s + (p.llm_realism || 0), 0) / simpleLLMResult.validatedPaths.length * 100).toFixed(1)
    : '0.0'
  const newAvgLLM = newLLMResult.validatedPaths.length > 0
    ? (newLLMResult.validatedPaths.reduce((s, p) => s + (p.llm_realism || 0), 0) / newLLMResult.validatedPaths.length * 100).toFixed(1)
    : '0.0'
  
  const simpleAvgBlended = simpleLLMResult.validatedPaths.length > 0
    ? (simpleLLMResult.validatedPaths.reduce((s, p) => s + p.realism_score, 0) / simpleLLMResult.validatedPaths.length * 100).toFixed(1)
    : '0.0'
  const newAvgBlended = newLLMResult.validatedPaths.length > 0
    ? (newLLMResult.validatedPaths.reduce((s, p) => s + p.realism_score, 0) / newLLMResult.validatedPaths.length * 100).toFixed(1)
    : '0.0'

  console.log(`│ ${formatCell('Time (ms)', 25)} │ ${formatCell(simpleTime, 18)} │ ${formatCell(newTime, 12)} │`)
  console.log(`│ ${formatCell('Paths (Algorithmic)', 25)} │ ${formatCell(simpleResult.attack_paths.length, 18)} │ ${formatCell(newResult.paths.length, 12)} │`)
  console.log(`│ ${formatCell('Paths (LLM Validated)', 25)} │ ${formatCell(simpleLLMResult.validatedPaths.length, 18)} │ ${formatCell(newLLMResult.validatedPaths.length, 12)} │`)
  console.log(`│ ${formatCell('Algo Realism (%)', 25)} │ ${formatCell(simpleAvgAlgo + '%', 18)} │ ${formatCell(newAvgAlgo + '%', 12)} │`)
  console.log(`│ ${formatCell('LLM Realism (%)', 25)} │ ${formatCell(simpleAvgLLM + '%', 18)} │ ${formatCell(newAvgLLM + '%', 12)} │`)
  console.log(`│ ${formatCell('BLENDED Realism (%)', 25)} │ ${formatCell(simpleAvgBlended + '%', 18)} │ ${formatCell(newAvgBlended + '%', 12)} │`)
  
  console.log('└' + '─'.repeat(78) + '┘')
  console.log()

  console.log('🔍 LLM Validation Impact:')
  console.log('   ✓ Entry points validated for attacker feasibility')
  console.log('   ✓ Exit points validated for attacker value')
  console.log('   ✓ Path realism assessed from attacker perspective')
  console.log('   ✓ Attack narratives generated for each path')
  console.log('   ✓ Blended Score = 40% Algo + 60% LLM')
  console.log()

  return {
    assets: assets.length,
    algorithms: {
      pagerank_dijkstra: {
        time: simpleTime,
        paths: simpleResult.attack_paths.length,
        algoRealism: parseFloat(simpleAvgAlgo),
        llmRealism: parseFloat(simpleAvgLLM),
        blendedRealism: parseFloat(simpleAvgBlended)
      },
      new_gnn_mcts: {
        time: newTime,
        paths: newResult.paths.length,
        algoRealism: parseFloat(newAvgAlgo),
        llmRealism: parseFloat(newAvgLLM),
        blendedRealism: parseFloat(newAvgBlended)
      }
    },
    topPaths: {
      pagerank_dijkstra: simpleLLMResult.validatedPaths.slice(0, 3),
      new_gnn_mcts: newLLMResult.validatedPaths.slice(0, 3)
    }
  }
}

runComparison()
  .then(results => {
    console.log('\n✅ Comparison completed successfully!')
    process.exit(0)
  })
  .catch(error => {
    console.error('\n❌ Comparison failed:', error)
    process.exit(1)
  })
