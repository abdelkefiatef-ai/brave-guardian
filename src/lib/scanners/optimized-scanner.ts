// ============================================================================
// OPTIMIZED SCANNER - Batched Commands for Maximum SSH Efficiency
// Reduces 10-15 SSH round-trips to 1 call per asset
// ============================================================================

import { spawn } from 'child_process'
import { createHash } from 'crypto'

// ============================================================================
// TYPES
// ============================================================================

export interface ScanTarget {
  host: string
  port?: number
  username: string
  auth: {
    type: 'password' | 'key' | 'agent'
    password?: string
    keyPath?: string
  }
  timeout?: number
}

export interface BatchedResult {
  host: string
  success: boolean
  data: Record<string, string>
  errors: Record<string, string>
  duration: number
  cached: boolean
}

export interface ScanConfig {
  timeout: number
  maxConcurrent: number
  cacheResults: boolean
  cacheTTL: number
  retryAttempts: number
  retryDelay: number
}

// ============================================================================
// BATCHED SCRIPT GENERATOR
// ============================================================================

interface CommandGroup {
  name: string
  commands: string[]
  parser: (output: string) => Record<string, string>
}

const LINUX_COMMAND_GROUPS: CommandGroup[] = [
  {
    name: 'system_info',
    commands: [
      'hostname',
      'uname -a',
      'cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null',
      'uptime',
      'cat /proc/cpuinfo | grep "model name" | head -1',
      'free -h',
      'df -h',
    ],
    parser: (output) => {
      const lines = output.split('\n')
      return {
        hostname: lines[0] || '',
        kernel: lines[1] || '',
        os: lines[2] || '',
        uptime: lines[3] || '',
        cpu: lines[4] || '',
        memory: lines[5] || '',
        disk: lines[6] || '',
      }
    }
  },
  {
    name: 'network_info',
    commands: [
      'ip addr show 2>/dev/null || ifconfig',
      'ip route 2>/dev/null || route -n',
      'cat /etc/resolv.conf',
      'ss -tlnp 2>/dev/null || netstat -tlnp',
      'ss -ulnp 2>/dev/null || netstat -ulnp',
    ],
    parser: (output) => ({
      interfaces: output,
      routes: '',
      dns: '',
      tcp_listening: '',
      udp_listening: '',
    })
  },
  {
    name: 'user_audit',
    commands: [
      'cat /etc/passwd',
      'cat /etc/shadow 2>/dev/null || echo "NO_SHADOW_ACCESS"',
      'cat /etc/group',
      'cat /etc/sudoers 2>/dev/null || echo "NO_SUDOERS_ACCESS"',
      'last -n 20',
      'who',
      'w',
    ],
    parser: (output) => ({
      passwd: output.split('\n')[0] || '',
      shadow: output.split('\n')[1] || '',
      group: output.split('\n')[2] || '',
      sudoers: output.split('\n')[3] || '',
      login_history: output.split('\n')[4] || '',
      logged_in: output.split('\n')[5] || '',
      active_users: output.split('\n')[6] || '',
    })
  },
  {
    name: 'security_config',
    commands: [
      'cat /etc/ssh/sshd_config 2>/dev/null',
      'iptables -L -n 2>/dev/null || echo "NO_IPTABLES"',
      'ufw status 2>/dev/null || echo "NO_UFW"',
      'firewall-cmd --list-all 2>/dev/null || echo "NO_FIREWALLD"',
      'getenforce 2>/dev/null || echo "NO_SELINUX"',
      'aa-status 2>/dev/null || echo "NO_APPARMOR"',
      'systemctl list-units --type=service --state=running',
    ],
    parser: (output) => ({
      sshd_config: output.split('\n')[0] || '',
      iptables_rules: output.split('\n')[1] || '',
      firewall_ufw: output.split('\n')[2] || '',
      firewalld_status: output.split('\n')[3] || '',
      selinux: output.split('\n')[4] || '',
      apparmor: output.split('\n')[5] || '',
      running_services: output.split('\n')[6] || '',
    })
  },
  {
    name: 'file_security',
    commands: [
      'find / -perm -4000 -type f 2>/dev/null | head -50',
      'find / -perm -2000 -type f 2>/dev/null | head -50',
      'find / -perm -0002 -type f 2>/dev/null | head -50',
      'find / -perm -0002 -type d 2>/dev/null | head -50',
      'ls -la /etc/cron* 2>/dev/null',
      'cat /etc/crontab 2>/dev/null',
    ],
    parser: (output) => ({
      suid_files: output.split('\n')[0] || '',
      sgid_files: output.split('\n')[1] || '',
      world_writable_files: output.split('\n')[2] || '',
      world_writable_dirs: output.split('\n')[3] || '',
      cron_dirs: output.split('\n')[4] || '',
      crontab: output.split('\n')[5] || '',
    })
  },
  {
    name: 'package_audit',
    commands: [
      'apt list --installed 2>/dev/null | head -100 || rpm -qa 2>/dev/null | head -100',
      'apt list --upgradable 2>/dev/null || yum check-update 2>/dev/null | head -50',
      'which docker && docker --version',
      'which kubectl && kubectl version --client 2>/dev/null',
    ],
    parser: (output) => ({
      installed_packages: output.split('\n')[0] || '',
      upgradable_packages: output.split('\n')[1] || '',
      docker: output.split('\n')[2] || '',
      kubernetes: output.split('\n')[3] || '',
    })
  },
  {
    name: 'process_audit',
    commands: [
      'ps aux --sort=-%mem | head -20',
      'ps aux --sort=-%cpu | head -20',
      'lsof -i -n -P 2>/dev/null | head -50',
      'cat /proc/*/cmdline 2>/dev/null | tr "\\0" " " | head -50',
    ],
    parser: (output) => ({
      top_memory: output.split('\n')[0] || '',
      top_cpu: output.split('\n')[1] || '',
      network_connections: output.split('\n')[2] || '',
      process_cmdlines: output.split('\n')[3] || '',
    })
  },
]

const WINDOWS_COMMAND_GROUPS: CommandGroup[] = [
  {
    name: 'system_info',
    commands: [
      'hostname',
      'systeminfo',
      'wmic os get Caption,Version,OSArchitecture /value',
      'wmic computersystem get TotalPhysicalMemory /value',
      'wmic cpu get Name,NumberOfCores /value',
    ],
    parser: (output) => {
      const lines = output.split('\n')
      return {
        hostname: lines[0] || '',
        systeminfo: lines.slice(1).join('\n'),
      }
    }
  },
  {
    name: 'user_audit',
    commands: [
      'net user',
      'net localgroup administrators',
      'net group "domain admins" /domain 2>nul',
      'wmic useraccount get Name,Disabled,PasswordRequired /value',
    ],
    parser: (output) => ({
      users: output,
    })
  },
  {
    name: 'security_config',
    commands: [
      'netsh advfirewall show allprofiles',
      'netsh advfirewall firewall show rule name=all | head -100',
      'wmic qfe list brief',
      'netsh winhttp show proxy',
      'gpresult /r 2>nul',
    ],
    parser: (output) => ({
      firewall: output,
    })
  },
  {
    name: 'service_audit',
    commands: [
      'wmic service where "state=\'running\'" get Name,DisplayName,StartName /value',
      'wmic service where "startmode=\'auto\' and state!=\'running\'" get Name,State',
      'sc query type= service state= all | findstr "SERVICE_NAME DISPLAY_NAME STATE"',
    ],
    parser: (output) => ({
      services: output,
    })
  },
]

// ============================================================================
// BATCHED SCRIPT BUILDER
// ============================================================================

function buildBatchedScript(groups: CommandGroup[], isWindows: boolean = false): string {
  const delimiter = '===BRAVE_GUARDIAN_MARKER==='
  const groupDelimiter = '===GROUP_END==='

  const scriptLines: string[] = []
  
  if (!isWindows) {
    scriptLines.push('#!/bin/bash')
    scriptLines.push('set -e')
    scriptLines.push('')
  }

  for (const group of groups) {
    if (!isWindows) {
      scriptLines.push(`echo "GROUP_START:${group.name}"`)
    } else {
      scriptLines.push(`echo GROUP_START:${group.name}`)
    }

    for (const cmd of group.commands) {
      if (!isWindows) {
        scriptLines.push(`echo "CMD: ${cmd.replace(/"/g, '\\"')}"`)
        scriptLines.push(`${cmd} 2>&1 || echo "CMD_FAILED"`)
        scriptLines.push(`echo "${delimiter}"`)
      } else {
        scriptLines.push(`echo CMD: ${cmd.replace(/"/g, '^"')}`)
        scriptLines.push(`${cmd} 2>&1`)
        scriptLines.push(`echo ${delimiter}`)
      }
    }

    if (!isWindows) {
      scriptLines.push(`echo "${groupDelimiter}"`)
    } else {
      scriptLines.push(`echo ${groupDelimiter}`)
    }
    scriptLines.push('')
  }

  return scriptLines.join('\n')
}

// ============================================================================
// RESULT PARSER
// ============================================================================

function parseBatchedOutput(
  output: string,
  groups: CommandGroup[]
): { data: Record<string, string>; errors: Record<string, string> } {
  const data: Record<string, string> = {}
  const errors: Record<string, string> = {}
  
  const groupDelimiter = '===GROUP_END==='
  const cmdDelimiter = '===BRAVE_GUARDIAN_MARKER==='
  
  const groupOutputs = output.split(groupDelimiter)
  
  for (let i = 0; i < groups.length && i < groupOutputs.length; i++) {
    const groupOutput = groupOutputs[i]
    const group = groups[i]
    
    // Find GROUP_START marker
    const groupStartMatch = groupOutput.match(/GROUP_START:(\w+)/)
    if (!groupStartMatch) continue
    
    const groupName = groupStartMatch[1]
    if (groupName !== group.name) continue
    
    // Split by command delimiter
    const cmdOutputs = groupOutput.split(cmdDelimiter)
    
    // Parse each command output
    for (let j = 0; j < group.commands.length && j < cmdOutputs.length; j++) {
      const cmdOutput = cmdOutputs[j]
      
      // Extract command name from marker
      const cmdMatch = cmdOutput.match(/CMD: (.+)/)
      if (cmdMatch) {
        const cmdName = group.commands[j]
        const result = cmdOutput.replace(/CMD: .+\n?/, '').trim()
        
        if (result.includes('CMD_FAILED')) {
          errors[`${group.name}_${j}`] = result
        } else {
          data[`${group.name}_${j}`] = result
        }
      }
    }
  }
  
  return { data, errors }
}

// ============================================================================
// OPTIMIZED SCANNER CLASS
// ============================================================================

export class OptimizedScanner {
  private config: ScanConfig
  private cache: Map<string, { data: BatchedResult; timestamp: number }> = new Map()
  private scriptCache: Map<string, string> = new Map()

  constructor(config: Partial<ScanConfig> = {}) {
    this.config = {
      timeout: config.timeout || 30000,
      maxConcurrent: config.maxConcurrent || 10,
      cacheResults: config.cacheResults ?? true,
      cacheTTL: config.cacheTTL || 3600000, // 1 hour
      retryAttempts: config.retryAttempts || 2,
      retryDelay: config.retryDelay || 1000,
    }
  }

  /**
   * Scan a single target with batched commands
   */
  async scanTarget(target: ScanTarget): Promise<BatchedResult> {
    const startTime = Date.now()
    const cacheKey = this.getCacheKey(target)
    
    // Check cache
    if (this.config.cacheResults) {
      const cached = this.cache.get(cacheKey)
      if (cached && Date.now() - cached.timestamp < this.config.cacheTTL) {
        return { ...cached.data, cached: true }
      }
    }
    
    const isWindows = target.port === 5985 || target.port === 5986
    
    // Get or create batched script
    const script = this.getBatchedScript(isWindows)
    
    // Execute with retries
    let lastError: Error | null = null
    for (let attempt = 0; attempt < this.config.retryAttempts; attempt++) {
      try {
        const result = await this.executeBatchedScript(target, script, isWindows)
        const duration = Date.now() - startTime
        
        const batchedResult: BatchedResult = {
          host: target.host,
          success: true,
          data: result,
          errors: {},
          duration,
          cached: false,
        }
        
        // Cache result
        if (this.config.cacheResults) {
          this.cache.set(cacheKey, { data: batchedResult, timestamp: Date.now() })
        }
        
        return batchedResult
      } catch (error) {
        lastError = error as Error
        if (attempt < this.config.retryAttempts - 1) {
          await this.sleep(this.config.retryDelay * (attempt + 1))
        }
      }
    }
    
    return {
      host: target.host,
      success: false,
      data: {},
      errors: { execution: lastError?.message || 'Unknown error' },
      duration: Date.now() - startTime,
      cached: false,
    }
  }

  /**
   * Scan multiple targets in parallel with concurrency control
   */
  async scanTargets(targets: ScanTarget[]): Promise<BatchedResult[]> {
    const results: BatchedResult[] = []
    const queue = [...targets]
    const inProgress: Promise<void>[] = []
    
    const processNext = async () => {
      while (queue.length > 0) {
        const target = queue.shift()
        if (!target) break
        
        const result = await this.scanTarget(target)
        results.push(result)
      }
    }
    
    // Start concurrent workers
    for (let i = 0; i < this.config.maxConcurrent; i++) {
      inProgress.push(processNext())
    }
    
    await Promise.all(inProgress)
    return results
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.cache.clear()
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; hitRate: number } {
    return {
      size: this.cache.size,
      hitRate: 0, // Would need hit tracking for real rate
    }
  }

  // Private methods

  private getBatchedScript(isWindows: boolean): string {
    const cacheKey = isWindows ? 'windows' : 'linux'
    
    if (!this.scriptCache.has(cacheKey)) {
      const groups = isWindows ? WINDOWS_COMMAND_GROUPS : LINUX_COMMAND_GROUPS
      this.scriptCache.set(cacheKey, buildBatchedScript(groups, isWindows))
    }
    
    return this.scriptCache.get(cacheKey)!
  }

  private async executeBatchedScript(
    target: ScanTarget,
    script: string,
    isWindows: boolean
  ): Promise<Record<string, string>> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        child.kill()
        reject(new Error(`Timeout after ${this.config.timeout}ms`))
      }, this.config.timeout)

      const args: string[] = isWindows
        ? this.buildWinRMArgs(target)
        : this.buildSSHArgs(target, script)

      const child = spawn(isWindows ? 'winrm' : 'ssh', args, {
        timeout: this.config.timeout,
      })

      let stdout = ''
      let stderr = ''

      child.stdout.on('data', (data) => {
        stdout += data.toString()
      })

      child.stderr.on('data', (data) => {
        stderr += data.toString()
      })

      child.on('close', (code) => {
        clearTimeout(timeout)
        
        if (code === 0) {
          const groups = isWindows ? WINDOWS_COMMAND_GROUPS : LINUX_COMMAND_GROUPS
          const parsed = parseBatchedOutput(stdout, groups)
          resolve(parsed.data)
        } else {
          reject(new Error(`Exit code ${code}: ${stderr}`))
        }
      })

      child.on('error', (error) => {
        clearTimeout(timeout)
        reject(error)
      })

      // For SSH, write script to stdin
      if (!isWindows) {
        child.stdin?.write(script)
        child.stdin?.end()
      }
    })
  }

  private buildSSHArgs(target: ScanTarget, script: string): string[] {
    const args: string[] = [
      '-o', 'StrictHostKeyChecking=no',
      '-o', 'UserKnownHostsFile=/dev/null',
      '-o', `ConnectTimeout=${Math.floor(this.config.timeout / 1000)}`,
      '-p', String(target.port || 22),
    ]

    if (target.auth.type === 'key' && target.auth.keyPath) {
      args.push('-i', target.auth.keyPath)
    }

    args.push(`${target.username}@${target.host}`)
    args.push('bash -s') // Read script from stdin

    return args
  }

  private buildWinRMArgs(target: ScanTarget): string[] {
    // WinRM command via PowerShell
    return [
      'invoke-command',
      '-computername', target.host,
      '-credential', target.username,
      '-scriptblock', '{ ... }', // Would be filled with script
    ]
  }

  private getCacheKey(target: ScanTarget): string {
    return createHash('sha256')
      .update(`${target.host}:${target.port || 22}`)
      .digest('hex')
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export { LINUX_COMMAND_GROUPS, WINDOWS_COMMAND_GROUPS, buildBatchedScript, parseBatchedOutput }
