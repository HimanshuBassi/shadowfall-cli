interface TerminalLine {
  id: string;
  content: string;
  type: 'system' | 'user' | 'output' | 'error' | 'success' | 'warning';
  timestamp?: string;
}

interface ScanResult {
  port: string;
  state: 'OPEN' | 'CLOSED' | 'FILTERED';
  service: string;
  version?: string;
}

interface Vulnerability {
  cve: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  port?: string;
  description: string;
}

interface SessionData {
  target: string | null;
  scanResults: ScanResult[];
  vulnerabilities: Vulnerability[];
  exploitHistory: string[];
  compromisedShell: boolean;
}

export class CommandProcessor {
  private static sessionData: SessionData = {
    target: null,
    scanResults: [],
    vulnerabilities: [],
    exploitHistory: [],
    compromisedShell: false
  };

  static async processCommand(
    command: string,
    addLine: (content: string, type: TerminalLine['type']) => void,
    addLines: (lines: TerminalLine[]) => void
  ): Promise<void> {
    const args = command.trim().split(' ');
    const cmd = args[0].toLowerCase();

    switch (cmd) {
      case 'help':
        this.showHelp(addLines);
        break;
      case 'scan':
        await this.handleScan(args, addLine, addLines);
        break;
      case 'vuln':
        await this.handleVuln(args, addLine, addLines);
        break;
      case 'exploit':
        await this.handleExploit(args, addLine, addLines);
        break;
      case 'report':
        await this.handleReport(args, addLine, addLines);
        break;
      case 'clear':
        // This would be handled by the parent component
        addLine('[SYSTEM] Terminal cleared.', 'system');
        break;
      case 'exit':
        this.handleExit(addLine);
        break;
      default:
        if (this.sessionData.compromisedShell && this.isShellCommand(cmd)) {
          await this.handleShellCommand(command, addLine);
        } else {
          addLine(`[ERROR] Unknown command: '${cmd}'. Type 'help' for available commands.`, 'error');
        }
    }
  }

  private static showHelp(addLines: (lines: TerminalLine[]) => void): void {
    const helpLines: TerminalLine[] = [
      { id: Date.now().toString(), content: '', type: 'output' },
      { id: (Date.now() + 1).toString(), content: '[HELP] Available modules:', type: 'system' },
      { id: (Date.now() + 2).toString(), content: '', type: 'output' },
      { id: (Date.now() + 3).toString(), content: 'scan <target> [-p <ports>] [-type <scan_type>]', type: 'output' },
      { id: (Date.now() + 4).toString(), content: '  - Perform port scan on target', type: 'output' },
      { id: (Date.now() + 5).toString(), content: '  - Example: scan 192.168.1.1 -p 1-1000 -type stealth', type: 'output' },
      { id: (Date.now() + 6).toString(), content: '', type: 'output' },
      { id: (Date.now() + 7).toString(), content: 'vuln <target> [-p <port>]', type: 'output' },
      { id: (Date.now() + 8).toString(), content: '  - Analyze target for vulnerabilities', type: 'output' },
      { id: (Date.now() + 9).toString(), content: '', type: 'output' },
      { id: (Date.now() + 10).toString(), content: 'exploit <CVE-ID> [-p <port>]', type: 'output' },
      { id: (Date.now() + 11).toString(), content: '  - Attempt to exploit discovered vulnerability', type: 'output' },
      { id: (Date.now() + 12).toString(), content: '', type: 'output' },
      { id: (Date.now() + 13).toString(), content: 'report generate [-format text]', type: 'output' },
      { id: (Date.now() + 14).toString(), content: '  - Generate comprehensive assessment report', type: 'output' },
      { id: (Date.now() + 15).toString(), content: '', type: 'output' },
      { id: (Date.now() + 16).toString(), content: 'clear - Clear terminal', type: 'output' },
      { id: (Date.now() + 17).toString(), content: 'exit  - Terminate session', type: 'output' },
      { id: (Date.now() + 18).toString(), content: '', type: 'output' },
    ];
    addLines(helpLines);
  }

  private static async handleScan(
    args: string[],
    addLine: (content: string, type: TerminalLine['type']) => void,
    addLines: (lines: TerminalLine[]) => void
  ): Promise<void> {
    if (args.length < 2) {
      addLine('[ERROR] Usage: scan <target> [-p <ports>] [-type <scan_type>]', 'error');
      return;
    }

    const target = args[1];
    let ports = '1-1000';
    let scanType = 'quick';

    // Parse arguments
    for (let i = 2; i < args.length; i++) {
      if (args[i] === '-p' && args[i + 1]) {
        ports = args[i + 1];
        i++;
      } else if (args[i] === '-type' && args[i + 1]) {
        scanType = args[i + 1];
        i++;
      }
    }

    this.sessionData.target = target;
    addLine(`[RECON] Probing target: ${target} on ports: ${ports}. Stand by...`, 'system');
    addLine('', 'output');

    // Simulate scanning progress
    await this.delay(1000);
    addLine('[SCANNING] Port enumeration in progress...', 'warning');
    await this.delay(1500);

    // Generate realistic scan results
    const scanResults = this.generateScanResults(target, ports, scanType);
    this.sessionData.scanResults = scanResults;

    // Display results
    const resultLines: TerminalLine[] = [
      { id: Date.now().toString(), content: '', type: 'output' },
      { id: (Date.now() + 1).toString(), content: 'PORT     STATE    SERVICE       VERSION', type: 'success' },
      { id: (Date.now() + 2).toString(), content: '-------- -------- ------------- ---------------------', type: 'success' },
    ];

    scanResults.forEach((result, index) => {
      const line = `${result.port.padEnd(8)} ${result.state.padEnd(8)} ${result.service.padEnd(13)} ${result.version || 'Unknown'}`;
      resultLines.push({
        id: (Date.now() + 3 + index).toString(),
        content: line,
        type: result.state === 'OPEN' ? 'success' : 'output'
      });
    });

    resultLines.push({ id: (Date.now() + 100).toString(), content: '', type: 'output' });
    resultLines.push({ id: (Date.now() + 101).toString(), content: `[COMPLETE] Scan finished. ${scanResults.filter(r => r.state === 'OPEN').length} open ports detected.`, type: 'success' });

    addLines(resultLines);
  }

  private static async handleVuln(
    args: string[],
    addLine: (content: string, type: TerminalLine['type']) => void,
    addLines: (lines: TerminalLine[]) => void
  ): Promise<void> {
    if (!this.sessionData.target) {
      addLine('[ERROR] No target specified. Run scan command first.', 'error');
      return;
    }

    const target = args[1] || this.sessionData.target;
    addLine(`[VULN-SCAN] Analyzing services on ${target} for known exploits.`, 'system');
    addLine('[VULN-SCAN] Cross-referencing with exploit database...', 'warning');

    await this.delay(2000);

    const vulnerabilities = this.generateVulnerabilities();
    this.sessionData.vulnerabilities = vulnerabilities;

    const vulnLines: TerminalLine[] = [
      { id: Date.now().toString(), content: '', type: 'output' },
      { id: (Date.now() + 1).toString(), content: '[VULNERABILITIES DETECTED]', type: 'error' },
      { id: (Date.now() + 2).toString(), content: '', type: 'output' },
    ];

    vulnerabilities.forEach((vuln, index) => {
      const severityColor = vuln.severity === 'CRITICAL' ? 'error' : 
                           vuln.severity === 'HIGH' ? 'warning' : 'output';
      vulnLines.push({
        id: (Date.now() + 3 + index * 3).toString(),
        content: `[${vuln.severity}] ${vuln.cve} - ${vuln.title}`,
        type: severityColor
      });
      vulnLines.push({
        id: (Date.now() + 4 + index * 3).toString(),
        content: `         ${vuln.description}`,
        type: 'output'
      });
      vulnLines.push({
        id: (Date.now() + 5 + index * 3).toString(),
        content: '',
        type: 'output'
      });
    });

    addLines(vulnLines);
  }

  private static async handleExploit(
    args: string[],
    addLine: (content: string, type: TerminalLine['type']) => void,
    addLines: (lines: TerminalLine[]) => void
  ): Promise<void> {
    if (args.length < 2) {
      addLine('[ERROR] Usage: exploit <CVE-ID> [-p <port>]', 'error');
      return;
    }

    const cveId = args[1];
    const vulnerability = this.sessionData.vulnerabilities.find(v => v.cve === cveId);

    if (!vulnerability) {
      addLine(`[ERROR] CVE ${cveId} not found in current assessment. Run vuln scan first.`, 'error');
      return;
    }

    addLine(`[EXPLOIT] Weaponizing ${cveId}. Deploying payload...`, 'warning');
    await this.delay(1000);
    addLine('[EXPLOIT] Loading exploit modules...', 'system');
    await this.delay(1500);
    addLine('[EXPLOIT] Establishing connection...', 'system');
    await this.delay(2000);

    // Simulate success/failure
    const success = Math.random() > 0.3; // 70% success rate

    if (success) {
      this.sessionData.compromisedShell = true;
      this.sessionData.exploitHistory.push(cveId);
      
      const successLines: TerminalLine[] = [
        { id: Date.now().toString(), content: '[+] Exploit successful!', type: 'success' },
        { id: (Date.now() + 1).toString(), content: '[+] Shell acquired on target system', type: 'success' },
        { id: (Date.now() + 2).toString(), content: '[+] Privilege escalation detected', type: 'success' },
        { id: (Date.now() + 3).toString(), content: '', type: 'output' },
        { id: (Date.now() + 4).toString(), content: 'victim-machine $> _', type: 'system' },
        { id: (Date.now() + 5).toString(), content: '', type: 'output' },
        { id: (Date.now() + 6).toString(), content: 'Available shell commands: whoami, ls, cat, pwd, exit', type: 'output' },
        { id: (Date.now() + 7).toString(), content: '', type: 'output' },
      ];
      addLines(successLines);
    } else {
      addLine('[-] Exploit failed. Target may be patched or protected.', 'error');
      addLine('[!] Consider alternative attack vectors.', 'warning');
    }
  }

  private static async handleReport(
    args: string[],
    addLine: (content: string, type: TerminalLine['type']) => void,
    addLines: (lines: TerminalLine[]) => void
  ): Promise<void> {
    if (!this.sessionData.target) {
      addLine('[ERROR] No assessment data available. Perform scans first.', 'error');
      return;
    }

    addLine('[REPORT] Compiling assessment data...', 'system');
    await this.delay(1000);

    const report = this.generateReport();
    const reportLines: TerminalLine[] = [
      { id: Date.now().toString(), content: '', type: 'output' },
      { id: (Date.now() + 1).toString(), content: '=== PENETRATION TEST REPORT ===', type: 'success' },
      { id: (Date.now() + 2).toString(), content: '', type: 'output' },
      ...report.split('\n').map((line, index) => ({
        id: (Date.now() + 3 + index).toString(),
        content: line,
        type: 'output' as const
      }))
    ];

    addLines(reportLines);
  }

  private static handleExit(addLine: (content: string, type: TerminalLine['type']) => void): void {
    addLine('[SYSTEM] Wiping logs and shredding temporary files...', 'system');
    addLine('[SYSTEM] Neural core shutting down...', 'system');
    addLine('[SYSTEM] Goodbye, Operator.', 'success');
  }

  private static isShellCommand(cmd: string): boolean {
    return ['whoami', 'ls', 'cat', 'pwd', 'exit', 'id', 'ps', 'netstat'].includes(cmd);
  }

  private static async handleShellCommand(
    command: string,
    addLine: (content: string, type: TerminalLine['type']) => void
  ): Promise<void> {
    const args = command.trim().split(' ');
    const cmd = args[0];

    await this.delay(300);

    switch (cmd) {
      case 'whoami':
        addLine('root', 'success');
        break;
      case 'id':
        addLine('uid=0(root) gid=0(root) groups=0(root)', 'success');
        break;
      case 'pwd':
        addLine('/root', 'output');
        break;
      case 'ls':
        addLine('Documents  Downloads  exploit.py  passwords.txt  sensitive_data/', 'output');
        break;
      case 'ps':
        addLine('PID TTY          TIME CMD', 'output');
        addLine('  1 ?        00:00:01 systemd', 'output');
        addLine(' 1337 pts/0   00:00:00 bash', 'output');
        break;
      case 'cat':
        if (args[1] === 'passwords.txt') {
          addLine('admin:password123', 'warning');
          addLine('user:qwerty', 'warning');
          addLine('root:toor', 'warning');
        } else {
          addLine(`cat: ${args[1] || 'file'}: No such file or directory`, 'error');
        }
        break;
      case 'exit':
        this.sessionData.compromisedShell = false;
        addLine('[+] Exiting shell. Returning to Shadowfall interface.', 'system');
        break;
      default:
        addLine(`bash: ${cmd}: command not found`, 'error');
    }
  }

  private static generateScanResults(target: string, ports: string, scanType: string): ScanResult[] {
    const commonServices = [
      { port: '22/tcp', service: 'ssh', version: 'OpenSSH 8.2p1' },
      { port: '80/tcp', service: 'http', version: 'nginx 1.18.0' },
      { port: '443/tcp', service: 'ssl/http', version: 'nginx 1.18.0' },
      { port: '21/tcp', service: 'ftp', version: 'vsftpd 3.0.3' },
      { port: '25/tcp', service: 'smtp', version: 'Postfix smtpd' },
      { port: '53/tcp', service: 'domain', version: 'ISC BIND 9.16.1' },
      { port: '135/tcp', service: 'msrpc', version: 'Microsoft Windows RPC' },
      { port: '445/tcp', service: 'microsoft-ds', version: 'Windows Server 2019' },
      { port: '3389/tcp', service: 'ms-wbt-server', version: 'Microsoft Terminal Services' },
      { port: '5432/tcp', service: 'postgresql', version: 'PostgreSQL DB 13.7' },
      { port: '3306/tcp', service: 'mysql', version: 'MySQL 8.0.30' },
      { port: '8080/tcp', service: 'http-proxy', version: 'Apache Tomcat 9.0.65' },
    ];

    // Randomly select 4-8 services
    const selectedServices = commonServices
      .sort(() => Math.random() - 0.5)
      .slice(0, Math.floor(Math.random() * 5) + 4);

    return selectedServices.map(service => ({
      port: service.port,
      state: Math.random() > 0.3 ? 'OPEN' : Math.random() > 0.5 ? 'FILTERED' : 'CLOSED',
      service: service.service,
      version: service.version
    }));
  }

  private static generateVulnerabilities(): Vulnerability[] {
    const vulnDatabase = [
      {
        cve: 'CVE-2021-44228',
        title: 'Log4Shell RCE',
        severity: 'CRITICAL' as const,
        port: '8080',
        description: 'Remote code execution in Apache Log4j'
      },
      {
        cve: 'CVE-2022-22965',
        title: 'Spring4Shell RCE',
        severity: 'CRITICAL' as const,
        port: '8080',
        description: 'Remote code execution in Spring Framework'
      },
      {
        cve: 'CVE-2021-34527',
        title: 'PrintNightmare',
        severity: 'HIGH' as const,
        port: '445',
        description: 'Windows Print Spooler privilege escalation'
      },
      {
        cve: 'CVE-2019-0708',
        title: 'BlueKeep RDP RCE',
        severity: 'HIGH' as const,
        port: '3389',
        description: 'Remote Desktop Services remote code execution'
      },
      {
        cve: 'CVE-2020-1472',
        title: 'Zerologon',
        severity: 'CRITICAL' as const,
        port: '445',
        description: 'Netlogon privilege escalation vulnerability'
      },
      {
        cve: 'CVE-2021-3156',
        title: 'Sudo Baron Samedit',
        severity: 'HIGH' as const,
        port: '22',
        description: 'Local privilege escalation via sudo'
      },
    ];

    // Return 2-4 random vulnerabilities
    return vulnDatabase
      .sort(() => Math.random() - 0.5)
      .slice(0, Math.floor(Math.random() * 3) + 2);
  }

  private static generateReport(): string {
    const { target, scanResults, vulnerabilities, exploitHistory } = this.sessionData;
    const openPorts = scanResults.filter(r => r.state === 'OPEN');
    
    return `
TARGET: ${target}
DATE: ${new Date().toLocaleDateString()}
TIME: ${new Date().toLocaleTimeString()}

EXECUTIVE SUMMARY
=================
Target ${target} was assessed for security vulnerabilities. The assessment 
identified ${openPorts.length} open ports and ${vulnerabilities.length} security vulnerabilities, 
including ${vulnerabilities.filter(v => v.severity === 'CRITICAL').length} critical-severity issues.

METHODOLOGY
===========
1. Network reconnaissance and port scanning
2. Service enumeration and version detection  
3. Vulnerability assessment using known CVE database
4. Exploitation attempts on discovered vulnerabilities
5. Post-exploitation activities (if applicable)

DETAILED FINDINGS
=================

Open Ports:
-----------
${openPorts.map(port => `${port.port} - ${port.service} (${port.version || 'Unknown'})`).join('\n')}

Vulnerabilities:
----------------
${vulnerabilities.map(v => `[${v.severity}] ${v.cve} - ${v.title}\n    Description: ${v.description}`).join('\n\n')}

${exploitHistory.length > 0 ? `
EXPLOITATION RESULTS
====================
Successfully exploited: ${exploitHistory.join(', ')}
System access: ${this.sessionData.compromisedShell ? 'ACHIEVED' : 'NOT ACHIEVED'}
` : ''}

RECOMMENDATIONS
===============
1. Patch all identified vulnerabilities immediately
2. Implement network segmentation and firewall rules
3. Enable logging and monitoring for suspicious activities
4. Conduct regular security assessments
5. Implement multi-factor authentication where possible
6. Update security policies and procedures

END OF REPORT
    `.trim();
  }

  private static delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}