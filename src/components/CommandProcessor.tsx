import { SessionManager } from '@/modules/SessionManager';
import { PortScanner } from '@/modules/PortScanner';
import { VulnerabilityScanner } from '@/modules/VulnerabilityScanner';
import { ExploitModule } from '@/modules/ExploitModule';
import { ReportGenerator } from '@/modules/ReportGenerator';

interface TerminalLine {
  id: string;
  content: string;
  type: 'system' | 'user' | 'output' | 'error' | 'success' | 'warning';
  timestamp?: string;
}

export class CommandProcessor {

  static async processCommand(
    command: string,
    addLine: (content: string, type: TerminalLine['type']) => void,
    addLines: (lines: TerminalLine[]) => void
  ): Promise<void> {
    const args = command.trim().split(' ');
    const cmd = args[0].toLowerCase();
    const sessionData = SessionManager.getSessionData();

    switch (cmd) {
      case 'help':
        this.showHelp(addLines);
        break;
      case 'scan':
        await PortScanner.performScan(args, addLine, addLines);
        break;
      case 'vuln':
        await VulnerabilityScanner.performVulnScan(args, addLine, addLines);
        break;
      case 'exploit':
        await ExploitModule.attemptExploit(args, addLine, addLines);
        break;
      case 'report':
        await ReportGenerator.generateReport(args, addLine, addLines);
        break;
      case 'clear':
        // This would be handled by the parent component
        addLine('[SYSTEM] Terminal cleared.', 'system');
        break;
      case 'exit':
        this.handleExit(addLine);
        break;
      default:
        if (sessionData.compromisedShell && ExploitModule.isShellCommand(cmd)) {
          await ExploitModule.handleShellCommand(command, addLine);
        } else {
          addLine(`[ERROR] Unknown command: '${cmd}'. Type 'help' for available commands.`, 'error');
        }
    }
  }

  private static showHelp(addLines: (lines: TerminalLine[]) => void): void {
    const helpLines: TerminalLine[] = [
      { id: Date.now().toString(), content: '', type: 'output' },
      { id: (Date.now() + 1).toString(), content: '╔═══════════════════════════════════════════════════════════╗', type: 'system' },
      { id: (Date.now() + 2).toString(), content: '║               PROJECT HIMANSHU PENETRATION                ║', type: 'system' },
      { id: (Date.now() + 3).toString(), content: '║                    COMMAND MODULES                        ║', type: 'system' },
      { id: (Date.now() + 4).toString(), content: '╚═══════════════════════════════════════════════════════════╝', type: 'system' },
      { id: (Date.now() + 5).toString(), content: '', type: 'output' },
      { id: (Date.now() + 6).toString(), content: '🔍 RECONNAISSANCE MODULE', type: 'warning' },
      { id: (Date.now() + 7).toString(), content: 'scan <target> [-p <ports>] [-type <scan_type>]', type: 'output' },
      { id: (Date.now() + 8).toString(), content: '  • Perform comprehensive port scanning', type: 'output' },
      { id: (Date.now() + 9).toString(), content: '  • Scan types: quick, stealth, comprehensive', type: 'output' },
      { id: (Date.now() + 10).toString(), content: '  • Example: scan 192.168.1.1 -p 1-1000 -type stealth', type: 'output' },
      { id: (Date.now() + 11).toString(), content: '', type: 'output' },
      { id: (Date.now() + 12).toString(), content: '🛡️ VULNERABILITY ASSESSMENT MODULE', type: 'warning' },
      { id: (Date.now() + 13).toString(), content: 'vuln <target> [-p <port>] [-deep]', type: 'output' },
      { id: (Date.now() + 14).toString(), content: '  • Analyze services for known vulnerabilities', type: 'output' },
      { id: (Date.now() + 15).toString(), content: '  • Cross-reference with CVE database', type: 'output' },
      { id: (Date.now() + 16).toString(), content: '  • Example: vuln 192.168.1.1 -p 80 -deep', type: 'output' },
      { id: (Date.now() + 17).toString(), content: '', type: 'output' },
      { id: (Date.now() + 18).toString(), content: '💥 EXPLOITATION MODULE', type: 'warning' },
      { id: (Date.now() + 19).toString(), content: 'exploit <CVE-ID> [-p <port>] [-payload <type>]', type: 'output' },
      { id: (Date.now() + 20).toString(), content: '  • Weaponize discovered vulnerabilities', type: 'output' },
      { id: (Date.now() + 21).toString(), content: '  • Payload types: default, reverse_shell', type: 'output' },
      { id: (Date.now() + 22).toString(), content: '  • Example: exploit CVE-2021-44228 -payload reverse_shell', type: 'output' },
      { id: (Date.now() + 23).toString(), content: '', type: 'output' },
      { id: (Date.now() + 24).toString(), content: '📊 REPORTING MODULE', type: 'warning' },
      { id: (Date.now() + 25).toString(), content: 'report generate [-format pdf|text]', type: 'output' },
      { id: (Date.now() + 26).toString(), content: '  • Generate comprehensive assessment reports', type: 'output' },
      { id: (Date.now() + 27).toString(), content: '  • PDF format includes executive summary', type: 'output' },
      { id: (Date.now() + 28).toString(), content: '  • Example: report generate -format pdf', type: 'output' },
      { id: (Date.now() + 29).toString(), content: '', type: 'output' },
      { id: (Date.now() + 30).toString(), content: '⚙️ SYSTEM COMMANDS', type: 'warning' },
      { id: (Date.now() + 31).toString(), content: 'clear - Clear terminal display', type: 'output' },
      { id: (Date.now() + 32).toString(), content: 'exit  - Terminate current session', type: 'output' },
      { id: (Date.now() + 33).toString(), content: '', type: 'output' },
    ];
    addLines(helpLines);
  }

  private static handleExit(addLine: (content: string, type: TerminalLine['type']) => void): void {
    SessionManager.clearSession();
    addLine('[SYSTEM] Wiping logs and shredding temporary files...', 'system');
    addLine('[SYSTEM] Neural core shutting down...', 'system');
    addLine('[SYSTEM] Goodbye, Operator.', 'success');
  }






    
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