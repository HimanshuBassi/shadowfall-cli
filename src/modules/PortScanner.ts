import { SessionManager, type ScanResult } from './SessionManager';

interface TerminalLine {
  id: string;
  content: string;
  type: 'system' | 'user' | 'output' | 'error' | 'success' | 'warning';
  timestamp?: string;
}

export class PortScanner {
  private static delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  static async performScan(
    args: string[],
    addLine: (content: string, type: TerminalLine['type']) => void,
    addLines: (lines: TerminalLine[]) => void
  ): Promise<void> {
    if (args.length < 2) {
      addLine('[ERROR] Usage: scan <target> [-p <ports>] [-type <scan_type>]', 'error');
      addLine('[INFO] Example: scan 192.168.1.1 -p 1-1000 -type stealth', 'output');
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

    // Validate scan type
    if (!['quick', 'stealth', 'comprehensive'].includes(scanType)) {
      addLine('[ERROR] Invalid scan type. Use: quick, stealth, or comprehensive', 'error');
      return;
    }

    SessionManager.setTarget(target);
    
    addLine(`[RECON] Initializing ${scanType} scan on target: ${target}`, 'system');
    addLine(`[RECON] Port range: ${ports} | Scan type: ${scanType.toUpperCase()}`, 'system');
    addLine('', 'output');

    // Simulate scanning progress based on scan type
    await this.simulateScanProgress(scanType, addLine);

    // Generate realistic scan results
    const scanResults = this.generateScanResults(target, ports, scanType);
    SessionManager.setScanResults(scanResults);

    // Display results in organized format
    this.displayScanResults(scanResults, addLines);
  }

  private static async simulateScanProgress(
    scanType: string,
    addLine: (content: string, type: TerminalLine['type']) => void
  ): Promise<void> {
    switch (scanType) {
      case 'quick':
        addLine('[SCANNING] TCP connect scan initiated...', 'warning');
        await this.delay(800);
        addLine('[SCANNING] Probing common ports...', 'warning');
        await this.delay(1200);
        break;
      
      case 'stealth':
        addLine('[SCANNING] SYN stealth scan initiated...', 'warning');
        await this.delay(1000);
        addLine('[SCANNING] Crafting SYN packets...', 'warning');
        await this.delay(1500);
        addLine('[SCANNING] Analyzing responses...', 'warning');
        await this.delay(800);
        break;
      
      case 'comprehensive':
        addLine('[SCANNING] Comprehensive scan initiated...', 'warning');
        await this.delay(1000);
        addLine('[SCANNING] TCP SYN scan in progress...', 'warning');
        await this.delay(1500);
        addLine('[SCANNING] UDP scan in progress...', 'warning');
        await this.delay(2000);
        addLine('[SCANNING] Service version detection...', 'warning');
        await this.delay(1800);
        break;
    }
  }

  private static displayScanResults(
    scanResults: ScanResult[],
    addLines: (lines: TerminalLine[]) => void
  ): void {
    const openPorts = scanResults.filter(r => r.state === 'OPEN');
    const filteredPorts = scanResults.filter(r => r.state === 'FILTERED');
    
    const resultLines: TerminalLine[] = [
      { id: Date.now().toString(), content: '', type: 'output' },
      { id: (Date.now() + 1).toString(), content: '╔═══════════════════════════════════════════════════════════╗', type: 'success' },
      { id: (Date.now() + 2).toString(), content: '║                    SCAN RESULTS                           ║', type: 'success' },
      { id: (Date.now() + 3).toString(), content: '╚═══════════════════════════════════════════════════════════╝', type: 'success' },
      { id: (Date.now() + 4).toString(), content: '', type: 'output' },
      { id: (Date.now() + 5).toString(), content: 'PORT     STATE    SERVICE       VERSION', type: 'success' },
      { id: (Date.now() + 6).toString(), content: '-------- -------- ------------- ---------------------', type: 'success' },
    ];

    scanResults.forEach((result, index) => {
      const line = `${result.port.padEnd(8)} ${result.state.padEnd(8)} ${result.service.padEnd(13)} ${result.version || 'Unknown'}`;
      const lineType = result.state === 'OPEN' ? 'success' : 
                      result.state === 'FILTERED' ? 'warning' : 'output';
      
      resultLines.push({
        id: (Date.now() + 7 + index).toString(),
        content: line,
        type: lineType
      });
    });

    resultLines.push({ id: (Date.now() + 100).toString(), content: '', type: 'output' });
    resultLines.push({ 
      id: (Date.now() + 101).toString(), 
      content: `[COMPLETE] Scan finished. ${openPorts.length} open ports | ${filteredPorts.length} filtered ports detected.`, 
      type: 'success' 
    });

    if (openPorts.length > 0) {
      resultLines.push({
        id: (Date.now() + 102).toString(),
        content: '[INFO] Run "vuln <target>" to analyze discovered services for vulnerabilities.',
        type: 'output'
      });
    }

    addLines(resultLines);
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
      { port: '1433/tcp', service: 'ms-sql-s', version: 'Microsoft SQL Server 2019' },
      { port: '6379/tcp', service: 'redis', version: 'Redis 6.2.5' },
      { port: '27017/tcp', service: 'mongodb', version: 'MongoDB 5.0.9' },
    ];

    // Determine number of services based on scan type
    let serviceCount = 4;
    if (scanType === 'comprehensive') serviceCount = 8;
    else if (scanType === 'stealth') serviceCount = 6;

    // Randomly select services
    const selectedServices = commonServices
      .sort(() => Math.random() - 0.5)
      .slice(0, Math.floor(Math.random() * 3) + serviceCount);

    return selectedServices.map(service => {
      let state: 'OPEN' | 'CLOSED' | 'FILTERED';
      
      // Adjust probabilities based on scan type
      if (scanType === 'comprehensive') {
        state = Math.random() > 0.2 ? 'OPEN' : Math.random() > 0.6 ? 'FILTERED' : 'CLOSED';
      } else if (scanType === 'stealth') {
        state = Math.random() > 0.4 ? 'OPEN' : Math.random() > 0.5 ? 'FILTERED' : 'CLOSED';
      } else {
        state = Math.random() > 0.3 ? 'OPEN' : Math.random() > 0.5 ? 'FILTERED' : 'CLOSED';
      }

      return {
        port: service.port,
        state,
        service: service.service,
        version: service.version
      };
    });
  }
}