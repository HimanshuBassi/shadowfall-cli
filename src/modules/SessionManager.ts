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
  scanTimestamp?: string;
  vulnScanTimestamp?: string;
}

export class SessionManager {
  private static sessionData: SessionData = {
    target: null,
    scanResults: [],
    vulnerabilities: [],
    exploitHistory: [],
    compromisedShell: false
  };

  static getSessionData(): SessionData {
    return this.sessionData;
  }

  static setTarget(target: string): void {
    this.sessionData.target = target;
  }

  static setScanResults(results: ScanResult[]): void {
    this.sessionData.scanResults = results;
    this.sessionData.scanTimestamp = new Date().toISOString();
  }

  static setVulnerabilities(vulnerabilities: Vulnerability[]): void {
    this.sessionData.vulnerabilities = vulnerabilities;
    this.sessionData.vulnScanTimestamp = new Date().toISOString();
  }

  static addExploit(cveId: string): void {
    this.sessionData.exploitHistory.push(cveId);
  }

  static setCompromisedShell(status: boolean): void {
    this.sessionData.compromisedShell = status;
  }

  static clearSession(): void {
    this.sessionData = {
      target: null,
      scanResults: [],
      vulnerabilities: [],
      exploitHistory: [],
      compromisedShell: false
    };
  }
}

export type { ScanResult, Vulnerability, SessionData };