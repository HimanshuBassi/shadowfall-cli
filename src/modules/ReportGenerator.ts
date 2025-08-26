import jsPDF from 'jspdf';
import { SessionManager } from './SessionManager';

interface TerminalLine {
  id: string;
  content: string;
  type: 'system' | 'user' | 'output' | 'error' | 'success' | 'warning';
  timestamp?: string;
}

export class ReportGenerator {
  private static delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  static async generateReport(
    args: string[],
    addLine: (content: string, type: TerminalLine['type']) => void,
    addLines: (lines: TerminalLine[]) => void
  ): Promise<void> {
    const sessionData = SessionManager.getSessionData();

    if (!sessionData.target) {
      addLine('[ERROR] No assessment data available. Perform scans first.', 'error');
      addLine('[INFO] Usage: report generate [-format pdf|text]', 'output');
      return;
    }

    let format = 'pdf'; // Default to PDF
    
    // Parse arguments
    for (let i = 1; i < args.length; i++) {
      if (args[i] === 'generate') continue;
      if (args[i] === '-format' && args[i + 1]) {
        format = args[i + 1].toLowerCase();
        i++;
      }
    }

    if (!['pdf', 'text'].includes(format)) {
      addLine('[ERROR] Invalid format. Use: pdf or text', 'error');
      return;
    }

    addLine('[REPORT] Compiling assessment data...', 'system');
    await this.delay(800);
    addLine('[REPORT] Generating executive summary...', 'warning');
    await this.delay(1000);
    addLine('[REPORT] Processing vulnerability data...', 'warning');
    await this.delay(1200);

    if (format === 'pdf') {
      await this.generatePDFReport(sessionData, addLine, addLines);
    } else {
      await this.generateTextReport(sessionData, addLine, addLines);
    }
  }

  private static async generatePDFReport(
    sessionData: any,
    addLine: (content: string, type: TerminalLine['type']) => void,
    addLines: (lines: TerminalLine[]) => void
  ): Promise<void> {
    addLine('[REPORT] Creating PDF document...', 'warning');
    await this.delay(1500);

    try {
      const pdf = new jsPDF();
      const pageWidth = pdf.internal.pageSize.getWidth();
      let yPosition = 20;

      // Helper function to add text with line wrapping
      const addTextLine = (text: string, fontSize: number = 12, isBold: boolean = false) => {
        if (yPosition > 270) {
          pdf.addPage();
          yPosition = 20;
        }
        
        pdf.setFontSize(fontSize);
        if (isBold) {
          pdf.setFont(undefined, 'bold');
        } else {
          pdf.setFont(undefined, 'normal');
        }
        
        const lines = pdf.splitTextToSize(text, pageWidth - 40);
        pdf.text(lines, 20, yPosition);
        yPosition += lines.length * (fontSize * 0.35) + 5;
      };

      // Title Page
      pdf.setFontSize(24);
      pdf.setFont(undefined, 'bold');
      pdf.text('PROJECT HIMANSHU PENETRATION', 20, 30);
      pdf.text('SECURITY ASSESSMENT REPORT', 20, 45);

      pdf.setFontSize(16);
      pdf.setFont(undefined, 'normal');
      pdf.text(`Target: ${sessionData.target}`, 20, 70);
      pdf.text(`Date: ${new Date().toLocaleDateString()}`, 20, 85);
      pdf.text(`Time: ${new Date().toLocaleTimeString()}`, 20, 100);

      yPosition = 120;

      // Executive Summary
      addTextLine('EXECUTIVE SUMMARY', 18, true);
      const openPorts = sessionData.scanResults.filter((r: any) => r.state === 'OPEN');
      const criticalVulns = sessionData.vulnerabilities.filter((v: any) => v.severity === 'CRITICAL');
      const highVulns = sessionData.vulnerabilities.filter((v: any) => v.severity === 'HIGH');

      addTextLine(`Target ${sessionData.target} was assessed for security vulnerabilities. The assessment identified ${openPorts.length} open ports and ${sessionData.vulnerabilities.length} security vulnerabilities, including ${criticalVulns.length} critical-severity and ${highVulns.length} high-severity issues.`);

      if (sessionData.exploitHistory.length > 0) {
        addTextLine(`${sessionData.exploitHistory.length} successful exploitations were performed, demonstrating the impact of the discovered vulnerabilities.`);
      }

      // Risk Assessment
      addTextLine('', 12); // Add space
      addTextLine('RISK ASSESSMENT', 16, true);
      let riskLevel = 'LOW';
      if (criticalVulns.length > 0) riskLevel = 'CRITICAL';
      else if (highVulns.length > 0) riskLevel = 'HIGH';
      else if (sessionData.vulnerabilities.length > 0) riskLevel = 'MEDIUM';

      addTextLine(`Overall Risk Level: ${riskLevel}`, 14, true);

      // Methodology
      addTextLine('', 12);
      addTextLine('METHODOLOGY', 16, true);
      addTextLine('1. Network reconnaissance and port scanning');
      addTextLine('2. Service enumeration and version detection');
      addTextLine('3. Vulnerability assessment using CVE database');
      addTextLine('4. Exploitation attempts on discovered vulnerabilities');
      addTextLine('5. Post-exploitation activities (if applicable)');

      // Detailed Findings
      addTextLine('', 12);
      addTextLine('DETAILED FINDINGS', 16, true);

      // Open Ports Section
      addTextLine('Open Ports:', 14, true);
      if (openPorts.length > 0) {
        openPorts.forEach((port: any) => {
          addTextLine(`${port.port} - ${port.service} (${port.version || 'Unknown'})`);
        });
      } else {
        addTextLine('No open ports detected.');
      }

      // Vulnerabilities Section
      addTextLine('', 12);
      addTextLine('Vulnerabilities:', 14, true);
      if (sessionData.vulnerabilities.length > 0) {
        sessionData.vulnerabilities.forEach((vuln: any) => {
          addTextLine(`[${vuln.severity}] ${vuln.cve} - ${vuln.title}`, 12, true);
          addTextLine(`Port: ${vuln.port || 'Multiple'}`);
          addTextLine(`Description: ${vuln.description}`);
          addTextLine(''); // Add space between vulnerabilities
        });
      } else {
        addTextLine('No vulnerabilities detected.');
      }

      // Exploitation Results
      if (sessionData.exploitHistory.length > 0) {
        addTextLine('EXPLOITATION RESULTS', 16, true);
        addTextLine('The following vulnerabilities were successfully exploited:');
        sessionData.exploitHistory.forEach((cve: string) => {
          const vuln = sessionData.vulnerabilities.find((v: any) => v.cve === cve);
          if (vuln) {
            addTextLine(`✓ ${cve} - ${vuln.title}`, 12, true);
          }
        });
      }

      // Recommendations
      addTextLine('', 12);
      addTextLine('RECOMMENDATIONS', 16, true);
      addTextLine('1. Immediately patch all critical and high-severity vulnerabilities');
      addTextLine('2. Implement network segmentation to limit attack surface');
      addTextLine('3. Deploy intrusion detection/prevention systems');
      addTextLine('4. Conduct regular security assessments');
      addTextLine('5. Implement security awareness training for staff');
      addTextLine('6. Review and update incident response procedures');

      // Save the PDF
      const pdfBlob = pdf.output('blob');
      const pdfUrl = URL.createObjectURL(pdfBlob);
      
      // Create download link
      const link = document.createElement('a');
      link.href = pdfUrl;
      link.download = `Himanshu_Penetration_Report_${sessionData.target}_${new Date().toISOString().split('T')[0]}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(pdfUrl);

      const successLines: TerminalLine[] = [
        { id: Date.now().toString(), content: '', type: 'output' },
        { id: (Date.now() + 1).toString(), content: '╔═══════════════════════════════════════════════════════════╗', type: 'success' },
        { id: (Date.now() + 2).toString(), content: '║                  REPORT GENERATED                         ║', type: 'success' },
        { id: (Date.now() + 3).toString(), content: '╚═══════════════════════════════════════════════════════════╝', type: 'success' },
        { id: (Date.now() + 4).toString(), content: '', type: 'output' },
        { id: (Date.now() + 5).toString(), content: '[SUCCESS] PDF report generated and downloaded successfully!', type: 'success' },
        { id: (Date.now() + 6).toString(), content: `[INFO] Filename: Himanshu_Penetration_Report_${sessionData.target}_${new Date().toISOString().split('T')[0]}.pdf`, type: 'output' },
        { id: (Date.now() + 7).toString(), content: '[INFO] Report includes executive summary, findings, and recommendations.', type: 'output' },
        { id: (Date.now() + 8).toString(), content: '', type: 'output' },
      ];

      addLines(successLines);

    } catch (error) {
      addLine('[ERROR] Failed to generate PDF report. Falling back to text format.', 'error');
      await this.generateTextReport(sessionData, addLine, addLines);
    }
  }

  private static async generateTextReport(
    sessionData: any,
    addLine: (content: string, type: TerminalLine['type']) => void,
    addLines: (lines: TerminalLine[]) => void
  ): Promise<void> {
    const { target, scanResults, vulnerabilities, exploitHistory } = sessionData;
    const openPorts = scanResults.filter((r: any) => r.state === 'OPEN');
    
    const report = `
TARGET: ${target}
DATE: ${new Date().toLocaleDateString()}
TIME: ${new Date().toLocaleTimeString()}

EXECUTIVE SUMMARY
=================
Target ${target} was assessed for security vulnerabilities. The assessment 
identified ${openPorts.length} open ports and ${vulnerabilities.length} security vulnerabilities, 
including ${vulnerabilities.filter((v: any) => v.severity === 'CRITICAL').length} critical-severity issues.

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
${openPorts.map((port: any) => `${port.port} - ${port.service} (${port.version || 'Unknown'})`).join('\n')}

Vulnerabilities:
----------------
${vulnerabilities.map((v: any) => `[${v.severity}] ${v.cve} - ${v.title}\n    Description: ${v.description}`).join('\n\n')}

${exploitHistory.length > 0 ? `
EXPLOITATION RESULTS
====================
Successfully exploited vulnerabilities:
${exploitHistory.map((cve: string) => `- ${cve}`).join('\n')}
` : ''}

RECOMMENDATIONS
===============
1. Immediately patch all critical and high-severity vulnerabilities
2. Implement network segmentation to limit attack surface
3. Deploy intrusion detection/prevention systems
4. Conduct regular security assessments
5. Implement security awareness training for staff

END OF REPORT
=============
Generated by Project Himanshu Penetration Suite
    `;

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
}