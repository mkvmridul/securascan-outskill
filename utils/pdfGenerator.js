import PDFDocument from 'pdfkit';
import { createWriteStream } from 'fs';

/**
 * Generate a PDF security report
 * @param {Object} report - The security scan report
 * @param {string} outputPath - Path to save the PDF
 * @returns {Promise<void>}
 */
export function generatePDF(report, outputPath) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ 
      size: 'A4',
      margins: { top: 50, bottom: 50, left: 50, right: 50 }
    });
    
    const stream = createWriteStream(outputPath);
    doc.pipe(stream);
    
    // Colors
    const colors = {
      primary: '#1a365d',
      critical: '#c53030',
      high: '#dd6b20',
      medium: '#d69e2e',
      low: '#38a169',
      gray: '#4a5568',
      lightGray: '#e2e8f0'
    };
    
    // Header
    doc.rect(0, 0, doc.page.width, 120).fill(colors.primary);
    doc.fillColor('white')
       .fontSize(28)
       .font('Helvetica-Bold')
       .text('🔒 SECURASCAN', 50, 40);
    doc.fontSize(14)
       .font('Helvetica')
       .text('AI-Powered Security Assessment Report', 50, 75);
    doc.fontSize(10)
       .text(`Generated: ${new Date().toLocaleString()}`, 50, 95);
    
    doc.moveDown(4);
    
    // Risk Score Box
    const riskScore = report.risk_score || 0;
    const riskColor = riskScore >= 75 ? colors.critical : 
                      riskScore >= 50 ? colors.high : 
                      riskScore >= 25 ? colors.medium : colors.low;
    
    doc.fillColor(colors.primary)
       .fontSize(16)
       .font('Helvetica-Bold')
       .text('RISK SCORE', 50, 140);
    
    doc.rect(50, 165, 150, 60).fill(riskColor);
    doc.fillColor('white')
       .fontSize(32)
       .font('Helvetica-Bold')
       .text(`${riskScore}/100`, 70, 180);
    
    // Findings Summary
    const meta = report.scan_metadata || {};
    doc.fillColor(colors.primary)
       .fontSize(16)
       .font('Helvetica-Bold')
       .text('FINDINGS SUMMARY', 250, 140);
    
    doc.fontSize(11).font('Helvetica');
    doc.fillColor(colors.critical).text(`Critical: ${meta.critical || 0}`, 250, 170);
    doc.fillColor(colors.high).text(`High: ${meta.high || 0}`, 250, 185);
    doc.fillColor(colors.medium).text(`Medium: ${meta.medium || 0}`, 250, 200);
    doc.fillColor(colors.low).text(`Low: ${meta.low || 0}`, 250, 215);
    
    // Triage Info
    const triage = report.triage || {};
    doc.fillColor(colors.primary)
       .fontSize(16)
       .font('Helvetica-Bold')
       .text('APPLICATION INFO', 400, 140);
    
    doc.fontSize(10).font('Helvetica').fillColor(colors.gray);
    doc.text(`Type: ${triage.app_type || 'Unknown'}`, 400, 170);
    doc.text(`Languages: ${(triage.languages || []).join(', ') || 'N/A'}`, 400, 185);
    doc.text(`Frameworks: ${(triage.frameworks || []).join(', ') || 'N/A'}`, 400, 200);
    doc.text(`Risk Level: ${triage.overall_risk_level || 'Unknown'}`, 400, 215);
    
    // Executive Summary
    doc.moveDown(2);
    let yPos = 260;
    
    doc.fillColor(colors.primary)
       .fontSize(16)
       .font('Helvetica-Bold')
       .text('EXECUTIVE SUMMARY', 50, yPos);
    
    yPos += 25;
    doc.fontSize(11)
       .font('Helvetica')
       .fillColor(colors.gray)
       .text(report.executive_summary || 'No summary available.', 50, yPos, { 
         width: doc.page.width - 100,
         align: 'justify'
       });
    
    yPos = doc.y + 30;
    
    // Top Priority Actions
    if (report.top_priority_actions?.length > 0) {
      doc.fillColor(colors.primary)
         .fontSize(16)
         .font('Helvetica-Bold')
         .text('TOP PRIORITY ACTIONS', 50, yPos);
      
      yPos += 25;
      
      for (const action of report.top_priority_actions.slice(0, 3)) {
        if (yPos > doc.page.height - 100) {
          doc.addPage();
          yPos = 50;
        }
        
        doc.rect(50, yPos, doc.page.width - 100, 50).fill(colors.lightGray);
        doc.fillColor(colors.critical)
           .fontSize(12)
           .font('Helvetica-Bold')
           .text(`#${action.priority}`, 60, yPos + 10);
        
        doc.fillColor(colors.gray)
           .fontSize(10)
           .font('Helvetica')
           .text(`${action.file}:${action.line}`, 90, yPos + 10);
        
        doc.fillColor(colors.primary)
           .text(action.action || '', 60, yPos + 28, { width: doc.page.width - 130 });
        
        yPos += 60;
      }
    }
    
    // Detailed Findings
    if (report.findings?.length > 0) {
      if (yPos > doc.page.height - 150) {
        doc.addPage();
        yPos = 50;
      }
      
      doc.fillColor(colors.primary)
         .fontSize(16)
         .font('Helvetica-Bold')
         .text('DETAILED FINDINGS', 50, yPos);
      
      yPos += 30;
      
      for (const finding of report.findings) {
        if (yPos > doc.page.height - 120) {
          doc.addPage();
          yPos = 50;
        }
        
        const sevColor = finding.severity === 'critical' ? colors.critical :
                         finding.severity === 'high' ? colors.high :
                         finding.severity === 'medium' ? colors.medium : colors.low;
        
        // Severity badge
        doc.rect(50, yPos, 70, 18).fill(sevColor);
        doc.fillColor('white')
           .fontSize(9)
           .font('Helvetica-Bold')
           .text(finding.severity?.toUpperCase() || 'UNKNOWN', 55, yPos + 4);
        
        // Finding type
        doc.fillColor(colors.primary)
           .fontSize(12)
           .font('Helvetica-Bold')
           .text(finding.type || 'Unknown', 130, yPos);
        
        yPos += 22;
        
        // File location
        doc.fillColor(colors.gray)
           .fontSize(9)
           .font('Helvetica')
           .text(`📁 ${finding.file || 'Unknown'}:${finding.line || '?'}`, 50, yPos);
        
        yPos += 15;
        
        // Description
        doc.fillColor(colors.gray)
           .fontSize(10)
           .font('Helvetica')
           .text(finding.description || '', 50, yPos, { 
             width: doc.page.width - 100,
             align: 'left'
           });
        
        yPos = doc.y + 8;
        
        // Remediation
        if (finding.remediation) {
          doc.fillColor(colors.low)
             .fontSize(9)
             .font('Helvetica-Bold')
             .text('→ Fix: ', 50, yPos, { continued: true })
             .font('Helvetica')
             .fillColor(colors.gray)
             .text(finding.remediation, { width: doc.page.width - 120 });
          
          yPos = doc.y + 8;
        }
        
        // Regulation risk
        if (finding.regulation_risk && finding.regulation_risk !== 'none') {
          doc.fillColor(colors.high)
             .fontSize(8)
             .font('Helvetica')
             .text(`⚠️ Regulation: ${finding.regulation_risk}`, 50, yPos);
          yPos = doc.y + 5;
        }
        
        // Divider
        doc.strokeColor(colors.lightGray)
           .moveTo(50, yPos + 5)
           .lineTo(doc.page.width - 50, yPos + 5)
           .stroke();
        
        yPos += 20;
      }
    }
    
    // OWASP Coverage
    if (report.owasp_coverage && Object.keys(report.owasp_coverage).length > 0) {
      if (yPos > doc.page.height - 200) {
        doc.addPage();
        yPos = 50;
      }
      
      doc.fillColor(colors.primary)
         .fontSize(16)
         .font('Helvetica-Bold')
         .text('OWASP 2025 COVERAGE', 50, yPos);
      
      yPos += 25;
      
      const owaspCategories = {
        'A01_Broken_Access_Control': 'A01: Broken Access Control',
        'A02_Cryptographic_Failures': 'A02: Cryptographic Failures',
        'A03_Injection': 'A03: Injection',
        'A04_Insecure_Design': 'A04: Insecure Design',
        'A05_Security_Misconfiguration': 'A05: Security Misconfiguration',
        'A06_Vulnerable_Components': 'A06: Vulnerable Components',
        'A07_Auth_Failures': 'A07: Auth Failures',
        'A08_Data_Integrity_Failures': 'A08: Data Integrity Failures',
        'A09_Logging_Failures': 'A09: Logging Failures',
        'A10_SSRF': 'A10: SSRF'
      };
      
      for (const [key, label] of Object.entries(owaspCategories)) {
        const count = report.owasp_coverage[key] || 0;
        const barWidth = Math.min(count * 20, 200);
        const barColor = count > 5 ? colors.critical : count > 2 ? colors.high : count > 0 ? colors.medium : colors.lightGray;
        
        doc.fillColor(colors.gray)
           .fontSize(9)
           .font('Helvetica')
           .text(label, 50, yPos, { width: 180 });
        
        doc.rect(230, yPos, barWidth || 5, 12).fill(barColor);
        doc.fillColor(count > 0 ? 'white' : colors.gray)
           .fontSize(8)
           .text(`${count}`, 235, yPos + 2);
        
        yPos += 18;
      }
    }
    
    // Footer
    const pages = doc.bufferedPageRange();
    for (let i = 0; i < pages.count; i++) {
      doc.switchToPage(i);
      doc.fillColor(colors.gray)
         .fontSize(8)
         .text(
           `SecuraScan Report | Page ${i + 1} of ${pages.count}`,
           50,
           doc.page.height - 30,
           { align: 'center', width: doc.page.width - 100 }
         );
    }
    
    doc.end();
    
    stream.on('finish', () => {
      console.log(`\x1b[32m[PDF]\x1b[0m Report saved to ${outputPath}`);
      resolve();
    });
    
    stream.on('error', reject);
  });
}
