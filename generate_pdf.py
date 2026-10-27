import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def generate_pdf():
    pdf_filename = "SENTINEL-X_Project_Report.pdf"
    
    # 0.35 inch margins to ensure a crisp single-page fit
    doc = SimpleDocTemplate(
        pdf_filename,
        pagesize=letter,
        leftMargin=0.38 * inch,
        rightMargin=0.38 * inch,
        topMargin=0.35 * inch,
        bottomMargin=0.35 * inch
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=15,
        textColor=colors.HexColor('#0f172a')
    )
    subtitle_style = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9,
        textColor=colors.HexColor('#0284c7'),
        textTransform='uppercase'
    )
    badge_style = ParagraphStyle(
        'DocBadge',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7,
        leading=8,
        textColor=colors.HexColor('#0369a1'),
        alignment=2 # Right aligned
    )
    h2_style = ParagraphStyle(
        'Heading2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=10,
        textColor=colors.HexColor('#0369a1'),
        spaceBefore=4,
        spaceAfter=2,
        textTransform='uppercase'
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor('#334155'),
        alignment=4 # Justified
    )
    bullet_style = ParagraphStyle(
        'Bullet',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.2,
        leading=9,
        textColor=colors.HexColor('#334155'),
        leftIndent=10
    )
    table_text = ParagraphStyle(
        'TableText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=6.8,
        leading=8.2,
        textColor=colors.HexColor('#334155')
    )
    table_head = ParagraphStyle(
        'TableHead',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7,
        leading=8.5,
        textColor=colors.HexColor('#0f172a')
    )

    story = []

    # Header Row Table
    header_data = [
        [
            Paragraph("<b>SENTINEL-X | ONE-PAGE PROJECT REPORT</b>", title_style),
            Paragraph("<b>ACADEMIC & INDUSTRIAL REVIEW</b>", badge_style)
        ],
        [
            Paragraph("ENTERPRISE DETECTION ENGINEERING & SOC AUTOMATION (SIEM/SOAR) PLATFORM", subtitle_style),
            Paragraph("October 2026", badge_style)
        ]
    ]
    t_header = Table(header_data, colWidths=[5.4 * inch, 2.0 * inch])
    t_header.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 1),
        ('TOPPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(t_header)
    story.append(Spacer(1, 2))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=4, spaceBefore=2))

    # 1. Project Title
    story.append(Paragraph("<b>1. Project Title</b>", h2_style))
    story.append(Paragraph("<b>SENTINEL-X: Enterprise-Style Detection Engineering & SOC Automation (SIEM/SOAR) Platform</b>", body_style))

    # 2. Why Did You Choose This Project?
    story.append(Paragraph("<b>2. Why Did You Choose This Project?</b>", h2_style))
    story.append(Paragraph(
        "Modern enterprise Security Operations Centers (SOCs) are overwhelmed by millions of raw, disparate logs (Linux, Windows Active Directory, network firewalls). Manually triaging logs causes alert fatigue and inflates Mean Time to Detect (MTTD) and Respond (MTTR). I chose this project to acquire hands-on mastery in <b>Detection Engineering, SIEM architecture, and SOAR automation</b>—the primary disciplines deployed by Tier-1 defense teams (CrowdStrike, Splunk, Palo Alto Cortex). Building this platform directly bridges theoretical cybersecurity concepts with adversary behavior through the <b>MITRE ATT&CK® framework</b>.",
        body_style
    ))

    # 3. Technologies / Tools Used
    story.append(Paragraph("<b>3. Technologies & Tools Used</b>", h2_style))
    tech_data = [
        [
            Paragraph("<b>Backend & Engine:</b> Python 3.15, FastAPI (Async REST API)", table_text),
            Paragraph("<b>Normalization Schema:</b> OCSF & Elastic Common Schema (ECS)", table_text)
        ],
        [
            Paragraph("<b>Detection Logic:</b> YAML Sigma rules, Sliding Time Windows", table_text),
            Paragraph("<b>Threat Intelligence:</b> Offline GeoIP, ASN, C2 DB, CMDB Asset Inventory", table_text)
        ],
        [
            Paragraph("<b>Database:</b> SQLite with persistent JSON indexing", table_text),
            Paragraph("<b>Frontend UI:</b> Cyber SOC Dark-Mode Dashboard (Tailwind CSS, Chart.js)", table_text)
        ]
    ]
    t_tech = Table(tech_data, colWidths=[3.7 * inch, 3.7 * inch])
    t_tech.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_tech)

    # 4. How You Completed the Project
    story.append(Paragraph("<b>4. How You Completed the Project (Approach & Methodology)</b>", h2_style))
    story.append(Paragraph("• <b>Ingestion & Normalization:</b> Engineered regex & lookahead parsers converting heterogeneous logs (Linux <i>auth.log</i>, Windows EVTX <i>4624/4625/4688</i>, Zeek, Web access) into standardized <i>NormalizedEvent</i> objects.", bullet_style))
    story.append(Paragraph("• <b>Rule Authoring & Stateful Detection:</b> Authored 9 multi-domain rules (Authentication, Endpoint, Network) with an in-memory sliding-window manager supporting immediate triggers and thresholding (&ge; 5 events / 60s).", bullet_style))
    story.append(Paragraph("• <b>Automated Context Enrichment:</b> Computed composite risk scores (0–100) via Threat Intelligence (Tor nodes, C2 trackers) and CMDB asset criticality (Tier-0 Domain Controller vs. Workstation).", bullet_style))
    story.append(Paragraph("• <b>SOC Incident Management:</b> Built automated ticketing engine assembling <i>INC-2026-XXXX</i> tickets with correlated evidence logs, visual chronological attack timelines, and MITRE ATT&CK tags.", bullet_style))
    story.append(Paragraph("• <b>SOAR Automated Containment:</b> Implemented closed-loop playbooks (Edge Firewall IP drops, EDR network host isolation, Active Directory account lockout) with comprehensive audit logging.", bullet_style))
    story.append(Paragraph("• <b>Operations UI & Simulator:</b> Created a real-time dark-mode SOC Dashboard with live metrics, MITRE heatmap, and a 1-click Attack Simulator replaying real-world attack scenarios.", bullet_style))

    # 5. What You Learned
    story.append(Paragraph("<b>5. What You Learned (Key Technical Skills & Concepts Gained)</b>", h2_style))
    story.append(Paragraph("• <b>Detection Engineering:</b> Authoring and tuning production-grade YAML Sigma rules with threshold condition logic.", bullet_style))
    story.append(Paragraph("• <b>Stateful Stream Correlation:</b> Implementing in-memory sliding time windows and cooldowns to mitigate alert storms.", bullet_style))
    story.append(Paragraph("• <b>MITRE ATT&CK® Mapping:</b> Aligning adversary techniques (T1110.001 Brute Force, T1059.001 PowerShell, T1003.001 LSASS Dumping, T1490 Ransomware Recovery Inhibiting, T1071.001 C2 Web Protocols).", bullet_style))
    story.append(Paragraph("• <b>SOAR Incident Response:</b> Designing closed-loop automated playbooks that slash containment response times from hours to milliseconds.", bullet_style))

    # 6. Challenges Faced & Solutions
    story.append(Paragraph("<b>6. Challenges Faced & Solutions</b>", h2_style))
    chal_data = [
        [
            Paragraph("<b>Challenge Encountered</b>", table_head),
            Paragraph("<b>Root Cause</b>", table_head),
            Paragraph("<b>Engineering Solution Implemented</b>", table_head)
        ],
        [
            Paragraph("<b>Disparate Log Syntaxes</b>", table_text),
            Paragraph("Heterogeneous key-value syntax across Windows EVTX, Linux syslog, and Zeek.", table_text),
            Paragraph("Engineered lookahead regex parsers extracting entities into standardized OCSF schema.", table_text)
        ],
        [
            Paragraph("<b>Alert Fatigue & Flooding</b>", table_text),
            Paragraph("High-frequency attacks triggered duplicate tickets per failed attempt.", table_text),
            Paragraph("Implemented stateful sliding-window pruning with 30s entity suppression cooldowns.", table_text)
        ],
        [
            Paragraph("<b>Python 3.15 Compatibility</b>", table_text),
            Paragraph("Standard PyYAML lacked pre-built binary wheels on Windows.", table_text),
            Paragraph("Integrated pure-Python StrictYAML, ensuring zero-compiler portability and stability.", table_text)
        ]
    ]
    t_chal = Table(chal_data, colWidths=[1.8 * inch, 2.7 * inch, 2.9 * inch])
    t_chal.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_chal)

    # 7. Final Outcome
    story.append(Paragraph("<b>7. Final Outcome</b>", h2_style))
    story.append(Paragraph(
        "Successfully delivered a production-style, self-contained <b>Enterprise SOC & Detection Platform</b> with a 100% automated <i>Log &rarr; Detection &rarr; Alert &rarr; Enrichment &rarr; Incident Ticket &rarr; SOAR Containment</i> pipeline, a modern dark-mode Cyber Operations Dashboard running at <b>http://localhost:8000</b>, a 1-click live attack simulation center, and <b>11/11 automated unit and integration tests passing in under 1 second</b>.",
        body_style
    ))

    story.append(Spacer(1, 3))
    story.append(HRFlowable(width="100%", thickness=0.8, color=colors.HexColor('#e2e8f0'), spaceAfter=2, spaceBefore=2))
    
    # Footer
    footer_data = [
        [
            Paragraph("Cybersecurity & SOC Detection Engineering | Intern Submission", table_text),
            Paragraph("Status: Verified & Operational &bull; 100% Test Pass Rate", ParagraphStyle('FRight', parent=table_text, alignment=2))
        ]
    ]
    t_footer = Table(footer_data, colWidths=[4.4 * inch, 3.0 * inch])
    t_footer.setStyle(TableStyle([
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(t_footer)

    doc.build(story)
    print(f"[+] Successfully generated: {os.path.abspath(pdf_filename)}")

if __name__ == "__main__":
    generate_pdf()
