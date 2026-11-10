"""Human-readable PDF from the same persisted evidence as the JSON export."""
from io import BytesIO
import json
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, LongTable, TableStyle


def render(report):
    output = BytesIO(); styles = getSampleStyleSheet(); story = []
    styles['BodyText'].fontSize = 9; styles['BodyText'].leading = 13
    styles['BodyText'].splitLongWords = True
    def p(value, style='BodyText'):
        # Untrusted filenames, metadata and source descriptions are plain text;
        # never pass ReportLab XML, images or external fetch instructions through.
        value = str(value).replace('\x00', '')
        return Paragraph(escape(value).replace('\n','<br/>'), styles[style])
    def add(value, style='BodyText'): story.append(p(value, style))
    def section(title): story.extend([Spacer(1,12),p(title,'Heading2')])
    def table(headers, rows, widths=None):
        if not rows:return
        content=[[p(c) for c in headers]]+[[p(c) for c in row] for row in rows]
        item=LongTable(content,colWidths=widths,repeatRows=1,hAlign='LEFT')
        item.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#e8edf3')),
            ('VALIGN',(0,0),(-1,-1),'TOP'),('LINEBELOW',(0,0),(-1,0),0.5,colors.HexColor('#8996aa')),
            ('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6)]))
        story.append(item)
    def short(value, limit=1500):
        text=value if isinstance(value,str) else json.dumps(value,ensure_ascii=False,default=str)
        return text if len(text)<=limit else text[:limit]+'… [full evidence in JSON]'
    engines={e['name']:e for e in report.get('engines',[])}
    data=lambda name:engines.get(name,{}).get('data',{})
    vulnerability=report.get('vulnerability_assessment',{}); identity=vulnerability.get('identity',{})
    sample=report.get('sample',{}); verdict=report.get('verdict',{})
    add('SentinelScan | Software analysis','Title')
    add(report.get('final_status',report.get('status','UNKNOWN')),'Heading2')
    add('Analysis '+report['analysis_id']+' · Generated '+str(report.get('generated_at','')))
    table(['File','Value'],[['Name',short(sample.get('filename',''),300)],['SHA-256',sample.get('sha256','')],
        ['Size',str(sample.get('size',''))+' bytes'],['Software',str(identity.get('name') or 'Unidentified')],
        ['Publisher / version',str(identity.get('vendor') or 'Unknown')+' / '+str(identity.get('version') or 'Unknown')],
        ['Architecture',identity.get('architecture') or data('static').get('architecture','Unknown')]], [105,410])
    section('Assessment')
    add('Malware assessment: '+verdict.get('security','INCONCLUSIVE')+' · Score '+str(verdict.get('score','unknown')))
    if verdict.get('overall_risk'):add('Overall risk: '+verdict['overall_risk'].replace('_',' '))
    approval=report.get('approval',{})
    add('Recommendation: '+approval.get('recommendation','REVIEW_REQUIRED'))
    for reason in approval.get('reasons',[]):add(reason)
    add('Vulnerability assessment: '+vulnerability.get('status','NOT_PERFORMED'))
    if vulnerability.get('conclusion'):add(vulnerability['conclusion'])
    if identity.get('source'):add('Identity source: '+identity['source'])
    if vulnerability.get('reason'):add(vulnerability['reason'])
    section('Analysis coverage')
    table(['Component','Status'],[[step['stage'],step['status']+(': '+short(step['error'],400) if step.get('error') else '')] for step in report.get('steps',[])],[110,405])
    for source in vulnerability.get('providers',[]):
        add(short(source))
    findings=vulnerability.get('findings',[])
    if findings:
        section('Published vulnerabilities')
        for finding in findings:
            add(finding['id']+' · '+finding.get('classification','UNKNOWN'),'Heading3')
            cvss=finding.get('cvss',{})
            add('Severity: '+str(cvss.get('severity') or 'Unspecified')+' · CVSS: '+str(cvss.get('score') if cvss.get('score') is not None else 'Unspecified')+
                ' · CISA KEV: '+('Yes' if finding.get('cisa_kev') else 'No' if finding.get('cisa_kev') is False else 'Not verified'))
            add(short(finding.get('description','')))
            for evidence in finding.get('version_evidence',[]):add('Version evidence: '+short(evidence,900))
            if finding.get('fixed_versions'):add('Published fixed versions: '+', '.join(finding['fixed_versions']))
            if finding.get('remediation'):add(finding['remediation'])
            for ref in finding.get('references',[]):
                add(('Public exploit reference (not executed): ' if ref.get('public_exploit_reference') else 'Source: ')+str(ref.get('url','')))
    for name,title in [('behavior','Behavioral observations'),('network','Network observations'),('dns','DNS observations')]:
        observed=data(name)
        rows=observed.get('events',[]) if name!='dns' else observed.get('queries',[])+observed.get('responses',[])
        if engines.get(name,{}).get('status')!='COMPLETED':continue
        section(title)
        if name in ('network','dns'):
            add('Monitoring: '+observed.get('monitoring_status','OPERATIONAL')+' · '+observed.get('traffic_status','')+' · Policy: '+observed.get('network_policy','unknown'))
        if not rows:add('Monitoring completed; no events were observed in this capture.')
        for event in rows[:100]:add(short(event,700))
        if len(rows)>100:add(f'{len(rows)-100} additional observations are included in the JSON export.')
    artifacts=data('sandbox').get('artifacts',{})
    if artifacts.get('files') or artifacts.get('errors'):
        section('Captured artifacts')
        for item in artifacts.get('files',[]):add(item['name']+' · '+str(item['size'])+' bytes · SHA-256 '+item['sha256'])
        for item in artifacts.get('errors',[]):add('Unavailable artifact: '+item['name']+' ('+item['error']+')')
    section('Scope and retention')
    add('Files, reports and analysis history expire 7 days after creation. Running analyses are protected until execution finishes.')
    for limitation in report.get('limitations',[]):add(limitation)
    def footer(canvas, doc):
        canvas.saveState();canvas.setFont('Helvetica',8);canvas.setFillColor(colors.HexColor('#536276'))
        canvas.drawString(40,24,'SentinelScan · '+report['analysis_id']);canvas.drawRightString(A4[0]-40,24,str(doc.page));canvas.restoreState()
    SimpleDocTemplate(output,pagesize=A4,rightMargin=40,leftMargin=40,topMargin=35,bottomMargin=40,
                      title='SentinelScan software analysis',author='SentinelScan').build(story,onFirstPage=footer,onLaterPages=footer)
    return output.getvalue()
