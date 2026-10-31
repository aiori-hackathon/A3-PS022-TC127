#!/usr/bin/env python3
"""Render the editable, restricted Markdown report to an A4 academic PDF."""
import hashlib
import html
import json
from pathlib import Path
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (BaseDocTemplate, Frame, PageTemplate, Paragraph,
                               Spacer, PageBreak, Table, TableStyle, Image, KeepTogether,
                               Preformatted)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.graphics.shapes import Drawing, Rect, Line, Polygon, String
from reportlab.graphics import renderSVG

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / 'reports'
WIDTH = A4[0] - 144
CACHE = REPORT / '.build'


def fonts():
    found = list(Path('/usr/share/fonts').rglob('LiberationSerif-Regular.ttf'))
    if found:
        folder = found[0].parent
        for name, file in [('Serif', 'Regular'), ('Serif-Bold', 'Bold'), ('Serif-Italic', 'Italic'), ('Serif-BoldItalic', 'BoldItalic')]:
            pdfmetrics.registerFont(TTFont(name, str(folder / ('LiberationSerif-' + file + '.ttf'))))
    else:
        from reportlab.pdfbase.pdfmetrics import Font
        for name, base in [('Serif','Times-Roman'),('Serif-Bold','Times-Bold'),('Serif-Italic','Times-Italic'),('Serif-BoldItalic','Times-BoldItalic')]:
            pdfmetrics.registerFont(Font(name,base,'WinAnsiEncoding'))
    pdfmetrics.registerFontFamily('Serif', normal='Serif', bold='Serif-Bold', italic='Serif-Italic', boldItalic='Serif-BoldItalic')


def inline(text):
    text = html.escape(text)
    for variable in ('R_s','R_g','B_s','B_g'):
        text = text.replace(variable,variable[0]+'<sub>'+variable[-1]+'</sub>')
    text = text.replace('q=10^9','q=10<super>9</super>')
    text = re.sub(r'`([^`]+)`', r'<font name="Courier" size="8.6">\1</font>', text)
    text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'\[([^\]]+)\]\((https?://[^)]+)\)', r'<link href="\2" color="black">\1</link>', text)
    return text


class ReportDoc(BaseDocTemplate):
    def __init__(self, filename):
        super().__init__(str(filename), pagesize=A4, leftMargin=72, rightMargin=72,
                         topMargin=64, bottomMargin=52,
                         title='ByteGuard — An eBPF/XDP-Based DNS Flood Mitigation System',
                         author='Team ByteGuard — Prashant Sengar and Janhvi Gokhale')
        frame = Frame(72,52,WIDTH,A4[1]-116, leftPadding=0,rightPadding=0,topPadding=0,bottomPadding=0)
        self.addPageTemplates(PageTemplate(id='academic', frames=[frame], onPage=self.decoration))
        self.heading_index = 0
    def beforeDocument(self):
        self.heading_index = 0
    def decoration(self, canvas, doc):
        canvas.saveState()
        canvas.setFont('Serif-Italic',8)
        canvas.drawRightString(A4[0]-72,A4[1]-32,'ByteGuard — PS-022 — Team A3-PS022-TC127')
        canvas.setStrokeColor(colors.black)
        canvas.setLineWidth(.45)
        canvas.line(72,A4[1]-38,A4[0]-72,A4[1]-38)
        canvas.setFont('Serif',8)
        canvas.drawCentredString(A4[0]/2,27,f'Page {doc.page}')
        canvas.restoreState()
    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name in ('H1','H2'):
            level = 0 if flowable.style.name == 'H1' else 1
            key = 'heading-' + str(self.heading_index)
            self.heading_index += 1
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(flowable.getPlainText(),key,level,False)
            if level == 0:
                self.notify('TOCEntry',(level,flowable.getPlainText(),self.page,key))


def node(d,x,y,w,h,lines,proposed=False):
    d.add(Rect(x,y,w,h,fillColor=colors.white,strokeColor=colors.black,strokeWidth=.8,
               strokeDashArray=[4,2] if proposed else None))
    if isinstance(lines,str): lines=lines.split('\n')
    for i,text in enumerate(lines):
        d.add(String(x+w/2,y+h/2+(len(lines)-1)*5.5-i*11,text,fontName='Serif',fontSize=9,textAnchor='middle'))


def arrow(d,x1,y1,x2,y2,dashed=False):
    d.add(Line(x1,y1,x2,y2,strokeColor=colors.black,strokeWidth=.8,strokeDashArray=[3,2] if dashed else None))
    import math
    a=math.atan2(y2-y1,x2-x1)
    points=[x2,y2,x2-6*math.cos(a-.45),y2-6*math.sin(a-.45),x2-6*math.cos(a+.45),y2-6*math.sin(a+.45)]
    d.add(Polygon(points,fillColor=colors.black,strokeColor=colors.black))


def diagram(kind):
    d=Drawing(WIDTH,240 if kind=='current' else 510)
    if kind=='current':
        boxes=[(0,'DNS traffic'),(113,'Bounded parser'),(226,'Admission control'),(339,'Linux / DNS server')]
        for x,label in boxes: node(d,x,200,108,40,label)
        for x in (108,221,334): arrow(d,x,220,x+5,220)
        d.add(String(360,183,'PASS continues; DROP ends here',fontName='Serif-Italic',fontSize=8,textAnchor='middle'))
        node(d,35,112,160,45,'BPF maps\nSource TAT / global credit / stats')
        node(d,242,112,160,45,'Go controller\nLoad, attach, aggregate per-CPU stats')
        d.add(Line(280,200,280,174,strokeColor=colors.black,strokeWidth=.8))
        d.add(Line(280,174,115,174,strokeColor=colors.black,strokeWidth=.8))
        arrow(d,115,174,115,157)
        arrow(d,195,134,242,134)
        node(d,242,46,160,34,'Prometheus — scrape /metrics')
        node(d,35,46,160,34,'Grafana — provisioned dashboard')
        arrow(d,322,112,322,80)
        arrow(d,242,63,195,63)
        d.add(String(WIDTH/2,16,'Client-observed DNS responses are measured separately by dnsperf.',fontName='Serif-Italic',fontSize=9,textAnchor='middle'))
    else:
        node(d,5,456,210,40,'Current baseline starting point\nBounded parser + per-IP GCRA')
        node(d,255,456,190,40,'Proposed protocol coverage\nVLAN / fragment policy / IPv6',True)
        arrow(d,255,476,215,476,True)
        node(d,5,382,210,48,'Proposed classification layers\nSubnet checks + source qualification',True)
        arrow(d,110,456,110,430)
        node(d,255,382,190,48,'Proposed bounded state\nSubnet + qualified-source maps',True)
        arrow(d,255,406,215,406,True)
        node(d,5,302,210,48,'Proposed evidence consultation\nQuery familiarity + valid cookie signal',True)
        arrow(d,110,382,110,350)
        node(d,255,302,190,48,'Proposed profile / cookie evidence\nUserspace or DNS-server assistance',True)
        arrow(d,255,326,215,326,True)
        node(d,5,222,210,48,'Proposed admission category\nQualified / discovery / best effort',True)
        arrow(d,110,302,110,270)
        d.add(Rect(5,140,440,52,fillColor=colors.white,strokeColor=colors.black,strokeWidth=.8))
        d.add(String(225,180,'Current global aggregate-budget concept (accounting anchor)',fontName='Serif',fontSize=9,textAnchor='middle'))
        d.add(Rect(14,144,422,27,fillColor=colors.white,strokeColor=colors.black,strokeWidth=.7,strokeDashArray=[4,2]))
        d.add(String(225,161,'Proposed protected | discovery | shared capacity',fontName='Serif',fontSize=9,textAnchor='middle'))
        d.add(String(225,150,'Partition sizes, borrowing and commit order undecided',fontName='Serif',fontSize=8,textAnchor='middle'))
        arrow(d,110,222,110,192)
        node(d,5,66,210,38,'Current downstream Linux / DNS server')
        arrow(d,110,140,110,104)
        node(d,255,66,190,38,'Proposed userspace learner\nBounded feedback / expiry / demotion',True)
        arrow(d,215,85,255,85,True)
        d.add(Line(445,85,450,85,strokeColor=colors.black,strokeDashArray=[3,2]))
        d.add(Line(450,85,450,326,strokeColor=colors.black,strokeDashArray=[3,2]))
        arrow(d,450,326,445,326,True)
        d.add(String(5,28,'Solid outline: implemented baseline component or concept.',fontName='Serif',fontSize=8.5))
        d.add(String(5,14,'Dashed outline/arrows: proposed layer, extension or feedback path; no measured improvement claimed.',fontName='Serif',fontSize=8.5))
    renderSVG.drawToFile(d,str(REPORT/'figures'/('architecture-'+kind+'.svg')))
    return d


def make_tables(data):
    groups=data['groups']
    def fmt(value,precision=3): return '—' if value is None else f'{value:.{precision}f}'
    performance=[['Mode','Attack PPS','Success (%)','Replies/s','Latency (ms)','Evidence']]
    cpu=[['Mode','Attack PPS','DNS CPU (%)','Host busy (%)','SoftIRQ (%)','Device RX PPS']]
    for g in groups:
        performance.append([g['mode'],str(g['attack_pps']),fmt(g['success_percent_mean'],1),fmt(g['noerror_qps_mean'],2),fmt(g['latency_ms_mean'],4),g['evidence_ids']])
        cpu.append([g['mode'],str(g['attack_pps']),fmt(g['dns_cpu_percent_mean'],3),fmt(g['host_busy_percent_mean'],2),fmt(g['softirq_percent_mean'],3),fmt(g['rx_pps_mean'],1)])
    trials=[['ID','Mode','Seed','NOERROR / sent','Success (%)','Replies/s']]
    filtering=[['ID','Mode','Admitted','Dropped','Source limit','Global limit']]
    index=[['ID','Original run directory (under build/bench/runs/)']]
    for r in data['trials']:
        if r['attack_pps']==3000:
            trials.append([r['evidence_id'],r['mode'],str(r['seed']),f'{r["noerror"]} / {r["sent"]}',fmt(r['success_percent'],1),fmt(r['noerror_qps'],1)])
            if r['mode']!='none':
                filtering.append([r['evidence_id'],r['mode'],str(r['admitted']),str(r['dropped']),str(r['source_drops']),str(r['global_drops'])])
        index.append([r['evidence_id'],r['run_id']])
    diagnostics=[['ID','Run suffix (see analysis.json)','NOERROR / sent','Success (%)']]
    for r in data['diagnostic_trials']:
        diagnostics.append([r['evidence_id'],r['run_id'].rsplit('__',1)[-1],f'{r["noerror"]} / {r["sent"]}',fmt(r['success_percent'],1)])
    return {'performance':performance,'cpu':cpu,'trials':trials,'filtering':filtering,'run-index':index,'diagnostics':diagnostics}


def main():
    fonts()
    CACHE.mkdir(exist_ok=True)
    data=json.loads((REPORT/'evidence/analysis.json').read_text())
    tables=make_tables(data)
    body=ParagraphStyle('Body',fontName='Serif',fontSize=10.5,leading=14,alignment=TA_JUSTIFY,spaceAfter=7,allowWidows=0,allowOrphans=0)
    styles={
      'body':body,
      'H1':ParagraphStyle('H1',parent=body,fontName='Serif-Bold',fontSize=15,leading=19,spaceBefore=10,spaceAfter=10,keepWithNext=True,alignment=0),
      'H2':ParagraphStyle('H2',parent=body,fontName='Serif-Bold',fontSize=11.5,leading=15,spaceBefore=10,spaceAfter=6,keepWithNext=True,alignment=0),
      'reference':ParagraphStyle('Reference',parent=body,alignment=0,spaceAfter=6),
      'caption':ParagraphStyle('Caption',parent=body,fontSize=8.5,leading=11,alignment=TA_CENTER,spaceBefore=5,spaceAfter=10),
      'cell':ParagraphStyle('Cell',parent=body,fontSize=8.4,leading=10.8,spaceAfter=0,alignment=0),
      'code':ParagraphStyle('Code',fontName='Courier',fontSize=7.8,leading=10,spaceBefore=4,spaceAfter=8),
    }
    story=[]
    centered=ParagraphStyle('Centered',parent=body,alignment=TA_CENTER)
    story += [Spacer(1,30), Paragraph('BYTEGUARD',ParagraphStyle('Title',fontName='Serif-Bold',fontSize=28,leading=34,alignment=TA_CENTER)),Spacer(1,14)]
    story.append(Table([['']],colWidths=[WIDTH],style=TableStyle([('LINEABOVE',(0,0),(-1,0),1,colors.black)])))
    story += [Spacer(1,17),Paragraph('An eBPF/XDP-Based DNS Flood Mitigation System',ParagraphStyle('Subtitle',parent=centered,fontName='Serif-BoldItalic',fontSize=16,leading=22)),Paragraph('Concurrency-safe per-source and aggregate admission control in the Linux datapath',ParagraphStyle('Tagline',parent=centered,fontName='Serif-Italic',fontSize=10,leading=14)),Spacer(1,20)]
    story.append(Table([['']],colWidths=[WIDTH],style=TableStyle([('LINEABOVE',(0,0),(-1,0),.65,colors.black)])))
    story += [Spacer(1,25),Paragraph('Implementation, synchronization, laboratory evaluation and future architecture',centered),Spacer(1,55),Paragraph('<b>Problem Statement:</b> PS-022 — DNS query flood mitigation using eBPF/XDP',centered),Paragraph('<b>Category:</b> Cybersecurity',centered),Spacer(1,74),Paragraph('<b>Team:</b> ByteGuard &nbsp;&nbsp; <b>Team code:</b> A3-PS022-TC127',centered),Paragraph('<b>Institution:</b> Indian Institute of Information Technology,<br/>Design and Manufacturing, Jabalpur',centered),Paragraph('<b>Prashant Sengar · Janhvi Gokhale</b>',centered),Paragraph('Faculty mentor: Dr. Nitish Andola',centered),Spacer(1,20),Paragraph('31 October 2026 — final documentation revision',centered),Spacer(1,26),Paragraph('Evidence-qualified engineering report. Available historical measurements are identified explicitly; an absent final campaign is not replaced with projected results.',ParagraphStyle('TitleNote',parent=body,fontName='Serif-Italic',fontSize=9,leading=12)),PageBreak()]
    story.append(Paragraph('Table of Contents',ParagraphStyle('TOCTitle',parent=styles['H1'])))
    toc=TableOfContents()
    toc.levelStyles=[ParagraphStyle('TOC1',fontName='Serif',fontSize=10,leading=13,spaceBefore=5),ParagraphStyle('TOC2',fontName='Serif',fontSize=8.6,leading=10.5,leftIndent=14,spaceBefore=2)]
    story += [toc,PageBreak()]
    lines=(REPORT/'source/report.md').read_text().splitlines()
    def add_table(rows):
        cells=[[Paragraph(inline(str(c)),styles['cell']) for c in row] for row in rows]
        n=len(rows[0])
        widths=[WIDTH/n]*n
        if n==2: widths=[48,WIDTH-48] if rows[0][0]=='ID' else [135,WIDTH-135]
        if n==3 and rows[0][0]=='ID':widths=[28,235,WIDTH-263]
        if n==4 and rows[0][0]=='ID':widths=[27,WIDTH-167,78,62]
        if n==4 and rows[0][0]=='Map':widths=[68,170,110,WIDTH-348]
        table=Table(cells,colWidths=widths,repeatRows=1,hAlign='LEFT')
        table.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),('LEFTPADDING',(0,0),(-1,-1),5),('RIGHTPADDING',(0,0),(-1,-1),5),('BACKGROUND',(0,0),(-1,0),colors.Color(.94,.94,.94)),('LINEABOVE',(0,0),(-1,0),.7,colors.black),('LINEBELOW',(0,0),(-1,0),.5,colors.black),('LINEBELOW',(0,1),(-1,-1),.25,colors.Color(.65,.65,.65))]))
        story.extend([table,Spacer(1,7)])
    i=0
    while i<len(lines):
        line=lines[i].strip()
        if not line: i+=1;continue
        if line=='<!-- pagebreak -->':story.append(PageBreak());i+=1;continue
        if line.startswith('# '):story.append(Paragraph(inline(line[2:]),styles['H1']));i+=1;continue
        if line.startswith('## '):story.append(Paragraph(inline(line[3:]),styles['H2']));i+=1;continue
        if line.startswith('```'):
            code=[];i+=1
            while i<len(lines) and not lines[i].startswith('```'):code.append(lines[i]);i+=1
            for code_line in code:
                if len(code_line)>94: raise ValueError('Code line too long: '+code_line)
            story.append(Preformatted('\n'.join(code),styles['code']));i+=1;continue
        if line.startswith('{{table:'):
            key=line[len('{{table:'):-2];add_table(tables[key]);i+=1;continue
        if line.startswith('{{figure:') or line.startswith('{{diagram:'):
            directive=line[2:-2];kind,payload=directive.split(':',1);key,caption=payload.split('|',1)
            if kind=='diagram':graphic=diagram(key)
            else:
                from PIL import Image as PILImage
                path=REPORT/'figures'/(key+'.png')
                with PILImage.open(path) as img:w,h=img.size
                graphic=Image(str(path),width=WIDTH,height=WIDTH*h/w)
            story.append(KeepTogether([graphic,Paragraph(inline(caption),styles['caption'])]));i+=1;continue
        if line.startswith('$$'):
            formula=line[2:-2].strip()
            from matplotlib import mathtext
            import matplotlib
            matplotlib.rcParams['mathtext.fontset']='stix'
            path=CACHE/(hashlib.sha256(formula.encode()).hexdigest()[:12]+'.png')
            mathtext.math_to_image('$'+formula+'$',str(path),dpi=220,format='png',color='black')
            from PIL import Image as PILImage
            with PILImage.open(path) as img:w,h=img.size
            scale=min(72/220,(WIDTH-12)/w)
            image=Image(str(path),width=w*scale,height=h*scale)
            image.hAlign='CENTER'
            story.extend([Spacer(1,5),image,Spacer(1,10)]);i+=1;continue
        if line.startswith('|'):
            rows=[]
            while i<len(lines) and lines[i].strip().startswith('|'):
                row=[v.strip() for v in lines[i].strip().strip('|').split('|')]
                if not all(re.fullmatch(r'[:\- ]+',v) for v in row):rows.append(row)
                i+=1
            add_table(rows);continue
        if line.startswith('- '):
            story.append(Paragraph('• '+inline(line[2:]),ParagraphStyle('Bullet',parent=body,leftIndent=10,firstLineIndent=-8,spaceAfter=4)));i+=1;continue
        if re.match(r'Table [A-Z]?\d+\.',line):
            if story and isinstance(story[-1], Spacer): story.pop()
            caption=Paragraph(inline(line),styles['caption'])
            if story and isinstance(story[-1], Table):
                table=story.pop()
                story.append(KeepTogether([table,caption]))
            else: story.append(caption)
            i+=1;continue
        para=[line];i+=1
        while i<len(lines) and lines[i].strip():para.append(lines[i].strip());i+=1
        story.append(Paragraph(inline(' '.join(para)),styles['reference'] if re.match(r'^\[\d+\]',para[0]) else body))
    ReportDoc(REPORT/'ByteGuard_Technical_Report.pdf').multiBuild(story)
    print('Built',REPORT/'ByteGuard_Technical_Report.pdf')


if __name__=='__main__':main()
