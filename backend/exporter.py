import csv, io
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.units import cm
from models import AnalyzeResponse

def to_csv(data: AnalyzeResponse) -> bytes:
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["=== CALL TIMING ==="])
    w.writerow(["Post-Dial Delay", data.answer_time or "N/A"])
    w.writerow(["Ring Time", data.ring_time or "N/A"])
    w.writerow(["Call Duration", data.call_duration or "N/A"])
    w.writerow([]); w.writerow(["=== PARTICIPANTS ==="])
    w.writerow(["Role","Number","IMSI","Device","IP"])
    for p in data.participants: w.writerow([p.role,p.number,p.imsi,p.device,p.ip])
    w.writerow([]); w.writerow(["=== CALL FLOW TIMELINE ==="])
    w.writerow(["Timestamp","Direction","Method","Description"])
    for ev in data.timeline: w.writerow([ev.timestamp,ev.direction,ev.method,ev.description])
    if data.bye_info:
        b = data.bye_info; w.writerow([]); w.writerow(["=== BYE ANALYSIS ==="])
        w.writerow(["Sender",b.sender]); w.writerow(["Number",b.sender_number])
        w.writerow(["Reason",b.reason or "None"])
        for e in b.evidence: w.writerow(["Evidence",e])
    if data.rtp_stats:
        w.writerow([]); w.writerow(["=== RTP STATS ==="])
        w.writerow(["Leg","Sent Pkts","Sent Bytes","Recv Pkts","Recv Bytes","Lost","Discarded","Jitter","Codec"])
        for r in data.rtp_stats: w.writerow([r.leg,r.ps,r.os,r.pr,r.or_,r.pl,r.pd,r.ji,r.codec])
    if data.anomalies:
        w.writerow([]); w.writerow(["=== ANOMALIES ==="])
        for a in data.anomalies: w.writerow([a])
    return buf.getvalue().encode("utf-8")

def to_pdf(data: AnalyzeResponse) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4),
                            leftMargin=1*cm, rightMargin=1*cm,
                            topMargin=1.5*cm, bottomMargin=1.5*cm)
    styles = getSampleStyleSheet()
    mono = ParagraphStyle("mono", fontName="Courier", fontSize=7, leading=10)
    story = []
    story.append(Paragraph("SIP Call Log Analysis Report", styles["Heading1"]))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("Call Timing", styles["Heading2"]))
    story.append(_tbl([["Metric","Value"],
        ["Post-Dial Delay", data.answer_time or "N/A"],
        ["Ring Time", data.ring_time or "N/A"],
        ["Call Duration", data.call_duration or "N/A"]],
        col_widths=[8*cm,6*cm])); story.append(Spacer(1,0.5*cm))
    story.append(Paragraph("Participants", styles["Heading2"]))
    rows = [["Role","Number","IMSI","Device","IP"]]
    for p in data.participants: rows.append([p.role or "",p.number or "",p.imsi or "",p.device or "",p.ip or ""])
    story.append(_tbl(rows, col_widths=[4*cm,4*cm,5*cm,9*cm,6*cm])); story.append(Spacer(1,0.5*cm))
    story.append(Paragraph("Call Flow Timeline", styles["Heading2"]))
    rows = [["Timestamp","Dir","Method","Description"]]
    for ev in data.timeline:
        rows.append([Paragraph(ev.timestamp,mono),ev.direction,ev.method,Paragraph(ev.description[:140],mono)])
    story.append(_tbl(rows, col_widths=[5*cm,1.5*cm,3.5*cm,18*cm])); story.append(Spacer(1,0.5*cm))
    if data.bye_info:
        b = data.bye_info; story.append(Paragraph("BYE Analysis", styles["Heading2"]))
        rows = [["Field","Value"],["Sender",b.sender],["Number",b.sender_number or ""],["Reason",b.reason or "None"]]
        for e in b.evidence: rows.append(["Evidence",e])
        story.append(_tbl(rows, col_widths=[5*cm,23*cm])); story.append(Spacer(1,0.3*cm))
        story.append(Paragraph("Raw BYE Snippet:", styles["Heading2"]))
        story.append(Paragraph(b.raw_snippet.replace("\n","<br/>"), mono)); story.append(Spacer(1,0.5*cm))
    if data.rtp_stats:
        story.append(Paragraph("RTP / Media Statistics", styles["Heading2"]))
        rows = [["Leg","Sent Pkts","Sent Bytes","Recv Pkts","Recv Bytes","Lost","Discarded","Jitter","Codec"]]
        for r in data.rtp_stats: rows.append([r.leg,r.ps,r.os,r.pr,r.or_,r.pl,r.pd,r.ji,r.codec or ""])
        story.append(_tbl(rows)); story.append(Spacer(1,0.5*cm))
    if data.anomalies:
        story.append(Paragraph("Anomalies", styles["Heading2"]))
        for a in data.anomalies: story.append(Paragraph(f"• {a}", styles["Normal"]))
    doc.build(story)
    return buf.getvalue()

def _tbl(data, col_widths=None):
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),8),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f0f4f8")]),
        ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#cccccc")),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("LEFTPADDING",(0,0),(-1,-1),4),
        ("RIGHTPADDING",(0,0),(-1,-1),4),
    ]))
    return t

