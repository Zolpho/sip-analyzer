import re
from typing import List, Dict, Any
from models import TimelineEvent, Participant, RTPStat

# ── Core regex patterns ──────────────────────────────────────────────────────
TS_RE      = re.compile(r'(\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}\.\d+)')
MODULE_RE  = re.compile(r'<([^>]+)>')
FROM_RE    = re.compile(r'[Ff]rom:\s*<?(?:sip:|tel:)?\+?(\d+)', re.MULTILINE)
TO_RE      = re.compile(r'[Tt]o:\s*<?(?:sip:|tel:)?\+?(\d+)',   re.MULTILINE)
UA_RE      = re.compile(r'[Uu]ser-[Aa]gent:\s*([^\r\n,;]+)',     re.MULTILINE)
REASON_RE  = re.compile(r'[Rr]eason:\s*([^\r\n]+)',               re.MULTILINE)
RTP_RE     = re.compile(
    r'P-RTP-Stat:\s*PS=?(\d+),OS=?(\d+),PR=?(\d+),OR=?(\d+),PL=?(\d+),PD=?(\d+),JI=?(\d+)',
    re.IGNORECASE
)
CONTACT_IP_RE = re.compile(r'[Cc]ontact:\s*<?sip:[^@]+@([\d.]+):?(\d*)', re.MULTILINE)
PAI_RE     = re.compile(r'[Pp]-[Aa]sserted-[Ii]dentity:\s*<?(?:sip:|tel:)?\+?(\d+)', re.MULTILINE)
SIP_METHODS = ['INVITE','BYE','CANCEL','REGISTER','PRACK','ACK',
               'NOTIFY','OPTIONS','UPDATE','INFO','MESSAGE','SUBSCRIBE']

# ── Block splitter ───────────────────────────────────────────────────────────
BLOCK_RE = re.compile(
    r'(\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}\.\d+)\s+<([^>]+)>[^\n]*\n'
    r'(?:-----\n)?(.*?)(?=\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}\.\d+\s+<|\Z)',
    re.DOTALL
)

def _extract_blocks(log: str):
    """Split log into (timestamp, module, body) tuples."""
    blocks = []
    # Normalise compressed grep output — insert newlines before SIP headers
    log = re.sub(r'((?:Via|From|To|Call-ID|CSeq|Contact|User-Agent|'
                 r'P-RTP-Stat|P-Asserted-Identity|Allow|Content-Length|'
                 r'Reason|Route|Supported|Require):\s)', r'\n\1', log)
    for m in BLOCK_RE.finditer(log):
        ts, module, body = m.group(1), m.group(2), m.group(3).strip()
        if body:
            blocks.append((ts, module, body))
    return blocks

def _first_line(body: str) -> str:
    for line in body.splitlines():
        line = line.strip()
        if line and not line.startswith('-----'):
            return line
    return ''

def _direction(module: str, body: str) -> str:
    if 'sending' in body[:120] or 'sending' in module:
        return 'OUT'
    if 'received' in body[:120]:
        return 'IN'
    return '→'

def _parse_timeline(blocks) -> List[TimelineEvent]:
    events = []
    for ts, module, body in blocks:
        first = _first_line(body)

        # Determine method
        method = None
        for m in SIP_METHODS:
            if re.match(rf'^{m}\s+', first):
                method = m
                break
        if method is None:
            m2 = re.match(r'^SIP/2\.0\s+(\d{3})\s+(.+)$', first)
            if m2:
                method = f"{m2.group(1)} {m2.group(2)[:30]}"
        if method is None:
            # Internal log line
            method = 'INTERNAL'

        # Description
        if method == 'INTERNAL':
            desc = first[:120] if first else body[:120]
        else:
            to_m   = TO_RE.search(body)
            from_m = FROM_RE.search(body)
            desc_parts = []
            if from_m: desc_parts.append(f"From: +{from_m.group(1)}")
            if to_m:   desc_parts.append(f"To: +{to_m.group(1)}")
            cid = re.search(r'[Cc]all-[Ii][Dd]:\s*(\S+)', body)
            if cid: desc_parts.append(f"Call-ID: {cid.group(1)[:30]}")
            desc = " | ".join(desc_parts) if desc_parts else first[:120]

        dir_ = _direction(module, body)
        events.append(TimelineEvent(
            timestamp=ts, direction=dir_, method=method, description=desc
        ))
    return events

def _parse_participants(blocks, log: str) -> List[Participant]:
    """Extract participants from all blocks."""
    seen: Dict[str, Participant] = {}

    for ts, module, body in blocks:
        first = _first_line(body)
        # Skip pure internal lines
        if not any(first.startswith(m) for m in SIP_METHODS) and \
           not first.startswith('SIP/2.0'):
            continue

        ua_m      = UA_RE.search(body)
        contact_m = CONTACT_IP_RE.search(body)
        pai_m     = PAI_RE.search(body)
        from_m    = FROM_RE.search(body)
        to_m      = TO_RE.search(body)

        ua  = ua_m.group(1).strip()      if ua_m      else None
        ip  = contact_m.group(1).strip() if contact_m else None

        for num_m in [from_m, to_m, pai_m]:
            if not num_m: continue
            num = num_m.group(1)
            if len(num) < 7: continue
            if num not in seen:
                seen[num] = Participant(number=f"+{num}", device=ua, ip=ip)
            else:
                if ua  and not seen[num].device: seen[num].device = ua
                if ip  and not seen[num].ip:     seen[num].ip     = ip

    return list(seen.values())

def _parse_rtp(blocks, log: str) -> List[RTPStat]:
    stats = []
    seen  = set()
    for ts, module, body in blocks:
        for m in RTP_RE.finditer(body):
            key = m.group(0)
            if key in seen: continue
            seen.add(key)
            # Try to identify leg
            from_m = FROM_RE.search(body)
            leg = f"+{from_m.group(1)}" if from_m else "unknown"
            # Try to get codec from nearby format line
            codec_m = re.search(r'Formats?\s+(?:for\s+\S+\s+)?changed\s+to\s+[\'"]?(\S+)[\'"]?', log)
            stats.append(RTPStat(
                leg=leg,
                ps=m.group(1), os=m.group(2),
                pr=m.group(3), or_=m.group(4),
                pl=m.group(5), pd=m.group(6),
                ji=m.group(7),
                codec=codec_m.group(1) if codec_m else None
            ))
    return stats

def _parse_anomalies(blocks, log: str) -> List[str]:
    anomalies = []
    for ts, module, body in blocks:
        first = _first_line(body)
        if 'SSRC' in body and 'expecting' in body:
            anomalies.append(f"[{ts}] RTCP SSRC mismatch: {body[:100]}")
        if '500 ' in first:
            anomalies.append(f"[{ts}] Server Internal Error: {first}")
        if 'Network down' in body:
            anomalies.append(f"[{ts}] Transport Network down: {body[:100]}")
        if 'quota' in body.lower() or 'rejected_initial' in body.lower():
            anomalies.append(f"[{ts}] Charging/quota failure: {body[:120]}")
        if 'L_Cancel' in body:
            anomalies.append(f"[{ts}] AuC L_Cancel (auth failure): {body[:100]}")
    # Retransmissions
    invite_branches: Dict[str, int] = {}
    branch_re = re.compile(r'branch=(z9hG4bK\S+)')
    for ts, module, body in blocks:
        if _first_line(body).startswith('INVITE'):
            bm = branch_re.search(body)
            if bm:
                b = bm.group(1)
                invite_branches[b] = invite_branches.get(b, 0) + 1
    for b, count in invite_branches.items():
        if count > 1:
            anomalies.append(f"INVITE retransmitted {count}x for branch {b}")
    return list(dict.fromkeys(anomalies))

def _parse_pgw(log: str) -> List[str]:
    events = []
    pgw_re = re.compile(
        r'(\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}\.\d+).*?'
        r'pgw/session/(create|delete).*?pgw_session["\s:]+([^,"}\s]+)', re.DOTALL)
    for m in pgw_re.finditer(log):
        events.append(f"[{m.group(1)}] PGW session {m.group(2).upper()}: {m.group(3)}")
    return events

def _parse_sdp(blocks) -> Dict[str, Any]:
    offered, answered = [], []
    for ts, module, body in blocks:
        first = _first_line(body)
        if 'v=0' not in body: continue
        ua_m = UA_RE.search(body)
        ua   = ua_m.group(1).strip() if ua_m else 'unknown'
        codecs = re.findall(r'a=rtpmap:\d+\s+([^\r\n/]+)', body)
        entry  = {'ua': ua, 'codecs': list(dict.fromkeys(codecs))}
        if first.startswith('INVITE') or first.startswith('SIP/2.0 183') \
           or first.startswith('SIP/2.0 180'):
            offered.append(entry)
        elif first.startswith('SIP/2.0 200'):
            answered.append(entry)
    return {'offered': offered[:2], 'answered': answered[:2]}

def parse_log(log: str) -> Dict[str, Any]:
    blocks = _extract_blocks(log)
    return {
        'timeline':     _parse_timeline(blocks),
        'participants': _parse_participants(blocks, log),
        'rtp_stats':    _parse_rtp(blocks, log),
        'anomalies':    _parse_anomalies(blocks, log),
        'pgw_events':   _parse_pgw(log),
        'sdp_info':     _parse_sdp(blocks),
        'raw_blocks':   blocks,
    }

