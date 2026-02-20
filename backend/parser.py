import re
from typing import List, Dict, Any
from models import TimelineEvent, Participant, RTPStat

# ── Core regex patterns ──────────────────────────────────────────────────────
TS_RE         = re.compile(r'(\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}\.\d+)')
MODULE_RE     = re.compile(r'<([^>]+)>')
FROM_RE       = re.compile(r'[Ff]rom:\s*<?(?:sip:|tel:)?\+?(\d+)', re.MULTILINE)
TO_RE         = re.compile(r'[Tt]o:\s*<?(?:sip:|tel:)?\+?(\d+)',   re.MULTILINE)
UA_RE         = re.compile(r'[Uu]ser-[Aa]gent:\s*([^\r\n,;]+)',     re.MULTILINE)
REASON_RE     = re.compile(r'[Rr]eason:\s*([^\r\n]+)',               re.MULTILINE)
RTP_RE        = re.compile(
    r'P-RTP-Stat:\s*PS=?(\d+),OS=?(\d+),PR=?(\d+),OR=?(\d+),PL=?(\d+),PD=?(\d+),JI=?(\d+)',
    re.IGNORECASE
)
CONTACT_IP_RE = re.compile(r'[Cc]ontact:\s*<?sip:[^@]+@([\d.]+):?(\d*)', re.MULTILINE)
PAI_RE        = re.compile(r'[Pp]-[Aa]sserted-[Ii]dentity:\s*<?(?:sip:|tel:)?\+?(\d+)', re.MULTILINE)
SIP_METHODS   = ['INVITE','BYE','CANCEL','REGISTER','PRACK','ACK',
                 'NOTIFY','OPTIONS','UPDATE','INFO','MESSAGE','SUBSCRIBE']

# ── Block splitter ───────────────────────────────────────────────────────────
BLOCK_RE = re.compile(
    r'(\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}\.\d+)\s+<([^>]+)>[^\n]*\n'
    r'(?:-----\n)?(.*?)(?=\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}\.\d+\s+<|\Z)',
    re.DOTALL
)

def _normalize(log: str) -> str:
    """Insert newlines before SIP headers in compressed grep output."""
    return re.sub(
        r'((?:Via|From|To|Call-ID|CSeq|Contact|User-Agent|'
        r'P-RTP-Stat|P-Asserted-Identity|P-Access-Network-Info|'
        r'Allow|Content-Length|Content-Type|Reason|Route|'
        r'Supported|Require|Expires|Authorization|Security-Verify|'
        r'Record-Route|Session-Expires|X-Asterisk):\s)',
        r'\n\1', log
    )

def _extract_blocks(log: str):
    log = _normalize(log)
    blocks = []
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

def _direction(body: str) -> str:
    first200 = body[:200]
    if 'sending' in first200: return 'OUT'
    if 'received' in first200: return 'IN'
    return '→'

def _normalize_number(num: str) -> str:
    """Normalize phone numbers to E.164 format without leading +."""
    num = num.lstrip('0')
    # If 9 digits and no country code, assume Swiss (+41)
    if len(num) == 9:
        num = '41' + num
    return num

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
            method = 'INTERNAL'

        # Build description
        to_m   = TO_RE.search(body)
        from_m = FROM_RE.search(body)
        desc_parts = []
        if from_m:
            fn = from_m.group(1)
            desc_parts.append(f"From: {fn}" if len(fn) >= 15 else f"From: +{fn}")
        if to_m:
            tn = to_m.group(1)
            desc_parts.append(f"To: {tn}" if len(tn) >= 15 else f"To: +{tn}")
        cid = re.search(r'[Cc]all-[Ii][Dd]:\s*(\S+)', body)
        if cid: desc_parts.append(f"Call-ID: {cid.group(1)[:30]}")
        desc = " | ".join(desc_parts) if desc_parts else first[:120]

        events.append(TimelineEvent(
            timestamp=ts,
            direction=_direction(body),
            method=method,
            description=desc
        ))
    return events

def _parse_participants(blocks, log: str) -> List[Participant]:
    seen: Dict[str, Dict] = {}

    for ts, module, body in blocks:
        first = _first_line(body)
        if not any(first.startswith(m) for m in SIP_METHODS) and \
           not first.startswith('SIP/2.0'):
            continue

        ua_m      = UA_RE.search(body)
        contact_m = CONTACT_IP_RE.search(body)
        from_m    = FROM_RE.search(body)
        to_m      = TO_RE.search(body)
        pai_m     = PAI_RE.search(body)

        ua_raw = ua_m.group(1).strip() if ua_m else None
        ip     = contact_m.group(1).strip() if contact_m else None

        # Skip YATE — it's the proxy, not an endpoint
        ua = None if (ua_raw and 'YATE' in ua_raw) else ua_raw

        for num_m in [from_m, to_m, pai_m]:
            if not num_m: continue
            num = num_m.group(1)
            if len(num) < 7: continue
            # Skip IMSI-style long numbers
            if len(num) > 15: continue
            norm = _normalize_number(num)
            if norm not in seen:
                seen[norm] = {
                    'number': f"+{norm}",
                    'device': ua,
                    'ip':     ip,
                    'role':   'Unknown'
                }
            else:
                if ua and not seen[norm]['device']: seen[norm]['device'] = ua
                if ip and not seen[norm]['ip']:     seen[norm]['ip']     = ip

    return [Participant(**p) for p in seen.values()]

def _parse_rtp(blocks, log: str) -> List[RTPStat]:
    stats     = []
    seen_keys = set()

    # Extract codec — strip trailing quotes/spaces
    codec_m = re.search(
        r'[Ff]ormats?\s+(?:for\s+\S+\s+)?changed\s+to\s+[\'"]?([^\s\'"]+)[\'"]?',
        log
    )
    codec = codec_m.group(1).strip("' ") if codec_m else None

    # Collect ALL P-RTP-Stat occurrences with context
    all_rtp = []
    for ts, module, body in blocks:
        for m in RTP_RE.finditer(body):
            from_m = FROM_RE.search(body)
            to_m   = TO_RE.search(body)

            # Use all 7 values as dedup key — catches mirrored legs with diff jitter
            key = (m.group(1), m.group(2), m.group(3),
                   m.group(4), m.group(5), m.group(6), m.group(7))
            if key in seen_keys:
                continue
            seen_keys.add(key)

            all_rtp.append({
                'ps':   m.group(1), 'os':  m.group(2),
                'pr':   m.group(3), 'or_': m.group(4),
                'pl':   m.group(5), 'pd':  m.group(6),
                'ji':   m.group(7),
                'from': _normalize_number(from_m.group(1)) if from_m else None,
                'to':   _normalize_number(to_m.group(1))   if to_m   else None,
            })

    # Assign leg labels
    for idx, r in enumerate(all_rtp):
        if r['from']:
            leg = f"+{r['from']}"
        elif r['to']:
            leg = f"+{r['to']}"
        else:
            leg = f"Leg {idx + 1}"

        stats.append(RTPStat(
            leg=leg,
            ps=r['ps'],  os=r['os'],
            pr=r['pr'],  or_=r['or_'],
            pl=r['pl'],  pd=r['pd'],
            ji=r['ji'],
            codec=codec
        ))
    return stats

def _parse_anomalies(blocks, log: str) -> List[str]:
    anomalies = []
    invite_branches: Dict[str, int] = {}
    branch_re = re.compile(r'branch=(z9hG4bK\S+)')

    for ts, module, body in blocks:
        first = _first_line(body)
        if 'SSRC' in body and 'expecting' in body:
            anomalies.append(f"[{ts}] RTCP SSRC mismatch")
        if re.match(r'^SIP/2\.0 5\d\d', first):
            anomalies.append(f"[{ts}] {first[:80]}")
        if 'Network down' in body:
            anomalies.append(f"[{ts}] Transport Network down")
        if 'quota' in body.lower() or 'rejected_initial' in body.lower():
            detail_parts = []

            # Extract IMSI from XML Diameter data
            imsi_m = re.search(
                r'<SubscriptionIdType>imsi</SubscriptionIdType>\s*'
                r'<SubscriptionIdData>(\d+)</SubscriptionIdData>',
                body, re.IGNORECASE
            )
            # Extract MSISDN/E164 from XML Diameter data
            e164_m = re.search(
                r'<SubscriptionIdType>e164</SubscriptionIdType>\s*'
                r'<SubscriptionIdData>(\d+)</SubscriptionIdData>',
                body, re.IGNORECASE
            )
            # Extract request type (initial/update/termination)
            reqtype_m = re.search(
                r'<CcRequestType>(\w+)</CcRequestType>',
                body, re.IGNORECASE
            )
            # Extract service context (32251=data, 32276=voice/SMS)
            svc_m = re.search(
                r'<ServiceContextId>(\d+)@',
                body, re.IGNORECASE
            )
            # Fallback: plain IMSI from pgw session line
            if not imsi_m:
                plain_m = re.search(r'pgw_session["\s:]+(\d{15})', body)
                if plain_m:
                    detail_parts.append(f"IMSI: {plain_m.group(1)}")
            else:
                detail_parts.append(f"IMSI: {imsi_m.group(1)}")

            if e164_m:
                detail_parts.append(f"MSISDN: +{e164_m.group(1)}")

            if reqtype_m:
                detail_parts.append(f"type: {reqtype_m.group(1)}")

            if svc_m:
                svc_map = {
                    '32251': 'data',
                    '32276': 'voice/SMS',
                    '32274': 'MMS',
                }
                svc_code = svc_m.group(1)
                detail_parts.append(f"service: {svc_map.get(svc_code, svc_code)}")

            detail = (' — ' + ' | '.join(detail_parts)) if detail_parts else ''
            anomalies.append(f"[{ts}] Charging/quota failure{detail}")

        if 'L_Cancel' in body:
            anomalies.append(f"[{ts}] AuC L_Cancel (auth failure)")
        if first.startswith('INVITE'):
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
        r'pgw/session/(create|delete).*?pgw_session["\s:]+([^,"}\s]+)',
        re.DOTALL
    )
    for m in pgw_re.finditer(log):
        events.append(f"[{m.group(1)}] PGW session {m.group(2).upper()}: {m.group(3)}")
    return events

def _parse_sdp(blocks) -> Dict[str, Any]:
    offered, answered = [], []
    for ts, module, body in blocks:
        if 'v=0' not in body: continue
        ua_m   = UA_RE.search(body)
        ua_raw = ua_m.group(1).strip() if ua_m else 'unknown'
        # Label YATE proxy blocks clearly
        ua     = 'IMS Core (YATE)' if ua_raw and 'YATE' in ua_raw else ua_raw
        codecs = re.findall(r'a=rtpmap:\d+\s+([^\r\n/]+)', body)
        entry  = {'ua': ua, 'codecs': list(dict.fromkeys(codecs))}
        first  = _first_line(body)
        if first.startswith('INVITE') or re.match(r'^SIP/2\.0 18[03]', first):
            offered.append(entry)
        elif re.match(r'^SIP/2\.0 200', first):
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
