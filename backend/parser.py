import re
from typing import List, Dict, Any
from models import TimelineEvent, Participant, RTPStat

# ── Core regex patterns ──────────────────────────────────────────────────────
TS_RE         = re.compile(r'(\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}\.\d+)')
MODULE_RE     = re.compile(r'<([^>]+)>')
#FROM_RE       = re.compile(r'[Ff]rom:\s*<?(?:sip:|tel:)?\+?(\d+)', re.MULTILINE)
#TO_RE         = re.compile(r'[Tt]o:\s*<?(?:sip:|tel:)?\+?(\d+)',   re.MULTILINE)
#UA_RE         = re.compile(r'[Uu]ser-[Aa]gent:\s*([^\r\n,;]+)',     re.MULTILINE)
REASON_RE     = re.compile(r'[Rr]eason:\s*([^\r\n]+)',               re.MULTILINE)
RTP_RE        = re.compile(
    r'P-RTP-Stat:\s*PS=?(\d+),OS=?(\d+),PR=?(\d+),OR=?(\d+),PL=?(\d+),PD=?(\d+),JI=?(\d+)',
    re.IGNORECASE
)
#CONTACT_IP_RE = re.compile(r'[Cc]ontact:\s*<?sip:[^@]+@([\d.]+):?(\d*)', re.MULTILINE)
#PAI_RE        = re.compile(r'[Pp]-[Aa]sserted-[Ii]dentity:\s*<?(?:sip:|tel:)?\+?(\d+)', re.MULTILINE)
FROM_RE = re.compile(
    r"(?:[Ff]rom:\s*<?(?:sip:|tel:)?\+?|param\['(?:caller|sip_from)'\]\s*=\s*'<?(?:sip:|tel:)?\+?)"
    r'(\d+)', re.MULTILINE
)
TO_RE = re.compile(
    r"(?:[Tt]o:\s*<?(?:sip:|tel:)?\+?|param\['(?:called|sip_to)'\]\s*=\s*'<?(?:sip:|tel:)?\+?)"
    r'(\d+)', re.MULTILINE
)
UA_RE = re.compile(
    r"(?:[Uu]ser-[Aa]gent:\s*|param\['(?:sip_user-agent|device)'\]\s*=\s*')"
    r"([^\r\n,;']+)", re.MULTILINE
)
CONTACT_IP_RE = re.compile(
    r"(?:[Cc]ontact:\s*<?sip:[^@]+@|param\['ip_host'\]\s*=\s*')"
    r'([\d.a-zA-Z.-]+)', re.MULTILINE
)
PAI_RE = re.compile(
    r"(?:[Pp]-[Aa]sserted-[Ii]dentity:\s*<?(?:sip:|tel:)?\+?|param\['sip_p-asserted-identity'\]\s*=\s*'<?(?:sip:|tel:)?\+?)"
    r'(\d+)', re.MULTILINE
)

SIP_METHODS   = ['INVITE','BYE','CANCEL','REGISTER','PRACK','ACK',
                 'NOTIFY','OPTIONS','UPDATE','INFO','MESSAGE','SUBSCRIBE']
DIAMETER_RE   = re.compile(
    r'\b(CCR|CCA|RAR|RAA|STR|STA|ASR|ASA|AAR|AAA|'
    r'DWR|DWA|DPR|DPA|UDR|UDA|PUR|PUA|SNR|SNA|PNR|PNA)\b',
    re.IGNORECASE
)
DIAM_RESULT_ATTR_RE = re.compile(
    r'\bdiameter_result="([^"]+)"',
    re.IGNORECASE
)

# ── Diameter-specific patterns based on actual log format ───────────────────

# Root tag attribute: diameter_result="DIAMETER_SUCCESS"
DIAM_RESULT_ATTR_RE = re.compile(
    r'<CreditControl(?:Request|Answer)[^>]*\bdiameter_result="([^"]+)"',
    re.IGNORECASE
)
# Fallback: flat key=value block (javascript:ALL dump)
DIAM_RESULT_KV_RE = re.compile(
    r"'diameter_result'\s*=\s*'([^']+)'",
    re.IGNORECASE
)
# <ResultCode> inside XML body (CCA top-level, NOT inside MultipleServicesCreditControl)
# We only want the first one (top-level), not the per-service one
DIAM_RESULT_CODE_RE = re.compile(
    r'<ResultCode[^>]*>(\d+)</ResultCode>',
    re.IGNORECASE
)
# Subscriber from XML (CCR and CCR embedded in xml= field)
DIAM_IMSI_XML_RE = re.compile(
    r'<SubscriptionIdType>imsi</SubscriptionIdType>\s*'
    r'<SubscriptionIdData>(\d+)</SubscriptionIdData>',
    re.IGNORECASE
)
DIAM_E164_XML_RE = re.compile(
    r'<SubscriptionIdType>e164</SubscriptionIdType>\s*'
    r'<SubscriptionIdData>(\d+)</SubscriptionIdData>',
    re.IGNORECASE
)
# Correlation key between CCR and CCA
DIAM_EEIDENT_RE = re.compile(r'\beeident="(\d+)"', re.IGNORECASE)

# Request type
DIAM_REQTYPE_RE = re.compile(
    r'<CcRequestType[^>]*>(\w+)</CcRequestType>',
    re.IGNORECASE
)
# Service context
DIAM_SVC_RE = re.compile(
    r'<ServiceContextId>(\d+)@',
    re.IGNORECASE
)
# APN
DIAM_APN_RE = re.compile(
    r'<CalledStationId>([^<]+)</CalledStationId>',
    re.IGNORECASE
)

# Result string → success/denied classification
_DIAM_SUCCESS_PREFIXES = ('DIAMETER_SUCCESS', '2001', '2')
_DIAM_RESULT_LABELS = {
    'DIAMETER_SUCCESS':               '✓ SUCCESS (2001)',
    'DIAMETER_CREDIT_LIMIT_REACHED':  '✗ CREDIT_LIMIT_REACHED (4010)',
    'DIAMETER_RATING_FAILED':         '✗ RATING_FAILED (4012)',
    'DIAMETER_AUTHORIZATION_REJECTED':'✗ AUTHORIZATION_REJECTED (5003)',
    'DIAMETER_USER_UNKNOWN':          '✗ USER_UNKNOWN (5030)',
    'DIAMETER_UNABLE_TO_COMPLY':      '✗ UNABLE_TO_COMPLY (5012)',
}

def _diam_result_fmt(result_str: str, result_code: str = None) -> str:
    """Return a human-readable result string with success/denied marker."""
    if result_str:
        label = _DIAM_RESULT_LABELS.get(result_str.upper())
        if label:
            return label
        # Unknown string — add code if we have it
        code = result_code or ''
        prefix = '✓' if result_str.upper().startswith('DIAMETER_SUCCESS') else '✗'
        return f"{prefix} {result_str}" + (f" ({code})" if code else "")
    if result_code:
        prefix = '✓' if result_code.startswith('2') else '✗'
        return f"{prefix} {result_code}"
    return '? unknown'

def _is_diam_success(result_str: str, result_code: str) -> bool:
    s = (result_str or '').upper()
    c = (result_code or '')
    return s == 'DIAMETER_SUCCESS' or c == '2001'


# ── Block splitter ───────────────────────────────────────────────────────────
BLOCK_RE = re.compile(
    r'(\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'(?:<([^>]+)>)?\s*'           # <module> is now optional
    r'([^\n]*)\n'                   # first line (group 3)
    r'(?:-----\n)?(.*?)(?=\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}\.\d+\s+|\Z)',  # lookahead no longer requires <
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
    # Strip shell prompt and grep '--' separators
    log = re.sub(r'^\[root@[^\n]*\n', '', log, flags=re.MULTILINE)
    log = re.sub(r'^\s*--\s*$', '', log, flags=re.MULTILINE)
    log = _normalize(log)
    blocks = []
    for m in BLOCK_RE.finditer(log):
        ts     = m.group(1)
        module = m.group(2) or 'engine'       # None for Format-B → 'engine'
        first  = (m.group(3) or '').strip()
        rest   = (m.group(4) or '').strip()
        body   = (first + '\n' + rest).strip()
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
    if len(num) == 9:
        num = '41' + num
    return num


def _parse_timeline(blocks) -> List[TimelineEvent]:
    events = []
    for ts, module, body in blocks:
        first = _first_line(body)

        # ── Determine method ─────────────────────────────────────────────────
        method      = None
        is_diameter = False

        # SIP request
        for m in SIP_METHODS:
            if re.match(rf'^{m}\s+', first):
                method = m
                break

        # SIP response
        if method is None:
            m2 = re.match(r'^SIP/2\.0\s+(\d{3})\s+(.+)$', first)
            if m2:
                method = f"{m2.group(1)} {m2.group(2)[:30]}"

                # Diameter — check first line and first 120 chars of body
        if method is None:
            dm = DIAMETER_RE.search(first) or DIAMETER_RE.search(body[:120])
            if dm:
                method      = dm.group(1)
                is_diameter = True

        # YATE engine message (call.route, call.execute, etc.)
        if method is None:
            yate_m = re.search(r"Returned\s+(?:true|false)\s+'([^']+)'", first)
            if yate_m:                          # ← nested inside, safe
                msg = yate_m.group(1)
                if 'call.route' in msg:
                    err_m = re.search(r"param\['error'\]\s*=\s*'([^']+)'", body)
                    method = f"ROUTE/FAIL:{err_m.group(1)}" if err_m else 'ROUTE/OK'
                else:
                    method = msg.upper().replace('.', '/')

        # Final fallback — must never be commented out
        if method is None:
            method = 'INTERNAL'

        # ── Build description ─────────────────────────────────────────────────
        desc_parts = []

        if is_diameter:
            # ── 1. Result — attribute on root tag takes priority ──────────
            result_str  = None
            result_code = None

            rm_attr = DIAM_RESULT_ATTR_RE.search(body)
            rm_kv   = DIAM_RESULT_KV_RE.search(body)
            if rm_attr:
                result_str = rm_attr.group(1)
            elif rm_kv:
                result_str = rm_kv.group(1)

            # Top-level <ResultCode> — first match only
            rc_m = DIAM_RESULT_CODE_RE.search(body)
            if rc_m:
                result_code = rc_m.group(1)

            desc_parts.append(_diam_result_fmt(result_str, result_code))

            # ── 2. Subscriber — from XML body or embedded xml= field ──────
            # The CCR always carries it; the CCA doesn't, so we also check
            # the 'xml' key-value field which contains the linked CCR XML
            imsi_m = DIAM_IMSI_XML_RE.search(body)
            e164_m = DIAM_E164_XML_RE.search(body)

            if e164_m:
                desc_parts.append(f"MSISDN:+{e164_m.group(1)}")
            if imsi_m:
                desc_parts.append(f"IMSI:{imsi_m.group(1)}")

            # ── 3. Request type ───────────────────────────────────────────
            rt_m = DIAM_REQTYPE_RE.search(body)
            if rt_m:
                desc_parts.append(f"type:{rt_m.group(1)}")

            # ── 4. Service / APN ──────────────────────────────────────────
            svc_m = DIAM_SVC_RE.search(body)
            apn_m = DIAM_APN_RE.search(body)
            if svc_m:
                svc_map = {'32251': 'data', '32276': 'voice/SMS', '32274': 'MMS'}
                desc_parts.append(f"svc:{svc_map.get(svc_m.group(1), svc_m.group(1))}")
            if apn_m:
                desc_parts.append(f"APN:{apn_m.group(1)}")
    
            # Fallback if nothing extracted
            if len(desc_parts) == 1 and desc_parts[0].startswith('?'):
                desc_parts.append(body[:120].replace('\n', ' '))

        else:
            # SIP path — unchanged
            to_m   = TO_RE.search(body)
            from_m = FROM_RE.search(body)
            if from_m:
                fn = from_m.group(1)
                desc_parts.append(f"From: {fn}" if len(fn) >= 15 else f"From: +{fn}")
            if to_m:
                tn = to_m.group(1)
                desc_parts.append(f"To: {tn}" if len(tn) >= 15 else f"To: +{tn}")
            cid = re.search(r"(?:[Cc]all-[Ii][Dd]:\s*|param\['sip_callid'\]\s*=\s*')(\S+?)(?:'|\s|$)", body)
            if cid:
                desc_parts.append(f"Call-ID: {cid.group(1)[:30]}")

        desc = " | ".join(desc_parts) if desc_parts else first[:120]

             # ── Color coding ─────────────────────────────────────────────────────
        if method == 'ROUTE/OK':
            color = 'green'
        elif method.startswith('ROUTE/FAIL'):
            color = 'red'
        else:
            color = ''

        events.append(TimelineEvent(
            timestamp=ts,
            direction=_direction(body),
            method=method,
            description=desc,
            color=color,
        ))
    return events


def _parse_participants(blocks, log: str) -> List[Participant]:
    seen: Dict[str, Dict] = {}

    for ts, module, body in blocks:
        first = _first_line(body)
        has_sip_params = ("param['caller']" in body or "param['sip_from']" in body)
        if not any(first.startswith(m) for m in SIP_METHODS) and \
           not first.startswith('SIP/2.0') and not has_sip_params:
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

def _parse_data_usage(log: str) -> List[Dict]:
    """Parse Diameter CCR termination messages to build per-session data usage."""
    sessions = {}

    # Match each timestamped block containing CreditControlRequest/Answer
    block_re = re.compile(
        r'(\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}\.\d+).*?'
        r'(CreditControlRequest|CreditControlAnswer)(.*?)'
        r'(?=\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}|\Z)',
        re.DOTALL
    )

    for m in block_re.finditer(log):
        ts   = m.group(1)
        kind = m.group(2)
        body = m.group(3)

        # Extract session ID as unique key
        sess_m = re.search(r'SessionId[^>]*?([a-z0-9.]+\d{10,}[a-z0-9.]*)', body, re.IGNORECASE)
        if not sess_m: continue
        sess_id = sess_m.group(1)

        # Extract identifiers
        imsi_m   = re.search(r'SubscriptionIdTypeimsiSubscriptionIdType\s*SubscriptionIdData(\d+)', body)
        e164_m   = re.search(r'SubscriptionIdTypee164SubscriptionIdType\s*SubscriptionIdData(\d+)', body)
        apn_m    = re.search(r'CalledStationId([a-zA-Z0-9._-]+)CalledStationId', body)
        ip_m     = re.search(r'PDPAddress[^>]*?([\d.]+)PDPAddress', body)
        reqtype_m= re.search(r'CcRequestType(\w+)CcRequestType', body)
        svc_m    = re.search(r'ServiceContextId(\d+)@', body)

        imsi    = imsi_m.group(1)    if imsi_m    else None
        msisdn  = e164_m.group(1)    if e164_m    else None
        apn     = apn_m.group(1)     if apn_m     else None
        ip      = ip_m.group(1)      if ip_m      else None
        reqtype = reqtype_m.group(1) if reqtype_m else None
        svc_code= svc_m.group(1)     if svc_m     else None

        svc_map = {'32251': 'data', '32276': 'voice/SMS', '32274': 'MMS'}
        service = svc_map.get(svc_code, svc_code) if svc_code else None

        # Init session record
        if sess_id not in sessions:
            sessions[sess_id] = {
                'session_id': sess_id,
                'imsi':       imsi,
                'msisdn':     f"+{msisdn}" if msisdn else None,
                'apn':        apn,
                'ip':         ip,
                'service':    service,
                'start_ts':   ts,
                'end_ts':     None,
                'in_bytes':   0,
                'out_bytes':  0,
                'total_bytes':0,
                'req_count':  0,
                'status':     'active',
            }
        else:
            # Update fields if newly found
            rec = sessions[sess_id]
            if imsi   and not rec['imsi']:   rec['imsi']   = imsi
            if msisdn and not rec['msisdn']: rec['msisdn'] = f"+{msisdn}"
            if apn    and not rec['apn']:    rec['apn']    = apn
            if ip     and not rec['ip']:     rec['ip']     = ip
            if service and not rec['service']: rec['service'] = service

        # Accumulate usage from UsedServiceUnit blocks
        for in_b  in re.findall(r'CcInputOctets(\d+)CcInputOctets',  body):
            sessions[sess_id]['in_bytes']  += int(in_b)
        for out_b in re.findall(r'CcOutputOctets(\d+)CcOutputOctets', body):
            sessions[sess_id]['out_bytes'] += int(out_b)
        for tot_b in re.findall(r'CcTotalOctets(\d+)CcTotalOctets',   body):
            sessions[sess_id]['total_bytes'] += int(tot_b)

        # Also accumulate voice time
        for cc_t in re.findall(r'CcTime(\d+)CcTime', body):
            sessions[sess_id].setdefault('voice_sec', 0)
            sessions[sess_id]['voice_sec'] += int(cc_t)

        sessions[sess_id]['req_count'] += 1

        # Mark termination
        if reqtype in ('termination', 'terminate'):
            sessions[sess_id]['end_ts']  = ts
            sessions[sess_id]['status']  = 'terminated'

    # Deduplicate and clean up — remove 0-usage duplicates per IMSI/APN
    result = []
    seen   = set()
    for s in sessions.values():
        key = (s.get('imsi'), s.get('apn'), s.get('start_ts', '')[:16])
        if key in seen: continue
        seen.add(key)

        # Format bytes human-readable
        def fmt_bytes(n):
            if n == 0: return '0 B'
            for unit in ['B','KB','MB','GB']:
                if n < 1024: return f"{n:.1f} {unit}"
                n /= 1024
            return f"{n:.1f} TB"

        s['in_bytes_fmt']    = fmt_bytes(s['in_bytes'])
        s['out_bytes_fmt']   = fmt_bytes(s['out_bytes'])
        s['total_bytes_fmt'] = fmt_bytes(s['total_bytes'])
        s['voice_sec_fmt']   = f"{s.get('voice_sec',0)}s" \
                               if s.get('voice_sec') else None
        result.append(s)

    # Sort by start time
    result.sort(key=lambda x: x.get('start_ts',''))
    return result


def parse_log(log: str) -> Dict[str, Any]:
    blocks = _extract_blocks(log)
    return {
        'timeline':     _parse_timeline(blocks),
        'participants': _parse_participants(blocks, log),
        'rtp_stats':    _parse_rtp(blocks, log),
        'anomalies':    _parse_anomalies(blocks, log),
        'pgw_events':   _parse_pgw(log),
        'sdp_info':     _parse_sdp(blocks),
        'data_usage':   _parse_data_usage(log),
        'raw_blocks':   blocks,
    }

