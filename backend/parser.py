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

# ── Diameter regex patterns ──────────────────────────────────────────────────
DIAMETER_RE = re.compile(
    r'(CreditControlRequest|CreditControlAnswer|'
    r'AuthorizationRequest|AuthorizationAnswer|'
    r'AccountingRequest|AccountingAnswer)',
    re.IGNORECASE
)
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
# <ResultCode> inside XML body — first (top-level) only
DIAM_RESULT_CODE_RE = re.compile(
    r'<ResultCode[^>]*>(\d+)</ResultCode>',
    re.IGNORECASE
)
# Subscriber from XML
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
# Fallback flat attribute forms
DIAM_IMSI_ATTR_RE   = re.compile(r"'?imsi'?\s*[=:]\s*'?(\d{14,16})'?", re.IGNORECASE)
DIAM_MSISDN_ATTR_RE = re.compile(
    r"(?:msisdn|called|calling|target)\s*[=:]\s*\+?(\d{7,15})", re.IGNORECASE
)
# Request type
DIAM_REQTYPE_RE = re.compile(
    r'<CcRequestType[^>]*>(\w+)</CcRequestType>',
    re.IGNORECASE
)
# Service context
DIAM_SVC_RE = re.compile(r'<ServiceContextId>(\d+)@', re.IGNORECASE)
# APN
DIAM_APN_RE = re.compile(r'<CalledStationId>([^<]+)</CalledStationId>', re.IGNORECASE)

# Result string → human label
_DIAM_RESULT_LABELS = {
    'DIAMETER_SUCCESS':                'SUCCESS',
    'DIAMETER_CREDIT_LIMIT_REACHED':   'CREDIT_LIMIT_REACHED',
    'DIAMETER_RATING_FAILED':          'RATING_FAILED',
    'DIAMETER_AUTHORIZATION_REJECTED': 'AUTHORIZATION_REJECTED',
    'DIAMETER_USER_UNKNOWN':           'USER_UNKNOWN',
    'DIAMETER_UNABLE_TO_COMPLY':       'UNABLE_TO_COMPLY',
    'DIAMETER_RESOURCES_EXCEEDED':     'RESOURCES_EXCEEDED',
}
_DIAM_CODE_LABELS = {
    '2001': 'SUCCESS',
    '4010': 'CREDIT_LIMIT_REACHED',
    '4011': 'RESOURCES_EXCEEDED',
    '4012': 'RATING_FAILED',
    '5002': 'UNKNOWN_SESSION_ID',
    '5003': 'AUTHORIZATION_REJECTED',
    '5006': 'RESOURCES_EXCEEDED',
    '5012': 'UNABLE_TO_COMPLY',
    '5030': 'USER_UNKNOWN',
    '5031': 'RATING_FAILED',
}

def _diam_result_fmt(result_str: str, result_code: str = None) -> str:
    """Return a human-readable result with success/denied marker."""
    prefix_ok  = '[OK]'
    prefix_err = '[ERR]'
    if result_str:
        key   = result_str.upper()
        label = _DIAM_RESULT_LABELS.get(key, result_str)
        code  = result_code or ''
        pfx   = prefix_ok if key == 'DIAMETER_SUCCESS' else prefix_err
        return f"{pfx} {label}" + (f" ({code})" if code and code != '2001' else
                                   f" (2001)"   if key == 'DIAMETER_SUCCESS' else "")
    if result_code:
        label = _DIAM_CODE_LABELS.get(result_code, result_code)
        pfx   = prefix_ok if result_code.startswith('2') else prefix_err
        return f"{pfx} {label} ({result_code})"
    return '? unknown'


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

        if method is None:
            method = 'INTERNAL'

        # ── Build description ─────────────────────────────────────────────────
        desc_parts = []

        if is_diameter:
            # 1. Result — XML root attribute first, then flat kv, then <ResultCode>
            result_str  = None
            result_code = None

            rm_attr = DIAM_RESULT_ATTR_RE.search(body)
            rm_kv   = DIAM_RESULT_KV_RE.search(body)
            if rm_attr:
                result_str = rm_attr.group(1)
            elif rm_kv:
                result_str = rm_kv.group(1)

            rc_m = DIAM_RESULT_CODE_RE.search(body)
            if rc_m:
                result_code = rc_m.group(1)

            desc_parts.append(_diam_result_fmt(result_str, result_code))

            # 2. Subscriber — XML form first, flat attribute fallback
            imsi_m = DIAM_IMSI_XML_RE.search(body) or DIAM_IMSI_ATTR_RE.search(body)
            e164_m = DIAM_E164_XML_RE.search(body) or DIAM_MSISDN_ATTR_RE.search(body)

            if e164_m:
                desc_parts.append(f"MSISDN:+{e164_m.group(1)}")
            if imsi_m:
                desc_parts.append(f"IMSI:{imsi_m.group(1)}")

            # 3. Request type
            rt_m = DIAM_REQTYPE_RE.search(body)
            if rt_m:
                desc_parts.append(f"type:{rt_m.group(1)}")

            # 4. Service / APN
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
            cid = re.search(r'[Cc]all-[Ii][Dd]:\s*(\S+)', body)
            if cid:
                desc_parts.append(f"Call-ID: {cid.group(1)[:30]}")

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
                    

