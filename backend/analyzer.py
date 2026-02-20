import re
from datetime import datetime
from typing import List, Optional
from models import AnalyzeRequest, AnalyzeResponse, Participant, ByeInfo, TimelineEvent
from parser import parse_log, FROM_RE, TO_RE, UA_RE, REASON_RE, _normalize_number

TS_FMT = "%Y-%m-%d_%H:%M:%S.%f"

def _ts(s):
    try: return datetime.strptime(s, TS_FMT)
    except: return None

def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    parsed    = parse_log(req.log)
    flags     = [f.lower() for f in (req.flags or [])]
    full      = "+full" in flags

    # Normalize input numbers for matching
    caller_norm = _normalize_number(re.sub(r'^\+', '', req.caller or ''))
    callee_norm = _normalize_number(re.sub(r'^\+', '', req.callee or ''))
    caller_imsi = req.caller_imsi or ''
    callee_imsi = req.callee_imsi or ''

    # Build relevant number set for filtering
    relevant = set(filter(None, [caller_norm, callee_norm, caller_imsi, callee_imsi]))

    timeline  = _filter_timeline(parsed["timeline"], relevant) \
                if relevant else parsed["timeline"]

    return AnalyzeResponse(
        participants  = _build_participants(req, parsed["participants"],
                                           caller_norm, callee_norm,
                                           caller_imsi, callee_imsi),
        timeline      = timeline,
        bye_info      = _analyze_bye(req, parsed["raw_blocks"], parsed["anomalies"],
                                     caller_norm, callee_norm, caller_imsi, callee_imsi),
        rtp_stats     = parsed["rtp_stats"],
        anomalies     = parsed["anomalies"],
        call_duration = _timing(timeline)[0],
        answer_time   = _timing(timeline)[1],
        ring_time     = _timing(timeline)[2],
        sdp_info      = parsed["sdp_info"]   if "+sdp"     in flags or full else None,
        data_usage    = parsed["data_usage"] if "+pgw"     in flags or full else None,
        pgw_events    = parsed["pgw_events"] if "+pgw"     in flags or full else None,
        routing_info  = _routing(parsed["raw_blocks"]) if "+routing" in flags or full else None,
    )

def _is_relevant(body: str, relevant: set) -> bool:
    """Return True if any relevant number/IMSI appears in this SIP block."""
    if not relevant:
        return True
    for r in relevant:
        if r and r in body:
            return True
    return False

def _filter_timeline(timeline: List[TimelineEvent], relevant: set) -> List[TimelineEvent]:
    """Keep only timeline events that reference at least one relevant number/IMSI."""
    if not relevant:
        return timeline
    filtered = []
    for ev in timeline:
        # Always keep INTERNAL events (PGW, VLR, etc.) — they don't have numbers
        if ev.method == 'INTERNAL':
            filtered.append(ev)
            continue
        # Check if any relevant number appears in description
        for r in relevant:
            if r and r in ev.description:
                filtered.append(ev)
                break
    return filtered

def _build_participants(req, detected, caller_norm, callee_norm,
                        caller_imsi, callee_imsi) -> List[Participant]:
    result = []
    used   = set()

    def _find_device_ip(norm):
        """Find device and IP from detected participants."""
        for p in detected:
            p_norm = _normalize_number(re.sub(r'^\+', '', p.number or ''))
            if p_norm == norm:
                return p.device, p.ip
        return None, None

    # Add caller if provided
    if req.caller:
        ua, ip = _find_device_ip(caller_norm)
        result.append(Participant(
            role   = 'Caller (MO)',
            number = req.caller if req.caller.startswith('+') else f'+{caller_norm}',
            imsi   = req.caller_imsi or None,
            device = ua,
            ip     = ip
        ))
        used.add(caller_norm)

    # Add callee if provided
    if req.callee:
        ua, ip = _find_device_ip(callee_norm)
        result.append(Participant(
            role   = 'Callee (MT)',
            number = req.callee if req.callee.startswith('+') else f'+{callee_norm}',
            imsi   = req.callee_imsi or None,
            device = ua,
            ip     = ip
        ))
        used.add(callee_norm)

    # Only add extra detected participants if they are NOT already listed
    # and if no caller/callee was specified (open analysis mode)
    if not req.caller and not req.callee:
        for p in detected:
            p_norm = _normalize_number(re.sub(r'^\+', '', p.number or ''))
            if p_norm not in used:
                used.add(p_norm)
                result.append(p)

    return result

def _analyze_bye(req, raw_blocks, anomalies, caller_norm, callee_norm, caller_imsi='', callee_imsi=''):
    bye_block = None
    for ts, module, body in raw_blocks:
        first = body.strip().splitlines()[0].strip() if body.strip() else ""
        # Find BYE relevant to our call participants
        if re.match(r'^BYE\s+', first):
            # If we have caller/callee, verify this BYE belongs to our call
            if caller_norm or callee_norm:
                if (caller_norm and caller_norm in body) or \
                   (callee_norm and callee_norm in body):
                    bye_block = (ts, body)
                    break
            else:
                bye_block = (ts, body)
                break

    if not bye_block: return None
    ts, body   = bye_block
    from_m     = FROM_RE.search(body)
    reason_m   = REASON_RE.search(body)
    ua_m       = UA_RE.search(body)
    sender_num = _normalize_number(from_m.group(1)) if from_m else "unknown"
    reason_txt = reason_m.group(1).strip() if reason_m else None

    if caller_norm and sender_num == caller_norm:
        sender_role = f"Caller ({req.caller})"
    elif callee_norm and sender_num == callee_norm:
        sender_role = f"Callee ({req.callee})"
    else:
        sender_role = f"+{sender_num}"

    evidence = []
    if reason_txt: evidence.append(f"Reason header: {reason_txt}")
    if ua_m: evidence.append(f"Sent by device: {ua_m.group(1).strip()}")
    for _, _, b in raw_blocks:
        if "Unregistered user" in b and \
           ((callee_norm and callee_norm in b) or (caller_norm and caller_norm in b)):
            evidence.append("Device de-registered immediately after BYE")
            break
    # Check hangup cause
    hup = re.search(r'X-Asterisk-HangupCause[:\s]+([^\r\n]+)', body)
    hup_code = re.search(r'X-Asterisk-HangupCauseCode[:\s]+(\d+)', body)
    if hup:
        evidence.append(f"Hangup cause: {hup.group(1).strip()}")
    if hup_code:
        cause_map = {
            '16': 'Normal call clearing',
            '17': 'User busy',
            '18': 'No user responding',
            '19': 'No answer from user',
            '21': 'Call rejected',
            '31': 'Normal, unspecified',
        }
        code = hup_code.group(1)
        desc = cause_map.get(code, 'Unknown cause')
        evidence.append(f"Q.850 cause {code}: {desc}")

    pgw_re = re.compile(
        r'(\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}\.\d+).*?'
        r'pgw/session/delete.*?(\d{15,})'
    )
    bye_ts = _ts(ts)
    for line in req.log.splitlines():
        m = pgw_re.search(line)
        if m:
            pgw_ts = _ts(m.group(1))
            imsi   = m.group(2)
            if bye_ts and pgw_ts and pgw_ts <= bye_ts:
                if not caller_imsi and not callee_imsi:
                    evidence.append(f"PGW session for IMSI {imsi} torn down before/at BYE")
                elif imsi in [caller_imsi, callee_imsi]:
                    evidence.append(f"PGW session for IMSI {imsi} torn down before/at BYE")

    if not evidence:
        evidence.append("No Reason header — likely user-initiated hang-up")

    return ByeInfo(
        sender      = sender_role,
        sender_number = f"+{sender_num}",
        reason      = reason_txt,
        raw_snippet = body.strip()[:700],
        evidence    = list(dict.fromkeys(evidence))
    )

def _timing(timeline):
    invite_ts = answer_ts = ring_ts = bye_ts = None

    # Find the Call-ID of the first INVITE to anchor all subsequent events
    anchor_callid = None
    for ev in timeline:
        if ev.method == "INVITE":
            # Extract Call-ID from description
            cid_m = re.search(r'Call-ID:\s*(\S+)', ev.description)
            if cid_m:
                anchor_callid = cid_m.group(1)
            invite_ts = _ts(ev.timestamp)
            break

    for ev in timeline:
        t = _ts(ev.timestamp)
        if not t: continue

        # If we have an anchor Call-ID, skip events from other calls
        if anchor_callid:
            cid_m = re.search(r'Call-ID:\s*(\S+)', ev.description)
            if cid_m and cid_m.group(1) != anchor_callid:
                continue

        if ev.method == "INVITE" and invite_ts is None:
            invite_ts = t
        if "180" in ev.method and ring_ts is None:
            ring_ts = t
        if ev.method.startswith("200") and "INVITE" in ev.description \
                and answer_ts is None:
            answer_ts = t
        if ev.method == "BYE" and bye_ts is None:
            bye_ts = t

    def fmt(d):
        if d is None: return None
        s = d.total_seconds()
        # Sanity check — reject implausible values over 1 hour
        if s > 3600: return None
        return f"{int(s//60)}m {s%60:.1f}s" if s >= 60 else f"{s:.1f}s"

    return (
        fmt((bye_ts - answer_ts)   if bye_ts and answer_ts   else None),
        fmt((answer_ts - invite_ts) if answer_ts and invite_ts else None),
        fmt((ring_ts - invite_ts)   if ring_ts and invite_ts  else None),
    )

def _routing(raw_blocks):
    via_re   = re.compile(r'^Via:\s*(.+)$',   re.MULTILINE)
    route_re = re.compile(r'^Route:\s*(.+)$', re.MULTILINE)
    routing  = []
    for ts, _, body in raw_blocks:
        first = body.strip().splitlines()[0].strip() if body.strip() else ""
        if re.match(r'^(INVITE|BYE|CANCEL)\s+', first):
            vias   = via_re.findall(body)
            routes = route_re.findall(body)
            if vias or routes:
                entry  = f"[{ts}] {first[:70]}"
                entry += "".join(f"\n  Via: {v.strip()}"   for v in vias)
                entry += "".join(f"\n  Route: {r.strip()}" for r in routes)
                routing.append(entry)
    return routing
