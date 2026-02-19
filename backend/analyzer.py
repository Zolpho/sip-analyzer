import re
from datetime import datetime
from typing import List, Optional
from models import AnalyzeRequest, AnalyzeResponse, Participant, ByeInfo, TimelineEvent
from parser import parse_log, FROM_RE, UA_RE, REASON_RE, SIP_METHODS

TS_FMT = "%Y-%m-%d_%H:%M:%S.%f"


def _ts(s: str) -> Optional[datetime]:
    try:
        return datetime.strptime(s, TS_FMT)
    except Exception:
        return None


def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    parsed   = parse_log(req.log)
    timeline = parsed["timeline"]
    anomalies= parsed["anomalies"]

    participants  = _build_participants(req, parsed["participants"])
    bye_info      = _analyze_bye(req, parsed["raw_blocks"], anomalies)
    duration, answer_time, ring_time = _timing(timeline)

    flags = [f.lower() for f in (req.flags or [])]
    full  = "+full" in flags

    return AnalyzeResponse(
        participants  = participants,
        timeline      = timeline,
        bye_info      = bye_info,
        rtp_stats     = parsed["rtp_stats"],
        anomalies     = anomalies,
        call_duration = duration,
        answer_time   = answer_time,
        ring_time     = ring_time,
        sdp_info      = parsed["sdp_info"]   if "+sdp"     in flags or full else None,
        pgw_events    = parsed["pgw_events"] if "+pgw"     in flags or full else None,
        routing_info  = _routing(parsed["raw_blocks"]) if "+routing" in flags or full else None,
    )


def _build_participants(req, detected: List[Participant]) -> List[Participant]:
    result, seen = [], set()

    def _find(num):
        clean = num.lstrip("+")
        for p in detected:
            if p.number and clean in p.number:
                return p.device, p.ip
        return None, None

    if req.caller:
        ua, ip = _find(req.caller)
        seen.add(req.caller.lstrip("+"))
        result.append(Participant(role="Caller (MO)", number=req.caller,
                                  imsi=req.caller_imsi, device=ua, ip=ip))
    if req.callee:
        ua, ip = _find(req.callee)
        seen.add(req.callee.lstrip("+"))
        result.append(Participant(role="Callee (MT)", number=req.callee,
                                  imsi=req.callee_imsi, device=ua, ip=ip))
    for p in detected:
        if p.number not in seen:
            seen.add(p.number)
            result.append(p)
    return result


def _analyze_bye(req, raw_blocks, anomalies) -> Optional[ByeInfo]:
    bye_block = None
    for ts, module, body in raw_blocks:
        first = body.strip().splitlines()[0].strip() if body.strip() else ""
        if re.match(r"^BYE\s+", first):
            bye_block = (ts, body)
            break
    if not bye_block:
        return None

    ts, body   = bye_block
    from_m     = FROM_RE.search(body)
    reason_m   = REASON_RE.search(body)
    ua_m       = UA_RE.search(body)
    sender_num = from_m.group(1) if from_m else "unknown"
    reason_txt = reason_m.group(1).strip() if reason_m else None

    callee_num  = (req.callee or "").lstrip("+")
    caller_num  = (req.caller or "").lstrip("+")
    callee_imsi = req.callee_imsi or ""

    if callee_num and callee_num in sender_num:
        sender_role = f"Callee ({req.callee})"
    elif callee_imsi and callee_imsi in body:
        sender_role = f"Callee IMSI ({callee_imsi})"
    elif caller_num and caller_num in sender_num:
        sender_role = f"Caller ({req.caller})"
    else:
        sender_role = f"+{sender_num}"

    evidence = []
    if reason_txt:
        evidence.append(f"Reason header: {reason_txt}")
    if ua_m:
        evidence.append(f"Sent by device: {ua_m.group(1).strip()}")

    bye_ts = _ts(ts)
    for _, _, b in raw_blocks:
        if "Unregistered user" in b:
            evidence.append("Device de-registered immediately after BYE")
            break

    pgw_re = re.compile(r"(\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}\.\d+).*pgw/session/delete.*?(\d{15,})")
    for line in req.log.splitlines():
        pgw_m = pgw_re.search(line)
        if pgw_m:
            pgw_ts = _ts(pgw_m.group(1))
            if bye_ts and pgw_ts and pgw_ts <= bye_ts:
                evidence.append(f"PGW data session for IMSI {pgw_m.group(2)} torn down before/at BYE")

    for a in anomalies:
        if "quota" in a or "charging" in a.lower():
            evidence.append(f"Note: {a}")

    if not evidence:
        evidence.append("No Reason header — likely user-initiated hang-up")

    return ByeInfo(
        sender=sender_role,
        sender_number=f"+{sender_num}",
        reason=reason_txt,
        raw_snippet=body.strip()[:700],
        evidence=list(dict.fromkeys(evidence)),
    )


def _timing(timeline: List[TimelineEvent]):
    invite_ts = answer_ts = ring_ts = bye_ts = None
    for ev in timeline:
        t = _ts(ev.timestamp)
        if not t:
            continue
        if ev.method == "INVITE" and invite_ts is None:
            invite_ts = t
        if ev.method == "180 Ringing" and ring_ts is None:
            ring_ts = t
        if ev.method.startswith("200") and "INVITE" in ev.description and answer_ts is None:
            answer_ts = t
        if ev.method == "BYE" and bye_ts is None:
            bye_ts = t

    def fmt(delta) -> Optional[str]:
        if delta is None:
            return None
        s = delta.total_seconds()
        return f"{int(s//60)}m {s%60:.1f}s" if s >= 60 else f"{s:.1f}s"

    return (
        fmt((bye_ts    - answer_ts)  if bye_ts    and answer_ts  else None),
        fmt((answer_ts - invite_ts)  if answer_ts and invite_ts  else None),
        fmt((ring_ts   - invite_ts)  if ring_ts   and invite_ts  else None),
    )


def _routing(raw_blocks) -> List[str]:
    via_re   = re.compile(r"^Via:\s*(.+)$",   re.MULTILINE)
    route_re = re.compile(r"^Route:\s*(.+)$",  re.MULTILINE)
    routing  = []
    for ts, _, body in raw_blocks:
        first = body.strip().splitlines()[0].strip() if body.strip() else ""
        if re.match(r"^(INVITE|BYE|CANCEL)\s+", first):
            vias   = via_re.findall(body)
            routes = route_re.findall(body)
            if vias or routes:
                entry = f"[{ts}] {first[:70]}"
                entry += "".join(f"\n  Via: {v.strip()}"   for v in vias)
                entry += "".join(f"\n  Route: {r.strip()}" for r in routes)
                routing.append(entry)
    return routing

