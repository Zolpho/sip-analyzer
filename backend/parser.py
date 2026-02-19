import re
from typing import List, Tuple, Optional
from models import TimelineEvent, Participant, RTPStat

SIP_METHODS = ["INVITE","ACK","BYE","CANCEL","REGISTER","OPTIONS",
               "UPDATE","PRACK","INFO","MESSAGE","SUBSCRIBE","NOTIFY","REFER"]

METHOD_RE   = re.compile(r"^(" + "|".join(SIP_METHODS) + r")\s+\S+\s+SIP/2\.0")
STATUS_RE   = re.compile(r"^SIP/2\.0\s+(\d{3})\s+(.+)")
UA_RE       = re.compile(r"^User-Agent:\s*(.+)$", re.MULTILINE)
CONTACT_IP  = re.compile(r"^Contact:\s*<sip:[^@]+@([\d\.]+):\d+", re.MULTILINE)
FROM_RE     = re.compile(r"^From:\s*<(?:sip:|tel:)\+?(\d+)[@;>]", re.MULTILINE)
TO_RE       = re.compile(r"^To:\s*<(?:sip:|tel:)\+?(\d+)[@;>]", re.MULTILINE)
RTP_STAT_RE = re.compile(r"P-RTP-Stat:\s*PS=(\d+),OS=(\d+),PR=(\d+),OR=(\d+),PL=(\d+),PD=(\d+),JI=(\d+)")
CODEC_RE    = re.compile(r"Formats for '(\w+)' changed to '([^']+)'")
REASON_RE   = re.compile(r"^Reason:\s*(.+)$", re.MULTILINE)
PGW_URL_RE  = re.compile(r"url=http://[^;]+pgw/session/(\w+)[^;]*;body=(\{[^}]+\})")
SSRC_RE     = re.compile(r"RTCP Received SSRC (\w+) but expecting (\w+)")
WARN_RE     = re.compile(r'Warning:\s*\d+\s+\S+\s+"([^"]+)"')
TRANSPORT_RE= re.compile(r"Transport\((\S+)\)")
SESSION_RE  = re.compile(r"Session '([^']+)'")


def split_blocks(raw: str):
    """Split raw log into (timestamp, module, body) tuples."""
    blocks = []
    current_ts = current_module = None
    current_lines = []
    line_re = re.compile(r"^(\d{4}-\d{2}-\d{2}_\d{2}:\d{2}:\d{2}\.\d+)\s+<([^>]+)>\s+(.*)")
    for line in raw.splitlines():
        m = line_re.match(line)
        if m:
            if current_ts is not None:
                blocks.append((current_ts, current_module, "\n".join(current_lines)))
            current_ts, current_module = m.group(1), m.group(2)
            current_lines = [m.group(3)]
        else:
            current_lines.append(line)
    if current_ts is not None:
        blocks.append((current_ts, current_module, "\n".join(current_lines)))
    return blocks


def extract_method(body: str) -> Optional[str]:
    first = body.strip().splitlines()[0].strip() if body.strip() else ""
    if METHOD_RE.match(first):
        return first.split()[0]
    s = STATUS_RE.match(first)
    if s:
        return f"{s.group(1)} {s.group(2)}"
    return None


def direction(body: str) -> str:
    if "sending" in body[:80]:
        return "OUT"
    if "received" in body[:80]:
        return "IN"
    return "INTERNAL"


def parse_log(raw: str) -> dict:
    blocks = split_blocks(raw)
    timeline: List[TimelineEvent] = []
    participants: List[Participant] = []
    rtp_stats: List[RTPStat] = []
    anomalies: List[str] = []
    pgw_events: List[str] = []
    sdp_blocks: List[str] = []
    last_codec: Optional[str] = None
    seen_numbers = set()

    for ts, module, body in blocks:
        method = extract_method(body)
        direc  = direction(body)

        # ── PGW events ────────────────────────────────────────────────────────
        for pgw_m in PGW_URL_RE.finditer(body):
            pgw_events.append(f"[{ts}] pgw/{pgw_m.group(1)}: {pgw_m.group(2)}")

        # ── Codec negotiation ─────────────────────────────────────────────────
        codec_m = CODEC_RE.search(body)
        if codec_m:
            last_codec = f"{codec_m.group(1)}/{codec_m.group(2)}"
            timeline.append(TimelineEvent(
                timestamp=ts, direction="INTERNAL", method="CODEC",
                description=f"Audio format negotiated: {codec_m.group(2)}",
                raw=body.strip()[:600]
            ))

        # ── RTP stats ─────────────────────────────────────────────────────────
        rtp_m = RTP_STAT_RE.search(body)
        if rtp_m:
            from_m = FROM_RE.search(body)
            leg = from_m.group(1) if from_m else "unknown"
            rtp_stats.append(RTPStat(
                leg=leg,
                ps=rtp_m.group(1), os=rtp_m.group(2),
                pr=rtp_m.group(3), or_=rtp_m.group(4),
                pl=rtp_m.group(5), pd=rtp_m.group(6),
                ji=rtp_m.group(7), codec=last_codec
            ))

        # ── Anomalies ─────────────────────────────────────────────────────────
        ssrc_m = SSRC_RE.search(body)
        if ssrc_m:
            anomalies.append(f"[{ts}] RTCP SSRC mismatch: received {ssrc_m.group(1)}, expected {ssrc_m.group(2)}")

        if "500 Server Internal Error" in body:
            w = WARN_RE.search(body)
            anomalies.append(f"[{ts}] 500 Internal Error: {w.group(1) if w else 'unknown'}")

        if "Network down" in body:
            t = TRANSPORT_RE.search(body)
            anomalies.append(f"[{ts}] Network down: {t.group(1) if t else 'transport'}")

        if "rejected_initial_low_quota" in body:
            s = SESSION_RE.search(body)
            anomalies.append(f"[{ts}] Online charging rejected (low quota): {s.group(1) if s else ''}")

        # ── Auto-detect participants from SIP messages ────────────────────────
        if method and "sip" in module:
            ua_m = UA_RE.search(body)
            ip_m = CONTACT_IP.search(body)
            from_m = FROM_RE.search(body)
            if from_m:
                num = from_m.group(1)
                if num not in seen_numbers:
                    seen_numbers.add(num)
                    participants.append(Participant(
                        role="detected",
                        number=num,
                        device=ua_m.group(1).strip() if ua_m else None,
                        ip=ip_m.group(1) if ip_m else None,
                    ))

        # ── SDP collection ────────────────────────────────────────────────────
        if "v=0" in body and "m=audio" in body:
            ua_m = UA_RE.search(body)
            sdp_blocks.append({"body": body, "ua": ua_m.group(1) if ua_m else "unknown"})

        # ── Timeline ─────────────────────────────────────────────────────────
        if method and module.split("/")[0] in ("sip", "ucn_vlr", "ucn_pgw", "RegexRoute"):
            from_m = FROM_RE.search(body)
            to_m   = TO_RE.search(body)
            src = f"+{from_m.group(1)}" if from_m else "?"
            dst = f"+{to_m.group(1)}" if to_m else "?"
            if method in SIP_METHODS:
                desc = f"{'→' if direc == 'OUT' else '←'} {method} from {src} to {dst}"
            else:
                desc = f"{method}"
            timeline.append(TimelineEvent(
                timestamp=ts, direction=direc, method=method,
                description=desc, raw=body.strip()[:700]
            ))
        elif module in ("ucn_vlr", "ucn_pgw", "RegexRoute") and not method:
            timeline.append(TimelineEvent(
                timestamp=ts, direction="INTERNAL", method=module.upper(),
                description=body.strip()[:200], raw=body.strip()[:700]
            ))

    sdp_info = _sdp_summary(sdp_blocks)
    return dict(timeline=timeline, participants=participants, rtp_stats=rtp_stats,
                anomalies=anomalies, pgw_events=pgw_events, sdp_info=sdp_info,
                raw_blocks=blocks)


def _sdp_summary(sdp_blocks):
    offered, answered = [], []
    for entry in sdp_blocks:
        codecs = re.findall(r"a=rtpmap:\d+ ([^/]+/\d+)", entry["body"])
        item = {"ua": entry["ua"], "codecs": codecs}
        if "YATE" in entry["ua"] or "INVITE" in entry["body"][:30]:
            offered.append(item)
        else:
            answered.append(item)
    return {"offered": offered, "answered": answered}

