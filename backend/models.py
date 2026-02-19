from pydantic import BaseModel
from typing import Optional, List

class AnalyzeRequest(BaseModel):
    caller: Optional[str] = None
    callee: Optional[str] = None
    caller_imsi: Optional[str] = None
    callee_imsi: Optional[str] = None
    log: str
    flags: Optional[List[str]] = []

class Participant(BaseModel):
    role: Optional[str] = "Unknown"
    number: Optional[str] = None
    imsi: Optional[str] = None
    device: Optional[str] = None
    ip: Optional[str] = None

class TimelineEvent(BaseModel):
    timestamp: str
    direction: str
    method: str
    description: str
    raw: Optional[str] = None

class RTPStat(BaseModel):
    leg: str
    ps: Optional[str] = None
    os: Optional[str] = None
    pr: Optional[str] = None
    or_: Optional[str] = None
    pl: Optional[str] = None
    pd: Optional[str] = None
    ji: Optional[str] = None
    codec: Optional[str] = None

class ByeInfo(BaseModel):
    sender: str
    sender_number: Optional[str] = None
    reason: Optional[str] = None
    raw_snippet: str
    evidence: List[str] = []

class AnalyzeResponse(BaseModel):
    participants: List[Participant] = []
    timeline: List[TimelineEvent] = []
    bye_info: Optional[ByeInfo] = None
    rtp_stats: List[RTPStat] = []
    anomalies: List[str] = []
    call_duration: Optional[str] = None
    answer_time: Optional[str] = None
    ring_time: Optional[str] = None
    sdp_info: Optional[dict] = None
    pgw_events: Optional[List[str]] = None
    routing_info: Optional[List[str]] = None

