from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PacketRecord:
    number: int
    epoch_time: float
    relative_time: float
    length: int
    src: str
    dst: str
    protocol: str
    info: str
    layers: List[str]
    sport: Optional[int] = None
    dport: Optional[int] = None
    stream_hint: str = ''
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw: Any = None
    iface: str = ''
