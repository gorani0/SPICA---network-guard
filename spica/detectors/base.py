"""탐지 모듈이 공통으로 쓰는 자료구조.

탐지 모듈은 직접 화면에 찍거나 차단하지 않고, '무엇을 발견했는지'만 이 객체로 돌려줌.
이렇게 판단과 행동을 분리하면 테스트할 때 네트워크나 방화벽 없이 반환값만 확인하면 되고,
나중에 출력 형식이나 차단 방식이 바뀌어도 탐지 코드는 손대지 않아도 됨.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DetectionFinding:
    """탐지 모듈이 찾아낸 의심 사건 한 건."""

    # 사건 종류. emitter 와 isolate 가 이 값으로 사건을 구분함. 예: "arp_spoof"
    event_type: str

    # 사람이 읽는 설명 문장
    message: str

    # 의심 단말의 MAC. 차단 대상이 될 수 있어 따로 둠. 해당 정보가 없으면 None
    source_mac: str | None = None

    # 판단 근거가 되는 추가 정보. 로그에 함께 남겨 두면 나중에 분석할 때 유용함
    details: dict[str, Any] = field(default_factory=dict)
