"""사건(event) 출력을 담당하는 모듈.

탐지 결과나 장애 진단 결과 같은 '사건'을 두 곳으로 동시에 내보냄.
1) 사람이 바로 보는 콘솔
2) 나중에 분석과 시각화에 쓰는 JSONL 로그 파일

JSONL 은 한 줄에 JSON 하나씩 쌓는 형식임. 사건이 생길 때마다 파일 끝에 덧붙이기만 하면 되고,
나중에 한 줄씩 읽어서 통계나 그래프로 가공하기 좋음.
탐지 모듈과 진단 모듈이 출력 방법을 각자 구현하지 않고 이 모듈 하나만 쓰도록 만들어,
출력 형식을 한 곳에서 관리함.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


class EventEmitter:
    """사건을 콘솔과 JSONL 로그에 기록하는 출력기."""

    def __init__(self, log_file_path: str | Path = "events.jsonl") -> None:
        self.log_file_path = Path(log_file_path)
        # 로그 파일이 들어갈 디렉터리가 아직 없으면 미리 만들어 둠
        self.log_file_path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event_type: str, **event_fields: Any) -> dict[str, Any]:
        """사건 하나를 기록함.

        event_type 은 사건의 종류(예: "arp_spoof"), event_fields 는 그 사건의 세부 정보
        (예: mac="aa:bb:..", message="가짜 ARP 응답 발견")를 자유롭게 넘기는 용도임.
        기록한 사건 레코드를 그대로 반환해서, 호출한 쪽에서 추가로 활용할 수 있게 함.
        """
        # 모든 사건에 공통으로 발생 시각과 종류를 붙여 레코드를 구성함
        event_record = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "event_type": event_type,
            **event_fields,
        }
        self._print_to_console(event_record)
        self._append_to_log(event_record)
        return event_record

    def _print_to_console(self, event_record: dict[str, Any]) -> None:
        # 콘솔에는 사람이 읽기 쉬운 한 줄 요약으로 보여줌
        timestamp = event_record["timestamp"]
        event_type = event_record["event_type"]
        message = event_record.get("message", "")
        print(f"[{timestamp}] {event_type} {message}".rstrip())

    def _append_to_log(self, event_record: dict[str, Any]) -> None:
        # JSONL 특성상 한 줄에 JSON 하나를 씀.
        # ensure_ascii=False 로 설정해 한글이 유니코드 escape 로 깨지지 않게 저장함
        log_line = json.dumps(event_record, ensure_ascii=False)
        with self.log_file_path.open("a", encoding="utf-8") as log_file:
            log_file.write(log_line + "\n")
