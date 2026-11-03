"""설정 파일(config/config.yaml)을 읽어서 검증하는 모듈.

네트워크 환경마다 달라지는 값(게이트웨이 주소, 허가된 DHCP 목록, 각종 임계값)을
코드에 직접 박아 넣지 않고 한 곳에 모아 두기 위한 모듈임.
이렇게 하면 나중에 실제 라즈베리파이로 옮기거나 다른 실험망에서 돌릴 때
코드는 그대로 두고 이 설정 파일만 바꾸면 됨.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

# 설정에 반드시 있어야 하는 항목들. 하나라도 없으면 실행 초반에 바로 멈추고 알려줌
REQUIRED_KEYS = ("gateway_ip", "gateway_mac", "allowed_dhcp_server_macs")


@dataclass
class SpicaConfig:
    """검증을 마친 설정값을 담는 컨테이너.

    dict 대신 dataclass 를 쓰는 이유는, 어떤 설정 항목이 있는지 한눈에 보이고
    오타로 없는 키를 참조하는 실수를 줄일 수 있기 때문임.
    """

    gateway_ip: str
    gateway_mac: str
    allowed_dhcp_server_macs: list[str]
    syn_flood_threshold_per_second: int = 200
    syn_ack_ratio_threshold: float = 0.3
    block_duration_minutes: int = 10
    whitelist_macs: list[str] = field(default_factory=list)

    @staticmethod
    def normalize_mac(mac_address: str) -> str:
        # MAC 주소는 대소문자를 구분하지 않으므로, 비교 실수를 막기 위해 소문자로 통일함
        return mac_address.strip().lower()


def load_config(config_path: str | Path = "config/config.yaml") -> SpicaConfig:
    """설정 파일을 읽어 SpicaConfig 로 변환함.

    문제가 있으면 애매하게 넘어가지 않고 명확한 예외를 던져서,
    잘못된 설정으로 시스템이 조용히 오작동하는 상황을 막음.
    """
    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(
            f"설정 파일을 찾을 수 없음: {config_path}. "
            f"config/config.example.yaml 을 복사해서 config.yaml 을 먼저 만들 것."
        )

    with config_path.open("r", encoding="utf-8") as config_file:
        raw_config = yaml.safe_load(config_file) or {}

    # 필수 항목 누락 검사. 빨리 실패해서(fail fast) 원인을 바로 알 수 있게 함
    missing_keys = [key for key in REQUIRED_KEYS if key not in raw_config]
    if missing_keys:
        raise ValueError(f"설정에 필수 항목이 빠져 있음: {missing_keys}")

    # MAC 관련 값은 이후 비교 편의를 위해 로딩 시점에 미리 소문자로 정규화해 둠
    normalized_gateway_mac = SpicaConfig.normalize_mac(raw_config["gateway_mac"])
    normalized_allowed_dhcp_macs = [
        SpicaConfig.normalize_mac(mac) for mac in raw_config["allowed_dhcp_server_macs"]
    ]
    normalized_whitelist_macs = [
        SpicaConfig.normalize_mac(mac) for mac in raw_config.get("whitelist_macs", [])
    ]

    return SpicaConfig(
        gateway_ip=raw_config["gateway_ip"],
        gateway_mac=normalized_gateway_mac,
        allowed_dhcp_server_macs=normalized_allowed_dhcp_macs,
        syn_flood_threshold_per_second=raw_config.get("syn_flood_threshold_per_second", 200),
        syn_ack_ratio_threshold=raw_config.get("syn_ack_ratio_threshold", 0.3),
        block_duration_minutes=raw_config.get("block_duration_minutes", 10),
        whitelist_macs=normalized_whitelist_macs,
    )
