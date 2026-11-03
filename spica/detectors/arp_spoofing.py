"""ARP 스푸핑(ARP 응답 위조) 탐지 모듈.

배경: ARP 는 "이 IP 를 쓰는 장비의 MAC 이 뭐냐"를 묻고 답하는 약속인데,
그 답(ARP 응답)에 대한 인증이 전혀 없음. 그래서 공격자가 "그 IP 는 내 MAC 이다"라고
거짓 응답을 뿌리면 주변 장비들이 그대로 믿어 버림.
특히 게이트웨이(공유기)를 사칭하면 피해자의 외부 트래픽을 전부 가로챌 수 있음.

탐지 전략 두 가지를 씀.
규칙 1) 게이트웨이 사칭: 게이트웨이 IP 라고 주장하는데 MAC 이 미리 등록한 정상값과 다르면 공격으로 봄.
규칙 2) 바인딩 급변: 특정 IP 의 MAC 이 이전에 관찰한 값과 갑자기 달라지면 의심함.
        게이트웨이가 아닌 일반 단말을 노린 스푸핑도 이 규칙으로 잡음.
"""
from __future__ import annotations

from scapy.layers.l2 import ARP
from scapy.packet import Packet

from spica.config_loader import SpicaConfig
from spica.detectors.base import DetectionFinding


class ArpSpoofingDetector:
    """패킷을 받아 ARP 스푸핑 의심 여부를 판단하는 탐지기."""

    # ARP 패킷의 op 필드가 2 이면 응답(reply)임. 스푸핑은 주로 가짜 응답으로 이뤄짐
    ARP_OPERATION_REPLY = 2

    def __init__(self, config: SpicaConfig) -> None:
        self.gateway_ip = config.gateway_ip
        self.expected_gateway_mac = SpicaConfig.normalize_mac(config.gateway_mac)

        # IP 별로 '지금까지 관찰한 MAC' 을 기억하는 표. 규칙 2 에서 급변을 판단하는 기준이 됨.
        # 게이트웨이는 정상 MAC 을 미리 신뢰값으로 넣어 둠
        self.ip_to_mac_bindings: dict[str, str] = {
            self.gateway_ip: self.expected_gateway_mac,
        }

    def inspect_packet(self, packet: Packet) -> list[DetectionFinding]:
        """패킷 하나를 검사해 발견한 의심 사건 목록을 반환함.

        의심이 없으면 빈 리스트를 반환함. 출력이나 차단은 하지 않고 판단 결과만 돌려줌.
        """
        # ARP 계층이 없는 패킷은 이 모듈의 관심사가 아니므로 바로 건너뜀
        if not packet.haslayer(ARP):
            return []

        arp_layer = packet[ARP]
        # 응답이 아닌 ARP(요청 등)는 스푸핑 판단 대상이 아님
        if arp_layer.op != self.ARP_OPERATION_REPLY:
            return []

        sender_ip = arp_layer.psrc
        sender_mac = SpicaConfig.normalize_mac(arp_layer.hwsrc)

        gateway_finding = self._check_gateway_impersonation(sender_ip, sender_mac)
        if gateway_finding is not None:
            # 게이트웨이 사칭은 확정적 신호라, 추가 검사 없이 바로 반환함
            return [gateway_finding]

        binding_finding = self._check_binding_change(sender_ip, sender_mac)
        if binding_finding is not None:
            return [binding_finding]

        return []

    def _check_gateway_impersonation(
        self, sender_ip: str, sender_mac: str
    ) -> DetectionFinding | None:
        # 게이트웨이 IP 가 아니면 이 규칙의 대상이 아님
        if sender_ip != self.gateway_ip:
            return None
        # 게이트웨이 IP 이면서 MAC 도 정상값이면 문제없음
        if sender_mac == self.expected_gateway_mac:
            return None

        return DetectionFinding(
            event_type="arp_spoof",
            message=(
                f"게이트웨이({sender_ip}) 사칭 의심. "
                f"정상 MAC {self.expected_gateway_mac} 이 아닌 {sender_mac} 이 응답함"
            ),
            source_mac=sender_mac,
            details={
                "claimed_ip": sender_ip,
                "expected_mac": self.expected_gateway_mac,
                "observed_mac": sender_mac,
            },
        )

    def _check_binding_change(
        self, sender_ip: str, sender_mac: str
    ) -> DetectionFinding | None:
        previously_seen_mac = self.ip_to_mac_bindings.get(sender_ip)

        # 처음 보는 IP 는 공격으로 단정할 수 없으므로 바인딩을 학습만 하고 넘어감
        if previously_seen_mac is None:
            self.ip_to_mac_bindings[sender_ip] = sender_mac
            return None

        # 이전에 본 MAC 과 같으면 정상
        if previously_seen_mac == sender_mac:
            return None

        # MAC 이 바뀌었으면 스푸핑 의심.
        # 주의: 여기서 바인딩을 새 MAC 으로 덮어쓰지 않음.
        #       공격자가 가짜 응답을 계속 보내 학습값을 오염시키는 것을 막기 위함.
        return DetectionFinding(
            event_type="arp_spoof",
            message=(
                f"{sender_ip} 의 MAC 이 {previously_seen_mac} 에서 {sender_mac} 로 바뀜. "
                f"ARP 스푸핑 가능성 있음"
            ),
            source_mac=sender_mac,
            details={
                "ip": sender_ip,
                "previous_mac": previously_seen_mac,
                "observed_mac": sender_mac,
            },
        )
