"""ARP 스푸핑 탐지 모듈 테스트.

실제 네트워크 없이, scapy 로 가짜 ARP 패킷을 만들어 탐지 로직만 검증함.
패킷을 '만드는' 동작은 관리자 권한이 필요 없으므로 일반 환경에서도 실행 가능함.
실행: 프로젝트 루트에서 python3 -m pytest tests/ -v
"""
from scapy.layers.l2 import ARP, Ether

from spica.config_loader import SpicaConfig
from spica.detectors.arp_spoofing import ArpSpoofingDetector

GATEWAY_IP = "192.168.10.1"
GATEWAY_MAC = "11:22:33:44:55:66"
NORMAL_HOST_IP = "192.168.10.80"
NORMAL_HOST_MAC = "00:11:22:33:44:55"
ATTACKER_MAC = "aa:bb:cc:dd:ee:ff"


def make_config() -> SpicaConfig:
    # 테스트용 최소 설정. 파일을 읽지 않고 직접 구성함
    return SpicaConfig(
        gateway_ip=GATEWAY_IP,
        gateway_mac=GATEWAY_MAC,
        allowed_dhcp_server_macs=[GATEWAY_MAC],
    )


def make_arp_reply(sender_ip: str, sender_mac: str) -> Ether:
    # op=2 는 ARP 응답. 스푸핑은 주로 가짜 응답으로 이뤄지므로 응답 패킷으로 만듦
    return Ether() / ARP(op=2, psrc=sender_ip, hwsrc=sender_mac)


def test_정상_게이트웨이_응답은_탐지되지_않음():
    detector = ArpSpoofingDetector(make_config())
    findings = detector.inspect_packet(make_arp_reply(GATEWAY_IP, GATEWAY_MAC))
    assert findings == []


def test_게이트웨이_사칭을_탐지함():
    detector = ArpSpoofingDetector(make_config())
    findings = detector.inspect_packet(make_arp_reply(GATEWAY_IP, ATTACKER_MAC))
    assert len(findings) == 1
    assert findings[0].event_type == "arp_spoof"
    assert findings[0].source_mac == ATTACKER_MAC


def test_처음_보는_단말은_학습만_하고_경보하지_않음():
    detector = ArpSpoofingDetector(make_config())
    findings = detector.inspect_packet(make_arp_reply(NORMAL_HOST_IP, NORMAL_HOST_MAC))
    assert findings == []


def test_일반_단말의_MAC_급변을_탐지함():
    detector = ArpSpoofingDetector(make_config())
    # 먼저 정상 MAC 을 한 번 관찰시켜 바인딩을 학습하게 함
    detector.inspect_packet(make_arp_reply(NORMAL_HOST_IP, NORMAL_HOST_MAC))
    # 같은 IP 가 다른 MAC 으로 다시 나타나면 스푸핑 의심
    findings = detector.inspect_packet(make_arp_reply(NORMAL_HOST_IP, ATTACKER_MAC))
    assert len(findings) == 1
    assert findings[0].source_mac == ATTACKER_MAC


def test_MAC_대소문자가_달라도_같은_값으로_취급함():
    detector = ArpSpoofingDetector(make_config())
    # 게이트웨이 MAC 을 대문자로 보내도 정상으로 인식해야 함(정규화 확인)
    findings = detector.inspect_packet(make_arp_reply(GATEWAY_IP, GATEWAY_MAC.upper()))
    assert findings == []


def test_ARP_요청은_검사하지_않음():
    detector = ArpSpoofingDetector(make_config())
    arp_request = Ether() / ARP(op=1, psrc=GATEWAY_IP, hwsrc=ATTACKER_MAC)
    assert detector.inspect_packet(arp_request) == []


def test_ARP가_아닌_패킷은_무시함():
    detector = ArpSpoofingDetector(make_config())
    assert detector.inspect_packet(Ether()) == []
