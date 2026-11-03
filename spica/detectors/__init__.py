"""탐지 모듈 모음.

각 탐지 모듈(ARP 스푸핑, SYN 홍수, 비인가 DHCP)은 패킷을 검사해서
의심 사건을 DetectionFinding 목록으로 돌려주는 역할만 함.
실제 출력(emitter)과 차단(isolate)은 모듈 밖에서 담당해, 역할을 분리함.
"""
