# SPICA, 소규모 네트워크 이상 트래픽 탐지 및 침입 탐지 시스템

창업동아리 SPICA 프로젝트. 소규모 네트워크(소형 사무실, 학교, 소규모 사업장)에서 이상 트래픽과 네트워크 침입을 탐지하고, 공격 단말을 격리하며, 장애 원인을 분석해 비전문가도 이해할 수 있는 한국어 해결 가이드를 제공하는 것을 목표로 한다.

최종 목표 하드웨어는 라즈베리파이지만, 현재는 물리 장비 없이 VirtualBox 가상환경에서 개발과 검증을 진행한다. 코드는 평범한 리눅스 프로그램이라, 나중에 실제 라즈베리파이로 그대로 옮길 수 있다.

## 개발 상태

초기 개발 단계. 기능 구현 순서는 탐지, 차단, 장애 진단, AI 가이드 순이다.

## 주요 기능 (MVP)

- 탐지: ARP 스푸핑, SYN 홍수(SYN Flood), 비인가 DHCP 서버(허가되지 않은 공유기)
- 차단: nftables 브리지 규칙으로 공격 단말 MAC을 일정 시간 격리(기본 10분, 자동 해제, 화이트리스트 지원)
- 진단: 규칙 기반 점검 후 RandomForest 로 장애 원인 분류
- 가이드: 로컬 LLM(Ollama)과 RAG 로 원인에 맞는 한국어 해결 방법 생성
- 기록: 콘솔 출력과 함께 모든 사건을 events.jsonl 에 저장(시각화는 이후 단계)

## 저장소 구조

```
SPICA---network-guard/
├── CLAUDE.md               # 프로젝트 작업 기준(하네스)
├── README.md
├── requirements.txt        # 파이썬 패키지 목록
├── config/
│   └── config.example.yaml # 설정 템플릿(복사해서 config.yaml 로 사용)
├── spica/                  # 본체 코드
│   ├── config_loader.py    # 설정 파일 읽기와 검증
│   ├── emitter.py          # 콘솔 출력과 events.jsonl 기록
│   ├── detectors/          # 탐지 모듈(예정)
│   ├── isolate.py          # 차단 모듈(예정)
│   ├── diagnose.py         # 장애 진단(예정)
│   └── guide.py            # LLM + RAG 가이드(예정)
├── ml/                     # 데이터 수집과 모델 학습(예정)
├── kb/                     # RAG 지식 문서(예정)
├── setup/                  # 환경 구성 스크립트(예정)
└── tests/                  # 테스트(예정)
```

## 실행 환경

- 운영체제: 리눅스(개발은 Ubuntu VM, 배포 대상은 라즈베리파이 OS)
- 파이썬: 3.10 이상 권장
- 패킷 캡처와 차단에는 관리자 권한(sudo)이 필요하다

## 설치

```bash
python3 -m pip install -r requirements.txt
```

설정 파일은 템플릿을 복사해서 실제 환경 값으로 채운다. 실제 설정 파일(config/config.yaml)은 깃에 올라가지 않는다.

```bash
cp config/config.example.yaml config/config.yaml
```

## 보안 주의

이 프로젝트는 방어 목적의 교육용이다. 공격 트래픽을 만들어 보는 모든 실험은 반드시 인터넷 및 실제 네트워크와 분리된 격리 가상망(VirtualBox 내부 네트워크)에서만 수행한다. 실제 네트워크를 대상으로 한 공격은 법으로 금지되어 있다.
