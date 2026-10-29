# NetBridge — 사내 망연계 자료전송 시스템

인터넷망과 업무망 사이에서 파일과 클립보드 텍스트를 결재 절차에 따라 주고받는 시스템입니다.
상용 망연계 제품을 대체할 수 있도록 만든 오픈소스 프로젝트입니다.

```
[인터넷망 PC]  →  외부 연계서버  ⇄ 연계 구간(mTLS) ⇄  내부 연계서버  ←  [업무망 PC]
 NetBridge 앱                                  계정·정책·결재·이력        NetBridge 앱
```

## 주요 기능

- **양방향 파일 전송**: 끌어다 놓기, 이어 올리기, SHA-256 무결성 확인, 송신·수신 IP 기록
- **결재**: 사전결재(승인 후 전달), 사후결재(즉시 전달 후 결재, 기한 초과 시 사전결재로 제한), 대결(기간 지정 대리 결재)
- **결재 규칙**: 방향·크기·확장자·부서 조건으로 사전/사후 결정. 맞는 규칙이 없으면 사전결재
- **클립보드**: 단축키(기본 `Alt+F3`, 사용자가 변경 가능) 한 번으로 반대편 PC 클립보드에 넣음. 결재 없음
- **세션 유지**: 한쪽에서 로그인하면 반대편 PC도 로그인. 네트워크가 잠깐 끊겨도 로그아웃할 때까지 유지
- **용량 한도**: 하루 총량, 파일 1개 크기. 전사 → 부서 → 개인 순으로 적용. 하루 기준은 한국 시간 자정
- **개인정보 탐지**: 주민·외국인등록번호, 휴대전화, 카드(Luhn), 계좌, 여권, 운전면허, 이메일 + 관리자 정규식.
  txt/csv/docx/xlsx/pptx/hwpx/pdf 내용을 검사하고 항목별로 기록만 / 사전결재 강제 / 차단
- **보안정책**: 세션 최대 시간, 화면 잠금, 비밀번호 규칙, 확장자, 보관 기간 등 규정 관련 값은 모두 관리자 화면에서 변경, 즉시 반영, JSON 내보내기·가져오기
- **감사 이력**: 로그인, 전송, 결재, 클립보드(개인정보는 가려서 저장), 정책 변경. 검색과 CSV 저장
- **관리자 화면**: 업무망 앱에서 관리자 계정으로만 열림

## 구성

| 경로 | 내용 |
|---|---|
| `crates/proto` | 앱과 서버가 함께 쓰는 요청·응답·이벤트·정책 타입 |
| `crates/pii` | 개인정보 탐지·가리기·문서 글자 추출 |
| `crates/server` | 연계서버 (`side = external / internal`) |
| `crates/clientcore` | 앱의 네트워크·설정·기기 키(DPAPI) |
| `crates/client` | eframe/egui 네이티브 Windows 앱 (`netbridge.exe`) |
| `installer/netbridge.nsi` | 앱 설치파일 (NSIS) |
| `deploy/` | 서버 설정 예시와 설치 안내 |

## 개발

```bash
cargo test --workspace            # 단위 + 두 서버를 실제로 띄우는 e2e 테스트
cargo run -p netbridge-client     # 개발용 앱 실행 (Linux에서도 동작, 트레이 제외)
```

로컬에서 두 서버 띄우기:

```bash
cargo run -p netbridge-server -- gen-certs --out dev/certs --external-host 127.0.0.1 --internal-host 127.0.0.1
# dev/external.toml, dev/internal.toml 은 deploy/ 예시를 복사해 주소를 127.0.0.1 로 바꿉니다
cargo run -p netbridge-server -- run --config dev/external.toml
cargo run -p netbridge-server -- init-admin --config dev/internal.toml --username admin --password 'Admin123!@'
cargo run -p netbridge-server -- run --config dev/internal.toml
```

## 배포물 만들기

```bash
./scripts/build-windows.sh   # dist/NetBridge-Setup-x.y.z.exe, dist/netbridge-server-x.y.z-{windows,linux}.zip
./scripts/vendor.sh          # 폐쇄망 반입용 소스 + 의존성 묶음 (cargo build --offline)
```

서버 설치 순서는 `deploy/README-server.txt`를 보세요.

## 라이선스

- NetBridge: MIT (`LICENSE`)

- 한글 글꼴: 나눔고딕 (SIL Open Font License, `assets/fonts/OFL.txt`)
