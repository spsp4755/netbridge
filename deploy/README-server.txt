NetBridge 연계서버 설치 안내
=============================

구성
  [인터넷망 PC] → 외부 연계서버 ⇄(연계 구간)⇄ 내부 연계서버 ← [업무망 PC]
  - 연계 구간은 내부 서버가 외부 서버로 먼저 접속합니다. 외부에서 내부로 들어오는 연결은 없습니다.
  - 계정·정책·결재·이력은 내부 서버에만 있습니다.

1. 인증서 만들기 (한 번, 안전한 PC에서)
   netbridge-server gen-certs --out certs --external-host <외부서버 IP> --internal-host <내부서버 IP>
   - ca.pem: 모든 서버와 모든 PC에 배포합니다.
   - ca.key: 서버에 두지 말고 따로 보관합니다.
   - external.pem/key → 외부 서버, internal.pem/key + link-client.pem/key → 내부 서버

2. 외부 연계서버 (인터넷망)
   - external.toml을 열어 listen(앱 접속 주소)과 [link] listen(연계 구간 주소)을 맞춥니다.
   - certs 폴더에 ca.pem, external.pem, external.key를 둡니다.
   - netbridge-server run --config external.toml

3. 내부 연계서버 (업무망)
   - internal.toml을 열어 [link] external_url을 외부 서버의 연계 구간 주소로 맞춥니다.
   - certs 폴더에 ca.pem, internal.pem, internal.key, link-client.pem, link-client.key를 둡니다.
   - 첫 관리자 만들기: netbridge-server init-admin --config internal.toml --username admin --password '<비밀번호>'
   - netbridge-server run --config internal.toml

4. PC 앱 설치
   - NetBridge-Setup-x.y.z.exe 옆에 ca.pem을 두고 설치하면 인증서가 함께 설치됩니다.
   - 서버 주소 고정(권장): 설치파일 옆에 server.toml 을 두고 설치합니다. 내용은 한 줄입니다.
       server_url = "https://<서버 IP>:8443"
     인터넷망 PC용은 외부 서버, 업무망 PC용은 내부 서버 주소를 넣습니다. 이렇게 설치하면 사용자는 서버 주소를 바꿀 수 없습니다.
   - server.toml 없이 설치하면 첫 실행 때 한 번만 서버 주소를 입력합니다. 그 뒤에는 관리자 계정으로 로그인한
     설정 화면에서만 바꿀 수 있고, 일반 사용자에게는 연결 정보가 보이지 않습니다.
   - 관리자는 업무망 PC 앱에서 관리자 계정으로 로그인해 사용자·결재자·정책을 설정합니다.

서비스로 등록 (부팅 시 자동 시작, 비정상 종료 시 자동 재시작)
  - Windows (관리자 권한 명령 프롬프트):
      netbridge-server.exe install-service --config C:\NetBridge\internal.toml
    · 서비스 이름은 기본으로 NetBridge-Internal / NetBridge-External 이며 --name 으로 바꿀 수 있습니다.
    · 등록과 함께 바로 시작합니다. 멈춤·시작은 "서비스"(services.msc) 또는 sc stop/start NetBridge-Internal.
    · 지우기: netbridge-server.exe uninstall-service --name NetBridge-Internal
  - Linux (systemd): netbridge-server.service 파일의 경로를 맞춘 뒤 /etc/systemd/system 에 복사합니다.
      sudo systemctl daemon-reload && sudo systemctl enable --now netbridge-server
      상태: systemctl status netbridge-server

상태 확인
  netbridge-server status --config internal.toml
  - 버전, DB 위치, 사용자 수, 오늘 전송 건수, 인증서 파일 유무, 외부 서버 연계 주소 접속 가능 여부를 보여 줍니다.
  - 모니터링: 로그인 없이 https://<서버>:8443/health 에 GET 하면 200 과 {"version":"x.y.z","ok":true} 가 옵니다.
    (사설 CA 인증서이므로 모니터링 도구에 ca.pem 을 등록하거나 인증서 검사를 끕니다)

로그
  - 화면 출력과 함께 설정 파일 옆 logs 폴더에 날짜별 파일(netbridge-server.YYYY-MM-DD.log, UTC 기준)로 남깁니다.
  - 설정 파일에서 바꿀 수 있습니다 (맨 위, [link] 앞):
      log_dir = "logs"        # 상대 경로는 설정 파일 기준
      log_keep_days = 30      # 이 개수만큼 최근 파일만 남김
  - 자세한 로그: 환경 변수 RUST_LOG=debug

백업
  netbridge-server backup --config internal.toml [--out D:\backup\nb.db]
  - 서버를 멈추지 않고 DB를 일관된 상태로 복사합니다. --out 이 없으면 data/backup/netbridge-날짜-시각.db (한국 시간).
  - 이미 있는 파일에는 덮어쓰지 않습니다.
  - 전송 파일 원본(data/files 폴더)은 DB에 없으므로 함께 복사합니다. 외부 서버에는 DB가 없습니다.
  - 매일 백업 예: Windows 작업 스케줄러 또는 cron (0 2 * * * /opt/netbridge/netbridge-server backup --config /opt/netbridge/internal.toml)
  - 복원: 서버를 멈추고 백업 파일을 data/netbridge.db 로 바꿔 넣은 뒤 시작합니다 (netbridge.db-wal, -shm 파일은 지웁니다).

여러 망 구성 (예: A·B·C·D 망, 통로 A-B, B-C, B-D, C-D)
  - 예시 설정: multinet/b-hub.toml (중앙), a-node.toml, c-node.toml, d-node.toml
  - 중앙 서버(role = "hub")는 계정·결재·정책·감사 DB를 가진 망 하나에 둡니다. 다른 모든 망 서버와 직접 연결되어야 합니다.
  - 나머지 망 서버(role = "node")는 파일만 보관하고, 앱의 요청은 중앙으로 전달합니다.
  - 중앙 서버 설정의 [[routes]] 가 허용 통로입니다. 없는 통로(A→C 등)로는 보낼 수 없습니다.
  - 중앙을 거치지 않는 통로(C-D)는 두 망 서버에 [link] neighbor_listen(이웃 전용 주소)을 열고,
    [[neighbors]] 에 상대 서버의 neighbor_listen 주소를 적습니다. 이웃 주소는 파일 받기만 하며,
    중앙 서버가 "지금 이 망으로 전달 중"이라고 확인한 전송만, 해시가 맞을 때만 받습니다.
  - 방화벽: 각 망 서버의 [link] listen(중앙 전용)은 중앙 서버 IP만, neighbor_listen 은 이웃 서버 IP만 허용하세요.
    파일은 C 서버에서 D 서버로 바로 가고 중앙(B) 서버를 거치지 않습니다. 받는 쪽은 해시를 확인합니다.
  - 인증서: netbridge-server gen-certs --server A=10.0.1.10 --server B=10.0.2.10 --server C=10.0.3.10 --server D=10.0.4.10
    망마다 <망ID>.pem/.key 를 그 망 서버의 tls_cert/tls_key 로 쓰고, ca.pem 과 link-client.* 를 함께 둡니다.
  - 통로별 정책(사용 여부, 클립보드, 한도, 확장자, 결재 규칙, 개인정보 조치, 파일 검사 조치)은
    중앙 망 PC의 관리자 콘솔 → "통로 정책" 탭에서 방향마다 따로 정합니다. 비워 둔 항목은 전역 값을 따릅니다.
  - 사용자별 사용 망은 관리자 콘솔 → 사용자 → 수정 → "사용 망" 에서 고릅니다 (기본: 모든 망).
  - 기존 두 망 설정(side = "internal" / "external")은 그대로 동작합니다. 업그레이드하면 기존 결재 규칙은 해당 방향 통로로 옮겨집니다.

파일 검사 (악성·위험 내용)
  - 모든 서버가 파일을 받을 때 내용으로 검사합니다(확장자를 믿지 않음):
    실행 파일 위장, 스크립트, 문서 매크로(Office·HWP), PDF 실행 요소, 압축 안의 위험 파일·암호 압축·압축 폭탄, 7z/RAR.
  - 결과별 조치(차단 / 사전결재 / 기록만)는 통로 정책에서 정합니다. 기본: 실행·스크립트·위험 압축·백신 탐지는 차단, 나머지는 사전결재.
  - 사내 백신이나 CDR(무해화) 제품은 각 서버 설정의 [[scanners]] 로 연결합니다 (multinet/b-hub.toml 예시 참고).
    command 의 종료 코드가 infected_exit_codes 이면 "백신 탐지", cdr_command 가 성공하면 결과 파일로 바꿔 전달합니다.
    검사는 파일이 있는 서버(보내는 망)에서 실행되므로 백신·CDR 은 그 망 서버에 설치합니다.
  - 알려진 한계: HWP 파일은 스크립트 저장소만 있어도 매크로로 봅니다(사전결재). PDF 의 압축된 객체 안 스크립트는 찾지 못합니다.

