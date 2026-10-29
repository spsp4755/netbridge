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
   - 첫 실행 때 서버 주소(https://<서버 IP>:8443)를 입력합니다. 인터넷망 PC는 외부 서버, 업무망 PC는 내부 서버 주소입니다.
   - 관리자는 업무망 PC 앱에서 관리자 계정으로 로그인해 사용자·결재자·정책을 설정합니다.

서비스로 등록
  - Linux(systemd): ExecStart=/opt/netbridge/netbridge-server run --config /opt/netbridge/internal.toml
  - Windows: 작업 스케줄러에서 "시스템 시작 시" netbridge-server.exe run --config internal.toml

백업
  - 내부 서버의 data/netbridge.db 와 data/files 폴더를 백업합니다.
