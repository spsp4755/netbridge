//! 외부 백신·CDR 명령 연동.

use crate::{Finding, ThreatKind};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct ExternalScanner {
    pub name: String,
    /// "{file}" 자리에 검사할 파일 경로가 들어간다. 비어 있으면 백신 검사 없음(CDR만).
    #[serde(default)]
    pub command: Vec<String>,
    /// 감염으로 보는 종료 코드. 비어 있으면 [1].
    #[serde(default)]
    pub infected_exit_codes: Vec<i32>,
    /// "{file}", "{out}" 자리 표시. 비어 있으면 CDR 없음.
    #[serde(default)]
    pub cdr_command: Vec<String>,
    /// 0이면 30초로 본다(Default 값 대비).
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    30
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExternalOutcome {
    pub findings: Vec<Finding>,
    pub replaced: bool,
}

/// 각 검사기를 차례로 돌린다. 등록된 감염 종료 코드면 AvInfected, 그 밖의 실패·시간 초과는 ScannerError.
/// 이어서 CDR 명령이 성공하면 `{out}` 결과로 `path`를 바꾼다(같은 폴더에서 rename).
pub fn run_external(path: &Path, scanners: &[ExternalScanner]) -> ExternalOutcome {
    let mut o = ExternalOutcome::default();
    let err = |o: &mut ExternalOutcome, s: &ExternalScanner, msg: String| o.findings.push(Finding { kind: ThreatKind::ScannerError, detail: format!("{}: {msg}", s.name) });
    for s in scanners {
        let timeout = Duration::from_secs(if s.timeout_secs == 0 { 30 } else { s.timeout_secs });
        if !s.command.is_empty() {
            let infected = if s.infected_exit_codes.is_empty() { &[1][..] } else { &s.infected_exit_codes[..] };
            match run(&s.command, path, None, timeout) {
                Ok((0, _)) => {}
                Ok((c, stdout)) if infected.contains(&c) => {
                    let line = stdout.lines().map(str::trim).find(|l| !l.is_empty()).map(str::to_string).unwrap_or_else(|| format!("감염(종료 코드 {c})"));
                    o.findings.push(Finding { kind: ThreatKind::AvInfected, detail: format!("{}: {line}", s.name) });
                }
                Ok((c, _)) => err(&mut o, s, format!("종료 코드 {c}")),
                Err(e) => err(&mut o, s, e),
            }
        }
        if !s.cdr_command.is_empty() {
            let mut out_name = path.file_name().unwrap_or_default().to_os_string();
            out_name.push(".cdr-out");
            let out = path.with_file_name(out_name);
            let _ = std::fs::remove_file(&out);
            match run(&s.cdr_command, path, Some(&out), timeout) {
                Ok((0, _)) if out.is_file() => match std::fs::rename(&out, path) {
                    Ok(()) => o.replaced = true,
                    Err(e) => err(&mut o, s, format!("CDR 결과로 바꾸지 못함: {e}")),
                },
                Ok((0, _)) => err(&mut o, s, "CDR 결과 파일이 없음".into()),
                Ok((c, _)) => err(&mut o, s, format!("CDR 실패(종료 코드 {c})")),
                Err(e) => err(&mut o, s, format!("CDR {e}")),
            }
            let _ = std::fs::remove_file(&out);
        }
    }
    o
}

/// 명령을 실행해 (종료 코드, 표준 출력 앞부분)을 돌려준다.
fn run(cmd: &[String], file: &Path, out: Option<&Path>, timeout: Duration) -> Result<(i32, String), String> {
    // shortcut: UTF-8이 아닌 경로는 손실 변환됨, 문제가 되면 OsString 치환으로 바꿈.
    let fill = |a: &String| {
        let a = a.replace("{file}", &file.to_string_lossy());
        out.map_or(a.clone(), |o| a.replace("{out}", &o.to_string_lossy()))
    };
    let mut child = Command::new(fill(&cmd[0])).args(cmd[1..].iter().map(fill)).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|e| format!("실행 실패: {e}"))?;
    let mut so = child.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut so).take(64 * 1024).read_to_end(&mut buf);
        let _ = tx.send(buf);
        let _ = std::io::copy(&mut so, &mut std::io::sink()); // 나머지는 버리되 파이프는 계속 비운다
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("시간 초과({}초)", timeout.as_secs()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(format!("대기 실패: {e}")),
        }
    };
    // 손자 프로세스가 출력 파이프를 붙잡고 있어도 오래 기다리지 않는다.
    let stdout = rx.recv_timeout(Duration::from_secs(2)).unwrap_or_default();
    let code = status.code().ok_or("신호로 종료됨")?;
    Ok((code, String::from_utf8_lossy(&stdout).into_owned()))
}
