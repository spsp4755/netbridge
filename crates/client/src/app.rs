use crate::hotkey::Hotkeys;
use crate::ui;
use eframe::egui::{self, Color32, RichText, ViewportCommand};
use netbridge_clientcore::config::{config_dir, ClientConfig};
use netbridge_clientcore::net::{Net, NetEvent};
use netbridge_clientcore::secret;
use netbridge_proto::*;
use std::future::Future;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Work finished in the background, applied to the app on the UI thread.
pub type Job = Box<dyn FnOnce(&mut App) + Send>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Setup,
    Connecting,
    Login,
    Main,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Send,
    Inbox,
    Outgoing,
    Approvals,
    Delegation,
    Settings,
    Admin,
}

pub struct Toast {
    pub text: String,
    pub error: bool,
    pub until: Instant,
}

pub struct App {
    pub ctx: egui::Context,
    pub rt: tokio::runtime::Handle,
    tx: Sender<Job>,
    rx: Receiver<Job>,
    pub cfg: ClientConfig,
    pub net: Option<Arc<Net>>,
    net_slot: Arc<Mutex<Option<Arc<Net>>>>,
    pub side: Option<Side>,
    pub me: Option<Me>,
    pub phase: Phase,
    pub screen: Screen,
    pub online: bool,
    events: Vec<tokio::task::JoinHandle<()>>,
    pub usage: Option<Usage>,
    pub toasts: Vec<Toast>,
    pub hotkeys: Option<Hotkeys>,
    pub hotkey_error: Option<String>,
    last_input: Instant,
    pub locked: bool,
    pub quitting: bool,
    #[cfg(windows)]
    _tray: Option<crate::tray::Tray>,
    pub setup: ui::setup::State,
    pub login: ui::login::State,
    pub send: ui::send::State,
    pub inbox: ui::inbox::State,
    pub outgoing: ui::history::State,
    pub approvals: ui::approvals::State,
    pub delegation: ui::delegation::State,
    pub settings: ui::settings::State,
    pub admin: ui::admin::State,
    pub lock: ui::login::LockState,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, rt: tokio::runtime::Handle) -> App {
        crate::fonts::install(&cc.egui_ctx);
        let (tx, rx) = channel();
        let loaded = ClientConfig::load();
        let mut app = App {
            ctx: cc.egui_ctx.clone(),
            rt,
            tx: tx.clone(),
            rx,
            cfg: loaded.clone().unwrap_or_default(),
            net: None,
            net_slot: Arc::new(Mutex::new(None)),
            side: None,
            me: None,
            phase: Phase::Setup,
            screen: Screen::Send,
            online: false,
            events: vec![],
            usage: None,
            toasts: vec![],
            hotkeys: None,
            hotkey_error: None,
            last_input: Instant::now(),
            locked: false,
            quitting: false,
            #[cfg(windows)]
            _tray: crate::tray::create(cc.egui_ctx.clone(), tx),
            setup: Default::default(),
            login: Default::default(),
            send: Default::default(),
            inbox: Default::default(),
            outgoing: Default::default(),
            approvals: Default::default(),
            delegation: Default::default(),
            settings: Default::default(),
            admin: Default::default(),
            lock: Default::default(),
        };
        app.setup.server_url = app.cfg.server_url.clone();
        app.setup.ca_path = app.cfg.ca_pem_path.display().to_string();
        app.init_hotkey();
        if loaded.is_some() {
            app.connect();
        }
        app
    }

    /// Runs `fut` on the runtime and applies its result on the UI thread.
    pub fn run<T: Send + 'static>(&self, fut: impl Future<Output = T> + Send + 'static, apply: impl FnOnce(&mut App, T) + Send + 'static) {
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        self.rt.spawn(async move {
            let v = fut.await;
            let _ = tx.send(Box::new(move |a: &mut App| apply(a, v)));
            ctx.request_repaint();
        });
    }

    /// Calls the API; errors become a toast (and a local logout when the session is gone).
    pub fn api(&self, req: ApiRequest, apply: impl FnOnce(&mut App, ApiResponse) + Send + 'static) {
        self.api_or(req, apply, |_, _| {});
    }

    pub fn api_or(&self, req: ApiRequest, apply: impl FnOnce(&mut App, ApiResponse) + Send + 'static, on_err: impl FnOnce(&mut App, &ApiError) + Send + 'static) {
        let Some(net) = self.net.clone() else { return };
        self.run(async move { net.call(req).await }, move |a, r| match r {
            Ok(v) => apply(a, v),
            Err(e) => {
                on_err(a, &e);
                a.api_error(e);
            }
        });
    }

    pub fn api_error(&mut self, e: ApiError) {
        if e.code == ErrorCode::SessionExpired && self.phase == Phase::Main {
            self.local_logout(&e.message);
        } else {
            self.toast_err(e.message);
        }
    }

    pub fn toast(&mut self, text: impl Into<String>) {
        self.toasts.push(Toast { text: text.into(), error: false, until: Instant::now() + Duration::from_secs(5) });
    }

    pub fn toast_err(&mut self, text: impl Into<String>) {
        self.toasts.push(Toast { text: text.into(), error: true, until: Instant::now() + Duration::from_secs(8) });
    }

    fn init_hotkey(&mut self) {
        match Hotkeys::new() {
            Ok(mut h) => {
                if let Err(e) = h.set(&self.cfg.hotkey) {
                    self.hotkey_error = Some(format!("{} ({})", e, self.cfg.hotkey));
                }
                let slot = self.net_slot.clone();
                let rt = self.rt.clone();
                let tx = self.tx.clone();
                let ctx = self.ctx.clone();
                h.on_press(move || send_clipboard(&slot, &rt, &tx, &ctx));
                self.hotkeys = Some(h);
            }
            Err(e) => self.hotkey_error = Some(e),
        }
    }

    /// Builds the connection from the saved settings and asks the server which network it serves.
    pub fn connect(&mut self) {
        self.stop_events();
        let net = match Net::new(&self.cfg.server_url, &self.cfg.ca_pem_path) {
            Ok(n) => Arc::new(n),
            Err(e) => {
                self.phase = Phase::Setup;
                self.setup.error = Some(e.to_string());
                return;
            }
        };
        self.net = Some(net.clone());
        *self.net_slot.lock().unwrap() = Some(net.clone());
        self.phase = Phase::Connecting;
        self.run(async move { net.hello().await }, |a, r| match r {
            Ok(h) => {
                a.side = Some(h.side);
                a.phase = Phase::Login;
                a.ctx.send_viewport_cmd(ViewportCommand::Title(format!("NetBridge 자료전송 — {}", h.side.label())));
                if let Some(user) = a.cfg.last_user.clone() {
                    a.login.username = user.clone();
                    if let Some(key) = secret::load_device_key(&config_dir(), &secret::slot(&a.cfg.server_url, &user)) {
                        a.start_events(key);
                    }
                }
            }
            Err(e) => {
                a.phase = Phase::Setup;
                a.setup.error = Some(e.message);
            }
        });
    }

    fn stop_events(&mut self) {
        for t in self.events.drain(..) {
            t.abort();
        }
        self.online = false;
    }

    /// Device WebSocket: pushes from the server. Clipboard and session tokens are applied right away
    /// in the background so they work while the window is hidden.
    pub fn start_events(&mut self, key: String) {
        self.stop_events();
        let Some(net) = self.net.clone() else { return };
        let (ntx, mut nrx) = tokio::sync::mpsc::unbounded_channel();
        // spawn_events uses tokio::spawn; the UI thread is outside the runtime
        let _rt = self.rt.enter();
        self.events.push(net.clone().spawn_events(key, ntx));
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        self.events.push(self.rt.spawn(async move {
            while let Some(ev) = nrx.recv().await {
                match &ev {
                    NetEvent::Event(Event::Clipboard { text, .. }) => {
                        let t = text.clone();
                        let _ = tokio::task::spawn_blocking(move || arboard::Clipboard::new().and_then(|mut c| c.set_text(t))).await;
                    }
                    NetEvent::Event(Event::SessionStarted { token, .. }) => net.set_token(Some(token.clone())),
                    NetEvent::Event(Event::SessionEnded { .. }) => net.set_token(None),
                    _ => {}
                }
                let _ = tx.send(Box::new(move |a: &mut App| a.on_net(ev)));
                ctx.request_repaint();
            }
        }));
    }

    fn on_net(&mut self, ev: NetEvent) {
        match ev {
            NetEvent::Connected => self.online = true,
            NetEvent::Disconnected(_) => self.online = false,
            NetEvent::Rejected => {
                if let Some(user) = &self.cfg.last_user {
                    secret::clear_device_key(&config_dir(), &secret::slot(&self.cfg.server_url, user));
                }
                self.online = false;
                if self.phase == Phase::Main {
                    self.local_logout("이 PC의 등록이 해제되었습니다. 다시 로그인하세요");
                }
            }
            NetEvent::Event(e) => match e {
                Event::SessionStarted { me, .. } => {
                    if self.phase != Phase::Main {
                        self.enter_main(me);
                        self.toast(format!("{}에서 로그인되어 자동으로 로그인했습니다", self.side.map(|s| s.other().label()).unwrap_or("반대편 망")));
                    }
                }
                Event::SessionEnded { reason } => {
                    if self.phase == Phase::Main {
                        self.local_logout(&reason);
                    }
                }
                Event::Clipboard { text, from_ip } => self.toast(format!("클립보드를 받았습니다 ({}자, {from_ip})", text.chars().count())),
                Event::TransferUpdated { transfer } => {
                    let incoming = Some(transfer.direction.from_side()) != self.side;
                    if incoming && transfer.state == TransferState::Available {
                        self.toast(format!("받을 파일이 도착했습니다: {}", transfer.file_name));
                    } else if !incoming && matches!(transfer.state, TransferState::Rejected | TransferState::Blocked) {
                        self.toast_err(format!("{}: {}", transfer.file_name, transfer.state.label()));
                    }
                    ui::inbox::refresh(self);
                    ui::history::refresh(self);
                    self.refresh_usage();
                }
                Event::ApprovalRequested { from, file_name, .. } => {
                    self.toast(format!("결재 요청: {from} — {file_name}"));
                    ui::approvals::refresh(self);
                }
                Event::Notice { message } => self.toasts.push(Toast { text: message, error: false, until: Instant::now() + Duration::from_secs(15) }),
                Event::PolicyChanged { policy } => {
                    if let Some(me) = &mut self.me {
                        me.policy = policy;
                    }
                }
            },
        }
    }

    pub fn enter_main(&mut self, me: Me) {
        self.settings.pw.forced = me.must_change_password;
        self.me = Some(me);
        self.phase = Phase::Main;
        self.screen = Screen::Send;
        self.last_input = Instant::now();
        self.locked = false;
        self.refresh_usage();
    }

    pub fn on_logged_in(&mut self, token: String, device_key: String, me: Me) {
        if let Some(net) = &self.net {
            net.set_token(Some(token));
        }
        let slot = secret::slot(&self.cfg.server_url, &me.username);
        let had = secret::load_device_key(&config_dir(), &slot);
        let user_changed = self.cfg.last_user.as_deref() != Some(me.username.as_str());
        if had.as_deref() != Some(device_key.as_str()) {
            if let Err(e) = secret::store_device_key(&config_dir(), &slot, &device_key) {
                self.toast_err(format!("기기 키를 저장할 수 없습니다: {e}"));
            }
        }
        if had.as_deref() != Some(device_key.as_str()) || user_changed || self.events.is_empty() {
            self.start_events(device_key);
        }
        if user_changed {
            self.cfg.last_user = Some(me.username.clone());
            let _ = self.cfg.save();
        }
        self.login.password.clear();
        self.enter_main(me);
    }

    pub fn refresh_usage(&self) {
        self.api(ApiRequest::Usage, |a, r| {
            if let ApiResponse::Usage(u) = r {
                a.usage = Some(u);
            }
        });
    }

    pub fn logout(&mut self) {
        if self.phase != Phase::Main {
            return;
        }
        self.api(ApiRequest::Logout, |a, _| a.local_logout("로그아웃했습니다"));
    }

    pub fn local_logout(&mut self, reason: &str) {
        if let Some(net) = &self.net {
            net.set_token(None);
        }
        self.me = None;
        self.usage = None;
        self.phase = Phase::Login;
        self.locked = false;
        self.send = Default::default();
        self.inbox = Default::default();
        self.outgoing = Default::default();
        self.approvals = Default::default();
        self.delegation = Default::default();
        self.settings = Default::default();
        self.admin = Default::default();
        self.toast(reason.to_string());
    }

    pub fn is_admin_console(&self) -> bool {
        self.side == Some(Side::Internal) && self.me.as_ref().is_some_and(|m| m.role == Role::Admin)
    }

    fn track_idle(&mut self, ctx: &egui::Context) {
        let active = ctx.input(|i| !i.events.is_empty() || i.pointer.is_moving());
        if active && !self.locked {
            self.last_input = Instant::now();
        }
        if self.phase != Phase::Main || self.locked {
            return;
        }
        if let Some(m) = self.me.as_ref().and_then(|m| m.policy.idle_lock_minutes) {
            let limit = Duration::from_secs(m as u64 * 60);
            if self.last_input.elapsed() >= limit {
                self.locked = true;
            } else {
                ctx.request_repaint_after(limit - self.last_input.elapsed() + Duration::from_millis(200));
            }
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let (dot, label) = if self.events.is_empty() {
                (Color32::GRAY, "로그인 전")
            } else if self.online {
                (Color32::from_rgb(30, 160, 70), "연결됨")
            } else {
                (Color32::from_rgb(200, 60, 50), "다시 연결 중…")
            };
            ui.label(RichText::new("●").color(dot));
            ui.label(label);
            ui.separator();
            if let Some(side) = self.side {
                ui.label(format!("{} 서버: {}", side.label(), self.cfg.server_url));
            }
            if let Some(me) = &self.me {
                ui.separator();
                ui.label(format!("내 IP: {}", me.client_ip));
                ui.separator();
                ui.label(format!("{} ({})", me.name, me.username));
            }
            if let Some(u) = &self.usage {
                ui.separator();
                ui.label(format!("오늘 사용량 {} / {}  (파일 1개 최대 {})", ui::fmt_bytes(u.used_today), ui::fmt_bytes(u.limits.daily_bytes), ui::fmt_bytes(u.limits.per_file_bytes)));
            }
            if self.me.is_some() {
                ui.separator();
                ui.label(format!("클립보드 단축키: {}", self.cfg.hotkey));
            }
        });
    }

    fn nav(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("NetBridge");
        if let Some(side) = self.side {
            ui.label(RichText::new(format!("{} PC", side.label())).color(Color32::from_rgb(22, 93, 196)).strong());
        }
        ui.add_space(12.0);
        let pending = self.approvals.items.iter().filter(|i| i.approval.status == ApprovalStatus::Pending).count();
        let items: Vec<(Screen, String)> = vec![
            (Screen::Send, "파일 보내기".into()),
            (Screen::Inbox, "받은 파일".into()),
            (Screen::Outgoing, "보낸 파일".into()),
            (Screen::Approvals, if pending > 0 { format!("결재함 ({pending})") } else { "결재함".into() }),
            (Screen::Delegation, "대결 지정".into()),
            (Screen::Settings, "설정".into()),
        ];
        for (s, label) in items {
            if ui.add_sized([150.0, 28.0], egui::SelectableLabel::new(self.screen == s, label)).clicked() {
                self.go(s);
            }
        }
        if self.is_admin_console() {
            ui.add_space(12.0);
            ui.label(RichText::new("관리자").small());
            if ui.add_sized([150.0, 28.0], egui::SelectableLabel::new(self.screen == Screen::Admin, "관리자 설정")).clicked() {
                self.go(Screen::Admin);
            }
        }
        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
            ui.add_space(8.0);
            if ui.button("로그아웃").clicked() {
                self.logout();
            }
        });
    }

    pub fn go(&mut self, s: Screen) {
        self.screen = s;
        match s {
            Screen::Inbox => ui::inbox::refresh(self),
            Screen::Outgoing => ui::history::refresh(self),
            Screen::Approvals => ui::approvals::refresh(self),
            Screen::Delegation => ui::delegation::refresh(self),
            Screen::Admin => ui::admin::refresh(self),
            _ => {}
        }
    }

    fn toasts(&mut self, ctx: &egui::Context) {
        let now = Instant::now();
        self.toasts.retain(|t| t.until > now);
        if self.toasts.is_empty() {
            return;
        }
        egui::Area::new(egui::Id::new("toasts")).anchor(egui::Align2::RIGHT_BOTTOM, [-16.0, -40.0]).show(ctx, |ui| {
            for t in self.toasts.iter().rev().take(5) {
                let fill = if t.error { Color32::from_rgb(253, 236, 234) } else { Color32::from_rgb(232, 242, 253) };
                egui::Frame::popup(ui.style()).fill(fill).show(ui, |ui| {
                    ui.set_max_width(420.0);
                    ui.label(&t.text);
                });
            }
        });
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

/// Global shortcut handler: reads the clipboard and sends it to the other network.
fn send_clipboard(slot: &Arc<Mutex<Option<Arc<Net>>>>, rt: &tokio::runtime::Handle, tx: &Sender<Job>, ctx: &egui::Context) {
    let notify = |job: Job| {
        let _ = tx.send(job);
        ctx.request_repaint();
    };
    let Some(net) = slot.lock().unwrap().clone().filter(|n| n.token().is_some()) else {
        notify(Box::new(|a: &mut App| a.toast_err("로그인한 뒤에 클립보드를 보낼 수 있습니다")));
        return;
    };
    let text = match arboard::Clipboard::new().and_then(|mut c| c.get_text()) {
        Ok(t) if !t.trim().is_empty() => t,
        _ => {
            notify(Box::new(|a: &mut App| a.toast_err("클립보드에 보낼 텍스트가 없습니다")));
            return;
        }
    };
    let tx = tx.clone();
    let ctx = ctx.clone();
    let n = text.chars().count();
    rt.spawn(async move {
        let r = net.call(ApiRequest::Clipboard { text }).await;
        let _ = tx.send(Box::new(move |a: &mut App| match r {
            Ok(_) => a.toast(format!("클립보드를 {}(으)로 보냈습니다 ({n}자)", a.side.map(|s| s.other().label()).unwrap_or("반대편 망"))),
            Err(e) => a.api_error(e),
        }));
        ctx.request_repaint();
    });
}

/// Windows sends Tab both as a key and as a "\t" text event, and egui's single-line fields insert
/// the text; no field here takes tabs, so the text event is dropped and Tab only moves focus.
pub fn drop_tab_text(events: &mut Vec<egui::Event>) {
    events.retain(|e| !matches!(e, egui::Event::Text(t) if t.chars().all(|c| c == '\t')));
}

impl eframe::App for App {
    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        drop_tab_text(&mut raw_input.events);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(job) = self.rx.try_recv() {
            job(self);
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.quitting {
            ctx.send_viewport_cmd(ViewportCommand::CancelClose);
            if cfg!(windows) {
                ctx.send_viewport_cmd(ViewportCommand::Visible(false));
            } else {
                ctx.send_viewport_cmd(ViewportCommand::Minimized(true));
            }
        }
        self.track_idle(ctx);

        match self.phase {
            Phase::Setup => {
                egui::CentralPanel::default().show(ctx, |ui| ui::setup::show(self, ui));
            }
            Phase::Connecting => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.centered_and_justified(|ui| {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("서버에 연결하는 중…");
                        });
                    });
                });
            }
            Phase::Login => {
                egui::TopBottomPanel::bottom("status").show(ctx, |ui| self.status_bar(ui));
                egui::CentralPanel::default().show(ctx, |ui| ui::login::show(self, ui));
            }
            Phase::Main => {
                egui::TopBottomPanel::bottom("status").show(ctx, |ui| self.status_bar(ui));
                egui::SidePanel::left("nav").resizable(false).exact_width(170.0).show(ctx, |ui| self.nav(ui));
                egui::CentralPanel::default().show(ctx, |ui| {
                    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| match self.screen {
                        Screen::Send => ui::send::show(self, ui),
                        Screen::Inbox => ui::inbox::show(self, ui),
                        Screen::Outgoing => ui::history::show(self, ui),
                        Screen::Approvals => ui::approvals::show(self, ui),
                        Screen::Delegation => ui::delegation::show(self, ui),
                        Screen::Settings => ui::settings::show(self, ui),
                        Screen::Admin => ui::admin::show(self, ui),
                    });
                });
                ui::send::reason_modal(self, ctx);
                if self.locked {
                    ui::login::lock_modal(self, ctx);
                } else if self.settings.pw.forced {
                    ui::settings::forced_password_modal(self, ctx);
                }
            }
        }
        self.toasts(ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_text_events_are_dropped() {
        let mut ev = vec![egui::Event::Text("\t".into()), egui::Event::Text("a\tb".into()), egui::Event::Text("k".into())];
        drop_tab_text(&mut ev);
        assert_eq!(ev, vec![egui::Event::Text("a\tb".into()), egui::Event::Text("k".into())]);
    }
}
