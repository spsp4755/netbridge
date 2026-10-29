//! Look and feel: palette, global style and the small set of widgets every screen shares.
use crate::fonts;
use eframe::egui::{self, Color32, CornerRadius, FontId, Margin, RichText, Shadow, Stroke, TextStyle};
use netbridge_proto::Side;

pub const ACCENT: Color32 = Color32::from_rgb(31, 94, 219);
pub const ACCENT_SOFT: Color32 = Color32::from_rgb(232, 240, 253);
pub const BG: Color32 = Color32::from_rgb(244, 246, 250);
pub const CARD: Color32 = Color32::WHITE;
pub const BORDER: Color32 = Color32::from_rgb(225, 229, 237);
pub const TEXT: Color32 = Color32::from_rgb(27, 36, 51);
pub const MUTED: Color32 = Color32::from_rgb(107, 117, 133);
pub const SUCCESS: Color32 = Color32::from_rgb(30, 142, 78);
pub const SUCCESS_SOFT: Color32 = Color32::from_rgb(228, 245, 235);
pub const WARN: Color32 = Color32::from_rgb(176, 108, 10);
pub const WARN_SOFT: Color32 = Color32::from_rgb(253, 243, 224);
pub const DANGER: Color32 = Color32::from_rgb(201, 58, 58);
pub const DANGER_SOFT: Color32 = Color32::from_rgb(252, 234, 234);
pub const NEUTRAL_SOFT: Color32 = Color32::from_rgb(237, 239, 243);
pub const NAV_BG: Color32 = Color32::from_rgb(16, 30, 54);
pub const NAV_TEXT: Color32 = Color32::from_rgb(196, 207, 225);
pub const NAV_SELECTED: Color32 = Color32::from_rgb(35, 61, 104);

/// Each network has its own colour so users always see which side they are on.
pub fn side_color(side: Side) -> Color32 {
    match side {
        Side::External => Color32::from_rgb(14, 150, 130),
        Side::Internal => Color32::from_rgb(64, 120, 235),
    }
}

pub fn apply(ctx: &egui::Context) {
    ctx.set_fonts(fonts::definitions());
    ctx.set_theme(egui::ThemePreference::Light);
    ctx.style_mut_of(egui::Theme::Light, |s| {
        s.text_styles = [
            (TextStyle::Heading, FontId::new(22.0, fonts::bold())),
            (TextStyle::Body, FontId::proportional(14.0)),
            (TextStyle::Button, FontId::proportional(14.0)),
            (TextStyle::Small, FontId::proportional(12.0)),
            (TextStyle::Monospace, FontId::monospace(13.0)),
        ]
        .into();
        s.spacing.item_spacing = egui::vec2(8.0, 8.0);
        s.spacing.button_padding = egui::vec2(14.0, 6.0);
        s.spacing.interact_size.y = 30.0;
        s.spacing.window_margin = Margin::same(20);
        s.spacing.menu_margin = Margin::same(8);
        let v = &mut s.visuals;
        let r = CornerRadius::same(6);
        v.panel_fill = BG;
        v.window_fill = CARD;
        v.window_stroke = Stroke::new(1.0_f32, BORDER);
        v.window_corner_radius = CornerRadius::same(12);
        v.window_shadow = Shadow { offset: [0, 8], blur: 28, spread: 0, color: Color32::from_black_alpha(40) };
        v.popup_shadow = Shadow { offset: [0, 4], blur: 14, spread: 0, color: Color32::from_black_alpha(30) };
        v.menu_corner_radius = CornerRadius::same(8);
        v.extreme_bg_color = CARD;
        v.faint_bg_color = Color32::from_rgb(248, 249, 252);
        v.code_bg_color = NEUTRAL_SOFT;
        v.hyperlink_color = ACCENT;
        v.selection.bg_fill = Color32::from_rgb(200, 218, 250);
        v.selection.stroke = Stroke::new(1.0_f32, ACCENT);
        v.override_text_color = None;
        let w = &mut v.widgets;
        w.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT);
        w.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
        w.noninteractive.corner_radius = r;
        w.inactive.bg_fill = CARD;
        w.inactive.weak_bg_fill = CARD;
        w.inactive.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(208, 214, 226));
        w.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT);
        w.inactive.corner_radius = r;
        w.hovered.bg_fill = Color32::from_rgb(242, 246, 253);
        w.hovered.weak_bg_fill = Color32::from_rgb(242, 246, 253);
        w.hovered.bg_stroke = Stroke::new(1.0_f32, ACCENT);
        w.hovered.fg_stroke = Stroke::new(1.0_f32, TEXT);
        w.hovered.corner_radius = r;
        w.hovered.expansion = 0.0;
        w.active.bg_fill = ACCENT_SOFT;
        w.active.weak_bg_fill = ACCENT_SOFT;
        w.active.bg_stroke = Stroke::new(1.0_f32, ACCENT);
        w.active.fg_stroke = Stroke::new(1.0_f32, TEXT);
        w.active.corner_radius = r;
        w.active.expansion = 0.0;
        w.open = w.active;
    });
}

pub fn bold(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text).font(FontId::new(size, fonts::bold()))
}

pub fn muted(text: impl Into<String>) -> RichText {
    RichText::new(text).color(MUTED)
}

/// Page title with an optional one-line explanation underneath.
pub fn page_header(ui: &mut egui::Ui, title: &str, subtitle: Option<&str>) {
    ui.add_space(6.0);
    ui.label(bold(title, 22.0).color(TEXT));
    if let Some(s) = subtitle {
        ui.label(muted(s));
    }
    ui.add_space(10.0);
}

/// Dialog window: roomier than the default popup frame.
pub fn modal_frame() -> egui::Frame {
    card_frame().inner_margin(Margin::same(24)).corner_radius(CornerRadius::same(12)).shadow(Shadow { offset: [0, 10], blur: 30, spread: 0, color: Color32::from_black_alpha(45) })
}

pub fn card_frame() -> egui::Frame {
    egui::Frame::new().fill(CARD).stroke(Stroke::new(1.0_f32, BORDER)).corner_radius(CornerRadius::same(10)).inner_margin(Margin::same(16)).shadow(Shadow {
        offset: [0, 1],
        blur: 4,
        spread: 0,
        color: Color32::from_black_alpha(8),
    })
}

/// White rounded panel that fills the available width.
pub fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    card_frame()
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

pub fn section_title(ui: &mut egui::Ui, text: &str) {
    ui.label(bold(text, 15.0).color(TEXT));
    ui.add_space(2.0);
}

fn filled(text: &str, fill: Color32) -> egui::Button<'static> {
    egui::Button::new(bold(text, 14.0).color(Color32::WHITE)).fill(fill).stroke(Stroke::NONE).min_size(egui::vec2(96.0, 34.0))
}

pub fn primary(text: &str) -> egui::Button<'static> {
    filled(text, ACCENT)
}

pub fn danger(text: &str) -> egui::Button<'static> {
    filled(text, DANGER)
}

pub fn secondary(text: &str) -> egui::Button<'static> {
    egui::Button::new(text.to_string()).min_size(egui::vec2(0.0, 34.0))
}

/// Small rounded label, e.g. a status.
pub fn pill(ui: &mut egui::Ui, text: &str, fg: Color32, bg: Color32) -> egui::Response {
    egui::Frame::new().fill(bg).corner_radius(CornerRadius::same(10)).inner_margin(Margin::symmetric(8, 2)).show(ui, |ui| ui.label(bold(text, 12.0).color(fg))).response
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tone {
    Info,
    Success,
    Warn,
    Danger,
    Neutral,
}

pub fn tone_colors(t: Tone) -> (Color32, Color32) {
    match t {
        Tone::Info => (ACCENT, ACCENT_SOFT),
        Tone::Success => (SUCCESS, SUCCESS_SOFT),
        Tone::Warn => (WARN, WARN_SOFT),
        Tone::Danger => (DANGER, DANGER_SOFT),
        Tone::Neutral => (MUTED, NEUTRAL_SOFT),
    }
}

pub fn tone_pill(ui: &mut egui::Ui, text: &str, t: Tone) -> egui::Response {
    let (fg, bg) = tone_colors(t);
    pill(ui, text, fg, bg)
}

/// Coloured strip with a message: warnings, errors, hints.
pub fn banner(ui: &mut egui::Ui, t: Tone, text: &str) {
    let (fg, bg) = tone_colors(t);
    egui::Frame::new().fill(bg).corner_radius(CornerRadius::same(8)).inner_margin(Margin::symmetric(12, 8)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(RichText::new(text).color(fg));
    });
}

/// Centred placeholder for an empty list.
pub fn empty_state(ui: &mut egui::Ui, icon: &str, title: &str, sub: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(36.0);
        ui.label(RichText::new(icon).size(40.0).color(Color32::from_rgb(170, 180, 198)));
        ui.add_space(6.0);
        ui.label(bold(title, 16.0).color(TEXT));
        ui.label(muted(sub));
        ui.add_space(36.0);
    });
}

/// Underlined tab strip; returns the clicked tab.
pub fn tab_bar<T: Copy + PartialEq>(ui: &mut egui::Ui, current: T, tabs: &[(T, &str)]) -> Option<T> {
    let mut picked = None;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 22.0;
        for (t, label) in tabs {
            let on = *t == current;
            let text = if on { bold(*label, 14.0).color(ACCENT) } else { RichText::new(*label).color(MUTED) };
            let r = ui.add(egui::Button::new(text).frame(false).min_size(egui::vec2(0.0, 34.0)));
            if on {
                let rect = r.rect;
                ui.painter().line_segment([rect.left_bottom(), rect.right_bottom()], Stroke::new(2.5_f32, ACCENT));
            }
            if r.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
            if r.clicked() {
                picked = Some(*t);
            }
        }
    });
    picked
}

/// Number tile for overview pages.
pub fn stat_tile(ui: &mut egui::Ui, label: &str, value: String, note: &str, color: Color32) {
    card(ui, |ui| {
        ui.label(muted(label));
        ui.label(bold(value, 26.0).color(color));
        ui.label(RichText::new(note).small().color(MUTED));
    });
}

/// Two-column key/value grid used in detail cards.
pub fn kv_grid(ui: &mut egui::Ui, id: impl std::hash::Hash, rows: &[(&str, String)]) {
    egui::Grid::new(id).num_columns(2).spacing([18.0, 6.0]).show(ui, |ui| {
        for (k, v) in rows {
            ui.label(muted(*k));
            ui.label(v);
            ui.end_row();
        }
    });
}
