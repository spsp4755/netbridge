use eframe::egui::{self, FontData, FontDefinitions, FontFamily};
use std::sync::Arc;

/// egui's bundled fonts have no Hangul; Nanum Gothic (OFL) goes first in both families.
pub fn install(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert("nanum".into(), Arc::new(FontData::from_static(include_bytes!("../../../assets/fonts/NanumGothic-Regular.ttf"))));
    fonts.families.entry(FontFamily::Proportional).or_default().insert(0, "nanum".into());
    fonts.families.entry(FontFamily::Monospace).or_default().push("nanum".into());
    ctx.set_fonts(fonts);
    ctx.style_mut(|s| {
        for (style, font) in s.text_styles.iter_mut() {
            font.size = match style {
                egui::TextStyle::Heading => 20.0,
                egui::TextStyle::Small => 11.0,
                _ => 14.0,
            };
        }
        s.spacing.item_spacing = egui::vec2(8.0, 6.0);
        s.spacing.button_padding = egui::vec2(10.0, 4.0);
    });
    ctx.set_theme(egui::ThemePreference::Light);
}
