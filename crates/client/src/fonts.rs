use eframe::egui::{FontData, FontDefinitions, FontFamily};
use std::sync::Arc;

/// Family for headings and emphasis (Nanum Gothic Bold).
pub fn bold() -> FontFamily {
    FontFamily::Name("bold".into())
}

/// egui's bundled fonts have no Hangul; Nanum Gothic (OFL) goes first, egui's fonts stay as symbol fallback.
pub fn definitions() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert("nanum".into(), Arc::new(FontData::from_static(include_bytes!("../../../assets/fonts/NanumGothic-Regular.ttf"))));
    fonts.font_data.insert("nanum-bold".into(), Arc::new(FontData::from_static(include_bytes!("../../../assets/fonts/NanumGothic-Bold.ttf"))));
    let proportional = fonts.families.entry(FontFamily::Proportional).or_default();
    proportional.insert(0, "nanum".into());
    let mut bold_chain = vec!["nanum-bold".to_string()];
    bold_chain.extend(proportional.iter().skip(1).cloned());
    fonts.families.insert(bold(), bold_chain);
    fonts.families.entry(FontFamily::Monospace).or_default().push("nanum".into());
    fonts
}
