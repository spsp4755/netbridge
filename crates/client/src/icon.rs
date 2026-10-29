include!("icon_pixels.rs");

pub fn icon_data() -> eframe::egui::IconData {
    let (rgba, n) = rgba();
    eframe::egui::IconData { rgba, width: n, height: n }
}
