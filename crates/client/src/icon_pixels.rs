/// 64×64 RGBA app icon: a blue tile with a white bridge between two pillars.
pub fn rgba() -> (Vec<u8>, u32) {
    let n = 64u32;
    let mut px = vec![0u8; (n * n * 4) as usize];
    for y in 0..n {
        for x in 0..n {
            let (fx, fy) = (x as f32, y as f32);
            let r = 12.0;
            let cx = fx.clamp(r, n as f32 - 1.0 - r);
            let cy = fy.clamp(r, n as f32 - 1.0 - r);
            let inside = (fx - cx).powi(2) + (fy - cy).powi(2) <= r * r;
            let i = ((y * n + x) * 4) as usize;
            if !inside {
                continue;
            }
            let pillar = (14..=20).contains(&x) || (43..=49).contains(&x);
            let deck = (34..=39).contains(&y) && (8..=55).contains(&x);
            let arch = {
                let dx = fx - 31.5;
                let ay = 34.0 - (1.0 - (dx / 17.0).powi(2)).max(0.0) * 16.0;
                (fx >= 17.0 && fx <= 46.0) && (fy - ay).abs() <= 2.5
            };
            let white = (pillar && (14..=50).contains(&y)) || deck || arch;
            let c = if white { [255, 255, 255, 255] } else { [22, 93, 196, 255] };
            px[i..i + 4].copy_from_slice(&c);
        }
    }
    (px, n)
}

