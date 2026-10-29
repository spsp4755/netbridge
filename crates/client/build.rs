// Embeds the app icon and version info into netbridge.exe on Windows targets.
#[allow(dead_code)]
mod icon {
    include!("src/icon_pixels.rs");
}

fn ico(rgba: &[u8], n: u32) -> Vec<u8> {
    // ICONDIR + one ICONDIRENTRY + 32bpp DIB (bottom-up BGRA) + AND mask
    let mask_row = n.div_ceil(32) * 4;
    let dib_len = 40 + n * n * 4 + mask_row * n;
    let mut v = vec![0, 0, 1, 0, 1, 0];
    v.extend([n as u8, n as u8, 0, 0, 1, 0, 32, 0]);
    v.extend(dib_len.to_le_bytes());
    v.extend(22u32.to_le_bytes());
    v.extend(40u32.to_le_bytes());
    v.extend((n as i32).to_le_bytes());
    v.extend((2 * n as i32).to_le_bytes());
    v.extend(1u16.to_le_bytes());
    v.extend(32u16.to_le_bytes());
    v.extend([0u8; 24]);
    for y in (0..n).rev() {
        for x in 0..n {
            let i = ((y * n + x) * 4) as usize;
            v.extend([rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]]);
        }
    }
    v.extend(vec![0u8; (mask_row * n) as usize]);
    v
}

fn main() {
    println!("cargo:rerun-if-changed=src/icon_pixels.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let (rgba, n) = icon::rgba();
    std::fs::write(out.join("netbridge.ico"), ico(&rgba, n)).unwrap();
    let ver = env!("CARGO_PKG_VERSION");
    let parts: Vec<&str> = ver.split('.').collect();
    let comma = format!("{},{},{},0", parts[0], parts[1], parts[2]);
    let rc = format!(
        r#"1 ICON "netbridge.ico"
1 VERSIONINFO
FILEVERSION {comma}
PRODUCTVERSION {comma}
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "041204B0"
    BEGIN
      VALUE "FileDescription", "NetBridge 자료전송"
      VALUE "ProductName", "NetBridge"
      VALUE "FileVersion", "{ver}"
      VALUE "ProductVersion", "{ver}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x0412, 1200
  END
END
"#
    );
    // windres reads the .rc as UTF-8 with this codepage pragma
    std::fs::write(out.join("netbridge.rc"), format!("#pragma code_page(65001)\n{rc}")).unwrap();
    embed_resource::compile(out.join("netbridge.rc"), embed_resource::NONE).manifest_optional().unwrap();
}
