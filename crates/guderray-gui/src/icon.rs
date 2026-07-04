//! Runtime-generated app icon (no asset files): a blue rounded square with a white
//! "play/forward" glyph, used for both the window titlebar and the system-tray icon.
//! Rendered at 4x supersampling then box-downsampled for clean anti-aliased edges,
//! since a hard-edged mask reads as a blurry blob at small taskbar sizes.

pub const SIZE: u32 = 64;
const SS: u32 = 4; // supersampling factor
const HI: u32 = SIZE * SS;

fn rounded_rect(x: f32, y: f32, x0: f32, y0: f32, x1: f32, y1: f32, r: f32) -> bool {
    if x < x0 || x > x1 || y < y0 || y > y1 {
        return false;
    }
    let cx = x.clamp(x0 + r, x1 - r);
    let cy = y.clamp(y0 + r, y1 - r);
    let dx = x - cx;
    let dy = y - cy;
    dx * dx + dy * dy <= r * r
}

fn in_triangle(px: f32, py: f32, ax: f32, ay: f32, bx: f32, by: f32, cx: f32, cy: f32) -> bool {
    let d1 = (px - bx) * (ay - by) - (ax - bx) * (py - by);
    let d2 = (px - cx) * (by - cy) - (bx - cx) * (py - cy);
    let d3 = (px - ax) * (cy - ay) - (cx - ax) * (py - ay);
    let has_neg = d1 < 0.0 || d2 < 0.0 || d3 < 0.0;
    let has_pos = d1 > 0.0 || d2 > 0.0 || d3 > 0.0;
    !(has_neg && has_pos)
}

/// Returns (rgba, width, height). RGBA8, non-premultiplied, anti-aliased via supersampling.
pub fn rgba() -> (Vec<u8>, u32, u32) {
    // render at HI x HI
    let mut hi = vec![[0u8; 4]; (HI * HI) as usize];
    let blue = [37u8, 99, 235, 255];
    let white = [255u8, 255, 255, 255];
    let hf = HI as f32;
    let margin = hf * 0.06;
    let radius = hf * 0.24;
    // bold centered "forward" triangle, larger than before for clarity at small sizes
    let (ax, ay) = (hf * 0.37, hf * 0.28);
    let (bx, by) = (hf * 0.37, hf * 0.72);
    let (cx, cy) = (hf * 0.74, hf * 0.50);
    for y in 0..HI {
        for x in 0..HI {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            if !rounded_rect(fx, fy, margin, margin, hf - margin, hf - margin, radius) {
                continue;
            }
            let color = if in_triangle(fx, fy, ax, ay, bx, by, cx, cy) { white } else { blue };
            hi[(y * HI + x) as usize] = color;
        }
    }

    // box-downsample HI x HI -> SIZE x SIZE
    let mut out = vec![0u8; (SIZE * SIZE * 4) as usize];
    for oy in 0..SIZE {
        for ox in 0..SIZE {
            let mut acc = [0u32; 4];
            for sy in 0..SS {
                for sx in 0..SS {
                    let sxp = ox * SS + sx;
                    let syp = oy * SS + sy;
                    let px = hi[(syp * HI + sxp) as usize];
                    for c in 0..4 {
                        acc[c] += px[c] as u32;
                    }
                }
            }
            let n = (SS * SS) as u32;
            let idx = ((oy * SIZE + ox) * 4) as usize;
            for c in 0..4 {
                out[idx + c] = (acc[c] / n) as u8;
            }
        }
    }
    (out, SIZE, SIZE)
}
