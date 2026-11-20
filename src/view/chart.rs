//! Charts drawn from plain elements: time columns on one y-axis, and horizontal bars.

use rune::tok::{Theme, space, type_};
use rune::{Color, El, col, el, row, text};

/// Plot height of a time chart, in points.
pub const H: f32 = 120.0;
/// Width of the y-axis label gutter.
const AXIS_W: f32 = 44.0;

/// Round a maximum up to a friendly axis top: 1, 2, 2.5 or 5 × 10ⁿ.
pub fn nice(v: f32) -> f32 {
    if !v.is_finite() || v <= 0.0 {
        return 1.0;
    }
    let p = 10f32.powf(v.log10().floor());
    for m in [1.0, 2.0, 2.5, 5.0] {
        if v <= m * p * 1.0001 {
            return m * p;
        }
    }
    10.0 * p
}

/// "2.5%" below 10 when the value has a fraction, else "50%".
pub fn pct(v: f32) -> String {
    if v > 0.0 && v < 10.0 && v.fract() != 0.0 { format!("{v:.1}%") } else { format!("{v:.0}%") }
}

/// A legend entry: swatch and name.
pub fn legend(label: &str, c: Color, t: Theme) -> El {
    row().gap(6.0).center_y().children([
        el().size(10.0, 10.0).radius(3.0).fill(c),
        text(label.to_owned()).font(type_::SECTION).color(t.text_secondary),
    ])
}

/// Time columns, one per sample (oldest first), each sample's segments stacked bottom-up in
/// `colors` order, on one y-axis from 0 to `max` with gridlines at 0, ½ and the top.
pub fn columns(key: &str, values: &[Vec<f32>], colors: &[Color], max: f32, t: Theme, label: impl Fn(f32) -> String) -> El {
    if values.is_empty() {
        return el().w_full().h(H).center().child(
            text("Waiting for the first readings…").font(type_::LABEL).color(t.text_secondary),
        );
    }
    let mut bars = row().w_full().h(H).items_end().gap(0.0).pin(Some(0.0), Some(0.0), Some(0.0), Some(0.0));
    for (i, segs) in values.iter().enumerate() {
        let mut stack = col().key(format!("{key}-{i}")).grow(1.0).min_w(0.0);
        for (seg, c) in segs.iter().zip(colors).rev() {
            let h = (seg / max * H).clamp(0.0, H);
            if h > 0.0 {
                stack = stack.child(el().w_full().h(h).fill(*c));
            }
        }
        bars = bars.child(stack);
    }
    let mut plot = el().grow(1.0).min_w(0.0).h(H);
    let mut axis = el().w(AXIS_W).h(H);
    for k in 0..=2 {
        let y = H * k as f32 / 2.0;
        plot = plot.child(el().pin(Some(0.0), Some(y.min(H - 1.0)), Some(0.0), None).h(1.0).fill(t.separator));
        // Labels are ~14 pt tall; centre each on its gridline.
        let v = max * (2 - k) as f32 / 2.0;
        axis = axis.child(text(label(v)).font(type_::SECTION).color(t.text_secondary).pin(Some(0.0), Some(y - 7.0), None, None));
    }
    plot = plot.child(bars);
    col().w_full().gap(4.0).children([
        row().w_full().gap(space::S2).children([axis, plot]),
        row().w_full().pl(AXIS_W + space::S2).justify_between().children([
            text("5 min ago").font(type_::SECTION).color(t.text_secondary),
            text("now").font(type_::SECTION).color(t.text_secondary),
        ]),
    ])
}

/// A horizontal bar `fraction` (0–1) of the available width.
pub fn hbar(fraction: f32, c: Color) -> El {
    let f = fraction.clamp(0.0, 1.0);
    row().grow(1.0).min_w(0.0).h(12.0).center_y().children([
        el().grow(f).h(12.0).radius(4.0).fill(c),
        el().grow(1.0 - f).h(12.0),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nice_rounds_up_to_friendly_tops() {
        assert_eq!(nice(0.0), 1.0);
        assert_eq!(nice(f32::NAN), 1.0);
        assert_eq!(nice(1.0), 1.0);
        assert_eq!(nice(1.3), 2.0);
        assert_eq!(nice(2.2), 2.5);
        assert_eq!(nice(3.0), 5.0);
        assert_eq!(nice(60.0), 100.0);
        assert_eq!(nice(7.5), 10.0);
    }

    #[test]
    fn pct_keeps_small_fractions() {
        assert_eq!(pct(2.5), "2.5%");
        assert_eq!(pct(5.0), "5%");
        assert_eq!(pct(50.0), "50%");
        assert_eq!(pct(0.0), "0%");
    }
}
