//! Activity log: the live unified log, newest first, each line said in words with the raw
//! message underneath. Repeats arrive already collapsed (`×N`).

use rune::tok::{Theme, space, type_};
use rune::{El, TextStyle, col, row, text};

use super::words::{Tone, count, doing};
use super::{dot, grouped, page_title};
use crate::state::State;

/// Rows drawn; the store keeps more, but a page this long is already a lot to read.
const SHOWN: usize = 60;

pub fn page(s: &State, t: Theme) -> El {
    let head = page_title("Activity log", "What Defender and Intune write to the system log, newest first. Repeats are grouped.", t);
    if s.events.is_empty() {
        return col().w_full().gap(16.0).children([
            head,
            text("New events land here as they happen.").font(type_::BODY).color(t.text_secondary),
        ]);
    }
    let rows = s.events.iter().rev().take(SHOWN).enumerate().map(|(i, e)| {
        let mut headline = doing(e.kind).to_owned();
        if e.perf {
            headline.push_str(" — its own log calls this a performance hit");
        }
        row().key(format!("event-{i}")).w_full().min_h(44.0).px(space::S3).py(6.0).center_y().gap(space::S3).children([
            text(e.t.clone()).font(type_::MONO_CAPTION).color(t.text_secondary).w(64.0),
            dot(e.kind.color(), 8.0),
            col().grow(1.0).min_w(0.0).gap(2.0).children([
                text(headline).font(TextStyle::new(13.5, 500.0)).color(if e.perf { Tone::Warn.color() } else { t.text }).wrap().min_w(0.0),
                text(e.title.clone()).font(type_::SECTION).color(t.text_secondary).truncate(),
            ]),
            text(if e.count > 1 { format!("×{}", count(e.count)) } else { String::new() }).font(type_::LABEL).color(t.text_secondary),
        ])
    }).collect();
    col().w_full().gap(16.0).children([head, grouped(rows, t)])
}
