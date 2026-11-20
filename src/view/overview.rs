//! Overview: one verdict, three tiles that open their pages, and what the software has been
//! doing over the past 3 hours.

use rune::tok::{Theme, space, type_};
use rune::{El, TextStyle, col, el, row, text};

use super::words::{self, Reading, Tone, count, doing, rate};
use super::{dot, panel};
use crate::classify::Kind;
use crate::state::{Backfill, Page, State};

pub fn page(s: &State, t: Theme, r: &Reading) -> El {
    col().w_full().gap(16.0).children([hero(r, t), tiles(s, r, t), activity(s, t)])
}

fn hero(r: &Reading, t: Theme) -> El {
    let (tone, headline, sub) = match r.protected {
        None => (Tone::Neutral, "Checking Defender…".to_owned(), "Asking Defender how it's doing.".to_owned()),
        Some(_) if !r.problems.is_empty() => (Tone::Warn, "Defender needs attention".to_owned(), r.problems.join(" · ")),
        Some(true) => (
            Tone::Good,
            "Your Mac is protected".to_owned(),
            format!("Defender's impact right now: {}. {}", r.impact.to_lowercase(), r.impact_line),
        ),
        Some(false) => (Tone::Warn, "Protection is off".to_owned(), "Defender is installed but not actively protecting this Mac.".to_owned()),
    };
    row().key("hero").w_full().gap(16.0).center_y().children([
        el().size(56.0, 56.0).radius(28.0).fill(tone.color().alpha(0.18)).center().child(dot(tone.color(), 22.0)),
        col().grow(1.0).min_w(0.0).gap(4.0).children([
            text(headline).font(TextStyle::new(24.0, 680.0)).color(t.text),
            text(sub).font(TextStyle::new(14.0, 400.0)).color(t.text_secondary).wrap().min_w(0.0),
        ]),
    ])
}

fn tiles(s: &State, r: &Reading, t: Theme) -> El {
    let tile = |key: &str, title: &str, tone: Tone, value: String, line: String, to: Page| {
        panel(t).key(key.to_owned()).grow(1.0).hover(t.hover).on_press(move |s: &mut State| s.page = to).children([
            row().gap(space::S2).center_y().children([
                dot(tone.color(), 8.0),
                text(title.to_owned()).font(type_::LABEL).color(t.text_secondary).grow(1.0),
                text("›").font(TextStyle::new(15.0, 500.0)).color(t.text_secondary),
            ]),
            text(value).font(TextStyle::new(22.0, 650.0)).color(t.text),
            text(line).font(type_::BODY).color(t.text_secondary).wrap().min_w(0.0),
        ])
    };
    row().w_full().gap(space::S3).equal_columns(3).children([
        tile("tile-impact", "Impact on your Mac", r.impact_tone, r.impact.to_owned(),
            format!("{:.1}% CPU · ≈{:.1}% battery an hour", s.live_cpu, r.battery_per_hour), Page::Performance),
        tile("tile-microsoft", "Talking to Microsoft", Tone::Neutral, format!("{} times", count(r.reports + r.calls)),
            format!("in the past 3 hours — {} telemetry batches, {} cloud check-ins", count(r.reports), count(r.calls)), Page::Privacy),
        tile("tile-threats", "Threats found", if r.threats == 0 { Tone::Good } else { Tone::Warn },
            if r.threats == 0 { "None".into() } else { format!("{} quarantined", r.threats) },
            if r.threats == 0 {
                "Nothing has been quarantined.".into()
            } else if r.behavior_alerts > 0 {
                "Suspicious behavior — your security team has likely been alerted.".into()
            } else {
                "Quarantined files can't run — nothing for you to do.".into()
            },
            Page::Protection),
    ])
}

fn activity(s: &State, t: Theme) -> El {
    let mut rows: Vec<(Kind, u64)> = Kind::ALL.iter().map(|k| (*k, words::total(s, *k))).filter(|(_, n)| *n > 0).collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.1));
    let sum: u64 = rows.iter().map(|(_, n)| n).sum();

    let status = match s.backfill {
        Backfill::None | Backfill::Running { .. } => "counting…".to_owned(),
        Backfill::Done { lines } => format!("{} log lines read", count(lines)),
    };
    let mut card = panel(t).key("doing").children([
        row().w_full().center_y().children([
            text("What it's been doing (past 3 hours)").font(TextStyle::new(15.0, 620.0)).color(t.text).grow(1.0),
            text(status).font(type_::SECTION).color(t.text_secondary),
        ]),
    ]);
    if rows.is_empty() {
        let quiet = matches!(s.backfill, Backfill::Done { .. });
        return card.child(
            text(if quiet { "It has been quiet for the past 3 hours." } else { "Counting what it did in the past 3 hours…" })
                .font(type_::BODY).color(t.text_secondary),
        );
    }
    // The proportions at a glance: one segmented bar, 2 pt gaps between segments.
    let mut bar = row().w_full().h(10.0).radius(5.0).clip_rounded(5.0).gap(2.0);
    for (k, n) in &rows {
        bar = bar.child(el().h(10.0).grow(*n as f32 / sum.max(1) as f32).fill(k.color()));
    }
    let mut list = col().w_full();
    for (k, n) in rows.iter().take(7) {
        list = list.child(row().key(format!("doing-{k:?}")).w_full().h(30.0).center_y().gap(space::S2).children([
            dot(k.color(), 8.0),
            text(doing(*k)).font(type_::BODY).color(t.text).grow(1.0).min_w(0.0).truncate(),
            text(rate(*n)).font(type_::BODY).color(t.text_secondary),
            text(count(*n)).font(type_::LABEL).color(t.text_secondary).w(56.0).align(rune::Align::End),
        ]));
    }
    card = card.child(bar).child(list);
    card
}
