//! Privacy: what Defender tells Microsoft, as far as the Mac's own log shows, and what it
//! can't show.

use rune::tok::{Theme, type_};
use rune::{El, col, text};

use super::words::{Reading, Tone, count, rate, upload_policy};
use super::{fact, grouped, page_title, panel, section};
use crate::state::State;

pub fn page(s: &State, t: Theme, r: &Reading) -> El {
    let setting = s.health.as_ref().map_or("unknown", |h| h.cloud_sample_submission.as_str());
    let cloud_on = s.health.as_ref().map(|h| h.cloud_enabled);

    let mut where_to = panel(t).key("destinations").children([
        section("Where it connected", t),
        text("macOS hides most addresses in its log for privacy, so most show as codes.")
            .font(type_::BODY).color(t.text_secondary).wrap().min_w(0.0),
    ]);
    if s.destinations.is_empty() {
        where_to = where_to.child(text("None seen yet.").font(type_::BODY).color(t.text_secondary));
    } else {
        let mut list = col().gap(4.0);
        for d in s.destinations.iter().rev().take(8) {
            list = list.child(text(d.clone()).font(type_::MONO_CAPTION.mono()).color(t.text_secondary));
        }
        where_to = where_to.child(list);
    }

    col().w_full().gap(16.0).children([
        page_title("Privacy", "What Defender tells Microsoft, as far as this Mac's own log shows. Past 3 hours plus this session.", t),
        grouped(vec![
            fact("pv-telemetry", Tone::Neutral, "Telemetry batches sent", format!("{} · {}", count(r.reports), rate(r.reports)), t),
            fact("pv-cloud", Tone::Neutral, "Cloud check-ins", format!("{} · {}", count(r.calls), rate(r.calls)), t),
            fact("pv-cloud-on", Tone::Neutral, "Cloud protection",
                match cloud_on { Some(true) => "On".into(), Some(false) => "Off".into(), None => "…".into() }, t),
            fact("pv-upload", Tone::Warn, "May upload automatically", upload_policy(setting).to_owned(), t),
        ], t),
        where_to,
        panel(t).key("good-to-know").fill(Tone::Warn.color().alpha(0.10)).children([
            section("Good to know", t),
            text("Your organisation's security console sees more than this app can: every program you start, with its full command line, plus file, login and network events. A quiet day here doesn't mean a quiet day there. Never put a password in a terminal command; use a file or a prompt instead.")
                .font(type_::BODY).color(t.text).wrap().min_w(0.0),
        ]),
    ])
}
