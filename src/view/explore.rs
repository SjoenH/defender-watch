//! Timeline: the past 24 hours of what Defender and Intune wrote to the log, to dig into.
//!
//! - a minimap of the whole day, with the window you're looking at; press or drag on it to
//!   move there;
//! - the main chart: stacked columns per kind, a lane of milestones above (detections,
//!   scans, definition updates, MDM check-ins) and Defender's CPU below;
//! - drag across the chart to zoom into that stretch, ⌘-scroll or pinch to zoom around the
//!   pointer, scroll sideways (or ← →) to pan, double-click to zoom in, Esc to let go;
//! - click a column for what happened in it; kind chips filter, a bar per kind solos it.

use rune::tok::{Theme, space, type_};
use rune::{Color, Drag, El, Phase, TextStyle, Tx, col, el, row, text};

use super::chart::nice;
use super::words::{Tone, count, doing};
use super::{dot, grouped, page_title, panel, section};
use crate::classify::{KINDS, Kind};
use crate::state::{SPANS, State};
use crate::timeline::Bin;

/// Main plot height, points.
const PLOT_H: f32 = 210.0;
/// CPU lane height.
const CPU_H: f32 = 64.0;
/// Milestone lane height.
const MARK_H: f32 = 22.0;
/// Minimap height.
const MINI_H: f32 = 34.0;
/// Width of the y-axis gutter.
const AXIS_W: f32 = 52.0;
/// The whole history the page can show, minutes.
const HISTORY: i64 = 24 * 60;

/// Kinds that mark a moment rather than make up the volume.
const MILESTONES: [Kind; 4] = [Kind::Threat, Kind::Scan, Kind::Definitions, Kind::Mdm];

pub fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::NetFilter => "Network filter",
        Kind::Eps => "Heartbeats",
        Kind::Auth => "Logins seen",
        Kind::Directory => "Directory lookups",
        Kind::Telemetry => "Telemetry",
        Kind::Cloud => "Cloud calls",
        Kind::Scan => "Scans",
        Kind::Threat => "Detections",
        Kind::Definitions => "Definitions",
        Kind::Mdm => "Intune / MDM",
        Kind::Dlp => "Data loss prevention",
        Kind::Other => "Other",
    }
}

/// The newest minute the page treats as "now".
pub fn latest(s: &State) -> i64 {
    let last = s.timeline.span().map_or(0, |x| x.1);
    if s.demo { last } else { crate::timeline::now_minute().max(last) }
}

fn limit(latest: i64) -> (i64, i64) {
    (latest + 1 - HISTORY, latest + 1)
}

fn span_text(minutes: i64) -> String {
    match minutes {
        m if m < 60 => format!("{m} min"),
        m if m % 60 == 0 => format!("{} h", m / 60),
        m => format!("{} h {} min", m / 60, m % 60),
    }
}

/// A tick step (minutes) that puts at most ~7 labels across `span`.
fn tick_step(span: i64) -> i64 {
    [1, 2, 5, 10, 15, 30, 60, 120, 180, 240, 360].into_iter().find(|s| span / s <= 7).unwrap_or(720)
}

pub fn page(s: &State, t: Theme) -> El {
    let head = page_title(
        "Timeline",
        "Everything Defender and Intune wrote to the system log, minute by minute, for the past 24 hours. \
         Drag across the chart to zoom in, ⌘-scroll or pinch to zoom, scroll sideways to pan, click a column to see what happened.",
        t,
    );
    if s.timeline.buckets.is_empty() {
        let msg = match s.backfill {
            crate::state::Backfill::Running { lines } => format!("Reading the past 24 hours of the log… {} lines so far", count(lines)),
            _ => "Reading the past 24 hours of the log…".to_owned(),
        };
        return col().w_full().gap(16.0).children([head, text(msg).font(type_::BODY).color(t.text_secondary)]);
    }
    let latest = latest(s);
    let (from, to) = s.explore.window(latest);
    let w = (s.explore_w - AXIS_W - space::S2).max(100.0);
    let max_bins = ((w / 4.0) as usize).clamp(30, 240);
    let bins = s.timeline.bins(from, to, max_bins);

    col().w_full().gap(14.0).children([
        head,
        toolbar(s, t, latest, from, to, bins.first().map_or(1, |b| b.minutes)),
        minimap(s, t, latest, from, to),
        stats(s, t, &bins),
        chart(s, t, &bins, from, to, latest),
        filters(s, t, &bins),
        breakdown(s, t, &bins),
        details(s, t, from, to),
    ])
}

// ── Toolbar ─────────────────────────────────────────────────────────────────────────────

fn chip(key: String, label: String, on: bool, t: Theme) -> El {
    let accent = Tone::Neutral.color();
    row().key(key).h(28.0).px(10.0).radius(14.0).center_y().gap(6.0)
        .fill(if on { accent.alpha(0.18) } else { t.card })
        .border(1.0, if on { accent.alpha(0.55) } else { t.card_border })
        .hover(t.hover)
        .child(text(label).font(if on { type_::TITLE } else { type_::BODY }).color(t.text))
}

fn toolbar(s: &State, t: Theme, latest: i64, from: i64, to: i64, per: i64) -> El {
    let live = s.explore.fixed.is_none();
    let mut spans = row().gap(6.0).center_y();
    for (minutes, label) in SPANS {
        let on = live && s.explore.span == minutes;
        spans = spans.child(chip(format!("span-{label}"), label.to_owned(), on, t).on_press(move |s: &mut State| {
            s.explore.fixed = None;
            s.explore.span = minutes;
            s.explore.picked = None;
        }));
    }
    let lim = limit(latest);
    let zoom_out = chip("zoom-out".into(), "Zoom out".into(), false, t)
        .on_press(move |s: &mut State| s.explore.zoom(latest, 0.5, 2.0, lim));
    let now = if live {
        row().gap(6.0).center_y().children([
            dot(Tone::Good.color(), 8.0),
            text("Live").font(type_::LABEL).color(t.text_secondary),
        ])
    } else {
        chip("back-to-now".into(), "Back to now ›".into(), false, t).on_press(move |s: &mut State| {
            s.explore.fixed = None;
            s.explore.picked = None;
        })
    };
    let range = format!(
        "{} {} – {} · {} · {}-minute columns",
        s.timeline.day(from), s.timeline.clock(from), s.timeline.clock(to), span_text(to - from), per
    );
    col().w_full().gap(8.0).children([
        row().w_full().gap(space::S2).center_y().children([spans, el().grow(1.0), zoom_out, now]),
        text(range).font(type_::SECTION).color(t.text_secondary),
    ])
}

// ── Minimap ─────────────────────────────────────────────────────────────────────────────

fn minimap(s: &State, t: Theme, latest: i64, from: i64, to: i64) -> El {
    let lim = limit(latest);
    let bins = s.timeline.bins(lim.0, lim.1, 144);
    let shown = s.explore.shown;
    let top = bins.iter().map(|b| b.total(&shown)).max().unwrap_or(1).max(1) as f32;
    let accent = Tone::Neutral.color();
    let mut cells = row().w_full().h(MINI_H).items_end();
    for (i, b) in bins.iter().enumerate() {
        let inside = b.start + b.minutes > from && b.start < to;
        let h = (b.total(&shown) as f32 / top * (MINI_H - 4.0)).max(if b.total(&shown) > 0 { 1.0 } else { 0.0 });
        let threat = b.kinds[Kind::Threat.index()] > 0;
        let mut cell = col().key(format!("mini-{i}")).grow(1.0).min_w(0.0).h(MINI_H).justify_end()
            .fill(if inside { accent.alpha(0.16) } else { t.card });
        if threat {
            cell = cell.fill(Tone::Bad.color().alpha(0.35));
        }
        cell = cell.child(el().w_full().h(h).fill(if inside { accent.alpha(0.85) } else { t.text_secondary.alpha(0.35) }));
        cells = cells.child(cell);
    }
    let n = bins.len().max(1) as f32;
    let first = bins.first().map_or(lim.0, |b| b.start);
    let per = bins.first().map_or(10, |b| b.minutes);
    let strip = cells.key("minimap").radius(6.0).clip_rounded(6.0).border(1.0, t.card_border)
        .drag_threshold(0.0)
        .on_drag(move |s: &mut State, d: &mut Drag, _: &mut Tx| {
            if d.w <= 0.0 || d.cancelled() {
                return;
            }
            let at = first + ((d.x / d.w).clamp(0.0, 1.0) * n) as i64 * per;
            let (f, tt) = s.explore.window(latest);
            let half = (tt - f) / 2;
            s.explore.set(at - half, at - half + (tt - f), lim);
        });
    let mut labels = row().w_full().justify_between();
    for k in 0..=4 {
        let m = lim.0 + HISTORY * k / 4;
        labels = labels.child(text(if k == 4 { "now".to_owned() } else { s.timeline.clock(m) }).font(type_::SECTION).color(t.text_secondary));
    }
    col().w_full().gap(4.0).children([strip, labels])
}

// ── Stats ───────────────────────────────────────────────────────────────────────────────

fn stats(s: &State, t: Theme, bins: &[Bin]) -> El {
    let shown = s.explore.shown;
    let total: u64 = bins.iter().map(|b| b.total(&shown) as u64).sum();
    let minutes: i64 = bins.iter().map(|b| b.minutes).sum::<i64>().max(1);
    let busiest = bins.iter().max_by_key(|b| b.total(&shown));
    let perf: u64 = bins.iter().map(|b| b.perf as u64).sum();
    let detections: u64 = bins.iter().map(|b| b.kinds[Kind::Threat.index()] as u64).sum();
    let stat = |key: &str, label: &str, value: String, note: String, tone: Option<Tone>| {
        panel(t).key(key.to_owned()).gap(2.0).padding(12.0).children([
            text(label.to_owned()).font(type_::LABEL).color(t.text_secondary),
            text(value).font(TextStyle::new(20.0, 650.0)).color(tone.map_or(t.text, Tone::color)),
            text(note).font(type_::SECTION).color(t.text_secondary).truncate(),
        ])
    };
    let busy = busiest.filter(|b| b.total(&shown) > 0).map_or_else(
        || ("—".to_owned(), "nothing in view".to_owned()),
        |b| (format!("{}/min", count((b.total(&shown) as i64 / b.minutes.max(1)) as u64)), format!("at {}", s.timeline.clock(b.start))),
    );
    row().w_full().gap(space::S3).equal_columns(4).children([
        stat("x-total", "Log lines in view", count(total), format!("≈{}/min on average", count(total / minutes as u64)), None),
        stat("x-busy", "Busiest moment", busy.0, busy.1, None),
        stat("x-perf", "Performance hits", count(perf), "its own log said so".into(), (perf > 0).then_some(Tone::Warn)),
        stat("x-threat", "Detections", count(detections), if detections > 0 { "click the red marker".into() } else { "none in view".into() },
            Some(if detections > 0 { Tone::Bad } else { Tone::Good })),
    ])
}

// ── The chart ───────────────────────────────────────────────────────────────────────────

/// The bin index under a fraction of the plot's width.
fn bin_at(f: f32, n: usize) -> usize {
    ((f.clamp(0.0, 0.9999) * n as f32) as usize).min(n.saturating_sub(1))
}

fn chart(s: &State, t: Theme, bins: &[Bin], from: i64, to: i64, latest: i64) -> El {
    let shown = s.explore.shown;
    let n = bins.len();
    let top = nice(bins.iter().map(|b| b.total(&shown) as f32 / b.minutes as f32).fold(0.0, f32::max));
    let hover = s.explore.hover.map(|f| bin_at(f, n));
    let brush = s.explore.brush.map(|(a, b)| (bin_at(a.min(b), n), bin_at(a.max(b), n)));
    let picked = s.explore.picked;
    let accent = Tone::Neutral.color();

    // Readout: what's under the pointer, else the picked column, else a hint.
    let focus = hover.or_else(|| picked.and_then(|(pf, _)| bins.iter().position(|b| b.start <= pf && pf < b.start + b.minutes)));
    let readout = match focus.and_then(|i| bins.get(i)) {
        Some(b) => {
            let mut r = row().w_full().gap(space::S3).center_y().child(
                text(format!("{}–{}", s.timeline.clock(b.start), s.timeline.clock(b.start + b.minutes)))
                    .font(type_::TITLE).color(t.text),
            ).child(text(format!("{} lines", count(b.total(&shown) as u64))).font(type_::BODY).color(t.text_secondary));
            let mut parts: Vec<(Kind, u32)> = Kind::ALL.iter().map(|k| (*k, b.kinds[k.index()])).filter(|(k, v)| *v > 0 && shown[k.index()]).collect();
            parts.sort_by_key(|p| std::cmp::Reverse(p.1));
            for (k, v) in parts.into_iter().take(5) {
                r = r.child(row().gap(4.0).center_y().children([
                    dot(k.color(), 7.0),
                    text(format!("{} {}", kind_name(k), count(v as u64))).font(type_::SECTION).color(t.text_secondary),
                ]));
            }
            if let Some(c) = b.cpu_avg {
                r = r.child(text(format!("CPU {c:.1}%")).font(type_::SECTION).color(t.text_secondary));
            }
            r
        }
        None => row().w_full().child(text("Point at the chart for the numbers; drag across it to zoom in.").font(type_::BODY).color(t.text_secondary)),
    };

    // Milestone lane.
    let mut marks = row().grow(1.0).min_w(0.0).h(MARK_H).center_y();
    for (i, b) in bins.iter().enumerate() {
        let mut cell = row().key(format!("mark-{i}")).grow(1.0).min_w(0.0).h(MARK_H).center();
        if let Some(k) = MILESTONES.iter().find(|k| b.marks & (1 << k.index()) != 0 && shown[k.index()]) {
            let size = if *k == Kind::Threat { 12.0 } else { 7.0 };
            cell = cell.child(dot(k.color(), size));
        }
        marks = marks.child(cell);
    }

    // Columns.
    let mut cols = row().w_full().h(PLOT_H).items_end();
    for (i, b) in bins.iter().enumerate() {
        let in_brush = brush.is_some_and(|(a, z)| (a..=z).contains(&i));
        let is_picked = picked.is_some_and(|(pf, _)| b.start <= pf && pf < b.start + b.minutes);
        let bg = if in_brush {
            accent.alpha(0.22)
        } else if is_picked {
            accent.alpha(0.16)
        } else if hover == Some(i) {
            t.text_secondary.alpha(0.12)
        } else if MILESTONES.iter().any(|k| *k == Kind::Threat && b.kinds[k.index()] > 0) && shown[Kind::Threat.index()] {
            Tone::Bad.color().alpha(0.10)
        } else {
            Color::TRANSPARENT
        };
        let mut stack = col().key(format!("col-{i}")).grow(1.0).min_w(0.0).h(PLOT_H).justify_end().fill(bg);
        if n <= 120 {
            stack = stack.px(0.5);
        }
        if b.perf > 0 && (shown[Kind::Directory.index()] || !s.explore.perf_only) {
            stack = stack.child(el().w_full().h(3.0).radius(1.5).fill(Tone::Warn.color()));
            stack = stack.child(el().h(2.0));
        }
        for k in Kind::ALL.iter().rev() {
            if !shown[k.index()] || (s.explore.perf_only && *k != Kind::Directory) {
                continue;
            }
            let v = b.kinds[k.index()] as f32 / b.minutes as f32;
            let h = (v / top * PLOT_H).clamp(0.0, PLOT_H);
            if h > 0.0 {
                stack = stack.child(el().w_full().h(h.max(1.0)).fill(k.color()));
            }
        }
        cols = cols.child(stack);
    }

    let mut plot = el().key("plot").grow(1.0).min_w(0.0).h(PLOT_H);
    let mut axis = el().w(AXIS_W).h(PLOT_H);
    for k in 0..=2 {
        let y = PLOT_H * k as f32 / 2.0;
        plot = plot.child(el().pin(Some(0.0), Some(y.min(PLOT_H - 1.0)), Some(0.0), None).h(1.0).fill(t.separator));
        let v = top * (2 - k) as f32 / 2.0;
        let label = if k == 0 { format!("{}/min", v.round() as u64) } else { format!("{}", v.round() as u64) };
        axis = axis.child(text(label).font(type_::SECTION).color(t.text_secondary).pin(Some(0.0), Some(y - 7.0), None, None));
    }
    let lim = limit(latest);
    let plot = plot.child(cols.pin(Some(0.0), Some(0.0), Some(0.0), Some(0.0)))
        .drag_threshold(0.0)
        .on_drawn_layout(|s: &mut State, r: [f32; 4]| {
            if (s.explore_w - r[2] - AXIS_W - space::S2).abs() > 0.5 {
                s.explore_w = r[2] + AXIS_W + space::S2;
            }
        })
        .on_pointer_move_local(move |s: &mut State, p: rune::PointerEvent, _: &mut Tx| {
            let w = (s.explore_w - AXIS_W - space::S2).max(1.0);
            s.explore.hover = Some((p.x / w).clamp(0.0, 1.0));
        })
        .on_hover_change(|s: &mut State, inside: bool, _: &mut Tx| {
            if !inside {
                s.explore.hover = None;
            }
        })
        .on_drag(move |s: &mut State, d: &mut Drag, _: &mut Tx| {
            if d.w <= 0.0 {
                return;
            }
            let f = (d.x / d.w).clamp(0.0, 1.0);
            let f0 = (d.start_x / d.w).clamp(0.0, 1.0);
            match d.phase {
                Phase::Down => s.explore.brush = Some((f0, f)),
                Phase::Move => s.explore.brush = Some((f0, f)),
                Phase::Up => {
                    s.explore.brush = None;
                    if d.cancelled() {
                        return;
                    }
                    let (wf, wt) = s.explore.window(latest);
                    let span = (wt - wf) as f32;
                    if (d.x - d.start_x).abs() > 6.0 {
                        let a = wf + (f0.min(f) * span) as i64;
                        let b = wf + (f0.max(f) * span).ceil() as i64;
                        s.explore.set(a, b.max(a + 5), lim);
                        s.explore.picked = None;
                    } else if d.clicks >= 2 {
                        s.explore.zoom(latest, f, 0.35, lim);
                    } else {
                        let max_bins = (((s.explore_w - AXIS_W - space::S2).max(100.0) / 4.0) as usize).clamp(30, 240);
                        let bins = s.timeline.bins(wf, wt, max_bins);
                        if let Some(b) = bins.get(bin_at(f, bins.len())) {
                            let pick = (b.start, b.start + b.minutes);
                            s.explore.picked = if s.explore.picked == Some(pick) { None } else { Some(pick) };
                        }
                    }
                }
            }
        })
        .on_wheel(move |s: &mut State, e: rune::WheelEvent, _: &mut Tx| {
            let w = (s.explore_w - AXIS_W - space::S2).max(1.0);
            let at = (e.x / w).clamp(0.0, 1.0);
            if e.mods.cmd {
                s.explore.zoom(latest, at, (e.dy * 0.006).exp().clamp(0.5, 2.0), lim);
                true
            } else if e.dx.abs() > e.dy.abs() {
                let (wf, wt) = s.explore.window(latest);
                let minutes = (-e.dx / w * (wt - wf) as f32).round() as i64;
                if minutes != 0 {
                    s.explore.pan(latest, minutes, lim);
                }
                true
            } else {
                false
            }
        })
        .on_magnify(move |s: &mut State, e: rune::MagnifyEvent, _: &mut Tx| {
            let w = (s.explore_w - AXIS_W - space::S2).max(1.0);
            s.explore.zoom(latest, (e.x / w).clamp(0.0, 1.0), 1.0 / (1.0 + e.delta).max(0.2), lim);
            true
        });

    // Time axis.
    let step = tick_step(to - from);
    let offset = s.timeline.offset_min.unwrap_or(0) as i64;
    let plot_w = (s.explore_w - AXIS_W - space::S2).max(1.0);
    let mut ticks = el().grow(1.0).min_w(0.0).h(16.0);
    let mut m = ((from + offset) / step + 1) * step - offset;
    while m < to {
        let x = (m - from) as f32 / (to - from) as f32 * plot_w;
        let label = if (m + offset).rem_euclid(1440) == 0 { s.timeline.day(m) } else { s.timeline.clock(m) };
        ticks = ticks.child(text(label).font(type_::SECTION).color(t.text_secondary).pin(Some((x - 16.0).clamp(0.0, (plot_w - 40.0).max(0.0))), Some(0.0), None, None));
        m += step;
    }

    // CPU lane.
    let cpu_top = nice(bins.iter().filter_map(|b| b.cpu_max).fold(0.0, f32::max));
    let has_cpu = bins.iter().any(|b| b.cpu_avg.is_some());
    let mut cpu_cols = row().w_full().h(CPU_H).items_end();
    for (i, b) in bins.iter().enumerate() {
        let mut c = el().key(format!("cpu-{i}")).grow(1.0).min_w(0.0).h(CPU_H);
        if let (Some(avg), Some(max)) = (b.cpu_avg, b.cpu_max) {
            let hm = (max / cpu_top * CPU_H).clamp(1.0, CPU_H);
            let ha = (avg / cpu_top * CPU_H).clamp(1.0, CPU_H);
            c = c.child(el().pin(Some(0.0), None, Some(0.0), Some(0.0)).h(hm).fill(Kind::Cloud.color().alpha(0.28)))
                .child(el().pin(Some(0.0), None, Some(0.0), Some(0.0)).h(ha).fill(Kind::Cloud.color()));
        }
        if hover == Some(i) {
            c = c.fill(t.text_secondary.alpha(0.12));
        }
        cpu_cols = cpu_cols.child(c);
    }
    let cpu_lane = if has_cpu {
        row().w_full().gap(space::S2).children([
            el().w(AXIS_W).h(CPU_H).children([
                text(format!("{}%", cpu_top.round() as u64)).font(type_::SECTION).color(t.text_secondary).pin(Some(0.0), Some(0.0), None, None),
                text("CPU").font(type_::SECTION).color(t.text_secondary).pin(Some(0.0), None, None, Some(0.0)),
            ]),
            el().grow(1.0).min_w(0.0).h(CPU_H).border_sides([1.0, 0.0, 0.0, 0.0], t.separator).child(cpu_cols.pin(Some(0.0), Some(0.0), Some(0.0), Some(0.0))),
        ])
    } else {
        row().w_full().pl(AXIS_W + space::S2).child(
            text("CPU is recorded only while this app is open; it fills in from now on.").font(type_::SECTION).color(t.text_secondary),
        )
    };

    panel(t).key("chart").gap(6.0).children([
        readout,
        row().w_full().gap(space::S2).children([
            el().w(AXIS_W).h(MARK_H).child(text("Events").font(type_::SECTION).color(t.text_secondary).pin(Some(0.0), Some(3.0), None, None)),
            marks,
        ]),
        row().w_full().gap(space::S2).children([axis, plot]),
        row().w_full().gap(space::S2).children([
            el().w(AXIS_W).h(16.0),
            ticks,
        ]),
        cpu_lane,
    ])
}

// ── Filters and breakdown ───────────────────────────────────────────────────────────────

fn filters(s: &State, t: Theme, bins: &[Bin]) -> El {
    let mut chips = row().w_full().gap(6.0).flex_wrap();
    for k in Kind::ALL {
        let total: u64 = bins.iter().map(|b| b.kinds[k.index()] as u64).sum();
        if total == 0 {
            continue;
        }
        let on = s.explore.shown[k.index()];
        chips = chips.child(
            row().key(format!("filter-{k:?}")).h(28.0).px(10.0).radius(14.0).center_y().gap(6.0)
                .fill(if on { k.color().alpha(0.16) } else { t.card })
                .border(1.0, if on { k.color().alpha(0.6) } else { t.card_border })
                .opacity(if on { 1.0 } else { 0.55 })
                .hover(t.hover)
                .on_press(move |s: &mut State| s.explore.shown[k.index()] = !s.explore.shown[k.index()])
                .children([
                    dot(k.color(), 8.0),
                    text(kind_name(k)).font(type_::BODY).color(t.text),
                    text(count(total)).font(type_::SECTION).color(t.text_secondary),
                ]),
        );
    }
    let all_on = s.explore.shown.iter().all(|x| *x);
    let perf = s.explore.perf_only;
    col().w_full().gap(8.0).children([
        row().w_full().center_y().gap(space::S2).children([
            section("Show", t).grow(1.0),
            chip("perf-only".into(), "Performance hits only".into(), perf, t).on_press(|s: &mut State| s.explore.perf_only = !s.explore.perf_only),
            chip("all-kinds".into(), if all_on { "Hide all".into() } else { "Show all".into() }, false, t)
                .on_press(move |s: &mut State| s.explore.shown = [!all_on; KINDS]),
        ]),
        chips,
    ])
}

fn breakdown(s: &State, t: Theme, bins: &[Bin]) -> El {
    let mut rows: Vec<(Kind, u64)> = Kind::ALL.iter()
        .map(|k| (*k, bins.iter().map(|b| b.kinds[k.index()] as u64).sum::<u64>()))
        .filter(|(_, n)| *n > 0)
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.1));
    let sum: u64 = rows.iter().map(|r| r.1).sum::<u64>().max(1);
    let top = rows.first().map_or(1, |r| r.1).max(1);
    let solo = |k: Kind, shown: &[bool; KINDS]| shown.iter().enumerate().all(|(i, on)| *on == (i == k.index()));
    let list: Vec<El> = rows.iter().map(|(k, n)| {
        let k = *k;
        let is_solo = solo(k, &s.explore.shown);
        let f = *n as f32 / top as f32;
        row().key(format!("share-{k:?}")).w_full().h(34.0).px(space::S3).center_y().gap(space::S3)
            .fill(if is_solo { k.color().alpha(0.12) } else { t.card })
            .hover(t.hover)
            .on_press(move |s: &mut State| {
                s.explore.shown = if solo(k, &s.explore.shown) { [true; KINDS] } else {
                    let mut only = [false; KINDS];
                    only[k.index()] = true;
                    only
                };
            })
            .children([
                dot(k.color(), 8.0),
                text(kind_name(k)).font(TextStyle::new(13.0, 500.0)).color(t.text).w(150.0).truncate(),
                row().grow(1.0).min_w(0.0).h(10.0).center_y().children([
                    el().grow(f).h(10.0).radius(4.0).fill(k.color()),
                    el().grow(1.0 - f).h(10.0),
                ]),
                text(format!("{:.0}%", *n as f32 / sum as f32 * 100.0)).font(type_::SECTION).color(t.text_secondary).w(40.0).align(rune::Align::End),
                text(count(*n)).font(type_::LABEL).color(t.text_secondary).w(64.0).align(rune::Align::End),
            ])
    }).collect();
    col().w_full().gap(8.0).children([
        row().w_full().center_y().children([
            section("What's in view", t).grow(1.0),
            text("Click a row to see only that").font(type_::SECTION).color(t.text_secondary),
        ]),
        grouped(list, t),
    ])
}

// ── Details ─────────────────────────────────────────────────────────────────────────────

fn details(s: &State, t: Theme, from: i64, to: i64) -> El {
    let (a, b, title) = match s.explore.picked {
        Some((a, b)) => (a, b, format!("What happened {}–{}", s.timeline.clock(a), s.timeline.clock(b))),
        None => (from, to, "Most repeated in view".to_owned()),
    };
    let lines = s.timeline.lines_in(a, b, &s.explore.shown, s.explore.perf_only);
    let mut head = row().w_full().center_y().gap(space::S2).child(section(&title, t).grow(1.0));
    if s.explore.picked.is_some() {
        head = head.child(chip("unpick".into(), "Show all in view".into(), false, t).on_press(|s: &mut State| s.explore.picked = None));
    }
    if lines.is_empty() {
        return col().w_full().gap(8.0).children([head, text("Nothing for the kinds shown.").font(type_::BODY).color(t.text_secondary)]);
    }
    let rows: Vec<El> = lines.into_iter().take(40).enumerate().map(|(i, (_, k, l))| {
        let mut headline = doing(k).to_owned();
        if l.perf {
            headline.push_str(" — its own log calls this a performance hit");
        }
        row().key(format!("dl-{i}")).w_full().min_h(46.0).px(space::S3).py(6.0).center_y().gap(space::S3).children([
            text(l.t.clone()).font(type_::MONO_CAPTION).color(t.text_secondary).w(64.0),
            dot(k.color(), 8.0),
            col().grow(1.0).min_w(0.0).gap(2.0).children([
                text(headline).font(TextStyle::new(13.0, 500.0)).color(if l.perf { Tone::Warn.color() } else { t.text }).wrap().min_w(0.0),
                text(format!("{} · {}", l.process, l.message)).font(type_::MONO_CAPTION.mono()).color(t.text_secondary).truncate(),
            ]),
            text(if l.count > 1 { format!("×{}", count(l.count as u64)) } else { String::new() }).font(type_::LABEL).color(t.text_secondary),
        ])
    }).collect();
    col().w_full().gap(8.0).children([head, grouped(rows, t)])
}

/// Keys for the Timeline page: ← → pan by a quarter, + − zoom, Esc lets go of a pick or a zoom.
pub fn on_key(s: &mut State, k: &rune::KeyEvent) -> bool {
    use rune::Key;
    let latest = latest(s);
    let lim = limit(latest);
    let (from, to) = s.explore.window(latest);
    let quarter = ((to - from) / 4).max(1);
    match k.key {
        Key::Left => s.explore.pan(latest, -quarter, lim),
        Key::Right => s.explore.pan(latest, quarter, lim),
        Key::Escape if s.explore.picked.is_some() => s.explore.picked = None,
        Key::Escape => s.explore.fixed = None,
        Key::Text(ref c) if c == "+" || c == "=" => s.explore.zoom(latest, 0.5, 0.5, lim),
        Key::Text(ref c) if c == "-" => s.explore.zoom(latest, 0.5, 2.0, lim),
        _ => return false,
    }
    true
}
