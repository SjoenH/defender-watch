//! Performance: how much of the Mac Defender takes, over the past 5 minutes.
//!
//! Units: a sample's `cpu` is the Defender family in percent of ONE core (sysinfo sums per
//! process); `system_cpu` is the whole Mac in percent of ALL cores. Dividing the family by
//! the core count puts both on one axis: percent of the whole Mac.

use rune::tok::{Theme, space, type_};
use rune::{Color, El, TextStyle, col, oklch, row, text};

use super::chart::{columns, hbar, legend, nice, pct};
use super::words::{Reading, count, process_name};
use super::{page_title, panel, section};
use crate::state::{CpuSample, State};

/// Above this whole-Mac CPU the machine counts as busy: Defender's work competes with yours.
const BUSY_PCT: f32 = 25.0;

fn cores() -> f32 {
    std::thread::available_parallelism().map_or(8, |n| n.get()) as f32
}

fn defender_blue() -> Color {
    oklch(0.64, 0.15, 250.0)
}

fn rest_gray(t: Theme) -> Color {
    t.text_secondary.alpha(0.45)
}

/// One sample as percent of the whole Mac: (Defender, everything else, Defender's share of
/// the Mac's work, or `None` while the Mac is idle and a share would be noise).
pub fn split(sample: &CpuSample, cores: f32) -> (f32, f32, Option<f32>) {
    let system = sample.system_cpu.max(0.0);
    let defender = sample.cpu.max(0.0) / cores.max(1.0);
    let share = (system >= 1.0).then(|| (defender / system * 100.0).min(100.0));
    (defender, (system - defender).max(0.0), share)
}

pub fn page(s: &State, t: Theme, r: &Reading) -> El {
    let n = cores();
    let split: Vec<_> = s.samples.iter().map(|x| split(x, n)).collect();
    let shares: Vec<f32> = split.iter().map(|(_, _, sh)| sh.unwrap_or(0.0)).collect();
    let busy: Vec<f32> = s.samples.iter().zip(&split)
        .filter(|(x, _)| x.system_cpu > BUSY_PCT)
        .filter_map(|(_, (_, _, sh))| *sh)
        .collect();
    let reads: Vec<f32> = s.samples.iter().map(|x| x.read_mb_s).collect();
    let avg = |v: &[f32]| if v.is_empty() { 0.0 } else { v.iter().sum::<f32>() / v.len() as f32 };

    let stat = |key: &str, label: &str, value: String, note: String| {
        panel(t).key(key.to_owned()).gap(4.0).children([
            text(label.to_owned()).font(type_::LABEL).color(t.text_secondary),
            text(value).font(TextStyle::new(22.0, 650.0)).color(t.text),
            text(note).font(type_::SECTION).color(t.text_secondary).wrap().min_w(0.0),
        ])
    };
    let stats = row().w_full().gap(space::S3).equal_columns(3).children([
        stat("stat-share", "Share of your Mac's work", pct(avg(&shares)),
            if busy.is_empty() { "on average, past 5 minutes".into() } else { format!("{} while your Mac was busy", pct(avg(&busy))) }),
        stat("stat-cpu", "Processor time used", format!("{} s", count(s.cpu_seconds as u64)), "since this window opened".into()),
        stat("stat-disk", "Disk reads", format!("{:.1} MB/s", avg(&reads)), "on average, past 5 minutes".into()),
    ]);

    let stacked: Vec<Vec<f32>> = split.iter().map(|(d, o, _)| vec![*d, *o]).collect();
    let mac_max = nice(s.samples.iter().map(|x| x.system_cpu).fold(10.0, f32::max)).min(100.0);
    let mac = chart_card("chart-mac", "Your Mac's processor", "percent of all cores", t,
        Some(row().gap(space::S3).children([legend("Defender", defender_blue(), t), legend("Everything else", rest_gray(t), t)])),
        columns("mac", &stacked, &[defender_blue(), rest_gray(t)], mac_max, t, pct));

    let share_max = nice(shares.iter().copied().fold(5.0, f32::max)).min(100.0);
    let share = chart_card("chart-share", "Defender's share of the work", "of everything the processor was doing", t, None,
        columns("share", &shares.iter().map(|v| vec![*v]).collect::<Vec<_>>(), &[defender_blue()], share_max, t, pct));

    let read_max = nice(reads.iter().copied().fold(1.0, f32::max));
    let disk = chart_card("chart-disk", "Disk reads by Defender", "megabytes per second", t, None,
        columns("disk", &reads.iter().map(|v| vec![*v]).collect::<Vec<_>>(), &[defender_blue()], read_max, t, |v| format!("{v:.1}")));

    col().w_full().gap(16.0).children([
        page_title("Performance", &format!("{}. {}", r.impact, r.impact_line), t),
        stats,
        mac,
        row().w_full().gap(space::S3).equal_columns(2).children([share, disk]),
        parts(s, t),
        text("Waiting is not counted: when Defender checks a file before an app may open it, the app waits without Defender using more processor. These charts can't see that wait.")
            .font(type_::SECTION).color(t.text_secondary).wrap().min_w(0.0),
    ])
}

fn chart_card(key: &str, title: &str, unit: &str, t: Theme, legend: Option<El>, plot: El) -> El {
    let mut head = row().w_full().gap(space::S3).center_y().child(
        col().grow(1.0).min_w(0.0).gap(1.0).children([
            text(title.to_owned()).font(type_::TITLE).color(t.text),
            text(unit.to_owned()).font(type_::SECTION).color(t.text_secondary),
        ]),
    );
    if let Some(l) = legend {
        head = head.child(l);
    }
    panel(t).key(key.to_owned()).gap(space::S3).children([head, plot])
}

/// Each process: what it is, its memory as a bar, and its CPU.
fn parts(s: &State, t: Theme) -> El {
    let mut procs: Vec<_> = s.procs.iter().collect();
    procs.sort_by(|a, b| b.mem_mb.total_cmp(&a.mem_mb));
    let max = procs.first().map_or(1.0, |p| p.mem_mb.max(1.0));
    let total: f32 = procs.iter().map(|p| p.mem_mb).sum();
    let mut rows = col().w_full().gap(8.0);
    for p in procs.iter().take(10) {
        rows = rows.child(row().key(format!("part-{}", p.pid)).w_full().min_h(24.0).center_y().gap(space::S3).children([
            col().w(200.0).children([
                text(process_name(&p.name)).font(type_::BODY).color(t.text).truncate(),
                text(p.name.clone()).font(type_::SECTION).color(t.text_secondary).truncate(),
            ]),
            hbar(p.mem_mb / max, p.group.color()),
            text(format!("{:.0} MB", p.mem_mb)).font(type_::LABEL).color(t.text).w(64.0),
            text(format!("{:.1}% CPU", p.cpu)).font(type_::LABEL).color(t.text_secondary).w(72.0),
        ]));
    }
    if procs.is_empty() {
        rows = rows.child(text("Looking for Defender and Intune processes…").font(type_::BODY).color(t.text_secondary));
    }
    panel(t).key("parts").gap(space::S3).children([
        row().w_full().center_y().children([
            section("The parts of Defender, by memory", t).grow(1.0),
            text(format!("{} MB in total", count(total as u64))).font(type_::SECTION).color(t.text_secondary),
        ]),
        rows,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(cpu: f32, system_cpu: f32) -> CpuSample {
        CpuSample { cpu, read_mb_s: 0.0, system_cpu }
    }

    #[test]
    fn split_puts_both_on_the_whole_mac() {
        // 20% of one core on a 10-core Mac is 2% of the Mac; the Mac at 20% leaves 18% for the rest.
        let (d, o, share) = split(&sample(20.0, 20.0), 10.0);
        assert!((d - 2.0).abs() < 1e-4);
        assert!((o - 18.0).abs() < 1e-4);
        assert!((share.unwrap_or_default() - 10.0).abs() < 1e-4);
    }

    #[test]
    fn idle_mac_has_no_share() {
        assert_eq!(split(&sample(0.5, 0.2), 10.0).2, None);
    }

    #[test]
    fn share_never_exceeds_everything() {
        // Sampling skew can make the family read above the system; cap the share at 100%.
        let (_, o, share) = split(&sample(200.0, 10.0), 10.0);
        assert_eq!(o, 0.0);
        assert_eq!(share, Some(100.0));
    }
}
