//! What Microsoft Defender and Intune are doing to this Mac, and what it costs.
//!
//! A Rune dashboard that watches the whole managed-device family — the wdavdaemon
//! processes, the endpoint-security and network-filter system extensions, the DLP agents,
//! telemetry writers, Company Portal and its SSO extension — and reports:
//!
//! - live CPU, memory and disk I/O per process, with a 5-minute CPU history;
//! - what the products *do* ("shenanigans"): network-filter reconnects, directory
//!   lookups, telemetry batches, auth packet logging — from the unified log, live and
//!   backfilled for the past 3 hours;
//! - quarantined threats and scan status from `mdatp`;
//! - the bill: CPU-seconds since the window opened, as an estimated battery cost.
//!
//! ```sh
//! cargo run -p defender-watch                      # live on this Mac
//! cargo run -p defender-watch -- --snap watch.png  # headless, seeded with demo data
//! defender-watch --install-notify                  # push a notification on every new detection
//! ```
//!
//! The app itself draws nothing but the state: `sampler` samples processes once a second,
//! `logstream` follows the unified log, `mdatp` asks the product's own CLI, and `poll`
//! drains what arrived.

mod classify;
#[cfg(target_os = "macos")]
mod logstream;
mod managed;
#[cfg(target_os = "macos")]
mod mdatp;
#[cfg(target_os = "macos")]
mod notify;
#[cfg(target_os = "macos")]
mod sampler;
mod state;
mod timeline;
mod view;

use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};

use rune::{AppSpec, Cx, Tx};
use state::{Page, State, Store};

static STORE: OnceLock<Arc<Store>> = OnceLock::new();

fn store() -> &'static Arc<Store> {
    STORE.get_or_init(|| Arc::new(Store::default()))
}

/// True when Rune will render headlessly instead of opening a window: no threads are
/// started, and the state is seeded with demo data so a snapshot has something to show.
fn headless() -> bool {
    std::env::args().any(|a| {
        matches!(
            a.as_str(),
            "--snap" | "--trace" | "--tree" | "--frames" | "--strip" | "--video" | "--script" | "--list-scenes" | "--out"
        )
    })
}

fn init() -> State {
    let mut s = State::new(headless() && demo());
    if s.demo {
        state::seed_demo(&mut s);
    }
    s
}

fn demo() -> bool {
    headless() && (std::env::args().any(|a| a == "--demo") || rune::extra_args().iter().any(|a| a == "--demo"))
}

fn setup(_: &mut State, wake: rune::Waker) {
    if headless() {
        return;
    }
    let wake_sampler = wake.clone();
    let wake_live = wake.clone();
    std::thread::spawn(move || sampler::run(store().clone(), wake_sampler));
    std::thread::spawn(move || logstream::run(store().clone(), wake_live));
    std::thread::spawn(move || logstream::run_backfill(store().clone(), wake));
}

/// Drain what the monitor threads left in the store, and say whether to redraw.
fn poll(s: &mut State, _: f64, _: &mut Tx) -> bool {
    if s.demo {
        return false;
    }
    if !store().dirty.swap(false, Ordering::AcqRel) {
        return false;
    }
    let mut snap = store().inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    s.absorb(&mut snap)
}

fn main() {
    #[cfg(target_os = "macos")]
    match std::env::args().nth(1).as_deref() {
        Some("--notify") => return notify::run(),
        Some("--install-notify") => return notify::install(),
        Some("--uninstall-notify") => return notify::uninstall(),
        _ => {}
    }
    rune::run(AppSpec::<State> {
        scenes: &[
            ("demo", |s| state::seed_demo(s)),
            ("performance", |s| { state::seed_demo(s); s.page = Page::Performance; }),
            ("privacy", |s| { state::seed_demo(s); s.page = Page::Privacy; }),
            ("protection", |s| { state::seed_demo(s); s.page = Page::Protection; }),
            ("activity", |s| { state::seed_demo(s); s.page = Page::Activity; }),
            ("explore", |s| { state::seed_demo(s); s.page = Page::Explore; }),
            ("explore-zoomed", |s| {
                state::seed_demo(s);
                s.page = Page::Explore;
                let latest = s.timeline.span().map_or(0, |x| x.1);
                s.explore.fixed = Some((latest - 30, latest + 1));
                s.explore.hover = Some(0.62);
                s.explore.picked = Some((latest - 22, latest - 21));
            }),
            ("explore-day", |s| {
                state::seed_demo(s);
                s.page = Page::Explore;
                s.explore.span = 1440;
                s.explore.hover = Some(0.205);
            }),
            ("management", |s| { state::seed_demo(s); s.page = Page::Management; }),
        ],
        on_key: Some(view::on_key),
        setup: Some(setup),
        poll: Some(poll),
        ..AppSpec::new("Defender Watch", (1000.0, 760.0), init, view::view)
    });
    #[cfg(target_os = "macos")]
    logstream::shutdown();
}

// `Cx` is in the signature below only through `view`; keep the import quiet in non-macOS
// builds where the modules the app needs are absent.
#[allow(unused)]
fn _keep(_: &mut Cx<State>) {}
