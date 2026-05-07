use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Gauge, Paragraph, Sparkline, Wrap};

use crate::backend::CrackingBackend;
use crate::cpu_backend::CpuBackend;
use crate::reporter::{CrackEvent, Reporter};

const ORANGE: Color = Color::Rgb(222, 74, 31);

const HASH_TYPES: &[&str] = &[
    "auto", "md5", "sha1", "sha256", "sha512", "sha3-256", "sha3-512", "bcrypt", "ntlm", "argon2",
    "scrypt", "pbkdf2",
];

const BANNER: &str = r#" ___.                 __                            ___.
 \_ |_________ __ ___/  |_  ____   ________________ \_ |__   ___________
  | __ \_  __ \  |  \   __\/ __ \_/ ___\_  __ \__  \ | __ \_/ __ \_  __ \
  | \_\ \  | \/  |  /|  | \  ___/\  \___|  | \// __ \| \_\ \  ___/|  | \/
  |___  /__|  |____/ |__|  \___  >\___  >__|  (____  /___  /\___  >__|
      \/                       \/     \/           \/    \/     \/"#;

const CRAB: &str = r#"        _~^~^~_
    \) /  o o  \ (/
      '_   -   _'
      / '-----' \"#;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    File,
    Wordlist,
    HashType,
    Rules,
    Cpu,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Configuring,
    Running,
    Done,
}

struct App {
    file: String,
    wordlist: String,
    hash_idx: usize,
    rules: bool,
    cpu: bool,
    focused: Field,

    phase: Phase,
    progress: u64,
    total: u64,
    cracked_lines: Vec<String>,
    hps_history: VecDeque<u64>,
    last_progress: u64,
    last_tick: Instant,
    final_found: Option<usize>,
    event_rx: Option<Receiver<CrackEvent>>,
    cancel: Arc<AtomicBool>,
    resolved_hash: String,
    error: Option<String>,
}

impl App {
    fn new() -> Self {
        Self {
            file: String::new(),
            wordlist: String::new(),
            hash_idx: 0,
            rules: false,
            cpu: false,
            focused: Field::File,
            phase: Phase::Configuring,
            progress: 0,
            total: 0,
            cracked_lines: Vec::new(),
            hps_history: VecDeque::new(),
            last_progress: 0,
            last_tick: Instant::now(),
            final_found: None,
            event_rx: None,
            cancel: Arc::new(AtomicBool::new(false)),
            resolved_hash: String::new(),
            error: None,
        }
    }
}

// autocompletition helper

fn list_path_matches(input: &str) -> Vec<String> {
    let (dir_to_read, prefix, dir_to_keep) = match input.rfind('/') {
        Some(i) => (&input[..=i], &input[i + 1..], &input[..=i]),
        None => (".", input, ""),
    };

    let entries = match std::fs::read_dir(dir_to_read) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            if name.starts_with(prefix) {
                let suffix = if e.file_type().ok()?.is_dir() {
                    "/"
                } else {
                    ""
                };
                Some(format!("{}{}{}", dir_to_keep, name, suffix))
            } else {
                None
            }
        })
        .take(4)
        .collect()
}

fn autocomplete_path(input: &str) -> Option<String> {
    let mut matches = list_path_matches(input);
    if matches.len() == 1 {
        matches.pop()
    } else {
        None
    }
}

fn panel_block(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(format!(" {} ", title))
        .border_style(Style::default().fg(ORANGE))
}

fn try_start_cracking(app: &mut App) -> bool {
    use std::fs;

    app.error = None;

    if app.file.is_empty() || app.wordlist.is_empty() {
        return false;
    }

    let content = match fs::read_to_string(&app.file) {
        Ok(c) => c,
        Err(e) => {
            app.error = Some(format!("file: {}", e));
            return false;
        }
    };
    let bytes = match fs::read(&app.wordlist) {
        Ok(b) => b,
        Err(e) => {
            app.error = Some(format!("wordlist: {}", e));
            return false;
        }
    };
    let wordlist = String::from_utf8_lossy(&bytes).to_string();
    let total = wordlist.lines().count() as u64;

    let hash_arg = HASH_TYPES[app.hash_idx].to_string();
    let resolved_hash = if hash_arg == "auto" {
        let first = content.lines().next().unwrap_or("");
        crate::detector::detect(first).to_string()
    } else {
        hash_arg
    };

    let (tx, rx) = std::sync::mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let reporter = Reporter::tui(total, tx, cancel.clone());

    let rules = app.rules;
    let resolved_clone = resolved_hash.clone();

    std::thread::spawn(move || {
        let hashes_vec: Vec<&str> = content.lines().collect();
        CpuBackend.run(&hashes_vec, &wordlist, &resolved_clone, rules, &reporter);
    });

    app.event_rx = Some(rx);
    app.cancel = cancel;
    app.total = total;
    app.progress = 0;
    app.last_progress = 0;
    app.last_tick = Instant::now();
    app.cracked_lines.clear();
    app.hps_history.clear();
    app.final_found = None;
    app.resolved_hash = resolved_hash;
    app.phase = Phase::Running;

    true
}

fn drain_events(app: &mut App) {
    if let Some(rx) = &app.event_rx {
        loop {
            match rx.try_recv() {
                Ok(CrackEvent::Progress { tested, total }) => {
                    app.progress = tested;
                    app.total = total;
                }
                Ok(CrackEvent::Cracked { line }) => {
                    app.cracked_lines.push(line);
                }
                Ok(CrackEvent::Done { found }) => {
                    app.final_found = Some(found);
                    app.phase = Phase::Done;
                }
                Err(_) => break,
            }
        }
    }
}

fn tick_hps(app: &mut App) {
    let now = Instant::now();
    if now.duration_since(app.last_tick) < Duration::from_millis(500) {
        return;
    }
    let dt = now.duration_since(app.last_tick).as_secs_f64().max(0.001);
    let delta = app.progress.saturating_sub(app.last_progress);
    let hps = (delta as f64 / dt) as u64;
    app.hps_history.push_back(hps);
    while app.hps_history.len() > 60 {
        app.hps_history.pop_front();
    }
    app.last_progress = app.progress;
    app.last_tick = now;
}

fn render_params(frame: &mut Frame, area: Rect, app: &App) {
    let orange = Style::default().fg(ORANGE);

    let mut lines: Vec<Line> = Vec::new();

    if app.phase == Phase::Configuring {
        let file_line = if app.focused == Field::File {
            Line::from(Span::styled(format!("> file: {}", app.file), orange))
        } else {
            Line::from(format!("  file: {}", app.file))
        };
        let word_line = if app.focused == Field::Wordlist {
            Line::from(Span::styled(
                format!("> wordlist: {}", app.wordlist),
                orange,
            ))
        } else {
            Line::from(format!("  wordlist: {}", app.wordlist))
        };
        let hash_line = if app.focused == Field::HashType {
            Line::from(Span::styled(
                format!("> hash: {}", HASH_TYPES[app.hash_idx]),
                orange,
            ))
        } else {
            Line::from(format!("  hash: {}", HASH_TYPES[app.hash_idx]))
        };
        let rules_txt = format!("rules: {}", if app.rules { "[x]" } else { "[ ]" });
        let rules_line = if app.focused == Field::Rules {
            Line::from(Span::styled(format!("> {}", rules_txt), orange))
        } else {
            Line::from(format!("  {}", rules_txt))
        };
        let cpu_txt = format!(
            "cpu:   {}",
            if app.cpu { "[x] force CPU" } else { "[ ] GPU" }
        );
        let cpu_line = if app.focused == Field::Cpu {
            Line::from(Span::styled(format!("> {}", cpu_txt), orange))
        } else {
            Line::from(format!("  {}", cpu_txt))
        };
        lines.push(file_line);
        lines.push(word_line);
        lines.push(hash_line);
        lines.push(rules_line);
        lines.push(cpu_line);
        lines.push(Line::from(""));

        let active: Option<&String> = match app.focused {
            Field::File => Some(&app.file),
            Field::Wordlist => Some(&app.wordlist),
            Field::HashType | Field::Rules | Field::Cpu => None,
        };
        let suggestions = match active {
            Some(s) if !s.is_empty() => list_path_matches(s),
            _ => Vec::new(),
        };
        for s in &suggestions {
            lines.push(Line::from(format!("  · {}", s)));
        }
        if let Some(err) = &app.error {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("! {}", err),
                Style::default().fg(Color::Red),
            )));
        }
    } else {
        lines.push(Line::from(format!("  file:     {}", app.file)));
        lines.push(Line::from(format!("  wordlist: {}", app.wordlist)));
        lines.push(Line::from(format!("  hash:     {}", app.resolved_hash)));
        lines.push(Line::from(format!(
            "  rules:    {}",
            if app.rules { "[x]" } else { "[ ]" }
        )));
        lines.push(Line::from(format!(
            "  cpu:      {}",
            if app.cpu { "[x] force CPU" } else { "[ ] GPU" }
        )));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(panel_block("params"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_perf(frame: &mut Frame, area: Rect, app: &App) {
    let block = panel_block("rendimiento");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(2)])
        .split(inner);

    let (lines, percent) = match app.phase {
        Phase::Configuring => (
            vec![
                Line::from(""),
                Line::from("  Hashes/s:  --"),
                Line::from("  Tested:    --"),
                Line::from("  ETA:       --"),
                Line::from("  Cracked:   --"),
            ],
            0u16,
        ),
        Phase::Running | Phase::Done => {
            let hps = app.hps_history.back().copied().unwrap_or(0);
            let eta = if hps > 0 && app.total > app.progress {
                let secs = (app.total - app.progress) / hps.max(1);
                format!("{}s", secs)
            } else if app.phase == Phase::Done {
                "0s".to_string()
            } else {
                "--".to_string()
            };
            let pct = if app.total > 0 {
                ((app.progress * 100) / app.total).min(100) as u16
            } else {
                0
            };
            let cracked_count = app.final_found.unwrap_or(app.cracked_lines.len());
            (
                vec![
                    Line::from(""),
                    Line::from(format!("  Hashes/s:  {}", fmt_hps(hps))),
                    Line::from(format!("  Tested:    {}/{}", app.progress, app.total)),
                    Line::from(format!("  ETA:       {}", eta)),
                    Line::from(format!("  Cracked:   {}", cracked_count)),
                    Line::from(""),
                    Line::from(Span::styled(
                        match app.phase {
                            Phase::Running => "  [running]",
                            Phase::Done => "  [done]",
                            _ => "",
                        },
                        Style::default().fg(ORANGE),
                    )),
                ],
                pct,
            )
        }
    };

    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        chunks[0],
    );

    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(ORANGE))
        .percent(percent)
        .label(format!("{}%", percent));
    frame.render_widget(gauge, chunks[1]);
}

fn fmt_hps(hps: u64) -> String {
    if hps >= 1_000_000 {
        format!("{:.2} MH/s", hps as f64 / 1_000_000.0)
    } else if hps >= 1_000 {
        format!("{:.2} KH/s", hps as f64 / 1_000.0)
    } else {
        format!("{} H/s", hps)
    }
}

fn render_banner(frame: &mut Frame, area: Rect) {
    let orange = Style::default().fg(ORANGE);
    let mut lines: Vec<Line> = BANNER
        .lines()
        .map(|l| Line::from(Span::styled(l.to_string(), orange)))
        .collect();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "                                    by erikgavs",
        orange,
    )));
    lines.push(Line::from(""));
    for l in CRAB.lines() {
        lines.push(Line::from(Span::styled(l.to_string(), orange)));
    }
    frame.render_widget(
        Paragraph::new(lines).block(panel_block("brutecraber")),
        area,
    );
}

fn parse_cracked(line: &str) -> Option<(String, String)> {
    let stripped = strip_ansi(line);
    let (left, right) = stripped.split_once(" -> ")?;
    let hex = left.split_whitespace().last()?.to_string();
    Some((hex, right.trim().to_string()))
}

fn render_cracking(frame: &mut Frame, area: Rect, app: &App) {
    let lines: Vec<Line> = match app.phase {
        Phase::Configuring => vec![
            Line::from(""),
            Line::from("  esperando inicio..."),
            Line::from("  (Enter para arrancar)"),
        ],
        Phase::Running | Phase::Done => {
            if app.cracked_lines.is_empty() {
                vec![
                    Line::from(""),
                    Line::from("  ningún hash crackeado todavía"),
                ]
            } else {
                let max = area.height.saturating_sub(2) as usize;
                let start = app.cracked_lines.len().saturating_sub(max);
                app.cracked_lines[start..]
                    .iter()
                    .map(|l| match parse_cracked(l) {
                        Some((hash, word)) => Line::from(format!("{} -> {}", hash, word)),
                        None => Line::from(strip_ansi(l)),
                    })
                    .collect()
            }
        }
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel_block("cracking en vivo"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            while let Some(&n) = chars.peek() {
                chars.next();
                if n.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn render_graph(frame: &mut Frame, area: Rect, app: &App) {
    let data: Vec<u64> = if app.hps_history.is_empty() {
        vec![0; 8]
    } else {
        app.hps_history.iter().copied().collect()
    };
    let current = app.hps_history.back().copied().unwrap_or(0);
    let title = format!("velocidad — {}", fmt_hps(current));
    let spark = Sparkline::default()
        .block(panel_block(&title))
        .data(&data)
        .style(Style::default().fg(ORANGE));
    frame.render_widget(spark, area);
}

fn render(frame: &mut Frame, app: &App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(frame.area());

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(60),
        ])
        .split(outer[0]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(outer[1]);

    render_params(frame, top[0], app);
    render_perf(frame, top[1], app);
    render_banner(frame, top[2]);
    render_cracking(frame, bottom[0], app);
    render_graph(frame, bottom[1], app);
}

pub fn run() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);

    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    loop {
        drain_events(&mut app);
        if app.phase == Phase::Running {
            tick_hps(&mut app);
        }

        terminal.draw(|frame| render(frame, &app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match app.phase {
                    Phase::Configuring => handle_key_configuring(&mut app, key.code),
                    Phase::Running => {
                        if key.code == KeyCode::Esc {
                            app.cancel.store(true, Ordering::Relaxed);
                        }
                    }
                    Phase::Done => {
                        if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                            break;
                        }
                    }
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

fn handle_key_configuring(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.phase = Phase::Done;
            app.final_found = Some(0);
        }
        KeyCode::Enter => {
            try_start_cracking(app);
        }
        KeyCode::Down => {
            app.focused = match app.focused {
                Field::File => Field::Wordlist,
                Field::Wordlist => Field::HashType,
                Field::HashType => Field::Rules,
                Field::Rules => Field::Cpu,
                Field::Cpu => Field::File,
            };
        }
        KeyCode::Up => {
            app.focused = match app.focused {
                Field::File => Field::Cpu,
                Field::Wordlist => Field::File,
                Field::HashType => Field::Wordlist,
                Field::Rules => Field::HashType,
                Field::Cpu => Field::Rules,
            };
        }
        KeyCode::Tab => match app.focused {
            Field::File => {
                if let Some(c) = autocomplete_path(&app.file) {
                    app.file = c;
                }
            }
            Field::Wordlist => {
                if let Some(c) = autocomplete_path(&app.wordlist) {
                    app.wordlist = c;
                }
            }
            Field::HashType => {
                app.hash_idx = (app.hash_idx + 1) % HASH_TYPES.len();
            }
            Field::Rules => app.rules = !app.rules,
            Field::Cpu => app.cpu = !app.cpu,
        },
        KeyCode::Char(c) => match app.focused {
            Field::File => app.file.push(c),
            Field::Wordlist => app.wordlist.push(c),
            Field::HashType => {}
            Field::Rules => {
                if c == ' ' {
                    app.rules = !app.rules;
                }
            }
            Field::Cpu => {
                if c == ' ' {
                    app.cpu = !app.cpu;
                }
            }
        },
        KeyCode::Left => {
            if app.focused == Field::HashType {
                app.hash_idx = if app.hash_idx == 0 {
                    HASH_TYPES.len() - 1
                } else {
                    app.hash_idx - 1
                };
            }
        }
        KeyCode::Backspace => match app.focused {
            Field::File => {
                app.file.pop();
            }
            Field::Wordlist => {
                app.wordlist.pop();
            }
            Field::HashType | Field::Rules | Field::Cpu => {}
        },
        _ => {}
    }
}
