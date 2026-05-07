use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Sparkline};
use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

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

const SPARK_DUMMY: &[u64] = &[2, 5, 3, 8, 6, 12, 9, 14, 11, 18, 15, 22];

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

struct App {
    file: String,
    wordlist: String,
    hash_idx: usize,
    rules: bool,
    cpu: bool,
    focused: Field,
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

fn render_params(frame: &mut Frame, area: Rect, app: &App) {
    let orange = Style::default().fg(ORANGE);

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

    let active: Option<&String> = match app.focused {
        Field::File => Some(&app.file),
        Field::Wordlist => Some(&app.wordlist),
        Field::HashType | Field::Rules | Field::Cpu => None,
    };
    let suggestions = match active {
        Some(s) if !s.is_empty() => list_path_matches(s),
        _ => Vec::new(),
    };

    let mut lines = vec![
        file_line,
        word_line,
        hash_line,
        rules_line,
        cpu_line,
        Line::from(""),
    ];
    for s in &suggestions {
        lines.push(Line::from(format!("  · {}", s)));
    }

    frame.render_widget(Paragraph::new(lines).block(panel_block("params")), area);
}

fn render_perf(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(""),
        Line::from("  Hashes/s:  --"),
        Line::from("  Tested:    --"),
        Line::from("  ETA:       --"),
    ];
    frame.render_widget(Paragraph::new(lines).block(panel_block("rendimiento")), area);
}

fn render_banner(frame: &mut Frame, area: Rect) {
    let orange = Style::default().fg(ORANGE);
    let mut lines: Vec<Line> = BANNER
        .lines()
        .map(|l| Line::from(Span::styled(l.to_string(), orange)))
        .collect();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("                                    by erikgavs", orange)));
    lines.push(Line::from(""));
    for l in CRAB.lines() {
        lines.push(Line::from(Span::styled(l.to_string(), orange)));
    }
    frame.render_widget(Paragraph::new(lines).block(panel_block("brutecraber")), area);
}

fn render_cracking(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(""),
        Line::from("  esperando inicio..."),
        Line::from("  (Enter para arrancar)"),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(panel_block("cracking en vivo")),
        area,
    );
}

fn render_graph(frame: &mut Frame, area: Rect) {
    let spark = Sparkline::default()
        .block(panel_block("gráfico"))
        .data(SPARK_DUMMY)
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
    render_perf(frame, top[1]);
    render_banner(frame, top[2]);
    render_cracking(frame, bottom[0]);
    render_graph(frame, bottom[1]);
}

pub fn run() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);

    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    loop {
        terminal.draw(|frame| render(frame, &app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Esc => break,
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
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
