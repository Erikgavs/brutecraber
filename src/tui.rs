use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

const HASH_TYPES: &[&str] = &[
    "auto", "md5", "sha1", "sha256", "sha512", "sha3-256", "sha3-512", "bcrypt", "ntlm", "argon2",
    "scrypt", "pbkdf2",
];

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
        .take(3)
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

pub fn run() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);

    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    loop {
        terminal.draw(|frame| {
            let area = frame.area();

            let orange = Style::default().fg(Color::Rgb(222, 74, 31));

            // if we are writing in file = orange, if not normal
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
                lines.push(Line::from(format!("    · {}", s)));
            }

            frame.render_widget(Paragraph::new(lines), area);
        })?;

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
