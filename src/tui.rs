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

struct App {
    file: String,
    wordlist: String,
    on_wordlist: bool,
}

impl App {
    fn new() -> Self {
        Self {
            file: String::new(),
            wordlist: String::new(),
            on_wordlist: false,
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
            let file_line = if !app.on_wordlist {
                Line::from(Span::styled(format!("> file: {}", app.file), orange))
            } else {
                Line::from(format!("  file: {}", app.file))
            };

            let word_line = if app.on_wordlist {
                Line::from(Span::styled(
                    format!("> wordlist: {}", app.wordlist),
                    orange,
                ))
            } else {
                Line::from(format!("  wordlist: {}", app.wordlist))
            };

            let active = if app.on_wordlist {
                &app.wordlist
            } else {
                &app.file
            };
            let suggestions = if active.is_empty() {
                Vec::new()
            } else {
                list_path_matches(active)
            };

            let mut lines = vec![file_line, word_line, Line::from("")];
            for s in &suggestions {
                lines.push(Line::from(format!("    · {}", s)));
            }

            frame.render_widget(Paragraph::new(lines), area);
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Esc => break,
                    KeyCode::Tab => app.on_wordlist = !app.on_wordlist,
                    KeyCode::Char(c) => {
                        if app.on_wordlist {
                            app.wordlist.push(c);
                        } else {
                            app.file.push(c);
                        }
                    }
                    KeyCode::Right => {
                        let target = if app.on_wordlist {
                            &mut app.wordlist
                        } else {
                            &mut app.file
                        };
                        if let Some(completed) = autocomplete_path(target) {
                            *target = completed
                        }
                    }
                    KeyCode::Backspace => {
                        if app.on_wordlist {
                            app.wordlist.pop();
                        } else {
                            app.file.pop();
                        }
                    }
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
