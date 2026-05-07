use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::widgets::{Block, Borders};
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

            let text = format!("file: {}", app.file);

            let orange = Style::default().fg(Color::Rgb(222, 74, 31));

            // if we are writing in file = orange, if not normal
            let file_line = if !app.on_wordlist {
                Line::from(Span::styled(format!("> file:    {}", app.file), orange))
            } else {
                Line::from(format!("  file:     {}", app.file))
            };

            let word_line = if app.on_wordlist {
                Line::from(Span::styled(
                    format!("> wordlist: {}", app.wordlist),
                    orange,
                ))
            } else {
                Line::from(format!("  wordlist: {}", app.wordlist))
            };

            frame.render_widget(Paragraph::new(vec![file_line, word_line]), area);
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
