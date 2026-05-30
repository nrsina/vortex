use std::io::{Stdout, stdout};

use anyhow::Result;
use bevy_ecs::prelude::Resource;
use crossterm::{
    ExecutableCommand, cursor,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

#[derive(Resource)]
pub struct TerminalContext(pub Terminal<CrosstermBackend<Stdout>>);

impl TerminalContext {
    pub fn init() -> Result<Self> {
        let mut out = stdout();
        out.execute(EnterAlternateScreen)?;
        enable_raw_mode()?;
        Ok(Self(Terminal::new(CrosstermBackend::new(out))?))
    }

    pub fn restore() -> Result<()> {
        let mut out = stdout();
        out.execute(LeaveAlternateScreen)?;
        out.execute(cursor::Show)?;
        disable_raw_mode()?;
        Ok(())
    }
}

impl Drop for TerminalContext {
    fn drop(&mut self) {
        let _ = TerminalContext::restore();
    }
}
