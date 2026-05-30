use std::time::Duration;

use bevy_ecs::prelude::*;
use crossterm::event::{self, Event, KeyEventKind};

#[derive(SystemSet, Debug, Clone, PartialEq, Eq, Hash)]
pub struct InputReady;

#[derive(Message)]
pub struct KeyEvent(pub event::KeyEvent);

#[derive(Message)]
#[allow(dead_code)]
pub struct MouseEvent(pub event::MouseEvent);

#[derive(Message)]
#[allow(dead_code)]
pub struct ResizeEvent {
    pub cols: u16,
    pub rows: u16,
}

pub fn poll_crossterm(
    mut keys: MessageWriter<KeyEvent>,
    mut mouse: MessageWriter<MouseEvent>,
    mut resize: MessageWriter<ResizeEvent>,
) -> Result {
    while event::poll(Duration::ZERO)? {
        match event::read()? {
            // Only forward press/repeat events. On Windows the console backend
            // also emits `Release` events, which would otherwise double every
            // keypress; Unix terminals never report releases. Keeping `Repeat`
            // preserves held-key autorepeat on backends that report it.
            Event::Key(k) if matches!(k.kind, KeyEventKind::Press | KeyEventKind::Repeat) => {
                keys.write(KeyEvent(k));
            }
            Event::Mouse(m) => {
                mouse.write(MouseEvent(m));
            }
            Event::Resize(c, r) => {
                resize.write(ResizeEvent { cols: c, rows: r });
            }
            _ => {}
        }
    }
    Ok(())
}

/// Clear pending key events. Wired into every `OnEnter(Screen::*)` schedule so
/// the key press that triggered a screen change isn't re-read by the next
/// screen's handler — `MessageReader` cursors are per-system and stale across
/// state transitions, e.g. pressing `b` to go from Processes → Dashboard would
/// otherwise be picked up again by `dashboard_keys` and drop the user into the
/// Picker.
pub fn drain_pending_keys(mut keys: ResMut<Messages<KeyEvent>>) {
    keys.clear();
}
