use bevy_app::AppExit;
use bevy_ecs::prelude::*;
use crossterm::event::{KeyCode, KeyModifiers};

use crate::core::terminal::input::KeyEvent;

/// Ctrl-C is the unconditional escape hatch — it must work on every screen,
/// regardless of whether a key handler is mid-iteration on input that would
/// otherwise consume the keystroke (e.g. filter editing). Other "looks
/// global" keys like `q` are intentionally NOT handled here because their
/// behaviour is screen-aware (suppressed during filter editing on the
/// picker) and pushing that check into a global system creates fragile
/// ordering with screen handlers that mutate the relevant state in the same
/// tick.
pub fn global_keys(mut keys: MessageReader<KeyEvent>, mut exit: MessageWriter<AppExit>) {
    for KeyEvent(k) in keys.read() {
        if matches!(k.code, KeyCode::Char('c')) && k.modifiers.contains(KeyModifiers::CONTROL) {
            exit.write(AppExit::Success);
        }
    }
}
