use crate::core::terminal::context::TerminalContext;

pub fn install() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = TerminalContext::restore();
        prev(info);
    }));
}
