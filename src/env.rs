use std::env;

use terminfo::Database;

use crate::config::Config;

/// Setup environment variables
pub fn setup(config: &Config) {
    // Default to 'alacritty' terminfo if it is available, otherwise
    // default to 'xterm-256color'. May be overridden by user's config
    // below.
    env::set_var(
        "TERM",
        if Database::from_name("alacritty").is_ok() {
            "alacritty"
        } else {
            "xterm-256color"
        },
    );

    // Advertise 24-bit color support
    env::set_var("COLORTERM", "truecolor");

    // Set env vars from config
    for (key, value) in config.env().iter() {
        env::set_var(key, value);
    }
}
