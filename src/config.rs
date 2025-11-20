use serde::Deserialize;
use std::fs;

/// Structura pentru configurația SMTP
#[derive(Deserialize, Clone)]
pub struct SmtpConfig {
    pub enabled: bool,
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: Vec<String>,
    // Adăugăm câmpul pentru subiect
    pub subject: String,
}

/// Structura care mapează direct fișierul `config.toml`.
#[derive(Deserialize, Clone)]
pub struct Config {
    pub bind_address: String,
    pub fast_scan_threshold: usize,
    pub fast_time_window_secs: u64,
    pub slow_scan_threshold: usize,
    pub slow_time_window_secs: u64,
    pub smtp: SmtpConfig,
}

/// Încarcă configurația din fișierul `config.toml` din rădăcina proiectului.
pub fn load() -> Result<Config, Box<dyn std::error::Error>> {
    let config_path = "config.toml";
    let config_content = fs::read_to_string(config_path)?;
    let config: Config = toml::from_str(&config_content)?;
    Ok(config)
}
