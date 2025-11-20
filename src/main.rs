// Declararea modulelor pentru a le face vizibile în proiect
mod config;
mod parser;
mod detector;
mod server;
mod alerter; // Adăugăm noul modul

use server::Server;
use log::{error, info};

fn main() {
    // Inițializează logger-ul.
    env_logger::init();

    // Încarcă configurația din fișierul config.toml
    let config = match config::load() {
        Ok(cfg) => {
            info!("Configurația a fost încărcată cu succes.");
            cfg
        },
        Err(e) => {
            error!("Eroare la încărcarea fișierului de configurare 'config.toml': {}", e);
            std::process::exit(1);
        }
    };

    // Creează o nouă instanță a serverului, pasând o referință la configurație.
    match Server::new(&config) {
        Ok(mut server) => {
            // Pornește bucla principală a serverului
            if let Err(e) = server.run() {
                error!("Eroare la rularea serverului: {}", e);
            }
        }
        Err(e) => {
            error!("Eroare la pornirea serverului: {}", e);
        }
    }
}
