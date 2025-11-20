use std::net::UdpSocket;
use crate::config::Config;
use crate::detector::Detector;
use crate::parser;
use crate::alerter::Alerter;
use log::{info, warn};

pub struct Server<'a> {
    socket: UdpSocket,
    detector: Detector<'a>,
    alerter: Option<Alerter>,
}

impl<'a> Server<'a> {
    pub fn new(config: &'a Config) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(&config.bind_address)?;
        info!("Detectorul de scanări de porturi ascultă pe {}", &config.bind_address);

        // Inițializează alerter-ul doar dacă este activat în configurație
        let alerter = Alerter::new(config.smtp.clone());
        if alerter.is_some() {
            info!("Alertele prin email sunt activate.");
        } else {
            info!("Alertele prin email sunt dezactivate.");
        }

        Ok(Server {
            socket,
            detector: Detector::new(config),
            alerter,
        })
    }

    pub fn run(&mut self) -> std::io::Result<()> {
        let mut buf = vec![0; 65535];
        loop {
            let (number_of_bytes, src_addr) = self.socket.recv_from(&mut buf)?;
            match std::str::from_utf8(&buf[..number_of_bytes]) {
                Ok(message) => {
                    // --- Funcționalitate nouă: Test forțat de e-mail ---
                    if message.trim() == "FORCE_EMAIL_TEST" {
                        info!("Am primit comanda de testare forțată a e-mailului de la {}", src_addr);
                        if let Some(alerter) = &self.alerter {
                            let subject = "Email de Test de la PDScanner";
                            let body = "Acesta este un e-mail de test generat automat pentru a verifica configurația SMTP.";
                            alerter.send_alert(subject, body);
                        } else {
                            warn!("Testul de e-mail nu a putut fi efectuat: alertele prin e-mail sunt dezactivate în configurație.");
                        }
                        continue; // Treci la următoarea iterație
                    }

                    let log_data = parser::parse_fortigate_log(message);
                    if let Some(alert_message) = self.detector.process_log(&log_data) {
                        // Loghează alerta în consolă/syslog
                        warn!("{}", alert_message);

                        // Trimite alerta prin email, dacă alerter-ul este activat
                        if let Some(alerter) = &self.alerter {
                            // Folosim subiectul din configurație
                            alerter.send_alert(&alerter.config.subject, &alert_message);
                        }
                    }
                }
                Err(e) => {
                    warn!("Am primit un pachet invalid de la {}: {}", src_addr, e);
                }
            }
        }
    }
}
