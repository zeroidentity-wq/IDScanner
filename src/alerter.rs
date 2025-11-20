use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use crate::config::SmtpConfig;
use log::error;

pub struct Alerter {
    pub config: SmtpConfig,
    mailer: SmtpTransport,
}

impl Alerter {
    pub fn new(config: SmtpConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }

        let creds = Credentials::new(config.username.clone(), config.password.clone());

        let mailer = SmtpTransport::relay(&config.server)
            .unwrap()
            .credentials(creds)
            .port(config.port)
            .build();

        Some(Alerter { config, mailer })
    }

    pub fn send_alert(&self, subject: &str, body: &str) {
        // 1. Începem cu MessageBuilder
        let mut email_builder = Message::builder()
            .from(self.config.from.parse().unwrap())
            .subject(subject);

        // 2. Adăugăm toți destinatarii la builder
        for recipient in &self.config.to {
            email_builder = email_builder.to(recipient.parse().unwrap());
        }

        // 3. Finalizăm email-ul adăugând corpul
        let email = email_builder.body(String::from(body)).unwrap();

        // 4. Trimitem email-ul finalizat
        match self.mailer.send(&email) {
            Ok(_) => (),
            Err(e) => error!("Nu am putut trimite email-ul de alertă: {:?}", e),
        }
    }
}
