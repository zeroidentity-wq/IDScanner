use anyhow::Result;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use log::{error, info, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::time;

/// Configurare pentru detectarea scan-urilor
#[derive(Debug, Clone)]
struct ScanDetectionConfig {
    /// Numărul minim de porturi diferite scanate pentru a declansa alertă (scan rapid)
    rapid_scan_threshold: usize,
    /// Interval de timp pentru scan rapid (în secunde)
    rapid_scan_window: u64,
    /// Numărul minim de porturi pentru scan lent
    slow_scan_threshold: usize,
    /// Interval de timp pentru scan lent (în secunde)
    slow_scan_window: u64,
    /// Timpul de expirare pentru intrările în cache (în secunde)
    cache_expiry: u64,
}

impl Default for ScanDetectionConfig {
    fn default() -> Self {
        Self {
            rapid_scan_threshold: 10,      // 10+ porturi în interval scurt = scan rapid
            rapid_scan_window: 60,         // 1 minut
            slow_scan_threshold: 20,       // 20+ porturi în interval lung = scan lent
            slow_scan_window: 3600,        // 1 oră
            cache_expiry: 7200,            // 2 ore
        }
    }
}

/// Informații despre activitatea unui IP sursă
#[derive(Debug, Clone)]
struct SourceActivity {
    /// Lista de porturi scanate cu timestamp-uri
    port_accesses: Vec<(u16, u64)>,
    /// Ultimul timestamp de activitate
    last_seen: u64,
    /// Flag dacă a fost deja raportată o alertă recentă
    alert_sent: bool,
}

impl SourceActivity {
    fn new() -> Self {
        Self {
            port_accesses: Vec::new(),
            last_seen: current_timestamp(),
            alert_sent: false,
        }
    }

    /// Adaugă un nou port accesat
    fn add_port(&mut self, port: u16) {
        let now = current_timestamp();
        self.port_accesses.push((port, now));
        self.last_seen = now;
    }

    /// Curăță intrările vechi bazat pe fereastra de timp
    fn cleanup(&mut self, window: u64) {
        let cutoff = current_timestamp().saturating_sub(window);
        self.port_accesses.retain(|(_, timestamp)| *timestamp > cutoff);
    }

    /// Numără porturile unice într-o anumită fereastră de timp
    fn unique_ports_in_window(&self, window: u64) -> usize {
        let cutoff = current_timestamp().saturating_sub(window);
        self.port_accesses
            .iter()
            .filter(|(_, timestamp)| *timestamp > cutoff)
            .map(|(port, _)| port)
            .collect::<std::collections::HashSet<_>>()
            .len()
    }
}

/// Eveniment CEF parsat
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CefEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dest_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dest_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    timestamp: String,
    raw: String,
}

/// Alertă de scan detectat
#[derive(Debug, Serialize)]
struct ScanAlert {
    alert_type: String,
    source_ip: String,
    unique_ports_scanned: usize,
    time_window_seconds: u64,
    detection_time: String,
    severity: String,
    message: String,
}

impl ScanAlert {
    fn new(
        alert_type: String,
        source_ip: String,
        unique_ports: usize,
        window: u64,
    ) -> Self {
        let severity = if alert_type == "RAPID_SCAN" {
            "HIGH"
        } else {
            "MEDIUM"
        };

        let message = format!(
            "Scan de rețea {} detectat: IP {} a accesat {} porturi unice în ultimele {} secunde",
            alert_type, source_ip, unique_ports, window
        );

        Self {
            alert_type,
            source_ip,
            unique_ports_scanned: unique_ports,
            time_window_seconds: window,
            detection_time: Utc::now().to_rfc3339(),
            severity: severity.to_string(),
            message,
        }
    }

    /// Trimite alerta către ArcSight SIEM (format CEF)
    fn to_cef(&self) -> String {
        format!(
            "CEF:0|CustomIDS|NetworkScanner|1.0|{}|{}|{}|src={} msg={} cnt={}",
            self.alert_type,
            self.message,
            self.severity,
            self.source_ip,
            self.message.replace('|', "\\|"),
            self.unique_ports_scanned
        )
    }
}

/// Parser pentru formate CEF și Raw Syslog
struct LogParser {
    cef_regex: Regex,
}

impl LogParser {
    fn new() -> Result<Self> {
        // Regex pentru parsing CEF
        let cef_regex = Regex::new(
            r"CEF:\d+\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|(.*)"
        )?;
        
        Ok(Self { cef_regex })
    }

    /// Parsează un log CEF sau Raw Syslog
    fn parse(&self, log_line: &str) -> Option<CefEvent> {
        // Încearcă să parseze ca CEF
        if let Some(cef_event) = self.parse_cef(log_line) {
            return Some(cef_event);
        }

        // Fallback: încearcă să parseze ca Raw Syslog
        self.parse_raw_syslog(log_line)
    }

    /// Parsează format CEF
    fn parse_cef(&self, log_line: &str) -> Option<CefEvent> {
        if !log_line.starts_with("CEF:") {
            return None;
        }

        let caps = self.cef_regex.captures(log_line)?;
        let extension = caps.get(1)?.as_str();

        let mut event = CefEvent {
            source_ip: None,
            dest_ip: None,
            dest_port: None,
            action: None,
            protocol: None,
            timestamp: Utc::now().to_rfc3339(),
            raw: log_line.to_string(),
        };

        // Parsează extension (key=value pairs)
        for pair in extension.split_whitespace() {
            if let Some((key, value)) = pair.split_once('=') {
                match key {
                    "src" => event.source_ip = Some(value.to_string()),
                    "dst" => event.dest_ip = Some(value.to_string()),
                    "dpt" => event.dest_port = value.parse().ok(),
                    "act" => event.action = Some(value.to_string()),
                    "proto" => event.protocol = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        Some(event)
    }

    /// Parsează Raw Syslog (format simplificat)
    fn parse_raw_syslog(&self, log_line: &str) -> Option<CefEvent> {
        // Exemplu simplificat: caută pattern-uri comune în syslog
        // Format așteptat: "... src=X.X.X.X dst=Y.Y.Y.Y dport=ZZZZ action=DENY ..."
        
        let src_regex = Regex::new(r"(?:src=|source=|SRC=)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").ok()?;
        let dst_regex = Regex::new(r"(?:dst=|dest=|destination=|DST=)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").ok()?;
        let dport_regex = Regex::new(r"(?:dport=|dpt=|DPT=)(\d+)").ok()?;
        let action_regex = Regex::new(r"(?:action=|ACT=|act=)(\w+)").ok()?;

        let source_ip = src_regex.captures(log_line)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        let dest_ip = dst_regex.captures(log_line)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        let dest_port = dport_regex.captures(log_line)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse().ok());

        let action = action_regex.captures(log_line)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        // Necesită cel puțin source IP și destination port pentru detectare
        if source_ip.is_some() && dest_port.is_some() {
            Some(CefEvent {
                source_ip,
                dest_ip,
                dest_port,
                action,
                protocol: None,
                timestamp: Utc::now().to_rfc3339(),
                raw: log_line.to_string(),
            })
        } else {
            None
        }
    }
}

/// Detector de scan-uri de rețea
struct ScanDetector {
    config: ScanDetectionConfig,
    activity_map: Arc<DashMap<String, SourceActivity>>,
    parser: LogParser,
}

impl ScanDetector {
    fn new(config: ScanDetectionConfig) -> Result<Self> {
        Ok(Self {
            config,
            activity_map: Arc::new(DashMap::new()),
            parser: LogParser::new()?,
        })
    }

    /// Procesează un eveniment de log
    async fn process_event(&self, log_line: &str) -> Option<ScanAlert> {
        let event = self.parser.parse(log_line)?;

        // Ignoră evenimente fără source IP sau destination port
        let source_ip = event.source_ip.as_ref()?;
        let dest_port = event.dest_port?;

        // Opțional: filtrare după action (doar DENY/BLOCK)
        // Decomentează dacă vrei să analizezi doar trafic blocat
        // if let Some(action) = &event.action {
        //     if !action.eq_ignore_ascii_case("deny") && !action.eq_ignore_ascii_case("block") {
        //         return None;
        //     }
        // }

        // Actualizează activitatea sursei
        let mut activity = self.activity_map
            .entry(source_ip.clone())
            .or_insert_with(SourceActivity::new);

        activity.add_port(dest_port);
        
        // Cleanup intrări vechi
        activity.cleanup(self.config.slow_scan_window);

        // Verifică scan rapid
        let rapid_ports = activity.unique_ports_in_window(self.config.rapid_scan_window);
        if rapid_ports >= self.config.rapid_scan_threshold && !activity.alert_sent {
            activity.alert_sent = true;
            return Some(ScanAlert::new(
                "RAPID_SCAN".to_string(),
                source_ip.clone(),
                rapid_ports,
                self.config.rapid_scan_window,
            ));
        }

        // Verifică scan lent
        let slow_ports = activity.unique_ports_in_window(self.config.slow_scan_window);
        if slow_ports >= self.config.slow_scan_threshold && !activity.alert_sent {
            activity.alert_sent = true;
            return Some(ScanAlert::new(
                "SLOW_SCAN".to_string(),
                source_ip.clone(),
                slow_ports,
                self.config.slow_scan_window,
            ));
        }

        None
    }

    /// Task de curățare periodică a cache-ului
    async fn cleanup_task(activity_map: Arc<DashMap<String, SourceActivity>>, cache_expiry: u64) {
        let mut interval = time::interval(Duration::from_secs(300)); // Verifică la fiecare 5 minute
        
        loop {
            interval.tick().await;
            
            let cutoff = current_timestamp().saturating_sub(cache_expiry);
            activity_map.retain(|_, activity| activity.last_seen > cutoff);
            
            info!("Cleanup: {} IP-uri active în cache", activity_map.len());
        }
    }
}

/// Obține timestamp-ul curent în secunde
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Trimite alertă către ArcSight SIEM
async fn send_alert_to_siem(alert: &ScanAlert, siem_addr: &str) -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let cef_message = alert.to_cef();
    
    socket.send_to(cef_message.as_bytes(), siem_addr).await?;
    
    info!("Alertă trimisă către SIEM ({}): {}", siem_addr, cef_message);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Inițializare logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    info!("🚀 Starting Intrusion Detection Scanner");

    // Configurare
    let listen_addr = "0.0.0.0:5555"; // Portul pe care ascultă programul
    let siem_addr = "127.0.0.1:514"; // Adresa ArcSight SIEM pentru alerte
    
    let config = ScanDetectionConfig::default();
    info!("Configurare: {:?}", config);

    // Inițializare detector
    let detector = Arc::new(ScanDetector::new(config.clone())?);

    // Pornire task de cleanup
    let cleanup_map = detector.activity_map.clone();
    tokio::spawn(async move {
        ScanDetector::cleanup_task(cleanup_map, config.cache_expiry).await;
    });

    // Bind UDP socket
    let socket = UdpSocket::bind(listen_addr).await?;
    info!("📡 Listening on UDP {}", listen_addr);
    info!("🎯 Alerte vor fi trimise către SIEM: {}", siem_addr);

    let mut buf = vec![0u8; 65535];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, _addr)) => {
                let log_line = String::from_utf8_lossy(&buf[..len]);
                
                // Procesează evenimentul
                let detector_clone = detector.clone();
                let log_line_owned = log_line.to_string();
                let siem_addr_owned = siem_addr.to_string();
                
                tokio::spawn(async move {
                    if let Some(alert) = detector_clone.process_event(&log_line_owned).await {
                        warn!("⚠️  SCAN DETECTAT: {}", alert.message);
                        
                        // Trimite alertă către SIEM
                        if let Err(e) = send_alert_to_siem(&alert, &siem_addr_owned).await {
                            error!("Eroare la trimiterea alertei: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                error!("Eroare la primirea pachetului UDP: {}", e);
            }
        }
    }
}
