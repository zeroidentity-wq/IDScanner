use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use crate::config::Config;

// Structura pentru a stoca starea fiecărui IP sursă
struct IpState {
    fast_scan_ports: HashSet<u16>,
    slow_scan_ports: HashSet<u16>,
    last_fast_activity: Instant,
    last_slow_activity: Instant,
}

impl IpState {
    fn new() -> Self {
        IpState {
            fast_scan_ports: HashSet::new(),
            slow_scan_ports: HashSet::new(),
            last_fast_activity: Instant::now(),
            last_slow_activity: Instant::now(),
        }
    }
}

// Structura principală a detectorului, care gestionează starea tuturor IP-urilor
pub struct Detector<'a> {
    ip_tracker: HashMap<String, IpState>,
    config: &'a Config,
}

impl<'a> Detector<'a> {
    pub fn new(config: &'a Config) -> Self {
        Detector {
            ip_tracker: HashMap::new(),
            config,
        }
    }

    /// Procesează un log parsat și returnează un mesaj de alertă dacă o scanare este detectată.
    pub fn process_log(&mut self, log: &HashMap<&str, &str>) -> Option<String> {
        if let (Some(action), Some(src_ip), Some(dst_port_str)) =
            (log.get("action").map(|v| *v), log.get("srcip").map(|v| *v), log.get("dstport").map(|v| *v))
        {
            if action == "deny" {
                if let Ok(dst_port) = dst_port_str.parse::<u16>() {
                    let now = Instant::now();
                    let state = self.ip_tracker.entry(src_ip.to_string()).or_insert_with(IpState::new);

                    // --- Logica pentru Scanări Rapide ---
                    if now.duration_since(state.last_fast_activity) > Duration::from_secs(self.config.fast_time_window_secs) {
                        state.fast_scan_ports.clear();
                    }
                    state.last_fast_activity = now;
                    let is_new_fast_port = state.fast_scan_ports.insert(dst_port);

                    // --- Logica pentru Scanări Lente ---
                    if now.duration_since(state.last_slow_activity) > Duration::from_secs(self.config.slow_time_window_secs) {
                        state.slow_scan_ports.clear();
                    }
                    state.last_slow_activity = now;
                    state.slow_scan_ports.insert(dst_port);

                    // --- Verificare și Alertare ---
                    if is_new_fast_port && state.fast_scan_ports.len() > self.config.fast_scan_threshold {
                        let scan_type = get_scan_type(log);
                        let alert = format!(
                            "!!! ALERTĂ [SCANARE RAPIDĂ]: Tip: {}, Sursă: {}, Porturi: {} în {} secunde !!!",
                            scan_type, src_ip, state.fast_scan_ports.len(), self.config.fast_time_window_secs
                        );
                        state.fast_scan_ports.clear();
                        return Some(alert);
                    } else if state.slow_scan_ports.len() > self.config.slow_scan_threshold {
                        let alert = format!(
                            "!!! ALERTĂ [SCANARE LENTĂ]: Sursă: {}, Porturi: {} în ultimele 24 de ore !!!",
                            src_ip, state.slow_scan_ports.len()
                        );
                        state.slow_scan_ports.clear();
                        return Some(alert);
                    }
                }
            }
        }
        None
    }
}

// Determină tipul de scanare pe baza detaliilor din log
fn get_scan_type(log: &HashMap<&str, &str>) -> String {
    let proto = log.get("proto").map(|v| *v);
    let tcpflags = log.get("tcpflags").map(|v| *v);

    match proto {
        Some("6") => { // TCP
            match tcpflags {
                Some("FIN") => "Stealth FIN Scan".to_string(),
                Some("FIN-PSH-URG") => "Stealth XMAS Scan".to_string(),
                Some("") | None => "TCP SYN Scan".to_string(),
                _ => format!("TCP Scan (flags: {})", tcpflags.unwrap_or("N/A")),
            }
        },
        Some("17") => "UDP Scan".to_string(),
        Some("1") => "ICMP Activity".to_string(),
        _ => "Scanare Necunoscută".to_string(),
    }
}
