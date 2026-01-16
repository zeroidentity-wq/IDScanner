// ============================================================================
// NETWORK SCAN IDS - 100% INDEPENDENT, ZERO DISK I/O
// ============================================================================
// Acest IDS monitorizează log-uri în PARALEL cu ArcSight, fără a interveni
// în fluxul normal. Folosește exclusiv memorie (RAM) - zero disc I/O.
//
// Cargo.toml dependencies:
// [dependencies]
// serde = { version = "1.0", features = ["derive"] }
// serde_json = "1.0"
// chrono = "0.4"
// regex = "1.10"
// tokio = { version = "1", features = ["full"] }
// reqwest = { version = "0.11", features = ["json"] }
// dashmap = "5.5"
// ============================================================================

use chrono::{DateTime, Utc, Duration};
use dashmap::DashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;
use tokio::time;

// ============================================================================
// STRUCTURI DE DATE
// ============================================================================

/// Reprezentarea unei încercări de conexiune parsată din log
/// Exemplu: "SRC=192.168.1.100 DPT=22" devine un LogEntry
#[derive(Debug, Clone)]
struct LogEntry {
    /// Când s-a produs evenimentul (UTC)
    timestamp: DateTime<Utc>,
    
    /// IP-ul sursă care inițiază conexiunea
    source_ip: String,
    
    /// Portul destinație (ex: 22 pentru SSH, 80 pentru HTTP)
    dest_port: u16,
    
    /// Protocol (TCP, UDP, SSH, etc.)
    protocol: String,
    
    /// Acțiunea (DENY, DROP, FAILED_AUTH, etc.)
    action: String,
}

/// Pattern de scanare detectat pentru un IP
/// Această structură acumulează informații despre comportamentul unui IP
#[derive(Debug, Clone)]
struct ScanPattern {
    /// IP-ul care face scanarea
    source_ip: String,
    
    /// Lista porturilor unice accesate (folosim Vec pentru simplitate)
    /// În producție, ai putea folosi HashSet pentru unicitate automată
    unique_ports: Vec<u16>,
    
    /// Prima dată când am văzut acest IP
    first_seen: DateTime<Utc>,
    
    /// Ultima dată când am văzut acest IP
    last_seen: DateTime<Utc>,
    
    /// Numărul total de conexiuni (inclusiv pe aceleași porturi)
    connection_count: usize,
}

/// Eveniment în format CEF (Common Event Format) pentru ArcSight
/// CEF este formatul standard folosit de ArcSight pentru evenimente
#[derive(Debug, Serialize)]
struct ArcSightCEF {
    /// Versiunea CEF (întotdeauna 0)
    #[serde(rename = "CEFVersion")]
    cef_version: u8,
    
    /// Vendor-ul dispozitivului care generează evenimentul
    #[serde(rename = "DeviceVendor")]
    device_vendor: String,
    
    /// Produsul (IDS-ul nostru)
    #[serde(rename = "DeviceProduct")]
    device_product: String,
    
    /// Versiunea produsului
    #[serde(rename = "DeviceVersion")]
    device_version: String,
    
    /// ID unic pentru tipul de semnătură (ex: PORT_SCAN)
    #[serde(rename = "SignatureID")]
    signature_id: String,
    
    /// Numele evenimentului (ex: "Port Scan Detected")
    #[serde(rename = "Name")]
    name: String,
    
    /// Severitatea (0-10, unde 10 = critic)
    #[serde(rename = "Severity")]
    severity: u8,
    
    /// Câmpuri extinse cu detalii (format key=value)
    #[serde(rename = "Extension")]
    extension: String,
}

/// Configurația IDS-ului
/// Toate setările pentru comportamentul IDS-ului
#[derive(Clone)]
struct IDSConfig {
    // === Praguri de detecție ===
    /// Câte porturi unice trebuie scanate pentru a fi considerat "scan"
    /// Exemplu: dacă un IP încearcă 10+ porturi diferite = scanare
    port_scan_threshold: usize,
    
    /// Fereastra de timp în secunde pentru a considera evenimente corelate
    /// Exemplu: 10 porturi în 60 secunde = scanare; în 3600 secunde = poate normal
    time_window_secs: u64,
    
    /// Câte conexiuni rapide = burst suspect (posibil DDoS)
    connection_burst_threshold: usize,
    
    // === Socket UNIX pentru comunicare cu rsyslog ===
    /// Calea către UNIX socket (NU named pipe FIFO)
    /// Folosim socket pentru comunicare bidirecțională și flow control
    unix_socket_path: String,
    
    // === Integrare ArcSight ===
    /// Endpoint-ul HTTP/HTTPS pentru ArcSight Logger sau Connector
    arcsight_endpoint: String,
    
    /// Activează/dezactivează trimiterea către ArcSight
    arcsight_enabled: bool,
    
    // === Optimizare performanță ===
    /// Procesează log-urile în batch-uri (reduce lock contention)
    batch_size: usize,
    
    /// Cât de des curățăm datele vechi din memorie (secunde)
    cleanup_interval_secs: u64,
}

impl Default for IDSConfig {
    fn default() -> Self {
        Self {
            port_scan_threshold: 10,
            time_window_secs: 60,
            connection_burst_threshold: 50,
            unix_socket_path: "/var/run/ids.sock".to_string(),
            arcsight_endpoint: "https://arcsight.example.com:8443/cef".to_string(),
            arcsight_enabled: false, // Dezactivat implicit pentru testing
            batch_size: 50,
            cleanup_interval_secs: 300, // 5 minute
        }
    }
}

// ============================================================================
// ENGINE-UL IDS
// ============================================================================

/// Motorul principal al IDS-ului
/// Conține toate datele în memorie și logica de detecție
struct RsyslogIDS {
    /// Configurația (imutabilă după creare)
    config: IDSConfig,
    
    /// Tracker-ul de scanări
    /// DashMap = HashMap thread-safe fără Mutex global
    /// Cheie: IP address (String)
    /// Valoare: Pattern de scanare (ScanPattern)
    scan_tracker: Arc<DashMap<String, ScanPattern>>,
    
    /// Statistici generale (doar în memorie)
    /// Exemplu: "total_events" -> 12345, "alerts_generated" -> 42
    statistics: Arc<DashMap<String, u64>>,
}

impl RsyslogIDS {
    /// Constructor - creează un IDS nou
    /// 
    /// # Parametri
    /// * `config` - Configurația IDS-ului
    /// 
    /// # Returnează
    /// O nouă instanță de IDS
    fn new(config: IDSConfig) -> Self {
        Self {
            config,
            // Arc = Atomic Reference Counted pointer (pointer partajat între thread-uri)
            // DashMap = HashMap optimizat pentru concurență
            scan_tracker: Arc::new(DashMap::new()),
            statistics: Arc::new(DashMap::new()),
        }
    }

    // ========================================================================
    // PARSARE LOG-URI
    // ========================================================================
    
    /// Parsează o linie de log și extrage informațiile relevante
    /// 
    /// Suportă multiple formate:
    /// - Cisco ASA/Firewall: "%ASA src 1.2.3.4 dst 5.6.7.8:80"
    /// - Linux iptables: "SRC=1.2.3.4 DPT=22 PROTO=TCP"
    /// - SSH: "Failed password from 1.2.3.4 port 22"
    /// 
    /// # Parametri
    /// * `line` - Linia de log ca string
    /// 
    /// # Returnează
    /// * `Some(LogEntry)` dacă parsarea a reușit
    /// * `None` dacă linia nu conține informații relevante
    fn parse_syslog_line(&self, line: &str) -> Option<LogEntry> {
        // Regex = Regular Expression (expresie regulată)
        // .ok()? convertește Result în Option și returnează None dacă e eroare
        
        // Pattern pentru Cisco ASA/Firewall
        // Caută: "src" urmat de IP, apoi ":" și port
        let asa_re = Regex::new(
            r"(%ASA|%FTD).*src\s+(\d+\.\d+\.\d+\.\d+).*dst.*?:(\d+)"
        ).ok()?;
        
        // Pattern pentru Linux iptables
        // Caută: SRC=IP ... DPT=PORT ... PROTO=protocol
        let iptables_re = Regex::new(
            r"SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+).*PROTO=(\w+)"
        ).ok()?;
        
        // Pattern pentru SSH failed login
        // Caută: "from IP port PORT"
        let ssh_re = Regex::new(
            r"Failed password.*from\s+(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)"
        ).ok()?;
        
        // Pattern generic pentru DENY/DROP
        let deny_re = Regex::new(
            r"DENY.*?(\d+\.\d+\.\d+\.\d+).*?port\s+(\d+)"
        ).ok()?;

        // Încearcă fiecare pattern până găsești unul care se potrivește
        // captures() returnează Option<Captures> - None dacă nu se potrivește
        
        if let Some(caps) = asa_re.captures(line) {
            // caps.get(0) = întregul match
            // caps.get(1) = primul grup (%ASA sau %FTD)
            // caps.get(2) = al doilea grup (IP-ul)
            // ? = returnează None dacă grupul lipsește
            return Some(LogEntry {
                timestamp: Utc::now(),
                hostname: "firewall".to_string(),
                source_ip: caps.get(2)?.as_str().to_string(),
                dest_port: caps.get(3)?.as_str().parse().ok()?, // parse() convertește str în u16
                protocol: "TCP".to_string(),
                action: "DENY".to_string(),
            });
        }
        
        if let Some(caps) = iptables_re.captures(line) {
            return Some(LogEntry {
                timestamp: Utc::now(),
                hostname: "linux-fw".to_string(),
                source_ip: caps.get(1)?.as_str().to_string(),
                dest_port: caps.get(2)?.as_str().parse().ok()?,
                protocol: caps.get(3)?.as_str().to_string(),
                action: "DROP".to_string(),
            });
        }
        
        if let Some(caps) = ssh_re.captures(line) {
            return Some(LogEntry {
                timestamp: Utc::now(),
                hostname: "ssh-server".to_string(),
                source_ip: caps.get(1)?.as_str().to_string(),
                dest_port: caps.get(2)?.as_str().parse().unwrap_or(22), // unwrap_or = valoare default
                protocol: "SSH".to_string(),
                action: "FAILED_AUTH".to_string(),
            });
        }
        
        if let Some(caps) = deny_re.captures(line) {
            return Some(LogEntry {
                timestamp: Utc::now(),
                hostname: "unknown".to_string(),
                source_ip: caps.get(1)?.as_str().to_string(),
                dest_port: caps.get(2)?.as_str().parse().ok()?,
                protocol: "TCP".to_string(),
                action: "DENY".to_string(),
            });
        }
        
        // Nicio regulă nu s-a potrivit
        None
    }

    // ========================================================================
    // DETECȚIE SCANĂRI
    // ========================================================================
    
    /// Analizează un LogEntry și detectează pattern-uri de scanare
    /// 
    /// Logica:
    /// 1. Actualizează pattern-ul pentru IP-ul sursă
    /// 2. Verifică dacă depășește pragurile de scanare
    /// 3. Generează alerte dacă detectează comportament suspect
    /// 
    /// # Parametri
    /// * `entry` - Evenimentul de log parsât
    /// 
    /// # Returnează
    /// * `Some(Vec<ArcSightCEF>)` - listă de alerte dacă s-a detectat ceva
    /// * `None` - dacă totul e normal
    fn analyze_and_detect(&self, entry: LogEntry) -> Option<Vec<ArcSightCEF>> {
        let mut alerts = Vec::new(); // Vector gol pentru alerte
        let ip = entry.source_ip.clone(); // Clone IP-ul pentru a-l folosi mai târziu
        
        // Actualizează sau creează pattern pentru acest IP
        // entry() returnează un Entry care permite atomic update sau insert
        self.scan_tracker
            .entry(ip.clone())
            .and_modify(|pattern| {
                // Cazul 1: IP-ul există deja - actualizează-l
                pattern.last_seen = entry.timestamp;
                pattern.connection_count += 1;
                
                // Adaugă portul doar dacă e nou
                if !pattern.unique_ports.contains(&entry.dest_port) {
                    pattern.unique_ports.push(entry.dest_port);
                }
            })
            .or_insert_with(|| {
                // Cazul 2: IP nou - creează pattern nou
                ScanPattern {
                    source_ip: ip.clone(),
                    unique_ports: vec![entry.dest_port], // Vector cu un singur element
                    first_seen: entry.timestamp,
                    last_seen: entry.timestamp,
                    connection_count: 1,
                }
            });

        // Acum verifică dacă pattern-ul indică scanare
        // get() returnează Option<Ref<String, ScanPattern>>
        if let Some(pattern) = self.scan_tracker.get(&ip) {
            // Calculează diferența de timp în secunde
            let time_diff = (pattern.last_seen - pattern.first_seen).num_seconds();
            
            // === DETECȚIE 1: PORT SCAN ===
            // Un IP scanează multe porturi într-o fereastră scurtă de timp
            if pattern.unique_ports.len() >= self.config.port_scan_threshold 
                && time_diff <= self.config.time_window_secs as i64 {
                
                // Calculează severitatea bazat pe numărul de porturi
                let severity = match pattern.unique_ports.len() {
                    n if n >= 100 => 10, // Scanare masivă = CRITIC
                    n if n >= 50 => 8,   // Scanare mare = HIGH
                    n if n >= 20 => 6,   // Scanare medie = MEDIUM
                    _ => 4,              // Scanare mică = LOW
                };
                
                // Creează alerta CEF
                alerts.push(self.create_cef_alert(
                    "PORT_SCAN",
                    "Horizontal Port Scan Detected",
                    severity,
                    &format!(
                        "src={} portCount={} timeWindow={}s ports={}",
                        ip,
                        pattern.unique_ports.len(),
                        time_diff,
                        // Afișează primele 20 porturi pentru a nu face mesajul prea lung
                        pattern.unique_ports.iter()
                            .take(20)
                            .map(|p| p.to_string()) // Convertește u16 în String
                            .collect::<Vec<_>>()    // Colectează într-un Vec
                            .join(",")              // Unește cu virgulă
                    ),
                ));
            }
            
            // === DETECȚIE 2: CONNECTION BURST ===
            // Multe conexiuni foarte rapide (posibil DDoS, brute force)
            if pattern.connection_count >= self.config.connection_burst_threshold
                && time_diff <= 10 { // Foarte rapid = 10 secunde
                
                alerts.push(self.create_cef_alert(
                    "CONN_BURST",
                    "Connection Burst Detected",
                    7,
                    &format!(
                        "src={} connCount={} timeWindow={}s avgRate={}/s",
                        ip, 
                        pattern.connection_count, 
                        time_diff,
                        if time_diff > 0 { pattern.connection_count as i64 / time_diff } else { 0 }
                    ),
                ));
            }
        }
        
        // Actualizează statistici
        // entry().and_modify().or_insert() = pattern comun în Rust
        self.statistics
            .entry("total_events".to_string())
            .and_modify(|count| *count += 1) // *count = dereferențiază și modifică valoarea
            .or_insert(1);
        
        // Returnează alerte dacă există, altfel None
        if !alerts.is_empty() {
            self.statistics
                .entry("alerts_generated".to_string())
                .and_modify(|c| *c += 1)
                .or_insert(1);
            
            Some(alerts)
        } else {
            None
        }
    }

    // ========================================================================
    // CREARE EVENIMENTE CEF
    // ========================================================================
    
    /// Creează un eveniment în format CEF pentru ArcSight
    /// 
    /// CEF Format: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
    /// 
    /// # Parametri
    /// * `sig_id` - ID-ul semnăturii (ex: "PORT_SCAN")
    /// * `name` - Numele evenimentului (ex: "Port Scan Detected")
    /// * `severity` - Severitatea 0-10
    /// * `extension` - Câmpuri extra în format "key=value key2=value2"
    fn create_cef_alert(&self, sig_id: &str, name: &str, severity: u8, extension: &str) -> ArcSightCEF {
        ArcSightCEF {
            cef_version: 0,
            device_vendor: "CustomIDS".to_string(),
            device_product: "RsyslogIDS".to_string(),
            device_version: "2.0".to_string(),
            signature_id: sig_id.to_string(),
            name: name.to_string(),
            severity,
            extension: extension.to_string(),
        }
    }

    // ========================================================================
    // TRIMITERE CĂTRE ARCSIGHT
    // ========================================================================
    
    /// Trimite alertă către ArcSight via HTTP/HTTPS
    /// 
    /// Folosește CEF (Common Event Format) - standard pentru SIEM-uri
    /// 
    /// # Parametri
    /// * `alert` - Alerta de trimis
    /// 
    /// # Returnează
    /// * `Ok(())` dacă trimiterea a reușit
    /// * `Err(...)` dacă a eșuat (nu oprește procesarea)
    async fn send_to_arcsight(&self, alert: &ArcSightCEF) -> Result<(), Box<dyn std::error::Error>> {
        // Verifică dacă ArcSight e activat
        if !self.config.arcsight_enabled {
            return Ok(());
        }

        // Construiește string-ul CEF conform standardului
        let cef_string = format!(
            "CEF:{}|{}|{}|{}|{}|{}|{}|{}",
            alert.cef_version,
            alert.device_vendor,
            alert.device_product,
            alert.device_version,
            alert.signature_id,
            alert.name,
            alert.severity,
            alert.extension
        );

        // Afișează alerta în consolă (pentru debugging)
        println!("\n🚨 [ALERT] {}", cef_string);

        // Creează client HTTP cu timeout
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;

        // Trimite POST request către ArcSight
        let response = client
            .post(&self.config.arcsight_endpoint)
            .header("Content-Type", "text/plain")
            .body(cef_string)
            .send()
            .await?;

        // Verifică răspunsul
        if response.status().is_success() {
            println!("✓ Alert sent to ArcSight");
        } else {
            eprintln!("✗ ArcSight error: {}", response.status());
        }

        Ok(())
    }

    // ========================================================================
    // MONITORIZARE SOCKET UNIX
    // ========================================================================
    
    /// Monitorizează UNIX socket pentru log-uri de la rsyslog
    /// 
    /// UNIX socket oferă:
    /// - Comunicare locală rapidă (fără network stack)
    /// - Flow control automat (dacă IDS-ul e lent, rsyslog așteaptă)
    /// - Izolare completă de ArcSight
    /// 
    /// # Returnează
    /// * `Ok(())` - nu se întoarce niciodată în condiții normale
    /// * `Err(...)` - doar dacă socket-ul nu poate fi deschis
    async fn monitor_unix_socket(&self) -> std::io::Result<()> {
        println!("📡 [*] Connecting to UNIX socket: {}", self.config.unix_socket_path);
        
        // Conectează-te la socket-ul creat de rsyslog
        // UnixStream = echivalentul TcpStream dar pentru UNIX sockets
        let stream = UnixStream::connect(&self.config.unix_socket_path).await?;
        
        println!("✓ Connected to rsyslog socket");
        
        // BufReader = buffer pentru citire eficientă linie cu linie
        let reader = BufReader::new(stream);
        let mut lines = reader.lines(); // Creează iterator peste linii
        
        let mut batch = Vec::new(); // Batch pentru procesare în grup
        
        // Loop infinit - citește linii până la eroare/deconectare
        while let Some(line) = lines.next_line().await? {
            // Parsează linia
            if let Some(entry) = self.parse_syslog_line(&line) {
                batch.push(entry);
                
                // Când batch-ul e plin, procesează-l
                if batch.len() >= self.config.batch_size {
                    self.process_batch(&mut batch).await;
                }
            }
            
            // Actualizează statistici de throughput
            self.statistics
                .entry("lines_processed".to_string())
                .and_modify(|c| *c += 1)
                .or_insert(1);
        }

        Ok(())
    }

    // ========================================================================
    // PROCESARE BATCH
    // ========================================================================
    
    /// Procesează un batch de log entries
    /// 
    /// Procesarea în batch-uri reduce contention pe DashMap și îmbunătățește
    /// performanța când ai volume mari de log-uri
    /// 
    /// # Parametri
    /// * `batch` - Vector de LogEntry-uri de procesat
    async fn process_batch(&self, batch: &mut Vec<LogEntry>) {
        // drain(..) mută elementele din vector și golește vectorul
        for entry in batch.drain(..) {
            // Analizează fiecare entry
            if let Some(alerts) = self.analyze_and_detect(entry) {
                // Trimite fiecare alertă către ArcSight
                for alert in alerts {
                    if let Err(e) = self.send_to_arcsight(&alert).await {
                        eprintln!("✗ Failed to send alert: {}", e);
                    }
                }
            }
        }
    }

    // ========================================================================
    // CLEANUP PERIODIC
    // ========================================================================
    
    /// Task de curățare periodică a datelor vechi din memorie
    /// 
    /// Rulează într-un thread separat și șterge pattern-urile vechi
    /// pentru a preveni creșterea infinită a memoriei
    async fn cleanup_task(&self) {
        // interval() creează un timer care "bate" la intervale regulate
        let mut interval = time::interval(
            std::time::Duration::from_secs(self.config.cleanup_interval_secs)
        );
        
        loop {
            interval.tick().await; // Așteaptă următorul interval
            
            // Calculează timpul de tăiere (păstrăm doar date mai noi)
            let cutoff = Utc::now() - Duration::seconds(self.config.time_window_secs as i64 * 2);
            
            // retain() = păstrează doar elementele care trec condiția
            self.scan_tracker.retain(|_, pattern| {
                pattern.last_seen > cutoff
            });
            
            // Afișează statistici
            let total = self.statistics.get("total_events").map(|v| *v).unwrap_or(0);
            let alerts = self.statistics.get("alerts_generated").map(|v| *v).unwrap_or(0);
            
            println!("🧹 [CLEANUP] {} tracked IPs, {} events, {} alerts", 
                     self.scan_tracker.len(), total, alerts);
        }
    }

    // ========================================================================
    // STATISTICI PERIODICE
    // ========================================================================
    
    /// Task care afișează statistici la intervale regulate
    async fn stats_task(&self) {
        let mut interval = time::interval(std::time::Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            println!("\n📊 === Statistics ===");
            
            // Iterează peste toate statisticile și afișează-le
            for entry in self.statistics.iter() {
                println!("  {}: {}", entry.key(), entry.value());
            }
            
            println!("  Active IP trackers: {}", self.scan_tracker.len());
            
            // Calculează rata de evenimente/secundă
            if let Some(total) = self.statistics.get("total_events") {
                let rate = *total as f64 / 60.0; // Ultimele 60 secunde
                println!("  Event rate: {:.2} events/sec", rate);
            }
            
            println!("==================\n");
        }
    }
}

// ============================================================================
// MAIN - PUNCTUL DE INTRARE
// ============================================================================

/// Funcția principală
/// 
/// #[tokio::main] = macro care transformă main() într-o funcție async
/// și creează runtime-ul Tokio pentru async/await
#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Banner de pornire
    println!("╔═══════════════════════════════════════╗");
    println!("║   Rsyslog IDS - 100% Independent      ║");
    println!("║   Zero Disk I/O - Pure Memory         ║");
    println!("║   ArcSight CEF Integration            ║");
    println!("╚═══════════════════════════════════════╝\n");

    // Creează configurația
    let config = IDSConfig {
        port_scan_threshold: 10,
        time_window_secs: 60,
        connection_burst_threshold: 50,
        unix_socket_path: "/var/run/ids.sock".to_string(),
        arcsight_endpoint: "https://arcsight.example.com:8443/cef".to_string(),
        arcsight_enabled: false, // Activează când ești gata
        batch_size: 50,
        cleanup_interval_secs: 300,
    };

    // Afișează configurația
    println!("⚙️  [CONFIG]");
    println!("    Port scan threshold: {} ports in {}s", 
             config.port_scan_threshold, config.time_window_secs);
    println!("    Connection burst: {} connections", config.connection_burst_threshold);
    println!("    UNIX socket: {}", config.unix_socket_path);
    println!("    ArcSight: {}", if config.arcsight_enabled { "✓ ENABLED" } else { "✗ DISABLED" });
    println!("    Batch size: {} events", config.batch_size);
    println!();

    // Creează IDS-ul și împachetează-l în Arc pentru partajare între thread-uri
    // Arc = Atomic Reference Counter - permite mai multe "proprietari" ai aceluiași obiect
    let ids = Arc::new(RsyslogIDS::new(config));

    // ========================================================================
    // SPAWN TASK-URI PARALELE
    // ========================================================================
    
    // Task 1: Cleanup periodic
    // Arc::clone() = creează o nouă referință (nu clonează datele!)
    let ids_cleanup = Arc::clone(&ids);
    tokio::spawn(async move {
        // move = mută ownership-ul lui ids_cleanup în closure
        ids_cleanup.cleanup_task().await;
    });

    // Task 2: Statistici periodice
    let ids_stats = Arc::clone(&ids);
    tokio::spawn(async move {
        ids_stats.stats_task().await;
    });

    // Task 3: Monitorizare socket (task principal)
    // Dacă socket-ul se închide, reîncearcă după 5 secunde
    println!("🚀 [START] IDS is now running...\n");
    
    loop {
        if let Err(e) = ids.monitor_unix_socket().await {
            eprintln!("✗ Socket error: {}. Retrying in 5s...", e);
            time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}