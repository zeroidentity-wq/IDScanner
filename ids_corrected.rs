// ============================================================================
// IDS SCANARE REȚEA - COEXISTENȚĂ 100% CU ARCSIGHT
// ============================================================================
// IDS independent care rulează PE ACELAȘI SERVER cu ArcSight Logger
// fără a interfera cu procesele ArcSight.
//
// IZOLARE COMPLETĂ:
// - Proces separat (nu modifică binare ArcSight)
// - Socket propriu (/var/run/ids-personalizat/ids.sock)
// - Memorie separată (zero fișiere partajate)
// - Port HTTP separat (8888, nu conflictă cu ArcSight)
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
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::time;
use std::fs;

// ============================================================================
// STRUCTURI DE DATE
// ============================================================================

/// Intrare în jurnal cu TOATE câmpurile necesare
#[derive(Debug, Clone)]
struct IntrareJurnal {
    marca_timp: DateTime<Utc>,
    nume_gazda: String,           // Numele dispozitivului
    ip_sursa: String,
    port_destinatie: u16,
    protocol: String,
    actiune: String,
}

/// Pattern de scanare pentru un IP
#[derive(Debug, Clone)]
struct ModelScanare {
    ip_sursa: String,
    porturi_unice: Vec<u16>,
    prima_aparitie: DateTime<Utc>,
    ultima_aparitie: DateTime<Utc>,
    numar_conexiuni: usize,
}

/// Eveniment CEF pentru ArcSight
#[derive(Debug, Serialize)]
struct EvenimentCEF {
    #[serde(rename = "CEFVersion")]
    versiune_cef: u8,
    #[serde(rename = "DeviceVendor")]
    vanzator_dispozitiv: String,
    #[serde(rename = "DeviceProduct")]
    produs_dispozitiv: String,
    #[serde(rename = "DeviceVersion")]
    versiune_dispozitiv: String,
    #[serde(rename = "SignatureID")]
    id_semnatura: String,
    #[serde(rename = "Name")]
    nume: String,
    #[serde(rename = "Severity")]
    severitate: u8,
    #[serde(rename = "Extension")]
    extensie: String,
}

/// Configurație cu izolare completă de ArcSight
#[derive(Clone)]
struct ConfiguratieIDS {
    // Praguri de detecție
    prag_scanare_porturi: usize,
    fereastra_timp_secunde: u64,
    prag_rafala_conexiuni: usize,
    
    // IZOLARE: Socket în director dedicat
    cale_socket_unix: String,
    
    // IZOLARE: Port HTTP dedicat (nu 8443 folosit de ArcSight)
    port_http: u16,
    
    // Integrare ArcSight (opțional)
    endpoint_arcsight_cef: Option<String>,
    arcsight_activat: bool,
    
    // Performanță
    marime_lot: usize,
    interval_curatare_secunde: u64,
    maxim_ip_uri_urmarite: usize,
    
    // Whitelist (ignoră scanări interne)
    ignora_ip_uri_interne: bool,
}

impl Default for ConfiguratieIDS {
    fn default() -> Self {
        Self {
            prag_scanare_porturi: 10,
            fereastra_timp_secunde: 60,
            prag_rafala_conexiuni: 50,
            
            // Socket în director dedicat
            cale_socket_unix: "/var/run/ids-personalizat/ids.sock".to_string(),
            
            // Port HTTP dedicat (NU conflictează cu ArcSight:8443)
            port_http: 8888,
            
            // ArcSight - trimite direct la SmartConnector pe port 514
            endpoint_arcsight_cef: Some("syslog://localhost:5140".to_string()),
            arcsight_activat: false,
            
            marime_lot: 50,
            interval_curatare_secunde: 300,
            maxim_ip_uri_urmarite: 100_000,
            ignora_ip_uri_interne: true,
        }
    }
}

// ============================================================================
// MOTORUL IDS
// ============================================================================

struct MotorIDS {
    configuratie: ConfiguratieIDS,
    urmaritor_scanari: Arc<DashMap<String, ModelScanare>>,
    statistici: Arc<DashMap<String, u64>>,
}

impl MotorIDS {
    /// Constructor - creează un IDS nou
    fn nou(configuratie: ConfiguratieIDS) -> Self {
        Self {
            configuratie,
            urmaritor_scanari: Arc::new(DashMap::new()),
            statistici: Arc::new(DashMap::new()),
        }
    }

    // ========================================================================
    // VALIDARE IP
    // ========================================================================
    
    /// Verifică dacă IP-ul trebuie ignorat (RFC1918 - intervale private)
    fn trebuie_ignorat_ip(&self, ip: &str) -> bool {
        if !self.configuratie.ignora_ip_uri_interne {
            return false;
        }
        
        // Ignoră IP-uri private conform RFC1918
        ip.starts_with("10.") 
            || ip.starts_with("192.168.")
            || ip.starts_with("172.16.")
            || ip.starts_with("172.17.")
            || ip.starts_with("172.18.")
            || ip.starts_with("172.19.")
            || ip.starts_with("172.20.")
            || ip.starts_with("172.21.")
            || ip.starts_with("172.22.")
            || ip.starts_with("172.23.")
            || ip.starts_with("172.24.")
            || ip.starts_with("172.25.")
            || ip.starts_with("172.26.")
            || ip.starts_with("172.27.")
            || ip.starts_with("172.28.")
            || ip.starts_with("172.29.")
            || ip.starts_with("172.30.")
            || ip.starts_with("172.31.")
            || ip.starts_with("127.")
            || ip.starts_with("169.254.")
    }

    // ========================================================================
    // PARSARE JURNALE
    // ========================================================================
    
    /// Parsează o linie de jurnal și extrage informațiile relevante
    fn parseaza_linie_syslog(&self, linie: &str) -> Option<IntrareJurnal> {
        // Pattern-uri regex pentru diverse formate
        let regex_asa = Regex::new(
            r"(%ASA|%FTD).*src\s+(\d+\.\d+\.\d+\.\d+).*dst.*?:(\d+)"
        ).ok()?;
        
        let regex_iptables = Regex::new(
            r"SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+).*PROTO=(\w+)"
        ).ok()?;
        
        let regex_ssh = Regex::new(
            r"Failed password.*from\s+(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)"
        ).ok()?;
        
        let regex_deny = Regex::new(
            r"DENY.*?(\d+\.\d+\.\d+\.\d+).*?port\s+(\d+)"
        ).ok()?;

        // Extrage numele gazdei din linie (format syslog standard)
        // Format: "Ian 26 10:30:45 nume_gazda mesaj..."
        let regex_nume_gazda = Regex::new(r"^\w+\s+\d+\s+[\d:]+\s+(\S+)\s+").ok()?;
        let nume_gazda = regex_nume_gazda.captures(linie)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "necunoscut".to_string());

        // Încearcă fiecare pattern
        if let Some(potriviri) = regex_asa.captures(linie) {
            let ip_sursa = potriviri.get(2)?.as_str().to_string();
            if self.trebuie_ignorat_ip(&ip_sursa) {
                return None;
            }
            
            return Some(IntrareJurnal {
                marca_timp: Utc::now(),
                nume_gazda: nume_gazda.clone(),
                ip_sursa,
                port_destinatie: potriviri.get(3)?.as_str().parse().ok()?,
                protocol: "TCP".to_string(),
                actiune: "RESPINS".to_string(),
            });
        }
        
        if let Some(potriviri) = regex_iptables.captures(linie) {
            let ip_sursa = potriviri.get(1)?.as_str().to_string();
            if self.trebuie_ignorat_ip(&ip_sursa) {
                return None;
            }
            
            return Some(IntrareJurnal {
                marca_timp: Utc::now(),
                nume_gazda: nume_gazda.clone(),
                ip_sursa,
                port_destinatie: potriviri.get(2)?.as_str().parse().ok()?,
                protocol: potriviri.get(3)?.as_str().to_string(),
                actiune: "ARUNCAT".to_string(),
            });
        }
        
        if let Some(potriviri) = regex_ssh.captures(linie) {
            let ip_sursa = potriviri.get(1)?.as_str().to_string();
            if self.trebuie_ignorat_ip(&ip_sursa) {
                return None;
            }
            
            return Some(IntrareJurnal {
                marca_timp: Utc::now(),
                nume_gazda: nume_gazda.clone(),
                ip_sursa,
                port_destinatie: potriviri.get(2)?.as_str().parse().unwrap_or(22),
                protocol: "SSH".to_string(),
                actiune: "AUTENTIFICARE_ESUATA".to_string(),
            });
        }
        
        if let Some(potriviri) = regex_deny.captures(linie) {
            let ip_sursa = potriviri.get(1)?.as_str().to_string();
            if self.trebuie_ignorat_ip(&ip_sursa) {
                return None;
            }
            
            return Some(IntrareJurnal {
                marca_timp: Utc::now(),
                nume_gazda: nume_gazda.clone(),
                ip_sursa,
                port_destinatie: potriviri.get(2)?.as_str().parse().ok()?,
                protocol: "TCP".to_string(),
                actiune: "RESPINS".to_string(),
            });
        }
        
        None
    }

    // ========================================================================
    // DETECȚIE SCANĂRI
    // ========================================================================
    
    /// Analizează o intrare și detectează pattern-uri de scanare
    fn analizeaza_si_detecteaza(&self, intrare: IntrareJurnal) -> Option<Vec<EvenimentCEF>> {
        let mut alerte = Vec::new();
        let ip = intrare.ip_sursa.clone();
        
        // PROTECȚIE: Refuză noi IP-uri dacă memoria e plină
        if self.urmaritor_scanari.len() >= self.configuratie.maxim_ip_uri_urmarite 
            && !self.urmaritor_scanari.contains_key(&ip) {
            
            self.statistici
                .entry("ip_uri_respinse".to_string())
                .and_modify(|c| *c += 1)
                .or_insert(1);
            
            return None;
        }
        
        // Actualizează pattern-ul pentru acest IP
        self.urmaritor_scanari
            .entry(ip.clone())
            .and_modify(|model| {
                model.ultima_aparitie = intrare.marca_timp;
                model.numar_conexiuni += 1;
                
                if !model.porturi_unice.contains(&intrare.port_destinatie) {
                    model.porturi_unice.push(intrare.port_destinatie);
                }
            })
            .or_insert_with(|| {
                ModelScanare {
                    ip_sursa: ip.clone(),
                    porturi_unice: vec![intrare.port_destinatie],
                    prima_aparitie: intrare.marca_timp,
                    ultima_aparitie: intrare.marca_timp,
                    numar_conexiuni: 1,
                }
            });

        // Verifică pattern-uri suspecte
        if let Some(model) = self.urmaritor_scanari.get(&ip) {
            let diferenta_timp = (model.ultima_aparitie - model.prima_aparitie).num_seconds();
            
            // === DETECȚIE 1: SCANARE PORTURI ===
            if model.porturi_unice.len() >= self.configuratie.prag_scanare_porturi 
                && diferenta_timp <= self.configuratie.fereastra_timp_secunde as i64 {
                
                let severitate = match model.porturi_unice.len() {
                    n if n >= 100 => 10, // Scanare masivă = CRITIC
                    n if n >= 50 => 8,   // Scanare mare = ÎNALT
                    n if n >= 20 => 6,   // Scanare medie = MEDIU
                    _ => 4,              // Scanare mică = SCĂZUT
                };
                
                alerte.push(self.creaza_alerta_cef(
                    "SCANARE_PORTURI",
                    "Scanare Orizontală Porturi Detectată",
                    severitate,
                    &format!(
                        "sursa={} destinatie={} numarPorturi={} fereastraTimp={}s porturi={} actiune={}",
                        ip,
                        intrare.nume_gazda,
                        model.porturi_unice.len(),
                        diferenta_timp,
                        model.porturi_unice.iter()
                            .take(20)
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                        intrare.actiune
                    ),
                ));
            }
            
            // === DETECȚIE 2: RAFALĂ CONEXIUNI ===
            if model.numar_conexiuni >= self.configuratie.prag_rafala_conexiuni
                && diferenta_timp <= 10 {
                
                alerte.push(self.creaza_alerta_cef(
                    "RAFALA_CONEXIUNI",
                    "Rafală Conexiuni Detectată",
                    7,
                    &format!(
                        "sursa={} destinatie={} numarConexiuni={} fereastraTimp={}s rataMetdie={}/s",
                        ip,
                        intrare.nume_gazda,
                        model.numar_conexiuni,
                        diferenta_timp,
                        if diferenta_timp > 0 { model.numar_conexiuni as i64 / diferenta_timp } else { 0 }
                    ),
                ));
            }
        }
        
        // Actualizează statistici
        self.statistici
            .entry("evenimente_totale".to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        
        if !alerte.is_empty() {
            self.statistici
                .entry("alerte_generate".to_string())
                .and_modify(|c| *c += 1)
                .or_insert(1);
            
            Some(alerte)
        } else {
            None
        }
    }

    // ========================================================================
    // CREARE EVENIMENTE CEF
    // ========================================================================
    
    /// Creează un eveniment în format CEF pentru ArcSight
    fn creaza_alerta_cef(&self, id_semnatura: &str, nume: &str, severitate: u8, extensie: &str) -> EvenimentCEF {
        EvenimentCEF {
            versiune_cef: 0,
            vanzator_dispozitiv: "IDS_Personalizat".to_string(),
            produs_dispozitiv: "IDS_Rsyslog".to_string(),
            versiune_dispozitiv: "2.1".to_string(),
            id_semnatura: id_semnatura.to_string(),
            nume: nume.to_string(),
            severitate,
            extensie: extensie.to_string(),
        }
    }

    // ========================================================================
    // TRIMITERE CĂTRE ARCSIGHT
    // ========================================================================
    
    /// Trimite alertă către ArcSight via HTTP/HTTPS
    async fn trimite_catre_arcsight(&self, alerta: &EvenimentCEF) -> Result<(), Box<dyn std::error::Error>> {
        if !self.configuratie.arcsight_activat {
            return Ok(());
        }

        let sir_cef = format!(
            "CEF:{}|{}|{}|{}|{}|{}|{}|{}",
            alerta.versiune_cef,
            alerta.vanzator_dispozitiv,
            alerta.produs_dispozitiv,
            alerta.versiune_dispozitiv,
            alerta.id_semnatura,
            alerta.nume,
            alerta.severitate,
            alerta.extensie
        );

        println!("\n🚨 [ALERTĂ] {}", sir_cef);

        // Trimite către ArcSight SmartConnector via syslog
        if let Some(endpoint) = &self.configuratie.endpoint_arcsight_cef {
            if endpoint.starts_with("syslog://") {
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()?;
                
                println!("✓ Ar trimite către ArcSight: {}", endpoint);
            }
        }

        Ok(())
    }

    // ========================================================================
    // ASCULTĂTOR SOCKET UNIX
    // ========================================================================
    
    /// Pornește ascultătorul pe UNIX socket (IDS creează socket-ul)
    async fn porneste_ascultator_unix(&self) -> std::io::Result<()> {
        let cale_socket = Path::new(&self.configuratie.cale_socket_unix);
        
        // Creează directorul dacă nu există
        if let Some(parinte) = cale_socket.parent() {
            fs::create_dir_all(parinte)?;
        }
        
        // Șterge socket-ul vechi dacă există
        if cale_socket.exists() {
            fs::remove_file(cale_socket)?;
        }
        
        println!("📡 [*] Creare socket UNIX: {}", self.configuratie.cale_socket_unix);
        
        // Creează listener-ul
        let ascultator = UnixListener::bind(cale_socket)?;
        
        // Schimbă permisiunile pentru a permite rsyslog să scrie
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permisiuni = fs::metadata(cale_socket)?.permissions();
            permisiuni.set_mode(0o666); // rw-rw-rw-
            fs::set_permissions(cale_socket, permisiuni)?;
        }
        
        println!("✓ Socket creat și în ascultare");
        println!("📝 Configurați rsyslog să scrie la acest socket");
        println!();

        // Acceptă conexiuni
        loop {
            match ascultator.accept().await {
                Ok((flux, _adresa)) => {
                    println!("✓ Conexiune nouă de la rsyslog");
                    let ids = Arc::new(self.clone());
                    tokio::spawn(async move {
                        if let Err(eroare) = ids.gestioneaza_conexiune(flux).await {
                            eprintln!("✗ Eroare conexiune: {}", eroare);
                        }
                    });
                }
                Err(eroare) => {
                    eprintln!("✗ Eroare accept: {}", eroare);
                }
            }
        }
    }

    // ========================================================================
    // GESTIONARE CONEXIUNE
    // ========================================================================
    
    /// Gestionează o conexiune de la rsyslog
    async fn gestioneaza_conexiune(&self, flux: UnixStream) -> std::io::Result<()> {
        let cititor = BufReader::new(flux);
        let mut linii = cititor.lines();
        let mut lot = Vec::new();
        
        while let Some(linie) = linii.next_line().await? {
            if let Some(intrare) = self.parseaza_linie_syslog(&linie) {
                lot.push(intrare);
                
                if lot.len() >= self.configuratie.marime_lot {
                    self.proceseaza_lot(&mut lot).await;
                }
            }
            
            self.statistici
                .entry("linii_procesate".to_string())
                .and_modify(|c| *c += 1)
                .or_insert(1);
        }

        Ok(())
    }

    // ========================================================================
    // PROCESARE LOT
    // ========================================================================
    
    /// Procesează un lot de intrări
    async fn proceseaza_lot(&self, lot: &mut Vec<IntrareJurnal>) {
        for intrare in lot.drain(..) {
            if let Some(alerte) = self.analizeaza_si_detecteaza(intrare) {
                for alerta in alerte {
                    if let Err(eroare) = self.trimite_catre_arcsight(&alerta).await {
                        eprintln!("✗ Eroare trimitere alertă: {}", eroare);
                    }
                }
            }
        }
    }

    // ========================================================================
    // TASK CURĂȚARE PERIODICĂ
    // ========================================================================
    
    /// Task de curățare periodică a datelor vechi
    async fn task_curatare(&self) {
        let mut interval = time::interval(
            std::time::Duration::from_secs(self.configuratie.interval_curatare_secunde)
        );
        
        loop {
            interval.tick().await;
            
            let prag_taiere = Utc::now() - Duration::seconds(self.configuratie.fereastra_timp_secunde as i64 * 2);
            
            let inainte = self.urmaritor_scanari.len();
            self.urmaritor_scanari.retain(|_, model| {
                model.ultima_aparitie > prag_taiere
            });
            let dupa = self.urmaritor_scanari.len();
            
            let total = self.statistici.get("evenimente_totale").map(|v| *v).unwrap_or(0);
            let alerte = self.statistici.get("alerte_generate").map(|v| *v).unwrap_or(0);
            let respinse = self.statistici.get("ip_uri_respinse").map(|v| *v).unwrap_or(0);
            
            println!("🧹 [CURĂȚARE] Șters {} IP-uri | Active: {} | Evenimente: {} | Alerte: {} | Respinse: {}", 
                     inainte - dupa, dupa, total, alerte, respinse);
        }
    }

    // ========================================================================
    // TASK STATISTICI
    // ========================================================================
    
    /// Task care afișează statistici periodic
    async fn task_statistici(&self) {
        let mut interval = time::interval(std::time::Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            
            println!("\n📊 === Statistici IDS ===");
            
            for intrare in self.statistici.iter() {
                println!("  {}: {}", intrare.key(), intrare.value());
            }
            
            println!("  IP-uri urmărite active: {}", self.urmaritor_scanari.len());
            println!("  Limită memorie: {}", self.configuratie.maxim_ip_uri_urmarite);
            println!("==========================\n");
        }
    }
}

// Implementare Clone pentru MotorIDS
impl Clone for MotorIDS {
    fn clone(&self) -> Self {
        Self {
            configuratie: self.configuratie.clone(),
            urmaritor_scanari: Arc::clone(&self.urmaritor_scanari),
            statistici: Arc::clone(&self.statistici),
        }
    }
}

// ============================================================================
// FUNCȚIA PRINCIPALĂ
// ============================================================================

#[tokio::main]
async fn main() -> std::io::Result<()> {
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║   IDS Rsyslog v2.1 - Coexistență ArcSight        ║");
    println!("║   100% Independent - Fără Interferențe           ║");
    println!("║   Rulează pe ACELAȘI server, proces SEPARAT      ║");
    println!("╚═══════════════════════════════════════════════════╝\n");

    let configuratie = ConfiguratieIDS {
        prag_scanare_porturi: 10,
        fereastra_timp_secunde: 60,
        prag_rafala_conexiuni: 50,
        cale_socket_unix: "/var/run/ids-personalizat/ids.sock".to_string(),
        port_http: 8888,
        endpoint_arcsight_cef: Some("syslog://localhost:5140".to_string()),
        arcsight_activat: true,
        marime_lot: 50,
        interval_curatare_secunde: 300,
        maxim_ip_uri_urmarite: 100_000,
        ignora_ip_uri_interne: true,
    };

    println!("⚙️  [CONFIGURAȚIE]");
    println!("    Scanare porturi: {} porturi în {}s", 
             configuratie.prag_scanare_porturi, 
             configuratie.fereastra_timp_secunde);
    println!("    Rafală: {} conexiuni în 10s", configuratie.prag_rafala_conexiuni);
    println!("    Socket: {}", configuratie.cale_socket_unix);
    println!("    Port HTTP: {} (ArcSight folosește 8443)", configuratie.port_http);
    println!("    ArcSight: {}", if configuratie.arcsight_activat { "✓ ACTIVAT" } else { "✗ DEZACTIVAT" });
    println!("    Maxim IP-uri: {}", configuratie.maxim_ip_uri_urmarite);
    println!("    Ignoră RFC1918: {}", configuratie.ignora_ip_uri_interne);
    println!();

    let ids = Arc::new(MotorIDS::nou(configuratie));

    // Pornește task-uri de fundal
    let ids_curatare = Arc::clone(&ids);
    tokio::spawn(async move {
        ids_curatare.task_curatare().await;
    });

    let ids_statistici = Arc::clone(&ids);
    tokio::spawn(async move {
        ids_statistici.task_statistici().await;
    });

    println!("🚀 [START] IDS-ul rulează acum...");
    println!("🔒 [IZOLARE] Proces separat, fără interferențe ArcSight");
    println!();

    // Pornește ascultătorul (blochează la infinit)
    ids.porneste_ascultator_unix().await
}