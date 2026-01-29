// ============================================================================
// SCANNER DE DETECTARE INTRUZIUNI - Versiune Educațională în Română
// ============================================================================
// Acest program detectează scan-uri de rețea (rapid și lent) din log-uri UDP
// și trimite alerte către ArcSight SIEM
// ============================================================================

// SECȚIUNEA 1: IMPORT-URI (Ce biblioteci folosim)
// ============================================================================
// anyhow - Pentru gestionarea erorilor într-un mod simplu
use anyhow::Result;

// chrono - Pentru lucrul cu date și timp
use chrono::{DateTime, Utc};

// dashmap - HashMap thread-safe (poate fi accesat din mai multe thread-uri simultan)
// Este ca un HashMap normal, dar sigur pentru programare concurentă
use dashmap::DashMap;

// log - Pentru a afișa mesaje de logging (info, warning, error)
use log::{error, info, warn};

// regex - Pentru a căuta pattern-uri în text (expresii regulate)
use regex::Regex;

// serde - Pentru serializare/deserializare (convertire între struct-uri și JSON/text)
use serde::{Deserialize, Serialize};

// std - Bibliotecă standard Rust
use std::net::SocketAddr;           // Pentru adrese de rețea
use std::sync::Arc;                 // Arc = Atomic Reference Counted (pointer thread-safe)
use std::time::{Duration, SystemTime, UNIX_EPOCH}; // Pentru măsurarea timpului

// tokio - Framework async pentru Rust (permite rularea de cod concurrent eficient)
use tokio::net::UdpSocket;          // Socket UDP asincron
use tokio::time;                    // Utilități pentru timp asincron

// ============================================================================
// SECȚIUNEA 2: CONFIGURARE DETECTARE SCAN-URI
// ============================================================================

/// STRUCT = o structură de date (ca un class în alte limbaje)
/// Aceasta stochează setările pentru detectarea scan-urilor
/// 
/// #[derive(Debug, Clone)] înseamnă:
/// - Debug: Poți să afișezi struct-ul cu {:?}
/// - Clone: Poți să faci o copie a struct-ului
#[derive(Debug, Clone)]
struct ConfigurareDetecareScanuri {
    /// Câmpurile struct-ului (datele pe care le păstrează)
    
    /// Câte porturi diferite trebuie scanate rapid pentru alertă
    /// usize = unsigned size (număr întreg pozitiv, dimensiunea variază după sistem)
    prag_scanare_rapida: usize,
    
    /// Câte secunde definește "rapid" (fereastra de timp)
    /// u64 = unsigned 64-bit integer (număr întreg pozitiv mare)
    fereastra_scanare_rapida: u64,
    
    /// Câte porturi pentru scan lent
    prag_scanare_lenta: usize,
    
    /// Câte secunde pentru scan lent (ex: 1 oră = 3600 secunde)
    fereastra_scanare_lenta: u64,
    
    /// După cât timp să ștergem datele vechi din memorie
    expirare_cache: u64,
}

// IMPL = implementation (implementare)
// Aici definim funcții (metode) pentru struct-ul nostru
impl ConfigurareDetecareScanuri {
    /// Default este un trait (interfață) care permite crearea valorilor implicite
    /// Self = tipul curent (ConfigurareDetecareScanuri)
    fn default() -> Self {
        // Self { ... } creează o nouă instanță a struct-ului
        Self {
            prag_scanare_rapida: 10,      // 10+ porturi = scan rapid
            fereastra_scanare_rapida: 60,  // în 1 minut
            prag_scanare_lenta: 20,        // 20+ porturi = scan lent
            fereastra_scanare_lenta: 3600, // în 1 oră (3600 secunde)
            expirare_cache: 7200,          // păstrează date 2 ore
        }
    }
}

// ============================================================================
// SECȚIUNEA 3: ACTIVITATEA UNUI IP SURSĂ
// ============================================================================

/// Struct care păstrează informații despre ce face un anumit IP
#[derive(Debug, Clone)]
struct ActivitateaSursei {
    /// Vec = Vector (listă dinamică în Rust)
    /// (u16, u64) = Tuplu cu 2 elemente: port (u16) și timestamp (u64)
    /// u16 = unsigned 16-bit (0-65535, perfect pentru numere de porturi)
    accesari_porturi: Vec<(u16, u64)>,
    
    /// Ultima dată când am văzut acest IP activ
    ultima_aparitie: u64,
    
    /// bool = boolean (true/false)
    /// Marchează dacă am trimis deja o alertă pentru acest IP
    alerta_trimisa: bool,
}

impl ActivitateaSursei {
    /// Constructor - creează o nouă instanță goală
    fn nou() -> Self {
        Self {
            // Vec::new() creează un vector gol
            accesari_porturi: Vec::new(),
            ultima_aparitie: timestamp_curent(),
            alerta_trimisa: false,
        }
    }

    /// Funcție care adaugă un port la lista de porturi accesate
    /// &mut self = referință mutabilă la sine (poate modifica struct-ul)
    fn adauga_port(&mut self, port: u16) {
        let acum = timestamp_curent();
        // push() adaugă un element la sfârșitul vectorului
        self.accesari_porturi.push((port, acum));
        self.ultima_aparitie = acum;
    }

    /// Șterge intrările vechi (cleanup)
    /// &mut self = poate modifica struct-ul
    /// fereastra: u64 = parametru de tip u64
    fn curata(&mut self, fereastra: u64) {
        // saturating_sub = scădere care nu permite overflow (nu merge sub 0)
        let limita = timestamp_curent().saturating_sub(fereastra);
        
        // retain() = păstrează doar elementele care îndeplinesc condiția
        // |(_, timestamp)| = closure (funcție anonimă) cu parametrii
        // _ = ignoră primul element al tuplului (portul)
        // *timestamp = dereferențiere (ia valoarea din pointer)
        self.accesari_porturi.retain(|(_, timestamp)| *timestamp > limita);
    }

    /// Numără câte porturi UNICE au fost accesate în fereastra de timp
    /// &self = referință imutabilă (doar citește, nu modifică)
    /// -> usize = tipul valorii returnate
    fn porturi_unice_in_fereastra(&self, fereastra: u64) -> usize {
        let limita = timestamp_curent().saturating_sub(fereastra);
        
        // PROGRAMARE FUNCȚIONALĂ - înlănțuire de operații:
        self.accesari_porturi
            .iter()                    // 1. Iterează prin vector
            .filter(|(_, timestamp)| *timestamp > limita)  // 2. Filtrează (păstrează doar cele noi)
            .map(|(port, _)| port)     // 3. Transformă (ia doar portul, ignoră timestamp-ul)
            .collect::<std::collections::HashSet<_>>()  // 4. Colectează într-un HashSet (elimină duplicate automat)
            .len()                     // 5. Returnează dimensiunea (numărul de porturi unice)
    }
}

// ============================================================================
// SECȚIUNEA 4: EVENIMENT CEF (Log parsat)
// ============================================================================

/// Struct care reprezintă un eveniment de securitate parsat din log
/// 
/// #[derive(Debug, Clone, Serialize, Deserialize)] înseamnă:
/// - Serialize: Poate fi convertit în JSON/text
/// - Deserialize: Poate fi creat din JSON/text
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EvenimentCef {
    /// Option<T> = Poate fi Some(valoare) sau None (lipsă)
    /// Este similar cu "nullable" din alte limbaje
    
    /// #[serde(skip_serializing_if = "Option::is_none")]
    /// = Când convertim în JSON, ignoră câmpul dacă este None
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_sursa: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_destinatie: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    port_destinatie: Option<u16>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    actiune: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    
    timestamp: String,
    
    // String = text alocat pe heap (poate crește dinamic)
    raw: String,  // Log-ul original, neprelucrat
}

// ============================================================================
// SECȚIUNEA 5: ALERTĂ DE SCAN DETECTAT
// ============================================================================

/// Struct care reprezintă o alertă când detectăm un scan
#[derive(Debug, Serialize)]
struct AlertaScan {
    tip_alerta: String,              // "RAPID_SCAN" sau "SLOW_SCAN"
    ip_sursa: String,                 // IP-ul atacatorului
    porturi_unice_scanate: usize,    // Câte porturi a scanat
    fereastra_timp_secunde: u64,     // În cât timp
    timp_detectare: String,           // Când am detectat
    severitate: String,               // "HIGH", "MEDIUM", etc.
    mesaj: String,                    // Mesaj descriptiv
}

impl AlertaScan {
    /// Constructor pentru o alertă nouă
    /// 
    /// Parametri:
    /// tip_alerta: String - tipul de scan detectat
    /// ip_sursa: String - IP-ul atacatorului
    /// porturi_unice: usize - câte porturi a scanat
    /// fereastra: u64 - în câte secunde
    /// 
    /// -> Self înseamnă că funcția returnează o instanță a struct-ului
    fn nou(
        tip_alerta: String,
        ip_sursa: String,
        porturi_unice: usize,
        fereastra: u64,
    ) -> Self {
        // if/else în formă expresie (returnează o valoare)
        let severitate = if tip_alerta == "RAPID_SCAN" {
            "HIGH"      // Scan rapid = pericol mare
        } else {
            "MEDIUM"    // Scan lent = pericol mediu
        };

        // format!() = ca printf/sprintf - creează un String formatat
        // {} = placeholder pentru a insera variabile
        let mesaj = format!(
            "Scan de rețea {} detectat: IP {} a accesat {} porturi unice în ultimele {} secunde",
            tip_alerta, ip_sursa, porturi_unice, fereastra
        );

        // Creează și returnează struct-ul
        Self {
            tip_alerta,
            ip_sursa,
            porturi_unice_scanate: porturi_unice,
            fereastra_timp_secunde: fereastra,
            timp_detectare: Utc::now().to_rfc3339(),  // Data/ora curentă în format ISO
            severitate: severitate.to_string(),        // Convertește &str în String
            mesaj,
        }
    }

    /// Convertește alerta în format CEF pentru ArcSight
    /// &self = referință imutabilă (doar citește din struct)
    /// -> String = returnează un String
    fn in_format_cef(&self) -> String {
        format!(
            "CEF:0|CustomIDS|NetworkScanner|1.0|{}|{}|{}|src={} msg={} cnt={}",
            self.tip_alerta,
            self.mesaj,
            self.severitate,
            self.ip_sursa,
            // replace() înlocuiește caracterele periculoase pentru CEF
            self.mesaj.replace('|', "\\|"),
            self.porturi_unice_scanate
        )
    }
}

// ============================================================================
// SECȚIUNEA 6: PARSER DE LOG-URI
// ============================================================================

/// Struct care parsează (analizează) log-uri în diverse formate
struct ParsorLoguri {
    regex_cef: Regex,  // Pattern pentru CEF
}

impl ParsorLoguri {
    /// Constructor - creează un nou parser
    /// Result<T> = poate returna Ok(valoare) sau Err(eroare)
    /// Este cum gestionezi erori în Rust (în loc de try/catch)
    fn nou() -> Result<Self> {
        // Regex pentru a extrage partea de extensie din CEF
        // r"..." = raw string (backslash-urile nu sunt escape)
        let regex_cef = Regex::new(
            r"CEF:\d+\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|(.*)"
        )?;  // ? = dacă e eroare, returnează eroarea imediat (early return)
        
        Ok(Self { regex_cef })  // Ok() = succes
    }

    /// Parsează un log (încearcă CEF, apoi Syslog)
    /// &self = referință imutabilă
    /// log_line: &str = referință la un string slice (nu deține string-ul)
    /// -> Option<EvenimentCef> = poate returna Some(eveniment) sau None
    fn parseaza(&self, linie_log: &str) -> Option<EvenimentCef> {
        // if let = pattern matching condiționat
        // Încearcă să parseze ca CEF
        if let Some(eveniment_cef) = self.parseaza_cef(linie_log) {
            return Some(eveniment_cef);  // Succes! Returnează
        }

        // Dacă CEF a eșuat, încearcă Syslog
        self.parseaza_syslog(linie_log)
    }

    /// Parsează format CEF
    fn parseaza_cef(&self, linie_log: &str) -> Option<EvenimentCef> {
        // Verifică dacă începe cu "CEF:"
        if !linie_log.starts_with("CEF:") {
            return None;  // Nu e CEF, returnează None (lipsă)
        }

        // captures() = găsește pattern-ul în text
        // ? = dacă nu găsește, returnează None imediat
        let capturi = self.regex_cef.captures(linie_log)?;
        
        // get(1) = ia primul grup capturat (extensia)
        // as_str() = convertește în &str
        let extensie = capturi.get(1)?.as_str();

        // Creează un eveniment gol
        let mut eveniment = EvenimentCef {
            ip_sursa: None,
            ip_destinatie: None,
            port_destinatie: None,
            actiune: None,
            protocol: None,
            timestamp: Utc::now().to_rfc3339(),
            raw: linie_log.to_string(),  // to_string() = creează un String deținut
        };

        // Parsează perechile key=value din extensie
        // split_whitespace() = împarte după spații
        for pereche in extensie.split_whitespace() {
            // split_once('=') = împarte în 2 la primul '='
            if let Some((cheie, valoare)) = pereche.split_once('=') {
                // match = switch statement puternic din Rust
                match cheie {
                    "src" => eveniment.ip_sursa = Some(valoare.to_string()),
                    "dst" => eveniment.ip_destinatie = Some(valoare.to_string()),
                    "dpt" => eveniment.port_destinatie = valoare.parse().ok(),  // parse() convertește string în număr
                    "act" => eveniment.actiune = Some(valoare.to_string()),
                    "proto" => eveniment.protocol = Some(valoare.to_string()),
                    _ => {}  // _ = ignoră alte chei necunoscute
                }
            }
        }

        Some(eveniment)  // Returnează evenimentul parsat
    }

    /// Parsează format Raw Syslog (simplificat)
    fn parseaza_syslog(&self, linie_log: &str) -> Option<EvenimentCef> {
        // Creează pattern-uri regex pentru diferite formate
        // (?:...) = grup non-capturat (alternativă)
        // \d{1,3} = cifră de 1-3 ori (pentru adrese IP)
        let regex_sursa = Regex::new(r"(?:src=|source=|SRC=)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").ok()?;
        let regex_dest = Regex::new(r"(?:dst=|dest=|destination=|DST=)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").ok()?;
        let regex_port_dest = Regex::new(r"(?:dport=|dpt=|DPT=)(\d+)").ok()?;
        let regex_actiune = Regex::new(r"(?:action=|ACT=|act=)(\w+)").ok()?;

        // Caută IP-ul sursă în text
        // and_then() = aplică funcția dacă valoarea nu e None
        // map() = transformă valoarea
        let ip_sursa = regex_sursa.captures(linie_log)
            .and_then(|c| c.get(1))  // Ia primul grup capturat
            .map(|m| m.as_str().to_string());  // Convertește în String

        let ip_dest = regex_dest.captures(linie_log)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        let port_dest = regex_port_dest.captures(linie_log)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse().ok());  // parse() și ok() pentru conversie sigură

        let actiune = regex_actiune.captures(linie_log)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        // Necesită cel puțin IP sursă și port destinație
        // is_some() = verifică dacă Option are o valoare (nu e None)
        if ip_sursa.is_some() && port_dest.is_some() {
            Some(EvenimentCef {
                ip_sursa,
                ip_destinatie: ip_dest,
                port_destinatie: port_dest,
                actiune,
                protocol: None,
                timestamp: Utc::now().to_rfc3339(),
                raw: linie_log.to_string(),
            })
        } else {
            None  // Nu avem destule date
        }
    }
}

// ============================================================================
// SECȚIUNEA 7: DETECTOR DE SCAN-URI (Motorul principal)
// ============================================================================

/// Struct-ul principal care detectează scan-urile
struct DetectorScanuri {
    configurare: ConfigurareDetecareScanuri,
    
    /// Arc = Atomic Reference Counted
    /// Pointer thread-safe care numără referințele
    /// DashMap = HashMap thread-safe (poate fi accesat din mai multe thread-uri)
    harta_activitati: Arc<DashMap<String, ActivitateaSursei>>,
    
    parsor: ParsorLoguri,
}

impl DetectorScanuri {
    /// Constructor
    fn nou(configurare: ConfigurareDetecareScanuri) -> Result<Self> {
        Ok(Self {
            configurare,
            harta_activitati: Arc::new(DashMap::new()),  // Arc::new() face pointer-ul thread-safe
            parsor: ParsorLoguri::nou()?,
        })
    }

    /// Procesează un eveniment de log
    /// async = funcție asincronă (poate aștepta fără să blocheze thread-ul)
    /// &self = referință imutabilă
    async fn proceseaza_eveniment(&self, linie_log: &str) -> Option<AlertaScan> {
        // Parsează log-ul
        let eveniment = self.parsor.parseaza(linie_log)?;

        // Extrage IP sursă și port destinație
        // as_ref() = convertește &Option<String> în Option<&String>
        let ip_sursa = eveniment.ip_sursa.as_ref()?;
        let port_dest = eveniment.port_destinatie?;

        // OPȚIONAL: Filtrare după acțiune (decomentează pentru a activa)
        // if let Some(actiune) = &eveniment.actiune {
        //     if !actiune.eq_ignore_ascii_case("deny") && !actiune.eq_ignore_ascii_case("block") {
        //         return None;
        //     }
        // }

        // Actualizează sau creează intrarea pentru acest IP
        // entry() = obține acces la o cheie din HashMap
        // or_insert_with() = inserează o valoare nouă dacă cheia nu există
        let mut activitate = self.harta_activitati
            .entry(ip_sursa.clone())  // clone() = creează o copie a String-ului
            .or_insert_with(ActivitateaSursei::nou);  // Closure fără parametri

        activitate.adauga_port(port_dest);
        
        // Curăță intrările vechi
        activitate.curata(self.configurare.fereastra_scanare_lenta);

        // Verifică dacă avem scan rapid
        let porturi_rapide = activitate.porturi_unice_in_fereastra(
            self.configurare.fereastra_scanare_rapida
        );
        
        // >= = mai mare sau egal
        // && = operatorul logic AND
        // ! = negare (NOT)
        if porturi_rapide >= self.configurare.prag_scanare_rapida && !activitate.alerta_trimisa {
            activitate.alerta_trimisa = true;  // Marchează că am trimis alerta
            return Some(AlertaScan::nou(
                "RAPID_SCAN".to_string(),
                ip_sursa.clone(),
                porturi_rapide,
                self.configurare.fereastra_scanare_rapida,
            ));
        }

        // Verifică dacă avem scan lent
        let porturi_lente = activitate.porturi_unice_in_fereastra(
            self.configurare.fereastra_scanare_lenta
        );
        
        if porturi_lente >= self.configurare.prag_scanare_lenta && !activitate.alerta_trimisa {
            activitate.alerta_trimisa = true;
            return Some(AlertaScan::nou(
                "SLOW_SCAN".to_string(),
                ip_sursa.clone(),
                porturi_lente,
                self.configurare.fereastra_scanare_lenta,
            ));
        }

        None  // Nu am detectat scan
    }

    /// Task (sarcină) de curățare periodică a cache-ului
    /// async fn = funcție asincronă
    /// Rulează în background și șterge IP-urile vechi
    async fn task_curatare(
        harta_activitati: Arc<DashMap<String, ActivitateaSursei>>,
        expirare_cache: u64
    ) {
        // interval() = creează un timer care "tick"-ează periodic
        // Duration::from_secs(300) = 300 secunde = 5 minute
        let mut interval = time::interval(Duration::from_secs(300));
        
        // loop = buclă infinită (rulează mereu)
        loop {
            // .await = așteaptă asincron (fără să blocheze thread-ul)
            interval.tick().await;  // Așteaptă următorul tick (5 minute)
            
            let limita = timestamp_curent().saturating_sub(expirare_cache);
            
            // retain() = păstrează doar elementele care îndeplinesc condiția
            // |_, activitate| = closure cu 2 parametri (ignorăm primul)
            harta_activitati.retain(|_, activitate| activitate.ultima_aparitie > limita);
            
            // info!() = macro pentru logging (ca println! dar pentru log-uri)
            info!("Curățare: {} IP-uri active în cache", harta_activitati.len());
        }
    }
}

// ============================================================================
// SECȚIUNEA 8: FUNCȚII UTILITARE
// ============================================================================

/// Obține timestamp-ul curent în secunde de la UNIX EPOCH (1 ian 1970)
fn timestamp_curent() -> u64 {
    SystemTime::now()  // Ora curentă
        .duration_since(UNIX_EPOCH)  // Diferența față de 1970
        .unwrap()  // unwrap() = extrage valoarea sau panică (oprește programul) dacă e eroare
        .as_secs()  // Convertește în secunde
}

/// Trimite alertă către ArcSight SIEM prin UDP
/// async = funcție asincronă
async fn trimite_alerta_catre_siem(alerta: &AlertaScan, adresa_siem: &str) -> Result<()> {
    // Creează un socket UDP
    // "0.0.0.0:0" = bind pe orice interfață, port aleatoriu
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    
    let mesaj_cef = alerta.in_format_cef();
    
    // Trimite pachetul UDP
    // as_bytes() = convertește String în &[u8] (array de bytes)
    socket.send_to(mesaj_cef.as_bytes(), adresa_siem).await?;
    
    info!("Alertă trimisă către SIEM ({}): {}", adresa_siem, mesaj_cef);
    
    // Ok(()) = returnează succes fără valoare
    Ok(())
}

// ============================================================================
// SECȚIUNEA 9: FUNCȚIA MAIN (Punctul de intrare)
// ============================================================================

/// Funcția principală a programului
/// 
/// #[tokio::main] = macro care transformă main() într-un runtime asincron Tokio
/// Fără acest macro, nu am putea folosi async/await
#[tokio::main]
async fn main() -> Result<()> {
    // PASUL 1: Inițializare logging
    // Setează nivelul de logging din variabila de mediu RUST_LOG
    // Dacă nu există, folosește "info" ca default
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    info!("🚀 Pornire Scanner de Detectare Intruziuni");

    // PASUL 2: Configurare
    let adresa_ascultare = "0.0.0.0:5555";  // Unde ascultă programul
    let adresa_siem = "127.0.0.1:514";       // Unde trimitem alertele
    
    let configurare = ConfigurareDetecareScanuri::default();
    info!("Configurare: {:?}", configurare);  // {:?} = afișare pentru debugging

    // PASUL 3: Inițializare detector
    // Arc::new() = face un pointer thread-safe (poate fi partajat între thread-uri)
    let detector = Arc::new(DetectorScanuri::nou(configurare.clone())?);

    // PASUL 4: Pornire task de curățare în background
    // clone() = creează o copie a pointer-ului Arc (incrementează contorul de referințe)
    let harta_curatare = detector.harta_activitati.clone();
    
    // tokio::spawn() = lansează un task asincron în background
    // async move = closure asincron care "preia" (move) ownership-ul variabilelor
    tokio::spawn(async move {
        DetectorScanuri::task_curatare(harta_curatare, configurare.expirare_cache).await;
    });

    // PASUL 5: Deschide socket UDP
    let socket = UdpSocket::bind(adresa_ascultare).await?;
    info!("📡 Ascult pe UDP {}", adresa_ascultare);
    info!("🎯 Alertele vor fi trimise către SIEM: {}", adresa_siem);

    // PASUL 6: Buffer pentru primirea pachetelor
    // vec![0u8; 65535] = creează un vector de 65535 bytes inițializați cu 0
    // 65535 = dimensiunea maximă a unui pachet UDP
    let mut buffer = vec![0u8; 65535];

    // PASUL 7: Buclă principală - primește și procesează pachete
    loop {
        // match = switch puternic pentru pattern matching
        // recv_from() = primește date UDP și adresa sursă
        match socket.recv_from(&mut buffer).await {
            // Ok((len, _addr)) = succes, primim lungimea și adresa (ignorăm adresa cu _)
            Ok((lungime, _adresa)) => {
                // Convertește bytes în text (UTF-8)
                // from_utf8_lossy() = convertește, înlocuind caracterele invalide cu �
                // &buffer[..lungime] = slice din buffer, de la 0 la lungime
                let linie_log = String::from_utf8_lossy(&buffer[..lungime]);
                
                // Clone referințele pentru a le muta în task-ul async
                let detector_clonat = detector.clone();
                let linie_log_detinuta = linie_log.to_string();  // Creează String deținut
                let adresa_siem_detinuta = adresa_siem.to_string();
                
                // Lansează un task asincron pentru a procesa evenimentul
                // Astfel, nu blocăm primirea următoarelor pachete
                tokio::spawn(async move {
                    // if let Some() = pattern matching pentru Option
                    if let Some(alerta) = detector_clonat.proceseaza_eveniment(&linie_log_detinuta).await {
                        // warn!() = logging pentru warning
                        warn!("⚠️  SCAN DETECTAT: {}", alerta.mesaj);
                        
                        // Trimite alerta către SIEM
                        // if let Err(e) = verifică dacă Result este eroare
                        if let Err(e) = trimite_alerta_catre_siem(&alerta, &adresa_siem_detinuta).await {
                            // error!() = logging pentru erori
                            error!("Eroare la trimiterea alertei: {}", e);
                        }
                    }
                });
            }
            // Err(e) = eroare la primirea pachetului
            Err(e) => {
                error!("Eroare la primirea pachetului UDP: {}", e);
            }
        }
    }
    
    // Nota: Bucla infinită nu se termină niciodată în mod normal
    // Programul se oprește doar dacă primește signal (Ctrl+C) sau eroare critică
}

// ============================================================================
// SFATURI PENTRU ÎNVĂȚARE RUST
// ============================================================================
//
// 1. OWNERSHIP (Proprietate):
//    - Fiecare valoare are un singur "owner" (proprietar)
//    - Când owner-ul iese din scope, valoarea e distrusă (drop)
//    - Nu există garbage collector - memoria e gestionată automat și sigur
//
// 2. BORROWING (Împrumut):
//    - &T = referință imutabilă (read-only)
//    - &mut T = referință mutabilă (read-write)
//    - Poți avea multe & sau o singură &mut la un moment dat
//
// 3. LIFETIME (Durata de viață):
//    - Determină cât timp o referință este validă
//    - Compilatorul verifică automat în majoritatea cazurilor
//
// 4. OPTION & RESULT:
//    - Option<T> = Some(valoare) sau None (lipsa valorii)
//    - Result<T, E> = Ok(valoare) sau Err(eroare)
//    - Înlocuiesc null/undefined și excepțiile din alte limbaje
//
// 5. PATTERN MATCHING:
//    - match, if let, while let
//    - Foarte puternic pentru destructurare și ramificație logică
//
// 6. ASYNC/AWAIT:
//    - Cod asincron fără callback hell
//    - Tokio = runtime pentru executare asincronă
//
// 7. TRAITS:
//    - Ca interfețele din alte limbaje
//    - Debug, Clone, Default, etc. sunt traits
//
// RESURSE DE ÎNVĂȚARE:
// - "The Rust Programming Language" (The Book) - carte oficială gratuită
// - Rust by Example - exemple practice
// - Rustlings - exerciții interactive
//
// ============================================================================
