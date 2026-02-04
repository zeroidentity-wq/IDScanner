# 🔧 Exemple Practice de Modificări

Acest document conține exemple concrete de cum să modifici codul pentru a învăța Rust.

## 📋 Cuprins

1. [Modificări Simple (Pentru Începători)](#1-modificări-simple)
2. [Modificări Intermediare](#2-modificări-intermediare)
3. [Modificări Avansate](#3-modificări-avansate)
4. [Debugging Tehnici](#4-debugging-tehnici)

---

## 1. Modificări Simple

### 1.1 Schimbă Mesajele de Log

**Locație:** `src/main.rs` sau `src/main_educational_ro.rs`

**Original:**
```rust
info!("🚀 Pornire Scanner de Detectare Intruziuni");
```

**Modificat:**
```rust
info!("===========================================");
info!("🔒 SISTEM DE SECURITATE - IDS SCANNER v1.0");
info!("🏢 Compania: ACME Security");
info!("📅 Data: {}", Utc::now().format("%Y-%m-%d %H:%M:%S"));
info!("===========================================");
```

**Ce înveți:** String formatting, chrono usage

---

### 1.2 Adaugă Timestamp în Format Românesc

**Adaugă funcție nouă:**
```rust
/// Formatează timestamp-ul în format românesc frumos
fn formateaza_data_ro(timestamp: u64) -> String {
    // Convertește timestamp în DateTime
    let datetime = DateTime::<Utc>::from_timestamp(timestamp as i64, 0)
        .unwrap_or_else(|| Utc::now());
    
    // Formatează: "29 Ianuarie 2025, 14:30:45"
    datetime.format("%d %B %Y, %H:%M:%S").to_string()
}
```

**Folosește-o:**
```rust
info!(
    "Ultimă activitate de la {}: {}",
    ip_sursa,
    formateaza_data_ro(activitate.ultima_aparitie)
);
```

**Ce înveți:** Funcții, DateTime formatting, unwrap_or_else

---

### 1.3 Adaugă Culori în Output

**Adaugă dependență în Cargo.toml:**
```toml
[dependencies]
colored = "2.0"
```

**Folosește-o:**
```rust
use colored::*;

// În main():
println!("{}", "🚀 Scanner pornit!".green().bold());

// Pentru alerte:
warn!(
    "{}",
    format!("⚠️  SCAN DETECTAT: {}", alerta.mesaj)
        .red()
        .bold()
);
```

**Ce înveți:** Crate-uri externe, trait methods chaining

---

### 1.4 Contorizează Alertele

**Adaugă în main():**
```rust
// După inițializare detector, înainte de loop
use std::sync::atomic::{AtomicU64, Ordering};

let contor_alerte = Arc::new(AtomicU64::new(0));

// În task-ul de procesare, când trimitem alerta:
let contor_clone = contor_alerte.clone();
tokio::spawn(async move {
    if let Some(alerta) = detector_clonat.proceseaza_eveniment(&linie_log_detinuta).await {
        // Incrementează contorul atomic (thread-safe)
        contor_clone.fetch_add(1, Ordering::SeqCst);
        
        warn!(
            "⚠️  SCAN #{} DETECTAT: {}",
            contor_clone.load(Ordering::SeqCst),
            alerta.mesaj
        );
        
        // ... trimite alerta
    }
});

// Task de statistici (la fiecare 60 secunde)
let contor_stats = contor_alerte.clone();
tokio::spawn(async move {
    let mut interval = time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        info!(
            "📊 Statistici: {} alerte trimise în total",
            contor_stats.load(Ordering::SeqCst)
        );
    }
});
```

**Ce înveți:** AtomicU64 (sincronizare thread-safe), Arc cloning

---

## 2. Modificări Intermediare

### 2.1 Implementează Whitelist de IP-uri

**Pasul 1: Modifică struct-ul de configurare**

```rust
#[derive(Debug, Clone)]
struct ConfigurareDetecareScanuri {
    prag_scanare_rapida: usize,
    fereastra_scanare_rapida: u64,
    prag_scanare_lenta: usize,
    fereastra_scanare_lenta: u64,
    expirare_cache: u64,
    
    // ADAUGĂ ACEST CÂMP:
    lista_alba_ip: Vec<String>,  // IP-uri permise
}
```

**Pasul 2: Actualizează Default**

```rust
impl ConfigurareDetecareScanuri {
    fn default() -> Self {
        Self {
            prag_scanare_rapida: 10,
            fereastra_scanare_rapida: 60,
            prag_scanare_lenta: 20,
            fereastra_scanare_lenta: 3600,
            expirare_cache: 7200,
            
            // ADAUGĂ LISTA ALBĂ:
            lista_alba_ip: vec![
                "10.0.0.1".to_string(),      // Load balancer
                "192.168.1.100".to_string(), // Scanner Nessus legitim
                "172.16.0.5".to_string(),    // Monitoring tool
            ],
        }
    }
}
```

**Pasul 3: Verifică în proceseaza_eveniment**

```rust
async fn proceseaza_eveniment(&self, linie_log: &str) -> Option<AlertaScan> {
    let eveniment = self.parsor.parseaza(linie_log)?;
    let ip_sursa = eveniment.ip_sursa.as_ref()?;
    let port_dest = eveniment.port_destinatie?;
    
    // VERIFICĂ LISTA ALBĂ:
    if self.configurare.lista_alba_ip.contains(ip_sursa) {
        // Log că am ignorat IP-ul (opțional)
        debug!("IP {} este în lista albă - ignorat", ip_sursa);
        return None;
    }
    
    // ... rest cod
}
```

**Testare:**
```bash
# Trimite log de la IP în whitelist
echo "CEF:0|Test|FW|1.0|100|Test|5|src=10.0.0.1 dst=2.2.2.2 dpt=80 act=DENY" | nc -u localhost 5555

# Nu ar trebui să genereze alertă chiar dacă scanează multe porturi
```

**Ce înveți:** Vec, contains(), Option chaining

---

### 2.2 Citește Configurarea din Fișier TOML

**Pasul 1: Adaugă dependențe**

```toml
[dependencies]
# ... dependențe existente
toml = "0.8"
serde = { version = "1.0", features = ["derive"] }
```

**Pasul 2: Fă struct-ul serializabil**

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigurareDetecareScanuri {
    prag_scanare_rapida: usize,
    fereastra_scanare_rapida: u64,
    prag_scanare_lenta: usize,
    fereastra_scanare_lenta: u64,
    expirare_cache: u64,
    lista_alba_ip: Vec<String>,
}
```

**Pasul 3: Funcție de citire**

```rust
use std::fs;

impl ConfigurareDetecareScanuri {
    /// Încarcă configurarea din fișier TOML
    fn din_fisier(cale: &str) -> Result<Self> {
        // Citește fișierul
        let continut = fs::read_to_string(cale)?;
        
        // Parsează TOML
        let config: Self = toml::from_str(&continut)?;
        
        Ok(config)
    }
}
```

**Pasul 4: Creează fișier config.toml**

```toml
# config.toml
prag_scanare_rapida = 10
fereastra_scanare_rapida = 60
prag_scanare_lenta = 20
fereastra_scanare_lenta = 3600
expirare_cache = 7200

lista_alba_ip = [
    "10.0.0.1",
    "192.168.1.100",
    "172.16.0.5"
]
```

**Pasul 5: Folosește în main()**

```rust
async fn main() -> Result<()> {
    // ...
    
    // Încearcă să încarci din fișier, altfel folosește default
    let configurare = ConfigurareDetecareScanuri::din_fisier("config.toml")
        .unwrap_or_else(|e| {
            warn!("Nu pot citi config.toml: {}. Folosesc valori default.", e);
            ConfigurareDetecareScanuri::default()
        });
    
    info!("Configurare încărcată: {:?}", configurare);
    
    // ... rest cod
}
```

**Ce înveți:** File I/O, TOML parsing, serde, error handling avanzat

---

### 2.3 Salvează Alertele în Fișier JSON

**Adaugă funcție:**

```rust
use std::fs::OpenOptions;
use std::io::Write;
use serde_json;

/// Salvează alertă în fișier JSON (append)
async fn salveaza_alerta_json(alerta: &AlertaScan) -> Result<()> {
    // Serializează în JSON cu pretty print
    let json = serde_json::to_string_pretty(alerta)?;
    
    // Deschide fișier în mod append (creează dacă nu există)
    let mut fisier = OpenOptions::new()
        .create(true)      // Creează dacă nu există
        .append(true)      // Adaugă la final
        .open("alerte.json")?;
    
    // Scrie JSON + newline
    writeln!(fisier, "{},", json)?;
    
    Ok(())
}
```

**Folosește-o:**

```rust
tokio::spawn(async move {
    if let Some(alerta) = detector_clonat.proceseaza_eveniment(&linie_log_detinuta).await {
        warn!("⚠️  SCAN DETECTAT: {}", alerta.mesaj);
        
        // Salvează în JSON
        if let Err(e) = salveaza_alerta_json(&alerta).await {
            error!("Eroare salvare JSON: {}", e);
        }
        
        // Trimite către SIEM
        if let Err(e) = trimite_alerta_catre_siem(&alerta, &adresa_siem_detinuta).await {
            error!("Eroare la trimiterea alertei: {}", e);
        }
    }
});
```

**Verificare:**

```bash
# După câteva alerte, verifică fișierul:
cat alerte.json | jq .

# Formatează frumos cu jq:
cat alerte.json | jq -s .
```

**Ce înveți:** File I/O async, JSON serialization, error propagation

---

### 2.4 Adaugă Metrici Prometheus

**Adaugă dependențe:**

```toml
[dependencies]
# ... dependențe existente
prometheus = "0.13"
lazy_static = "1.4"
```

**Definește metrici:**

```rust
use prometheus::{IntCounter, IntGauge, Registry};
use lazy_static::lazy_static;

lazy_static! {
    /// Număr total de alerte
    static ref ALERTE_TOTAL: IntCounter = IntCounter::new(
        "ids_alerte_total",
        "Numărul total de alerte detectate"
    ).unwrap();
    
    /// Număr de IP-uri monitorizate
    static ref IP_URI_ACTIVE: IntGauge = IntGauge::new(
        "ids_ipuri_active",
        "Numărul de IP-uri active în cache"
    ).unwrap();
    
    /// Registry pentru toate metricile
    static ref REGISTRY: Registry = {
        let r = Registry::new();
        r.register(Box::new(ALERTE_TOTAL.clone())).unwrap();
        r.register(Box::new(IP_URI_ACTIVE.clone())).unwrap();
        r
    };
}
```

**Actualizează metrici:**

```rust
// Când detectezi alertă:
if let Some(alerta) = detector_clonat.proceseaza_eveniment(&linie_log_detinuta).await {
    ALERTE_TOTAL.inc();  // Incrementează contorul
    warn!("⚠️  SCAN DETECTAT: {}", alerta.mesaj);
    // ...
}

// În task-ul de cleanup:
async fn task_curatare(harta_activitati: Arc<DashMap<String, ActivitateaSursei>>, expirare_cache: u64) {
    let mut interval = time::interval(Duration::from_secs(300));
    loop {
        interval.tick().await;
        let limita = timestamp_curent().saturating_sub(expirare_cache);
        harta_activitati.retain(|_, activitate| activitate.ultima_aparitie > limita);
        
        // Actualizează metrica
        IP_URI_ACTIVE.set(harta_activitati.len() as i64);
        
        info!("Curățare: {} IP-uri active", harta_activitati.len());
    }
}
```

**Exportă metrici (HTTP endpoint):**

```rust
use warp::Filter;

// Adaugă în main(), după pornirea detector-ului:
tokio::spawn(async move {
    // Endpoint /metrics pentru Prometheus
    let metrics_route = warp::path!("metrics").map(|| {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = REGISTRY.gather();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    });
    
    warp::serve(metrics_route)
        .run(([0, 0, 0, 0], 9090))
        .await;
});

info!("📊 Metrici Prometheus disponibile pe http://localhost:9090/metrics");
```

**Testare:**

```bash
# Verifică metrici:
curl http://localhost:9090/metrics

# Output:
# ids_alerte_total 5
# ids_ipuri_active 12
```

**Ce înveți:** Lazy static, web servers (warp), observability

---

## 3. Modificări Avansate

### 3.1 Implementează Detecție Network Sweep

**Obiectiv:** Detectează când un IP scanează același port pe multe destinații.

**Pasul 1: Struct nou**

```rust
#[derive(Debug, Clone)]
struct ActivitateDestinatie {
    /// Lista de IP-uri destinație accesate cu timestamp
    destinatii: Vec<(String, u64)>,
    ultima_aparitie: u64,
}

impl ActivitateDestinatie {
    fn nou() -> Self {
        Self {
            destinatii: Vec::new(),
            ultima_aparitie: timestamp_curent(),
        }
    }
    
    fn adauga_destinatie(&mut self, ip_dest: String) {
        let acum = timestamp_curent();
        self.destinatii.push((ip_dest, acum));
        self.ultima_aparitie = acum;
    }
    
    fn destinatii_unice_in_fereastra(&self, fereastra: u64) -> usize {
        let limita = timestamp_curent().saturating_sub(fereastra);
        self.destinatii
            .iter()
            .filter(|(_, timestamp)| *timestamp > limita)
            .map(|(ip, _)| ip)
            .collect::<std::collections::HashSet<_>>()
            .len()
    }
}
```

**Pasul 2: Adaugă în detector**

```rust
struct DetectorScanuri {
    configurare: ConfigurareDetecareScanuri,
    harta_activitati: Arc<DashMap<String, ActivitateaSursei>>,
    
    // ADAUGĂ:
    // Cheie = (IP sursă, Port destinație)
    harta_sweep: Arc<DashMap<(String, u16), ActivitateDestinatie>>,
    
    parsor: ParsorLoguri,
}
```

**Pasul 3: Detectează în proceseaza_eveniment**

```rust
async fn proceseaza_eveniment(&self, linie_log: &str) -> Option<AlertaScan> {
    let eveniment = self.parsor.parseaza(linie_log)?;
    let ip_sursa = eveniment.ip_sursa.as_ref()?;
    let port_dest = eveniment.port_destinatie?;
    let ip_dest = eveniment.ip_destinatie.as_ref()?;  // Avem nevoie de destinație!
    
    // ... logică existentă pentru port scan
    
    // DETECTARE NETWORK SWEEP:
    let cheie_sweep = (ip_sursa.clone(), port_dest);
    let mut activitate_sweep = self.harta_sweep
        .entry(cheie_sweep)
        .or_insert_with(ActivitateDestinatie::nou);
    
    activitate_sweep.adauga_destinatie(ip_dest.clone());
    
    let destinatii_unice = activitate_sweep.destinatii_unice_in_fereastra(300); // 5 min
    if destinatii_unice >= 20 {  // 20+ destinații
        return Some(AlertaScan {
            tip_alerta: "NETWORK_SWEEP".to_string(),
            ip_sursa: ip_sursa.clone(),
            porturi_unice_scanate: destinatii_unice,
            fereastra_timp_secunde: 300,
            timp_detectare: Utc::now().to_rfc3339(),
            severitate: "HIGH".to_string(),
            mesaj: format!(
                "Network sweep detectat: IP {} scanează portul {} pe {} destinații",
                ip_sursa, port_dest, destinatii_unice
            ),
        });
    }
    
    None
}
```

**Ce înveți:** Tuple keys în HashMap, pattern detection avanzat

---

### 3.2 Dashboard Web Simplu

**Adaugă dependențe:**

```toml
[dependencies]
# ... dependențe existente
axum = "0.7"
tower-http = { version = "0.5", features = ["fs", "cors"] }
```

**Creează endpoint API:**

```rust
use axum::{routing::get, Router, Json};
use std::sync::Arc;

#[derive(Serialize)]
struct StatisticiDashboard {
    ip_uri_active: usize,
    alerte_totale: u64,
    top_scaneri: Vec<(String, usize)>,
}

async fn obtine_statistici(
    detector: Arc<DetectorScanuri>
) -> Json<StatisticiDashboard> {
    // Calculează top 10 scaneri
    let mut top_scaneri: Vec<(String, usize)> = detector
        .harta_activitati
        .iter()
        .map(|entry| {
            let ip = entry.key().clone();
            let porturi = entry.value().accesari_porturi.len();
            (ip, porturi)
        })
        .collect();
    
    top_scaneri.sort_by(|a, b| b.1.cmp(&a.1));
    top_scaneri.truncate(10);
    
    Json(StatisticiDashboard {
        ip_uri_active: detector.harta_activitati.len(),
        alerte_totale: ALERTE_TOTAL.get(),
        top_scaneri,
    })
}

// În main(), după inițializare detector:
let detector_web = detector.clone();
tokio::spawn(async move {
    let app = Router::new()
        .route("/api/stats", get(move || {
            let d = detector_web.clone();
            async move { obtine_statistici(d).await }
        }));
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .unwrap();
    
    axum::serve(listener, app).await.unwrap();
});

info!("🌐 Dashboard disponibil pe http://localhost:8080/api/stats");
```

**Testare:**

```bash
curl http://localhost:8080/api/stats | jq .
```

**Ce înveți:** Web frameworks (axum), async HTTP, JSON APIs

---

## 4. Debugging Tehnici

### 4.1 Folosește dbg! Macro

```rust
// În loc de:
let eveniment = self.parsor.parseaza(linie_log)?;

// Folosește dbg! pentru a vedea valoarea:
let eveniment = dbg!(self.parsor.parseaza(linie_log)?);

// Output:
// [src/main.rs:123] self.parsor.parseaza(linie_log)? = EvenimentCef {
//     ip_sursa: Some("192.168.1.100"),
//     port_destinatie: Some(22),
//     ...
// }
```

### 4.2 Conditional Logging

```rust
// Doar pentru un IP specific:
if ip_sursa == "192.168.1.100" {
    debug!("Procesare specială pentru IP debug: {:?}", eveniment);
}

// Sau cu variabilă de mediu:
if std::env::var("DEBUG_IP").is_ok() {
    info!("Debug mode activat pentru toate IP-urile");
}
```

### 4.3 Panic Hook Customizat

```rust
// În main(), la început:
std::panic::set_hook(Box::new(|panic_info| {
    error!("PANICĂ: {:?}", panic_info);
    // Salvează crash log
    let crash_log = format!("{:?}", panic_info);
    std::fs::write("crash.log", crash_log).ok();
}));
```

### 4.4 Testare Unitară

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parsare_cef() {
        let parsor = ParsorLoguri::nou().unwrap();
        let log = "CEF:0|Test|FW|1.0|100|Test|5|src=1.1.1.1 dst=2.2.2.2 dpt=80 act=DENY";
        
        let eveniment = parsor.parseaza(log).unwrap();
        
        assert_eq!(eveniment.ip_sursa, Some("1.1.1.1".to_string()));
        assert_eq!(eveniment.port_destinatie, Some(80));
    }
    
    #[test]
    fn test_detectie_scan_rapid() {
        // TODO: Implementează test pentru detectare scan rapid
    }
}
```

**Rulare teste:**

```bash
cargo test
cargo test -- --nocapture  # Cu output
cargo test test_parsare_cef  # Test specific
```

---

## 📚 Resurse Suplimentare

- **Rust Book**: https://doc.rust-lang.org/book/
- **Rust by Example**: https://doc.rust-lang.org/rust-by-example/
- **Tokio Tutorial**: https://tokio.rs/tokio/tutorial

**Succes la experimentare! 🚀**
