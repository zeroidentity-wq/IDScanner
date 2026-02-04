# 📚 Ghid de Învățare Rust prin Proiectul IDS Scanner

Acest ghid te va ajuta să înveți Rust pas cu pas, folosind proiectul de IDS Scanner ca exemplu practic.

## 🎯 Cuprins

1. [Concepte Fundamentale Rust](#1-concepte-fundamentale-rust)
2. [Cum să Studiezi Codul](#2-cum-să-studiezi-codul)
3. [Exerciții Practice](#3-exerciții-practice)
4. [Dezvoltări Viitoare](#4-dezvoltări-viitoare)
5. [Resurse de Învățare](#5-resurse-de-învățare)

---

## 1. Concepte Fundamentale Rust

### 1.1 Ownership (Proprietate) 🔑

**Ce este?** În Rust, fiecare valoare are un singur "proprietar" (owner). Când proprietarul iese din scope, valoarea este automat distrusă.

**Exemplu din proiect:**
```rust
fn adauga_port(&mut self, port: u16) {
    let acum = timestamp_curent();  // 'acum' este deținut de această funcție
    self.accesari_porturi.push((port, acum));
    // La sfârșitul funcției, 'acum' este distrus automat
}
```

**De ce e important?**
- Nu ai memory leaks (scurgeri de memorie)
- Nu ai garbage collector (performanță mai bună)
- Compilatorul garantează siguranța memoriei

**Exercițiu:**
```rust
// Încearcă să compilezi acest cod. De ce dă eroare?
fn test_ownership() {
    let s1 = String::from("test");
    let s2 = s1;  // s1 se mută în s2
    println!("{}", s1);  // EROARE: s1 nu mai este valabil!
}

// Corectare: folosește clone() sau referință (&)
fn test_ownership_fix() {
    let s1 = String::from("test");
    let s2 = s1.clone();  // Creează o copie
    println!("{}", s1);   // OK!
}
```

### 1.2 Borrowing (Împrumut) 📖

**Ce este?** Poți "împrumuta" o valoare fără să o deții, folosind referințe.

**Tipuri de împrumut:**
- `&T` - Referință imutabilă (read-only)
- `&mut T` - Referință mutabilă (read-write)

**Exemplu din proiect:**
```rust
// Referință imutabilă - doar citește
fn porturi_unice_in_fereastra(&self, fereastra: u64) -> usize {
    // &self = împrumut imutabil - nu modifică struct-ul
}

// Referință mutabilă - poate modifica
fn adauga_port(&mut self, port: u16) {
    // &mut self = împrumut mutabil - poate modifica struct-ul
}
```

**Regulile împrumutului:**
1. Poți avea **multe** împrumuturi imutabile (`&T`) SAU
2. Poți avea **un singur** împrumut mutabil (`&mut T`)
3. Dar NICIODATĂ ambele în același timp!

**Exercițiu:**
```rust
// De ce dă eroare acest cod?
fn test_borrowing() {
    let mut vec = vec![1, 2, 3];
    let r1 = &vec;        // OK: împrumut imutabil
    let r2 = &vec;        // OK: alt împrumut imutabil
    let r3 = &mut vec;    // EROARE: nu poți avea &mut când există &
    println!("{:?}", r1);
}
```

### 1.3 Structs și Implementări 🏗️

**Ce este un struct?** O structură de date personalizată (ca un class în alte limbaje, dar fără moștenire).

**Exemplu din proiect:**
```rust
// Definirea struct-ului
#[derive(Debug, Clone)]  // Macro-uri care generează cod automat
struct ActivitateaSursei {
    accesari_porturi: Vec<(u16, u64)>,
    ultima_aparitie: u64,
    alerta_trimisa: bool,
}

// Implementarea metodelor pentru struct
impl ActivitateaSursei {
    // Funcție constructor (asociată)
    fn nou() -> Self {
        Self {
            accesari_porturi: Vec::new(),
            ultima_aparitie: timestamp_curent(),
            alerta_trimisa: false,
        }
    }
    
    // Metodă care primește &self (nu modifică)
    fn porturi_unice(&self) -> usize {
        // ...
    }
    
    // Metodă care primește &mut self (poate modifica)
    fn adauga_port(&mut self, port: u16) {
        // ...
    }
}
```

**Exercițiu:** Creează propriul struct
```rust
// Creează un struct pentru a ține evidența login-urilor unui user
struct LoginTracker {
    username: String,
    failed_attempts: u32,
    last_login: u64,
    is_locked: bool,
}

impl LoginTracker {
    // TODO: Implementează constructor
    fn new(username: String) -> Self {
        // ...
    }
    
    // TODO: Implementează metodă care adaugă o încercare eșuată
    fn add_failed_attempt(&mut self) {
        // ...
    }
    
    // TODO: Implementează metodă care verifică dacă e blocat
    fn is_account_locked(&self) -> bool {
        // ...
    }
}
```

### 1.4 Option și Result 🎁

**Option<T>** - Reprezintă o valoare care poate lipsi
```rust
enum Option<T> {
    Some(T),  // Are o valoare
    None,     // Nu are valoare
}
```

**Result<T, E>** - Reprezintă succes sau eroare
```rust
enum Result<T, E> {
    Ok(T),    // Succes cu valoare
    Err(E),   // Eroare
}
```

**Exemplu din proiect:**
```rust
// Option: IP-ul poate lipsi
ip_sursa: Option<String>,

// Verificare:
if ip_sursa.is_some() {
    let ip = ip_sursa.unwrap();  // Extrage valoarea (panică dacă e None!)
}

// Mai sigur:
if let Some(ip) = ip_sursa {
    // Folosește ip
}

// Cel mai sigur:
match ip_sursa {
    Some(ip) => println!("IP: {}", ip),
    None => println!("Lipsește IP"),
}

// Result: funcție care poate eșua
fn parseaza() -> Result<EvenimentCef> {
    // dacă ceva e greșit:
    return Err(anyhow!("Eroare de parsare"));
    
    // dacă totul e ok:
    Ok(eveniment)
}

// Folosirea lui ?:
let eveniment = self.parsor.parseaza(linie_log)?;
// ? = dacă e Err, returnează eroarea imediat
```

**Exercițiu:**
```rust
// Implementează o funcție care divide două numere
fn divide(a: i32, b: i32) -> Result<i32, String> {
    // TODO: Returnează Err dacă b == 0
    // TODO: Altfel returnează Ok cu rezultatul
}

// Test:
match divide(10, 2) {
    Ok(result) => println!("Rezultat: {}", result),
    Err(e) => println!("Eroare: {}", e),
}
```

### 1.5 Colecții 📦

**Vec<T>** - Vector dinamic (array redimensionabil)
```rust
let mut porturi = Vec::new();     // Vector gol
porturi.push(80);                  // Adaugă element
porturi.push(443);

// sau
let porturi = vec![80, 443, 22];  // Macro pentru inițializare
```

**HashMap<K, V>** / **DashMap<K, V>** - Dicționar (key-value)
```rust
use std::collections::HashMap;

let mut map = HashMap::new();
map.insert("ip", "192.168.1.1");
map.insert("port", "80");

// Accesare:
if let Some(ip) = map.get("ip") {
    println!("IP: {}", ip);
}

// DashMap = HashMap thread-safe (din proiect)
let harta: Arc<DashMap<String, ActivitateaSursei>> = Arc::new(DashMap::new());
```

**Exemplu din proiect:**
```rust
// Vector de tuple
accesari_porturi: Vec<(u16, u64)>,

// Adăugare:
self.accesari_porturi.push((port, timestamp));

// Iterare:
for (port, timestamp) in &self.accesari_porturi {
    println!("Port: {}, Timp: {}", port, timestamp);
}
```

### 1.6 Pattern Matching 🎯

**match** - Switch puternic
```rust
match valoare {
    pattern1 => expresie1,
    pattern2 => expresie2,
    _ => expresie_default,  // _ = orice altceva
}
```

**Exemplu din proiect:**
```rust
// Match simplu:
match cheie {
    "src" => eveniment.ip_sursa = Some(valoare.to_string()),
    "dst" => eveniment.ip_destinatie = Some(valoare.to_string()),
    "dpt" => eveniment.port_destinatie = valoare.parse().ok(),
    _ => {}  // Ignoră alte cazuri
}

// Match cu Result:
match socket.recv_from(&mut buffer).await {
    Ok((lungime, adresa)) => {
        // Procesează datele
    }
    Err(e) => {
        error!("Eroare: {}", e);
    }
}

// if let - match simplificat pentru un singur caz:
if let Some(eveniment) = self.parsor.parseaza(linie_log) {
    // Folosește eveniment
}
```

**Exercițiu:**
```rust
// Creează un enum pentru tipuri de alerte
enum AlertType {
    RapidScan,
    SlowScan,
    BruteForce,
    SuspiciousIP(String),  // Poate conține date
}

// TODO: Implementează funcție care returnează severitate
fn get_severity(alert: AlertType) -> &'static str {
    match alert {
        // Completează cu pattern matching
    }
}
```

### 1.7 Programare Funcțională 🔄

Rust suportă programare funcțională cu **iteratori** și **closures**.

**Iterator chains (înlănțuire):**
```rust
// Din proiect - foarte elegant!
self.accesari_porturi
    .iter()                          // 1. Creează iterator
    .filter(|(_, ts)| *ts > limita)  // 2. Filtrează
    .map(|(port, _)| port)           // 3. Transformă
    .collect::<HashSet<_>>()         // 4. Colectează
    .len()                           // 5. Numără
```

**Closures (funcții anonime):**
```rust
// Sintaxă: |parametri| expresie
let adauga_10 = |x| x + 10;
println!("{}", adauga_10(5));  // 15

// În proiect:
.filter(|(_, timestamp)| *timestamp > limita)
//       ↑parametri↑      ↑expresie↑
```

**Exercițiu:**
```rust
// Dat un vector de porturi, găsește toate porturile > 1000
let porturi = vec![22, 80, 443, 3306, 8080, 3389];

// TODO: Folosește filter și collect pentru a obține doar porturile > 1000
let porturi_mari: Vec<_> = porturi
    .iter()
    // ... completează cu filter și collect
```

### 1.8 Async/Await ⚡

**Ce este?** Programare asincronă - cod care poate "aștepta" fără să blocheze thread-ul.

**De ce?** Pentru a gestiona multe conexiuni simultan fără să consumăm thread-uri.

**Concepte:**
- `async fn` - funcție asincronă
- `.await` - așteaptă rezultatul unei operații async
- `tokio::spawn` - lansează un task asincron

**Exemplu din proiect:**
```rust
// Funcție asincronă
async fn proceseaza_eveniment(&self, linie_log: &str) -> Option<AlertaScan> {
    // Cod sincron normal
    let eveniment = self.parsor.parseaza(linie_log)?;
    // ...
}

// Lansare task asincron în background
tokio::spawn(async move {
    // Cod care rulează asincron
    DetectorScanuri::task_curatare(harta, expirare).await;
});

// Buclă principală
loop {
    // Așteaptă packet UDP (asincron - nu blochează)
    match socket.recv_from(&mut buffer).await {
        Ok((len, _)) => {
            // Pentru fiecare packet, lansează un task nou
            tokio::spawn(async move {
                // Procesare în paralel
            });
        }
        Err(e) => { /* ... */ }
    }
}
```

**De ce e puternic?**
- Putem procesa mii de pachete simultan
- Nu blocăm primirea de noi pachete
- Consumăm resurse minime

---

## 2. Cum să Studiezi Codul

### Metoda Pas-cu-Pas 📖

**Pasul 1: Înțelege Flow-ul Principal**

Pornește de la funcția `main()` și urmărește execuția:

```
main()
  ↓
1. Inițializare logging
  ↓
2. Configurare (adrese, praguri)
  ↓
3. Creare detector
  ↓
4. Pornire task cleanup (background)
  ↓
5. Deschidere socket UDP
  ↓
6. Loop infinit:
     - Primește packet
     - Lansează task pentru procesare
     - Repeat
```

**Pasul 2: Studiază Fiecare Modul**

1. **Configurare** - Struct-uri simple cu date
2. **Parser** - Regex și string processing
3. **Detector** - Logica principală de detecție
4. **Alerting** - Trimitere UDP către SIEM

**Pasul 3: Rulează și Experimentează**

```bash
# Compilează
cargo build

# Rulează cu debug logging
RUST_LOG=debug cargo run

# În alt terminal, trimite test
echo "CEF:0|Test|FW|1.0|100|Test|5|src=1.1.1.1 dst=2.2.2.2 dpt=80 act=DENY" | nc -u localhost 5555
```

**Pasul 4: Modifică Codul**

Începe cu modificări simple:
```rust
// Schimbă mesajul de alertă
let mesaj = format!(
    "🚨 ATENȚIE! IP {} scanează porturi! 🚨",
    ip_sursa
);

// Schimbă pragurile
prag_scanare_rapida: 5,  // Mai sensibil
```

### Debugging cu println! și dbg! 🐛

```rust
// println! - afișare simplă
println!("Primim log: {}", linie_log);

// dbg! - afișare pentru debugging (cu tip și loc)
dbg!(&eveniment);  // Afișează struct-ul complet

// info!, warn!, error! - logging profesional
info!("Procesare eveniment pentru IP: {}", ip_sursa);
warn!("Prag atins: {} porturi", numar_porturi);
error!("Eroare la parsare: {}", err);
```

---

## 3. Exerciții Practice

### Exercițiul 1: Adaugă Whitelist 🏳️

**Obiectiv:** Permite anumite IP-uri să nu genereze alerte.

```rust
// 1. Adaugă câmp în ConfigurareDetecareScanuri:
struct ConfigurareDetecareScanuri {
    // ... câmpuri existente
    ip_uri_permise: Vec<String>,  // ADAUGĂ ACEST CÂMP
}

// 2. Actualizează default():
fn default() -> Self {
    Self {
        // ... valori existente
        ip_uri_permise: vec![
            "10.0.0.1".to_string(),      // Scanner legitim
            "192.168.1.100".to_string(), // Monitoring tool
        ],
    }
}

// 3. În proceseaza_eveniment(), verifică whitelist:
async fn proceseaza_eveniment(&self, linie_log: &str) -> Option<AlertaScan> {
    let eveniment = self.parsor.parseaza(linie_log)?;
    let ip_sursa = eveniment.ip_sursa.as_ref()?;
    
    // VERIFICĂ WHITELIST
    if self.configurare.ip_uri_permise.contains(ip_sursa) {
        return None;  // IP permis, ignoră
    }
    
    // ... rest cod
}
```

### Exercițiul 2: Statistici în Timp Real 📊

**Obiectiv:** Afișează statistici la fiecare 60 secunde.

```rust
// Adaugă task nou în main():
tokio::spawn(async move {
    let mut interval = time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        
        // TODO: Afișează statistici
        // - Număr total de IP-uri monitorizate
        // - Număr de alerte trimise
        // - Top 5 IP-uri cu cele mai multe accesări
    }
});
```

### Exercițiul 3: Detectare Network Sweep 🔍

**Obiectiv:** Detectează când un IP scanează același port pe multe destinații.

```rust
// Hint: Creează un nou struct
struct DestinationActivity {
    destinations: Vec<(String, u64)>,  // (IP dest, timestamp)
}

// Adaugă în DetectorScanuri:
struct DetectorScanuri {
    // ... câmpuri existente
    harta_destinatii: Arc<DashMap<(String, u16), DestinationActivity>>,
    // cheie = (IP sursă, Port destinație)
}

// TODO: Implementează logică de detecție
// Dacă un IP accesează același port pe 20+ destinații diferite → alertă
```

### Exercițiul 4: Export JSON 📝

**Obiectiv:** Salvează alertele într-un fișier JSON.

```rust
use std::fs::OpenOptions;
use std::io::Write;

async fn salveaza_alerta_json(alerta: &AlertaScan) -> Result<()> {
    // TODO:
    // 1. Serializează alerta în JSON cu serde_json
    // 2. Deschide fișier "alerts.json" în mod append
    // 3. Scrie JSON-ul în fișier
    // 4. Adaugă newline
    
    Ok(())
}
```

### Exercițiul 5: Rate Limiting per IP ⏱️

**Obiectiv:** Trimite maximum 1 alertă per IP la fiecare 5 minute.

```rust
// Adaugă în ActivitateaSursei:
struct ActivitateaSursei {
    // ... câmpuri existente
    ultima_alerta_trimisa: Option<u64>,  // timestamp ultima alertă
}

// În proceseaza_eveniment(), verifică:
if let Some(ultima) = activitate.ultima_alerta_trimisa {
    if timestamp_curent() - ultima < 300 {  // 5 minute
        return None;  // Prea devreme pentru altă alertă
    }
}
```

---

## 4. Dezvoltări Viitoare

### Nivel Începător 🌱

1. **Citire configurare din fișier TOML/YAML**
   - Învață: serde, file I/O
   - Biblioteci: `toml`, `serde_yaml`

2. **Logging în fișier**
   - Învață: file handling, error handling
   - Biblioteci: `tracing`, `tracing-subscriber`

3. **Comandă de help (--help)**
   - Învață: CLI arguments
   - Biblioteci: `clap`

### Nivel Intermediar 🌿

1. **Dashboard web simplu**
   - Învață: web servers, HTML
   - Biblioteci: `axum`, `askama` (templates)

2. **Baza de date pentru alerte**
   - Învață: SQL, async database
   - Biblioteci: `sqlx` (PostgreSQL/MySQL)

3. **Filtrare avansată (regex în configurare)**
   - Învață: pattern matching complex
   - Design pattern: Builder

4. **Metrici Prometheus**
   - Învață: observability, monitoring
   - Biblioteci: `prometheus`

### Nivel Avansat 🌳

1. **Machine Learning pentru detecție**
   - Învață: ML în Rust
   - Biblioteci: `smartcore`, `linfa`

2. **Clustering (rulare pe mai multe servere)**
   - Învață: distributed systems
   - Biblioteci: `redis` pentru state partajat

3. **Protocol buffer pentru performanță**
   - Învață: serialization eficientă
   - Biblioteci: `prost`

4. **Plugin system**
   - Învață: dynamic loading, traits avansate
   - Biblioteci: `libloading`

---

## 5. Resurse de Învățare

### Cărți 📚

1. **"The Rust Programming Language"** (The Book)
   - Gratuită online: https://doc.rust-lang.org/book/
   - Cea mai bună resursă pentru începători

2. **"Rust by Example"**
   - https://doc.rust-lang.org/rust-by-example/
   - Învățare prin exemple practice

3. **"Rustlings"**
   - https://github.com/rust-lang/rustlings
   - Exerciții interactive

### Cursuri Video 🎥

1. **Rustacean Station Podcast**
   - Interviuri cu developeri Rust

2. **Jon Gjengset pe YouTube**
   - Streaming de cod Rust avansat

3. **Let's Get Rusty**
   - Tutorial-uri pentru începători

### Comunitate 👥

1. **r/rust pe Reddit**
   - Comunitate activă și prietenoasă

2. **Rust Users Forum**
   - https://users.rust-lang.org/

3. **Discord-ul oficial Rust**
   - Chat în timp real

### Documentație 📖

1. **std docs** - https://doc.rust-lang.org/std/
2. **docs.rs** - Documentație pentru toate crate-urile
3. **Rust Cheat Sheet** - https://cheats.rs/

### Proiecte Practice 🛠️

După ce stăpânești acest proiect, încearcă:

1. **CLI tool** - crate manager, file converter
2. **Web scraper** - cu `reqwest` și `scraper`
3. **Chat server** - cu `tokio` și WebSockets
4. **Game** - cu `bevy` sau `macroquad`

---

## 🎯 Plan de Studiu Recomandat

### Săptămâna 1-2: Fundamentele
- [ ] Citește capitolele 1-10 din "The Book"
- [ ] Rulează și înțelege `main_educational_ro.rs`
- [ ] Completează exercițiile din secțiunea 1

### Săptămâna 3-4: Ownership și Borrowing
- [ ] Capitolele 4-5 din "The Book"
- [ ] Experimentează cu modificări în cod
- [ ] Implementează Exercițiul 1 (Whitelist)

### Săptămâna 5-6: Collections și Error Handling
- [ ] Capitolele 8-9 din "The Book"
- [ ] Implementează Exercițiile 2-3
- [ ] Înțelege flow-ul complet de erori

### Săptămâna 7-8: Async și Concurrency
- [ ] Capitolul 16 din "The Book"
- [ ] Documentația Tokio
- [ ] Implementează Exercițiile 4-5

### Săptămâna 9+: Proiecte Proprii
- [ ] Alege o dezvoltare viitoare
- [ ] Implementează feature complet
- [ ] Contribuie la proiecte open-source

---

## 💡 Sfaturi Finale

1. **Nu te grăbi** - Rust are o curbă de învățare mai abruptă, dar merită
2. **Citește mesajele compilatorului** - Sunt foarte detaliate și utile
3. **Scrie cod** - Teoria e importantă, dar practica e esențială
4. **Cere ajutor** - Comunitatea Rust e foarte prietenoasă
5. **Citește cod** - Explorează crate-uri populare pe GitHub

**Baftă la învățat Rust! 🦀**
