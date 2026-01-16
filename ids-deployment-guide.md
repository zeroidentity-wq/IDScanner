# 🛡️ Ghid Complet de Deployment - Rsyslog IDS (100% Independent)

## 📋 Cuprins
1. [Arhitectura Soluției](#arhitectura)
2. [De ce e 100% Sigur](#de-ce-sigur)
3. [Instalare Pas cu Pas](#instalare)
4. [Verificare Non-Interferență](#verificare)
5. [Concepte Rust pentru Începători](#concepte-rust)
6. [Troubleshooting](#troubleshooting)

---

## 🏗️ Arhitectura Soluției {#arhitectura}

```
┌─────────────────────────────────────────────────────────────┐
│  SURSE LOG (Firewall, Servere, Aplicații)                   │
└──────────────────────┬──────────────────────────────────────┘
                       │ syslog (514/UDP sau 514/TCP)
                       ▼
┌──────────────────────────────────────────────────────────────┐
│                    RSYSLOG SERVER                            │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Main Processing Pipeline                              │  │
│  │  ┌──────────────┐    ┌──────────────┐                 │  │
│  │  │  Parse logs  │ -> │  Filtering   │                 │  │
│  │  └──────────────┘    └──────┬───────┘                 │  │
│  │                              │                         │  │
│  │           ┌──────────────────┼──────────────────┐      │  │
│  │           │                  │                  │      │  │
│  │           ▼                  ▼                  ▼      │  │
│  │  ┌────────────────┐  ┌──────────────┐  ┌──────────┐  │  │
│  │  │   ArcSight     │  │ Local Files  │  │ IDS Copy │  │  │
│  │  │   Forward      │  │ /var/log/*   │  │ (ruleset)│  │  │
│  │  │  (ORIGINAL)    │  │              │  │          │  │  │
│  │  └────────┬───────┘  └──────────────┘  └────┬─────┘  │  │
│  │           │                                  │        │  │
│  │           │ Trimis                           │ call   │  │
│  │           │ imediat                          │ async  │  │
│  │           │ (prioritate)                     │ queue  │  │
│  └───────────┼──────────────────────────────────┼────────┘  │
└──────────────┼──────────────────────────────────┼───────────┘
               │                                  │
               │ TCP/TLS                          │ UNIX Socket
               │ (neatins)                        │ /var/run/ids.sock
               ▼                                  ▼
     ┌─────────────────┐              ┌──────────────────────┐
     │  ArcSight ESM   │              │    Rust IDS          │
     │  (SIEM Central) │              │  (Procesare locală)  │
     │                 │              │                      │
     │  - RAW logs     │              │  - Detectare scanări │
     │  - Original     │  ◄───CEF───  │  - Alerte trimise    │
     │  - Complet      │   (alerte)   │    doar la detecție  │
     └─────────────────┘              └──────────────────────┘
```

### 🔑 Puncte Cheie

- **Flux Paralel**: ArcSight primește log-uri DIRECT, IDS primește COPII
- **Prioritizare**: Forward către ArcSight are prioritate maximă
- **Izolare**: IDS-ul rulează în ruleset separat cu queue propriu
- **Zero Dependențe**: Dacă IDS pică, ArcSight nu e afectat
- **Zero Disk I/O**: IDS folosește doar RAM (DashMap în memorie)

---

## ✅ De ce e 100% Sigur {#de-ce-sigur}

### 1️⃣ **Ordinea de Procesare**
```
Rsyslog procesează în această ordine:
1. Parse mesaj
2. Forward către ArcSight (PRIORITATE 1)
3. Scriere în /var/log/* (PRIORITATE 2)  
4. Copy către IDS (PRIORITATE 3 - cel mai puțin important)
```

### 2️⃣ **Queue Asincron**
```bash
queue.type="LinkedList"        # Coadă asincronă
queue.size="10000"             # Buffer de 10k mesaje
queue.discardMark="9000"       # La 90% capacitate, începe să arunce
```

**Ce înseamnă?**
- Rsyslog NU așteaptă ca IDS-ul să proceseze
- Rsyslog scrie în queue și continuă imediat
- Dacă IDS-ul e lent, queue-ul bufferează
- Dacă queue-ul se umple, DOAR mesajele către IDS se aruncă
- ArcSight nu e afectat NICIODATĂ

### 3️⃣ **Timeout-uri Protectoare**
```bash
action.writeTimeout="1000"     # Max 1 secundă per write
action.resumeRetryCount="5"    # Max 5 încercări
action.resumeInterval="5"      # 5 sec între încercări
```

**Scenario de Failure:**
```
Situație: IDS-ul se blochează complet

Pas 1: Rsyslog încearcă să scrie în socket
Pas 2: După 1 secundă (timeout), marchează action ca "suspended"
Pas 3: Încercă din nou după 5 secunde (retry)
Pas 4: După 5 retry-uri eșuate, abandonează temporar
Pas 5: Continuă să proceseze log-uri NORMAL către ArcSight

REZULTAT: ArcSight primește TOATE log-urile, IDS pierde date (acceptabil)
```

### 4️⃣ **UNIX Socket vs Named Pipe (FIFO)**

| Caracteristică | Named Pipe (FIFO) | UNIX Socket | De ce Socket? |
|---------------|-------------------|-------------|---------------|
| **Blocant** | DA - poate bloca writer-ul | NU - async I/O | Socket protejează rsyslog |
| **Flow Control** | Manual | Automat (kernel) | Kernel gestionează bufferele |
| **Bidirectional** | NU | DA | Poți trimite comenzi înapoi |
| **Perms** | File-based | Socket-based | Mai granular control |

### 5️⃣ **Zero Disk I/O în IDS**

**Rust IDS folosește:**
```rust
// DashMap = HashMap thread-safe, în MEMORIE
scan_tracker: Arc<DashMap<String, ScanPattern>>

// Nu există:
// - File::open() pentru write
// - Database connections
// - Log rotation
// - Disk buffering
```

**De ce e important?**
- Disk I/O poate cauza blocking dacă disk-ul e lent
- RAM e predictibil și rapid
- Nu afectează sistemul de fișiere
- Nu competiție cu ArcSight pentru IOPS

---

## 🚀 Instalare Pas cu Pas {#instalare}

### Pas 1: Pregătire Sistem

```bash
# Update sistem
sudo apt update && sudo apt upgrade -y

# Instalează dependențe
sudo apt install -y rsyslog build-essential pkg-config libssl-dev

# Verifică că rsyslog rulează
sudo systemctl status rsyslog
```

### Pas 2: Instalare Rust

```bash
# Instalează Rust (rustup)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Reload environment
source $HOME/.cargo/env

# Verifică instalarea
rustc --version
cargo --version
```

### Pas 3: Compilare IDS

```bash
# Creează proiect
cargo new --bin rsyslog-ids
cd rsyslog-ids

# Editează Cargo.toml și adaugă dependencies:
cat > Cargo.toml << 'EOF'
[package]
name = "rsyslog-ids"
version = "2.0.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
chrono = "0.4"
regex = "1.10"
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.11", features = ["json"] }
dashmap = "5.5"
EOF

# Copiază codul IDS în src/main.rs (din artifact-ul anterior)

# Compilează (release mode = optimizat)
cargo build --release

# Binarul compilat e în: target/release/rsyslog-ids
```

### Pas 4: Instalare ca Serviciu

```bash
# Copiază binarul în sistem
sudo cp target/release/rsyslog-ids /usr/local/bin/
sudo chmod +x /usr/local/bin/rsyslog-ids

# Creează serviciu systemd
sudo tee /etc/systemd/system/rust-ids.service > /dev/null << 'EOF'
[Unit]
Description=Rsyslog Network Scan IDS
Documentation=https://github.com/your-repo/rsyslog-ids
After=network.target
Before=rsyslog.service
# IMPORTANT: IDS-ul trebuie să pornească ÎNAINTE de rsyslog
# pentru a crea socket-ul

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/rsyslog-ids
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Limitări de resurse (opțional)
MemoryLimit=512M
CPUQuota=50%

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/run

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload

# Activează și pornește
sudo systemctl enable rust-ids
sudo systemctl start rust-ids

# Verifică status
sudo systemctl status rust-ids
```

### Pas 5: Configurare Rsyslog

```bash
# Copiază configurația în rsyslog.d
sudo tee /etc/rsyslog.d/99-ids-unix-socket.conf > /dev/null << 'EOF'
# [Copiază conținutul din artifact-ul de configurare rsyslog]
EOF

# Verifică sintaxa
sudo rsyslogd -N1 -f /etc/rsyslog.conf

# Restart rsyslog
sudo systemctl restart rsyslog
```

### Pas 6: Verificare Inițială

```bash
# 1. Verifică că socket-ul e creat
ls -la /var/run/ids.sock
# Ar trebui: srwxr-xr-x 1 root root ... /var/run/ids.sock

# 2. Verifică că IDS primește date
sudo journalctl -u rust-ids -f

# 3. Trimite log de test
logger -p auth.warning "Test: SRC=1.2.3.4 DPT=22"

# 4. Verifică în IDS logs - ar trebui să vezi mesajul procesat
```

---

## 🔍 Verificare Non-Interferență {#verificare}

### Test 1: Baseline ArcSight

```bash
# Înainte de a activa IDS, notează rata de evenimente în ArcSight
# Ex: 1000 evenimente/minut de la acest server

# Pe server
logger -p auth.info "Baseline test $(date)"

# În ArcSight: caută "Baseline test" 
# Notează timestamp-ul - trebuie să fie < 5 secunde
```

### Test 2: Cu IDS Activ

```bash
# Activează IDS
sudo systemctl start rust-ids

# Trimite același test
logger -p auth.info "With IDS test $(date)"

# În ArcSight: verifică timestamp
# TREBUIE să fie similar (< 5 secunde diferență)
```

### Test 3: IDS Oprit Complet

```bash
# Oprește IDS
sudo systemctl stop rust-ids

# Șterge socket-ul
sudo rm -f /var/run/ids.sock

# Trimite log
logger -p auth.info "IDS stopped test $(date)"

# Verifică rsyslog logs - ar trebui să vezi warning
sudo tail -f /var/log/syslog | grep -i "ids\|error\|suspended"

# În ArcSight: mesajul TREBUIE să ajungă NORMAL
# Dacă nu ajunge = PROBLEMA! Ai configurat greșit
```

### Test 4: Stres Test

```bash
# Generează 10,000 mesaje rapid
for i in {1..10000}; do
    logger -p auth.info "Stress test message $i"
done

# Verifică în ArcSight: trebuie să vezi ~10,000 evenimente noi
# Verifică IDS: poate procesa un subset (acceptabil)

# Compară contoarele
# ArcSight: SELECT COUNT(*) WHERE source = 'acest-server' 
#           AND time > 'ultimul minut'
# Ar trebui: ~10,000

# IDS: journalctl -u rust-ids | grep "total_events"
# Poate fi mai mic (e OK, queue-ul a aruncat excesul)
```

### Test 5: Recovery după Failure

```bash
# Simulează crash IDS
sudo kill -9 $(pgrep rsyslog-ids)

# Trimite mesaje în timpul down-time
for i in {1..100}; do logger "During downtime $i"; done

# Systemd ar trebui să repornească IDS automat după 5 sec
sleep 6

# Verifică recovery
sudo systemctl status rust-ids

# În ArcSight: TOATE cele 100 mesaje trebuie să fie prezente
```

---

## 📚 Concepte Rust pentru Începători {#concepte-rust}

### 1. Ownership și Borrowing

```rust
// Rust are un sistem unic de ownership (proprietate)

// Exemplu simplu:
let s1 = String::from("hello");  // s1 "deține" string-ul
let s2 = s1;                     // Ownership se MUTĂ la s2
// println!("{}", s1);           // ❌ EROARE! s1 nu mai e valid

// Pentru a împărtăși date:
let s1 = String::from("hello");
let s2 = &s1;                    // s2 "împrumută" s1 (borrowing)
println!("{}", s1);              // ✅ OK! s1 e încă valid
```

**În codul nostru:**
```rust
let ids = Arc::new(RsyslogIDS::new(config));
//        ^^^^^^^^ Arc = Atomic Reference Counter
//                 Permite MULTIPLE ownership-uri

let ids_cleanup = Arc::clone(&ids);  // Clone-ază REFERINȚA, nu datele
// Ambele (ids și ids_cleanup) pot accesa același obiect
```

### 2. Option și Result

```rust
// Option<T> = poate fi Some(value) sau None
// Folosit când ceva poate lipsi

fn parse_port(s: &str) -> Option<u16> {
    s.parse().ok()  // ok() convertește Result în Option
}

let port = parse_port("80");
match port {
    Some(p) => println!("Port: {}", p),
    None => println!("Invalid port"),
}

// Syntax sugar: if let
if let Some(p) = parse_port("80") {
    println!("Port: {}", p);
}

// Chaining cu ?
fn example() -> Option<u16> {
    let s = "80";
    let port = s.parse().ok()?;  // ? = returnează None dacă e eroare
    Some(port)
}
```

**În codul nostru:**
```rust
if let Some(entry) = self.parse_syslog_line(&line) {
    // Parsarea a reușit, procesează entry
}
// Dacă parse_syslog_line returnează None, skipăm linia
```

### 3. Match Expressions

```rust
// Match = switch on steroids

let number = 42;
match number {
    1 => println!("One"),
    2..=10 => println!("Between 2 and 10"),  // Range inclusive
    n if n > 100 => println!("Big: {}", n),  // Guard condition
    _ => println!("Other"),                  // Default case
}
```

**În codul nostru:**
```rust
let severity = match pattern.unique_ports.len() {
    n if n >= 100 => 10,  // Dacă >= 100 porturi, severitate 10
    n if n >= 50 => 8,    // Dacă >= 50 porturi, severitate 8
    n if n >= 20 => 6,    // etc.
    _ => 4,               // Default
};
```

### 4. Closures (Funcții Anonime)

```rust
// Closure = funcție inline, poate "captura" variabile din context

let x = 10;
let add_x = |y| x + y;  // Closure care capturează x
println!("{}", add_x(5));  // Output: 15

// În Rust, closures pot fi:
// - FnOnce: consumă variabilele (move)
// - FnMut: modifică variabilele (mutable borrow)
// - Fn: doar citește (immutable borrow)
```

**În codul nostru:**
```rust
tokio::spawn(async move {
    //           ^^^^ move = mută ownership în closure
    ids_cleanup.cleanup_task().await;
});
// ids_cleanup e "mutat" în thread-ul nou
```

### 5. Async/Await

```rust
// async/await = programare asincronă (non-blocking)

async fn fetch_data() -> String {
    // Simulează operație I/O
    tokio::time::sleep(Duration::from_secs(1)).await;
    "data".to_string()
}

#[tokio::main]  // Macro care creează runtime async
async fn main() {
    let data = fetch_data().await;  // await = așteaptă rezultatul
    println!("{}", data);
}
```

**În codul nostru:**
```rust
async fn monitor_unix_socket(&self) -> std::io::Result<()> {
    let stream = UnixStream::connect(&path).await;
    //                                      ^^^^^ await = nu blochează thread-ul
    
    while let Some(line) = lines.next_line().await {
        //                                   ^^^^^ citire async
        // Procesează linia
    }
}
```

### 6. DashMap (Concurrent HashMap)

```rust
use dashmap::DashMap;

// HashMap normal (NOT thread-safe)
use std::collections::HashMap;
let mut map = HashMap::new();
map.insert("key", "value");

// DashMap (thread-safe, fără Mutex global)
let map = DashMap::new();
map.insert("key", "value");  // Nu trebuie mut!

// Multiple thread-uri pot scrie simultan
map.entry("key")
    .and_modify(|v| *v += 1)   // Dacă există, incrementează
    .or_insert(0);             // Dacă nu există, inserează 0
```

---

## 🔧 Troubleshooting {#troubleshooting}

### Problem 1: Socket-ul nu e creat

```bash
# Simptom
ls /var/run/ids.sock
# ls: cannot access '/var/run/ids.sock': No such file or directory

# Soluție
# 1. Verifică că IDS-ul rulează
sudo systemctl status rust-ids

# 2. Verifică logs pentru erori
sudo journalctl -u rust-ids -n 50

# 3. Verifică permisiuni
sudo ls -la /var/run/
# Ar trebui să poți crea fișiere acolo
```

### Problem 2: Rsyslog nu se conectează la socket

```bash
# Simptom
sudo tail /var/log/syslog | grep -i "error\|ids"
# rsyslogd: action 'ids_mirror' suspended...

# Soluție
# 1. Verifică că socket-ul există ȘI e socket (nu fișier)
file /var/run/ids.sock
# Ar trebui: socket

# 2. Test manual de conectare
sudo nc -U /var/run/ids.sock
# Dacă nu se conectează = IDS-ul nu ascultă

# 3. Restart în ordine corectă
sudo systemctl restart rust-ids
sleep 2
sudo systemctl restart rsyslog
```

### Problem 3: IDS primește date dar nu detectează

```bash
# Simptom
journalctl -u rust-ids -f
# Vezi "lines_processed" incrementare, dar zero alerte

# Soluție
# 1. Verifică pattern-urile regex
# Trimite un log care știi sigur că ar trebui să se potrivească
logger -p auth.info "SRC=192.168.1.100 DPT=22 PROTO=TCP"

# 2. Adaugă debug logging temporar în cod
# În parse_syslog_line(), adaugă:
println!("Trying to parse: {}", line);

# 3. Verifică pragurile
# Poate sunt setate prea sus?
# port_scan_threshold: 10 <- încearcă 5
# time_window_secs: 60 <- încearcă 120
```

### Problem 4: Memorie crescândă

```bash
# Simptom
ps aux | grep rsyslog-ids
# VSZ/RSS cresc constant

# Soluție
# 1. Verifică cleanup task-ul
journalctl -u rust-ids | grep CLEANUP
# Ar trebui să vezi cleanup la fiecare 5 min

# 2. Verifică dimensiunea tracker-ului
# Adaugă în stats_task():
println!("Tracker size: {}", self.scan_tracker.len());

# 3. Reduce time_window dacă e nevoie
# cleanup_interval_secs: 300 <- reduce la 180
```

### Problem 5: ArcSight primește duplicate

```bash
# Simptom
# În ArcSight vezi același mesaj de 2 ori

# Cauză
# Ai configurat greșit rsyslog - trimite și original și copie

# Verificare
sudo rsyslogd -N1 -f /etc/rsyslog.conf | grep -A10 "ids_mirror"

# Soluție
# Asigură-te că ruleset-ul are "stop" la final:
ruleset(name="ids_mirror") {
    action(...)
    stop  # <-- IMPORTANT!
}
```

---

## 📊 Monitorizare Continuă

### Metrics de urmărit

```bash
# 1. Rate de evenimente în ArcSight
# Ar trebui constant (ex: 1000/min)

# 2. IDS throughput
journalctl -u rust-ids | grep "Event rate"

# 3. Rsyslog queue size
# Instalează rsyslog-stats
sudo apt install rsyslog-pstats
# Apoi monitorizează /var/log/rsyslog-stats.log

# 4. Sistem resources
htop
# CPU al IDS-ului ar trebui < 10%
# Memorie < 500MB
```

### Alerting recomandat

- ❌ IDS oprit > 5 minute
- ❌ rsyslog suspended action "ids_mirror"
- ✅ ArcSight primește < X evenimente (drop rate)
- ⚠️ IDS memory > 1GB (potential memory leak)

---

## 🎯 Concluzie

Această arhitectură garantează:
- ✅ **Zero impact pe ArcSight** - folosim copii, nu redirecționări
- ✅ **Resilient** - dacă IDS pică, ArcSight continuă normal
- ✅ **Performant** - zero disk I/O, doar RAM
- ✅ **Scalabil** - poți adăuga multiple IDS-uri pe diferite servere
- ✅ **Maintainable** - cod curat, bine documentat, ușor de înțeles

Pentru întrebări sau probleme, consultă logs și folosește testele de mai sus!