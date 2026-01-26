# 🦀 Ghid Complet: IDS Rsyslog în Rust

## 📚 Cuprins

1. [Introducere în Proiect](#introducere)
2. [Ce Vei Învăța](#ce-vei-invata)
3. [Concepte Rust Fundamentale](#concepte-rust)
4. [Arhitectura Proiectului](#arhitectura)
5. [Anatomia Codului - Linie cu Linie](#anatomia-codului)
6. [Concepte de Securitate](#concepte-securitate)
7. [Testare și Debugging](#testare)
8. [Exerciții Practice](#exercitii)
9. [Resurse Suplimentare](#resurse)

---

## 🎯 Introducere în Proiect {#introducere}

### Ce Face Acest Program?

Imaginează-te că ai o casă (rețeaua ta) și vrei să știi dacă cineva încearcă să-ți verifice toate ușile și ferestrele (porturile) pentru a găsi una deschisă. Acest program este ca un **paznic vigilent** care:

1. **Monitorizează** - Citește jurnalele de securitate (logs) de la firewall-uri și servere
2. **Analizează** - Identifică pattern-uri suspecte (cineva bate la prea multe uși)
3. **Alertează** - Trimite alarme către sistemul de securitate (ArcSight)

### De Ce Rust?

```rust
// Rust îți garantează:
// ✅ Memorie sigură (nu poți accesa memorie invalidă)
// ✅ Paralelism sigur (thread-safe by design)
// ✅ Zero-cost abstractions (performanță ca C/C++)
// ✅ Previne 70% din bug-urile de securitate din C/C++
```

---

## 🎓 Ce Vei Învăța {#ce-vei-invata}

### Concepte Rust (Nivel Beginner → Intermediate)

- [ ] **Ownership și Borrowing** - Cum Rust gestionează memoria fără garbage collector
- [ ] **Structs și Traits** - Programare orientată pe date
- [ ] **Result și Option** - Gestionarea erorilor funcțional
- [ ] **Pattern Matching** - Switch-uri pe steroizi
- [ ] **Async/Await** - Programare asincronă modernă
- [ ] **Arc și Mutex** - Partajare date între thread-uri
- [ ] **Lifetimes** - Când Rust garantează că datele sunt valide

### Concepte de Securitate

- [ ] **Intrusion Detection** - Cum detectezi atacuri
- [ ] **Port Scanning** - Tehnici de scanare și detectare
- [ ] **CEF Format** - Standard pentru evenimente de securitate
- [ ] **SIEM Integration** - Integrare cu sisteme enterprise
- [ ] **Network Monitoring** - Monitorizare trafic rețea

### Concepte Sistem

- [ ] **Unix Sockets** - Comunicare inter-proces
- [ ] **Rsyslog** - Sistemul de logging din Linux
- [ ] **Regex** - Parsare text avansată
- [ ] **Concurrent Programming** - Programare paralelă

---

## 🧱 Concepte Rust Fundamentale {#concepte-rust}

### 1. Ownership - Regula de Aur a Rust

```rust
// CONCEPTUL PRINCIPAL: Fiecare valoare are UN SINGUR PROPRIETAR

fn exemplu_ownership() {
    let mesaj = String::from("Salut");  // mesaj DEȚINE String-ul
    
    // ❌ GREȘIT - mută ownership-ul
    let alt_mesaj = mesaj;
    // println!("{}", mesaj);  // EROARE! mesaj nu mai e valid
    
    // ✅ CORECT - clonează sau împrumută
    let mesaj2 = String::from("Salut");
    let alt_mesaj2 = mesaj2.clone();  // Face o copie
    println!("{} {}", mesaj2, alt_mesaj2);  // Ambele valide!
}

// CUM SE APLICĂ ÎN IDS:
fn proceseaza_intrare(intrare: IntrareJurnal) {  // Preia ownership
    // intrare e mutat aici, nu mai e valid în apelant
}

fn proceseaza_intrare_imprumut(intrare: &IntrareJurnal) {  // Împrumută
    // intrare e doar citit, rămâne valid în apelant
}
```

**Analogie**: Ownership e ca o carte din bibliotecă:
- **Move** = Dai cartea cuiva (tu n-o mai ai)
- **Clone** = Faci o fotocopie (amândoi aveți câte una)
- **Borrow** = Împrumuți cartea (o ai înapoi când termină)

### 2. Borrowing - Împrumut Sigur

```rust
// REGULA: Poți avea MULTE &T (read-only) SAU O SINGURĂ &mut T (read-write)

fn exemplu_borrowing() {
    let mut numar = 42;
    
    // ✅ CORECT - multe referințe read-only
    let ref1 = &numar;
    let ref2 = &numar;
    println!("{} {}", ref1, ref2);
    
    // ✅ CORECT - o singură referință mutabilă
    let ref_mut = &mut numar;
    *ref_mut += 10;  // * = dereferențiere (accesează valoarea)
    
    // ❌ GREȘIT - nu poți mixa
    // let ref3 = &numar;      // read-only
    // let ref_mut2 = &mut numar;  // EROARE! deja există &numar
}

// ÎN IDS-UL NOSTRU:
fn analizeaza_si_detecteaza(&self, intrare: IntrareJurnal) {
    //                      ^---- &self = împrumut read-only al self
    
    let ip = intrare.ip_sursa.clone();  // Clone pentru a evita move
    
    // Actualizează pattern (necesită acces mutabil)
    self.urmaritor_scanari
        .entry(ip.clone())
        .and_modify(|model| {  // |model| = closure, primește &mut
            model.numar_conexiuni += 1;  // Modifică direct
        });
}
```

**De Ce E Important?**
- Previne **data races** (2+ thread-uri modifică aceeași dată simultan)
- Previne **use-after-free** (accesezi memorie ștearsă)
- Garantat la **compile time** (zero overhead runtime!)

### 3. Result și Option - Gestionarea Erorilor

```rust
// Option<T> = Poate fi ceva SAU nimic
// Result<T, E> = Succes SAU Eroare

fn exemplu_option_result() {
    // Option - când ceva poate lipsi
    let numere = vec![1, 2, 3];
    let primul = numere.get(0);  // Option<&i32>
    
    match primul {
        Some(valoare) => println!("Primul: {}", valoare),
        None => println!("Lista e goală"),
    }
    
    // Operator ? = propagă eroarea automat
    fn citeste_fisier() -> Result<String, std::io::Error> {
        let continut = std::fs::read_to_string("fisier.txt")?;
        //                                                   ^--- Dacă e Err, returnează direct
        Ok(continut)
    }
}

// ÎN IDS:
fn parseaza_linie_syslog(&self, linie: &str) -> Option<IntrareJurnal> {
    let regex_asa = Regex::new(r"pattern").ok()?;
    //                                        ^--- Convertește Result în Option
    //                                            ^--- Dacă e None, returnează None
    
    if let Some(potriviri) = regex_asa.captures(linie) {
        let ip_sursa = potriviri.get(2)?.as_str().to_string();
        //                             ^--- Dacă grupul 2 nu există, returnează None
        
        Some(IntrareJurnal { /* ... */ })
    } else {
        None  // Nicio potrivire găsită
    }
}
```

**Avantaje vs Exceptions (C++/Java)**:
- Compilatorul **forțează** gestionarea erorilor
- Nu există **panică ascunsă** (trebuie să gestionezi explicit)
- **Zero overhead** - Result e doar un enum

### 4. Pattern Matching - Puterea lui `match`

```rust
// match = switch ultra-puternic + destructuring

enum TipEveniment {
    ScanarePorturi { ip: String, porturi: Vec<u16> },
    RafalaConexiuni { ip: String, numar: usize },
    Necunoscut,
}

fn proceseza_eveniment(eveniment: TipEveniment) {
    match eveniment {
        // Destructurează direct în variabile
        TipEveniment::ScanarePorturi { ip, porturi } => {
            println!("Scanare de la {} pe {} porturi", ip, porturi.len());
        }
        
        // Guard condition
        TipEveniment::RafalaConexiuni { ip, numar } if numar > 100 => {
            println!("ALERT: {} conexiuni de la {}", numar, ip);
        }
        
        // Catch-all
        _ => println!("Eveniment ignorat"),
    }
}

// ÎN IDS - Pattern cu if let:
if let Some(potriviri) = regex_asa.captures(linie) {
    // Execută doar dacă e Some, altfel skip
    let ip = potriviri.get(2)?.as_str();
}

// Echivalent cu:
match regex_asa.captures(linie) {
    Some(potriviri) => {
        let ip = potriviri.get(2)?.as_str();
    }
    None => {}  // Nu face nimic
}
```

### 5. Structs - Programare Orientată pe Date

```rust
// Struct = colecție de date înrudite

#[derive(Debug, Clone)]  // Macro-uri = cod generat automat
struct IntrareJurnal {
    marca_timp: DateTime<Utc>,
    ip_sursa: String,
    port_destinatie: u16,
}

// Implementare metodă pentru struct
impl IntrareJurnal {
    // Funcție asociată (ca static în Java)
    fn nou(ip: String, port: u16) -> Self {
        Self {  // Self = IntrareJurnal
            marca_timp: Utc::now(),
            ip_sursa: ip,
            port_destinatie: port,
        }
    }
    
    // Metodă pe instanță
    fn afiseaza(&self) {  // &self = împrumută instanța
        println!("IP: {}, Port: {}", self.ip_sursa, self.port_destinatie);
    }
}

// Folosire:
let intrare = IntrareJurnal::nou("1.2.3.4".to_string(), 80);
intrare.afiseaza();
```

### 6. Arc și DashMap - Thread Safety

```rust
use std::sync::Arc;
use dashmap::DashMap;

// Arc = Atomic Reference Counter
// Permite mai mulți "proprietari" ai aceluiași obiect
// Thread-safe prin atomic operations

fn exemplu_arc() {
    let date = Arc::new(vec![1, 2, 3]);
    
    let date_clone1 = Arc::clone(&date);  // Nu clonează Vec-ul!
    let date_clone2 = Arc::clone(&date);  // Doar incrementează counter
    
    // Acum avem 3 referințe către același Vec
    // Când ultima referință dispare, Vec-ul e șters
}

// DashMap = HashMap thread-safe fără lock global
// ÎN IDS:
struct MotorIDS {
    // Arc permite partajare între thread-uri
    urmaritor_scanari: Arc<DashMap<String, ModelScanare>>,
    //                 ^^^                ^^^^^^  ^^^^^^^^^^^
    //                  |                   |          |
    //          Thread-safe pointer    Cheie (IP)  Valoare
}

// DashMap permite:
self.urmaritor_scanari.entry(ip)
    .and_modify(|model| {  // Lock automat doar pe acest entry
        model.numar_conexiuni += 1;
    })
    .or_insert_with(|| ModelScanare::new());
```

**De Ce Arc și Nu Rc?**
- **Rc** (Reference Counted) - Nu e thread-safe, mai rapid
- **Arc** (Atomic Rc) - Thread-safe, puțin mai lent
- IDS-ul rulează pe **multiple thread-uri** → Arc obligatoriu

### 7. Async/Await - Programare Asincronă

```rust
// async = funcția poate aștepta fără a bloca thread-ul
// await = așteaptă ca o operație async să termine

async fn citeste_de_la_socket() -> std::io::Result<String> {
    let mut flux = UnixStream::connect("/var/run/ids.sock").await?;
    //                                                      ^^^^^^
    //                              Cedează controlul până e conectat
    
    let mut buffer = String::new();
    flux.read_to_string(&mut buffer).await?;
    Ok(buffer)
}

// Tokio runtime - motorul async
#[tokio::main]  // Creează runtime-ul automat
async fn main() {
    // spawn = pornește task în background
    tokio::spawn(async {
        loop {
            citeste_de_la_socket().await.unwrap();
        }
    });
    
    // Main thread poate face altceva
}

// DE CE ASYNC ÎN IDS?
// ✅ Multe conexiuni simultane (rsyslog, ArcSight, cleanup)
// ✅ Nu blochezi thread-ul când aștepți I/O
// ✅ Scalabilitate - mii de conexiuni pe un thread
```

**Async vs Thread-uri**:
```
THREAD-URI CLASICE:
[Thread 1] ████████████████ (blochează la I/O)
[Thread 2] ████████████████ (blochează la I/O)
Overhead: ~2MB/thread + context switches

ASYNC (Tokio):
[Thread 1] ██_██_██_██_██_█ (cedează când așteaptă)
           Task1 Task2 Task3 (multiplexare pe același thread)
Overhead: ~2KB/task, zero context switches
```

---

## 🏗️ Arhitectura Proiectului {#arhitectura}

### Diagrama de Flux

```
┌─────────────────────────────────────────────────────────┐
│                   FLUX DATE IDS                         │
└─────────────────────────────────────────────────────────┘

   Dispozitive        rsyslog           MotorIDS
   (Firewall,   ───▶  daemon    ───▶    (Rust)
   Servere)              │                  │
                         │                  ├─▶ Parsare
                         │                  │   (Regex)
                         │                  │
                         │                  ├─▶ Analiză
                         │                  │   (Pattern Matching)
                         ▼                  │
                   /var/log/syslog         ├─▶ Alertare
                   (backup)                 │   (CEF → ArcSight)
                                            │
                                            └─▶ Curățare
                                                (Memory Management)
```

### Structura Modulară

```rust
┌──────────────────────────────────────────┐
│           MAIN PROGRAM                   │
├──────────────────────────────────────────┤
│  • Configurare                           │
│  • Pornire task-uri paralele             │
│  • Gestionare erori                      │
└────────────┬─────────────────────────────┘
             │
    ┌────────┴────────┐
    │                 │
┌───▼────────┐  ┌────▼──────────┐
│ MotorIDS   │  │  Task-uri     │
├────────────┤  │  Background   │
│• Parsare   │  ├───────────────┤
│• Detecție  │  │• task_curatare│
│• Alertare  │  │• task_statistici
└────────────┘  └───────────────┘
      │
      ├─▶ IntrareJurnal (struct date)
      ├─▶ ModelScanare (tracking state)
      ├─▶ EvenimentCEF (format ArcSight)
      └─▶ ConfiguratieIDS (settings)
```

### Fluxul unei Linii de Log

```
1. PRIMIRE
   rsyslog ─[Unix Socket]─▶ MotorIDS::gestioneaza_conexiune()
                              │
2. PARSARE                    ▼
   "SRC=1.2.3.4 DPT=22" ──▶ parseaza_linie_syslog()
                              │
                              ▼
   IntrareJurnal {
       ip_sursa: "1.2.3.4",
       port_destinatie: 22,
       ...
   }
                              │
3. ANALIZĂ                    ▼
   analizeaza_si_detecteaza()
       │
       ├─▶ Verifică IP în DashMap
       ├─▶ Actualizează ModelScanare
       ├─▶ Verifică praguri (10 porturi/60s?)
       │
4. DECIZIE                    ▼
   Dacă prag depășit ──▶ creaza_alerta_cef()
                              │
5. ALERTARE                   ▼
   trimite_catre_arcsight() ─▶ [CEF Format] ─▶ ArcSight
```

---

## 🔬 Anatomia Codului - Linie cu Linie {#anatomia-codului}

### Secțiunea 1: Definirea Structurilor

```rust
#[derive(Debug, Clone)]
struct IntrareJurnal {
    marca_timp: DateTime<Utc>,
    nume_gazda: String,
    ip_sursa: String,
    port_destinatie: u16,
    protocol: String,
    actiune: String,
}
```

**Explicație Detaliată**:

```rust
#[derive(Debug, Clone)]
// ^^^^ Atribut (Attribute) = instrucțiuni pentru compilator
// 
// Debug = generează cod pentru fmt::Debug trait
//   Permite: println!("{:?}", intrare);
//   
// Clone = generează metodă clone()
//   Permite: let copie = intrare.clone();
```

```rust
marca_timp: DateTime<Utc>,
//          ^^^^^^^^^^^^^^
//          Tip din crate-ul chrono
//          DateTime = dată + timp
//          <Utc> = timezone UTC (parametru generic)
```

```rust
port_destinatie: u16,
//               ^^^ 
//               u = unsigned (fără semn)
//               16 = 16 biți (0-65535)
//               Porturile sunt 0-65535, deci u16 perfect
```

**De Ce Aceste Tipuri?**

| Câmp | Tip | Motivație |
|------|-----|-----------|
| `marca_timp` | `DateTime<Utc>` | Precisie nanosecundă, timezone aware |
| `nume_gazda` | `String` | Alocată pe heap, lungime variabilă |
| `ip_sursa` | `String` | Mai ușor de manipulat decât array de bytes |
| `port_destinatie` | `u16` | 2 bytes suficienți pentru 0-65535 |
| `protocol` | `String` | "TCP", "UDP", "SSH" - lungime variabilă |
| `actiune` | `String` | "RESPINS", "ARUNCAT" - variabil |

### Secțiunea 2: Parsarea cu Regex

```rust
fn parseaza_linie_syslog(&self, linie: &str) -> Option<IntrareJurnal> {
    let regex_iptables = Regex::new(
        r"SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+).*PROTO=(\w+)"
    ).ok()?;
    
    if let Some(potriviri) = regex_iptables.captures(linie) {
        let ip_sursa = potriviri.get(1)?.as_str().to_string();
        // ...
    }
}
```

**Explicație Regex Pas cu Pas**:

```
Pattern: r"SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+).*PROTO=(\w+)"
         ^                                                 ^
         |                                                 |
    r = raw string (\ nu e escape character)

Defalcat:
SRC=                    Literalmente "SRC="
(\d+\.\d+\.\d+\.\d+)   Grup 1: IP address
                        \d+ = una sau mai multe cifre
                        \. = punct literal (\ escapează .)
.*                      Zero sau mai multe caractere (orice)
DPT=(\d+)              Grup 2: Port (cifre)
.*                      
PROTO=(\w+)            Grup 3: Protocol (litere/cifre)
                        \w = [a-zA-Z0-9_]
```

**Exemplu de Parsare**:

```
Input:  "Jan 26 10:30:45 firewall kernel: SRC=192.168.1.100 DST=10.0.0.1 DPT=22 PROTO=TCP"
                                            ^^^^^^^^^^^^^^^^          ^^        ^^^
                                            Grup 1                    Grup 2    Grup 3

potriviri.get(1) = Some("192.168.1.100")
potriviri.get(2) = Some("22")
potriviri.get(3) = Some("TCP")
```

**Operatori Speciali**:

```rust
.ok()?
// ^^^^
// .ok() convertește Result<T, E> în Option<T>
//   Ok(val) → Some(val)
//   Err(_) → None
//
// ? propagă None (early return)
//   Dacă e None, funcția returnează None imediat

potriviri.get(1)?
//              ^
// get() returnează Option<Match>
// ? transformă None în return None
```

### Secțiunea 3: Detecția Pattern-urilor

```rust
fn analizeaza_si_detecteaza(&self, intrare: IntrareJurnal) -> Option<Vec<EvenimentCEF>> {
    let mut alerte = Vec::new();
    let ip = intrare.ip_sursa.clone();
    
    // Actualizează sau inserează
    self.urmaritor_scanari
        .entry(ip.clone())
        .and_modify(|model| {
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
}
```

**Flow Diagram**:

```
IP există în DashMap?
    │
    ├─▶ DA
    │    │
    │    └─▶ and_modify() ──▶ Actualizează ModelScanare
    │                          • numar_conexiuni++
    │                          • Adaugă port la porturi_unice
    │
    └─▶ NU
         │
         └─▶ or_insert_with() ──▶ Creează ModelScanare nou
                                   • prima_aparitie = now
                                   • porturi_unice = [port]
```

**De Ce `and_modify` + `or_insert_with`?**

```rust
// ALTERNATIVA 1: Verificare manuală (GREȘIT în context multi-thread)
if self.urmaritor_scanari.contains_key(&ip) {
    // ❌ RACE CONDITION! Între contains_key și get_mut,
    //    alt thread poate șterge entry-ul
    let mut model = self.urmaritor_scanari.get_mut(&ip).unwrap();
    model.numar_conexiuni += 1;
} else {
    self.urmaritor_scanari.insert(ip, ModelScanare::new());
}

// ALTERNATIVA 2: DashMap entry API (✅ CORECT - Atomic)
self.urmaritor_scanari
    .entry(ip)           // Lock pe acest entry
    .and_modify(|model| {  // Dacă există
        model.numar_conexiuni += 1;
    })
    .or_insert_with(|| {  // Dacă nu există
        ModelScanare::new()
    });
    // Unlock automat aici
```

**Detecția Scanării**:

```rust
if model.porturi_unice.len() >= self.configuratie.prag_scanare_porturi 
    && diferenta_timp <= self.configuratie.fereastra_timp_secunde as i64 {
    
    // ALERTĂ!
}
```

```
EXEMPLU:
Configurație: prag_scanare_porturi = 10, fereastra_timp = 60s

IP 1.2.3.4 accesează:
Timp  Port
----  ----
10:00  22  ─┐
10:05  80   │
10:10  443  │
10:15  8080 │
10:20  3306 │ 9 porturi în 60s → OK (sub prag)
10:25  5432 │
10:30  6379 │
10:35  8888 │
10:40  3000 ─┘

10:45  9000 ─→ ALERTĂ! 10 porturi în 60s (prima_aparitie=10:00, ultima=10:45)
```

### Secțiunea 4: Async și Tokio

```rust
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let ids = Arc::new(MotorIDS::nou(configuratie));
    
    // Task 1: Curățare periodică
    let ids_curatare = Arc::clone(&ids);
    tokio::spawn(async move {
        ids_curatare.task_curatare().await;
    });
    
    // Task 2: Statistici
    let ids_statistici = Arc::clone(&ids);
    tokio::spawn(async move {
        ids_statistici.task_statistici().await;
    });
    
    // Main task: Socket listener
    ids.porneste_ascultator_unix().await
}
```

**Explicație Detaliată**:

```rust
#[tokio::main]
// Macro care transformă:
async fn main() { ... }

// În:
fn main() {
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(async { ... })
}
```

```rust
tokio::spawn(async move {
//           ^^^^^
//           Bloc async = Future care va fi executat
    
    ids_curatare.task_curatare().await;
    //           ^^^^^^^^^^^^^^^ returnează Future
    //                          ^^^^^^ așteaptă execuția
});
```

**Diferența dintre `async` și `move`**:

```rust
// async = funcția returnează Future
async fn exemplu() -> i32 {
    42
}
// exemplu() returnează Future<Output = i32>
// exemplu().await returnează i32

// move = closure preia ownership
let x = 5;
let closure = move || {  // x e mutat în closure
    println!("{}", x);
};
// x nu mai e valid aici
```

**Arc::clone în Context Async**:

```rust
let ids = Arc::new(MotorIDS::nou(config));
// ids = Arc<MotorIDS>
// Counter: 1

let ids_curatare = Arc::clone(&ids);
// Counter: 2 (ids și ids_curatare pointează la același MotorIDS)

tokio::spawn(async move {
    // ids_curatare e mutat în task
    // Task-ul "deține" acum o referință către MotorIDS
    ids_curatare.task_curatare().await;
    // Când task-ul termină, counter scade
});

// ids încă valid aici (Counter încă >= 1)
```

**Vizualizare Thread-uri Tokio**:

```
┌─────────────────────────────────────┐
│     Tokio Runtime (1-4 threads)     │
├─────────────────────────────────────┤
│                                     │
│  [Thread 1]                         │
│   ├─▶ Task: task_curatare()        │
│   ├─▶ Task: task_statistici()      │
│   └─▶ Task: porneste_ascultator()  │
│                                     │
│  [Thread 2]                         │
│   ├─▶ Task: gestioneaza_conexiune()│
│   └─▶ Task: gestioneaza_conexiune()│
│                                     │
└─────────────────────────────────────┘

Tokio face "work stealing" - dacă un thread e liber,
preia task-uri de la thread-urile ocupate.
```

---

## 🔐 Concepte de Securitate {#concepte-securitate}

### 1. Ce Este Port Scanning?

**Definiție**: Procesul prin care un atacator testează porturile unui sistem pentru a identifica servicii vulnerabile.

**Tipuri de Scanări**:

```
1. SCANARE ORIZONTALĂ (ce detectăm noi)
   Un IP → Mai multe porturi pe același host
   
   Atacator                    Țintă
   1.2.3.4  ───[port 22]───▶  Target
            ───[port 80]───▶  Target
            ───[port 443]──▶  Target
            ───[port 8080]─▶  Target
   
   Indiciu: Reconnaissance (recunoaștere)

2. SCANARE VERTICALĂ
   Un IP → Același port pe mai multe hosturi
   
   Atacator                    Ținte
   1.2.3.4  ───[port 22]───▶  10.0.0.1
            ───[port 22]───▶  10.0.0.2
            ───[port 22]───▶  10.0.0.3
   
   Indiciu: Căutare serviciu specific (ex: SSH)

3. SCANARE DISTRIBUITĂ
   Mai multe IP-uri → Un host
   
   Atacatori               Țintă
   1.2.3.4  ─┐
   5.6.7.8  ─┼─[diverse porturi]─▶  Target
   9.8.7.6  ─┘
   
   Indiciu: Atac coordonat sau botnet
```

**Tehnici de Scanare Comune**:

| Tehnică | Descriere | Cum se Detectează |
|---------|-----------|-------------------|
| **SYN Scan** | Trimite SYN, nu completează handshake | Multe SYN fără ACK |
| **Connect Scan** | Completează conexiunea TCP | Multe conexiuni scurte |
| **UDP Scan** | Testează porturi UDP | Multe pachete UDP către porturi închise |
| **Stealth Scan** | Fragmente, timings variabile | Pattern-uri neobișnuite |

**Cum Detectează IDS-ul Nostru**:

```rust
// PRAG: 10 porturi unice în 60 secunde
if model.porturi_unice.len() >= 10 
    && diferenta_timp <= 60 {
    
    ALERTĂ: Scanare Detectată!
}

// EXEMPLU REAL:
// IP 1.2.3.4 în 45 secunde:
// Porturi: [22, 23, 80, 443, 3306, 5432, 6379, 8080, 8443, 9000]
// 10 porturi → PRAG DEPĂȘIT → ALERTĂ
```

### 2. Connection Burst (Rafală Conexiuni)

**Definiție**: Multe conexiuni într-un interval foarte scurt - posibil DDoS sau brute force.

**Scenarii**:

```
SCENARIUL 1: SSH Brute Force
────────────────────────────
Atacatorul încearcă mii de parole:

10:00:00.001  SSH port 22 - Parolă: admin123
10:00:00.015  SSH port 22 - Parolă: password
10:00:00.023  SSH port 22 - Parolă: 123456
10:00:00.041  SSH port 22 - Parolă: qwerty
... (50+ încercări în 10 secunde)

→ IDS detectează: 50+ conexiuni/10s → ALERTĂ


SCENARIUL 2: DDoS (Distributed Denial of Service)
──────────────────────────────────────────────────
Mii de IP-uri atacă simultan:

1.2.3.4    ─┐
5.6.7.8    ─┤
9.8.7.6    ─┼─▶ [Server Web] ← Supraîncărcat
2.3.4.5    ─┤
6.7.8.9    ─┘
... (1000+ IP-uri)

→ Fiecare IP: 50+ conexiuni → Multiple alerte
```

**Cod Detecție**:

```rust
// PRAG: 50 conexiuni în 10 secunde
if model.numar_conexiuni >= 50 
    && diferenta_timp <= 10 {
    
    alerte.push(self.creaza_alerta_cef(
        "RAFALA_CONEXIUNI",
        "Possible DDoS or Brute Force",
        7,  // Severitate HIGH
        &format!("Rate: {}/s", numar_conexiuni / diferenta_timp)
    ));
}
```

### 3. Format CEF (Common Event Format)

**Ce Este CEF?**

Standard creat de ArcSight (acum Micro Focus) pentru evenimente de securitate. Permite interoperabilitate între sisteme SIEM.

**Structura CEF**:

```
CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension

CEF:0|IDS_Personalizat|IDS_Rsyslog|2.1|SCANARE_PORTURI|Scanare Orizontală Detectată|8|sursa=1.2.3.4 destinatie=firewall numarPorturi=15 fereastraTimp=45s porturi=22,23,80,443,3306,5432,6379,8080,8443,9000,3000,5000,6000,7000,8000
```

**Defalcare Câmpuri**:

| Câmp | Valoare | Explicație |
|------|---------|------------|
| `Version` | 0 | Versiunea CEF (întotdeauna 0) |
| `Vendor` | IDS_Personalizat | Cine face dispozitivul |
| `Product` | IDS_Rsyslog | Numele produsului |
| `Version` | 2.1 | Versiunea produsului |
| `SignatureID` | SCANARE_PORTURI | ID unic pentru tipul de eveniment |
| `Name` | Scanare Orizontală... | Descriere human-readable |
| `Severity` | 8 | 0-10 (10=CRITIC) |
| `Extension` | sursa=1.2.3.4... | Câmpuri personalizate key=value |

**Severitate în IDS-ul Nostru**:

```rust
let severitate = match model.porturi_unice.len() {
    n if n >= 100 => 10,  // 100+ porturi = CRITIC
    n if n >= 50  => 8,   // 50-99 = HIGH
    n if n >= 20  => 6,   // 20-49 = MEDIUM
    _             => 4,   // 10-19 = LOW
};
```

**Exemplu Real de Alertă**:

```
🚨 [ALERTĂ] CEF:0|IDS_Personalizat|IDS_Rsyslog|2.1|SCANARE_PORTURI|Scanare Orizontală Porturi Detectată|8|sursa=192.168.1.100 destinatie=firewall numarPorturi=15 fereastraTimp=45s porturi=22,23,80,443,3306,5432,6379,8080,8443,9000,3000,5000,6000,7000,8000 actiune=RESPINS

Traducere:
- Un IP (192.168.1.100) a scanat firewall-ul
- 15 porturi diferite în 45 secunde
- Severitate 8 (HIGH) - necesită investigație imediată
- Firewall-ul a respins conexiunile (actiune=RESPINS)
```

### 4. RFC1918 - Adrese Private

**Ce Sunt Adresele Private?**

Intervale IP rezervate pentru rețele interne (nu pot fi rutate pe Internet).

```
Interval RFC1918:
┌─────────────────────────────────┐
│ 10.0.0.0    - 10.255.255.255   │  (10/8)      - 16 milioane IP-uri
│ 172.16.0.0  - 172.31.255.255   │  (172.16/12) - 1 milion IP-uri
│ 192.168.0.0 - 192.168.255.255  │  (192.168/16) - 65536 IP-uri
└─────────────────────────────────┘

Plus:
- 127.0.0.0/8    (localhost)
- 169.254.0.0/16 (link-local, APIPA)
```

**De Ce Le Ignorăm în IDS?**

```rust
fn trebuie_ignorat_ip(&self, ip: &str) -> bool {
    if !self.configuratie.ignora_ip_uri_interne {
        return false;  // Nu ignora dacă e dezactivat
    }
    
    // Scanările interne sunt normale în rețeaua corporativă
    ip.starts_with("10.")       // Rețeaua internă
        || ip.starts_with("192.168.")  // Rețeaua de acasă/birou
        || ip.starts_with("172.16.")   // Rețeaua corporativă
        // ...
}
```

**Exemplu Practic**:

```
SCENARIUL 1: Scanare Internă (IGNORATĂ)
────────────────────────────────────────
IP Sursă: 192.168.1.50 (laptop coleg)
Porturi: 22, 80, 443 (verificare servicii interne)
Acțiune IDS: IGNORĂ (trafic intern legitim)


SCENARIUL 2: Scanare Externă (ALERTĂ)
──────────────────────────────────────
IP Sursă: 203.0.113.45 (Internet extern)
Porturi: 22, 23, 80, 443, 3306, 5432, ... (15 porturi)
Acțiune IDS: ALERTĂ IMEDIATĂ (atac extern!)
```

### 5. Memory Management în Context IDS

**Problema**: Un atacator poate genera milioane de log-uri false pentru a umple memoria.

**Soluția Noastră**:

```rust
// LIMITĂ HARD: Maxim 100.000 IP-uri urmărite
const maxim_ip_uri_urmarite: usize = 100_000;

if self.urmaritor_scanari.len() >= maxim_ip_uri_urmarite 
    && !self.urmaritor_scanari.contains_key(&ip) {
    
    // Respinge IP-ul nou
    self.statistici
        .entry("ip_uri_respinse".to_string())
        .and_modify(|c| *c += 1)
        .or_insert(1);
    
    return None;  // Nu adaugă în tracker
}
```

**Curățare Periodică**:

```rust
async fn task_curatare(&self) {
    let mut interval = time::interval(Duration::from_secs(300)); // La 5 minute
    
    loop {
        interval.tick().await;
        
        // Șterge IP-uri vechi (2x fereastra timp)
        let prag_taiere = Utc::now() - Duration::seconds(120);
        
        self.urmaritor_scanari.retain(|_, model| {
            model.ultima_aparitie > prag_taiere
        });
    }
}
```

**Calculul Memoriei**:

```
Structura ModelScanare:
- ip_sursa: String          ~20 bytes (IP ca text)
- porturi_unice: Vec<u16>   ~40 bytes (20 porturi * 2 bytes)
- marca_timp * 2            ~16 bytes
- numar_conexiuni: usize    ~8 bytes
TOTAL: ~84 bytes/IP

100.000 IP-uri * 84 bytes = ~8.4 MB (rezonabil!)

Fără limită:
1.000.000 IP-uri = ~84 MB
10.000.000 IP-uri = ~840 MB (PERICOL!)
```

---

## 🧪 Testare și Debugging {#testare}

### 1. Setup Mediu de Testare

**Creează Directorul Proiectului**:

```bash
# 1. Creează proiectul Rust
cargo new ids-rsyslog
cd ids-rsyslog

# 2. Editează Cargo.toml
cat > Cargo.toml << 'EOF'
[package]
name = "ids-rsyslog"
version = "2.1.0"
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

# 3. Copiază codul în src/main.rs
# (din artifact-ul "ids_corrected")
```

**Compilare**:

```bash
# Debug build (mai lent, cu simboluri debugging)
cargo build

# Release build (optimizat, rapid)
cargo build --release

# Rulare directă
cargo run

# Verifică sintaxă fără compilare completă
cargo check
```

### 2. Testare Manuală cu Date Simulate

**Creează Script de Testare**:

```bash
#!/bin/bash
# test_ids.sh - Generează log-uri false pentru testare

SOCKET="/var/run/ids-personalizat/ids.sock"

# Verifică dacă IDS-ul rulează
if [ ! -S "$SOCKET" ]; then
    echo "❌ IDS nu rulează! Socket-ul $SOCKET nu există."
    exit 1
fi

echo "✓ IDS detectat, trimit date de test..."

# Test 1: Scanare porturi (ar trebui să declanșeze alertă)
echo "📡 Test 1: Simulez scanare 15 porturi în 10 secunde..."
for port in 22 23 80 443 3306 5432 6379 8080 8443 9000 3000 5000 6000 7000 8000; do
    echo "$(date '+%b %d %H:%M:%S') testhost kernel: SRC=203.0.113.100 DST=10.0.0.1 DPT=$port PROTO=TCP" | nc -U "$SOCKET"
    sleep 0.5  # 500ms între porturi
done

echo "✓ Test 1 complet. Verifică consola IDS pentru alertă."
sleep 2

# Test 2: Rafală conexiuni (ar trebui să declanșeze alertă)
echo "📡 Test 2: Simulez 60 conexiuni în 5 secunde..."
for i in {1..60}; do
    echo "$(date '+%b %d %H:%M:%S') sshd: Failed password from 198.51.100.50 port 22" | nc -U "$SOCKET"
    sleep 0.08  # ~80ms între conexiuni
done

echo "✓ Test 2 complet. Verifică consola IDS pentru alertă."
sleep 2

# Test 3: Trafic normal (NU ar trebui alertă)
echo "📡 Test 3: Simulez trafic normal (sub praguri)..."
for i in {1..5}; do
    echo "$(date '+%b %d %H:%M:%S') firewall: SRC=192.168.1.50 DST=10.0.0.1 DPT=80 PROTO=TCP" | nc -U "$SOCKET"
    sleep 1
done

echo "✓ Test 3 complet. NU ar trebui să vezi alertă (trafic normal)."

echo ""
echo "🎉 Toate testele trimise!"
echo "📊 Verifică consola IDS pentru:"
echo "   - 2 alerte (Test 1 și Test 2)"
echo "   - Statistici actualizate"
```

**Rulează Testul**:

```bash
chmod +x test_ids.sh
sudo ./test_ids.sh
```

**Output Așteptat în Consola IDS**:

```
✓ Conexiune nouă de la rsyslog

🚨 [ALERTĂ] CEF:0|IDS_Personalizat|IDS_Rsyslog|2.1|SCANARE_PORTURI|Scanare Orizontală Porturi Detectată|8|sursa=203.0.113.100 destinatie=testhost numarPorturi=15 fereastraTimp=7s porturi=22,23,80,443,3306,5432,6379,8080,8443,9000,3000,5000,6000,7000,8000 actiune=RESPINS
✓ Ar trimite către ArcSight: syslog://localhost:5140

🚨 [ALERTĂ] CEF:0|IDS_Personalizat|IDS_Rsyslog|2.1|RAFALA_CONEXIUNI|Rafală Conexiuni Detectată|7|sursa=198.51.100.50 destinatie=sshd numarConexiuni=60 fereastraTimp=5s rataMetdie=12/s
✓ Ar trimite către ArcSight: syslog://localhost:5140

📊 === Statistici IDS ===
  evenimente_totale: 80
  alerte_generate: 2
  linii_procesate: 80
  IP-uri urmărite active: 2
==========================
```

### 3. Unit Testing în Rust

**Adaugă Teste în Cod**:

```rust
#[cfg(test)]
mod teste {
    use super::*;
    
    #[test]
    fn test_parsare_iptables() {
        let config = ConfiguratieIDS::default();
        let ids = MotorIDS::nou(config);
        
        let linie = "Jan 26 10:30:45 firewall kernel: SRC=192.168.1.100 DST=10.0.0.1 DPT=22 PROTO=TCP";
        let rezultat = ids.parseaza_linie_syslog(linie);
        
        assert!(rezultat.is_some(), "Parsarea ar trebui să reușească");
        
        let intrare = rezultat.unwrap();
        assert_eq!(intrare.ip_sursa, "192.168.1.100");
        assert_eq!(intrare.port_destinatie, 22);
        assert_eq!(intrare.protocol, "TCP");
    }
    
    #[test]
    fn test_ignorare_ip_privat() {
        let config = ConfiguratieIDS {
            ignora_ip_uri_interne: true,
            ..Default::default()
        };
        let ids = MotorIDS::nou(config);
        
        assert!(ids.trebuie_ignorat_ip("192.168.1.1"), "192.168.x.x ar trebui ignorat");
        assert!(ids.trebuie_ignorat_ip("10.0.0.1"), "10.x.x.x ar trebui ignorat");
        assert!(!ids.trebuie_ignorat_ip("8.8.8.8"), "8.8.8.8 NU ar trebui ignorat");
    }
    
    #[test]
    fn test_detectie_scanare() {
        let config = ConfiguratieIDS {
            prag_scanare_porturi: 5,  // Prag scăzut pentru test
            fereastra_timp_secunde: 60,
            ..Default::default()
        };
        let ids = MotorIDS::nou(config);
        
        // Simulează 6 porturi diferite
        for port in [22, 23, 80, 443, 3306, 5432] {
            let intrare = IntrareJurnal {
                marca_timp: Utc::now(),
                nume_gazda: "test".to_string(),
                ip_sursa: "1.2.3.4".to_string(),
                port_destinatie: port,
                protocol: "TCP".to_string(),
                actiune: "RESPINS".to_string(),
            };
            
            let rezultat = ids.analizeaza_si_detecteaza(intrare);
            
            if port == 5432 {  // Ultimul port (al 6-lea)
                assert!(rezultat.is_some(), "Ar trebui să genereze alertă la al 6-lea port");
            }
        }
    }
}
```

**Rulează Testele**:

```bash
cargo test

# Output:
running 3 tests
test teste::test_parsare_iptables ... ok
test teste::test_ignorare_ip_privat ... ok
test teste::test_detectie_scanare ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured
```

### 4. Debugging cu Print Statements

**Tehnica Simplă - println! și dbg!**:

```rust
fn analizeaza_si_detecteaza(&self, intrare: IntrareJurnal) -> Option<Vec<EvenimentCEF>> {
    println!("🔍 DEBUG: Analizez IP {}", intrare.ip_sursa);
    
    let ip = intrare.ip_sursa.clone();
    
    // dbg! afișează expresia ȘI valoarea
    dbg!(&ip);  // Output: [src/main.rs:123] &ip = "1.2.3.4"
    
    if let Some(model) = self.urmaritor_scanari.get(&ip) {
        println!("  📊 Model existent: {} porturi, {} conexiuni",
                 model.porturi_unice.len(),
                 model.numar_conexiuni);
    }
    
    // ...
}
```

**Debugging Avansat cu env_logger**:

```rust
// În Cargo.toml, adaugă:
// env_logger = "0.11"
// log = "0.4"

use log::{info, warn, error, debug};

#[tokio::main]
async fn main() {
    // Inițializează logger-ul
    env_logger::init();
    
    info!("🚀 IDS pornit");
    // ...
}

fn analizeaza_si_detecteaza(&self, intrare: IntrareJurnal) {
    debug!("Analizez intrare: {:?}", intrare);
    
    if alerta_generata {
        warn!("⚠️  Alertă generată pentru IP {}", ip);
    }
}
```

**Rulează cu Logging**:

```bash
# Afișează doar ERROR și WARNING
RUST_LOG=warn cargo run

# Afișează INFO, WARN, ERROR
RUST_LOG=info cargo run

# Afișează totul (inclusiv DEBUG)
RUST_LOG=debug cargo run

# Filtrare pe modul
RUST_LOG=ids_rsyslog=debug cargo run
```

### 5. Debugging cu GDB/LLDB

**Compilare cu Simboluri Debug**:

```bash
cargo build  # Debug build automat are simboluri
```

**Rulare în Debugger**:

```bash
# Linux - GDB
rust-gdb target/debug/ids-rsyslog

# macOS - LLDB
rust-lldb target/debug/ids-rsyslog
```

**Comenzi Utile GDB**:

```gdb
(gdb) break main.rs:150        # Breakpoint la linia 150
(gdb) run                      # Rulează programul
(gdb) print intrare            # Afișează variabila
(gdb) backtrace                # Stack trace
(gdb) continue                 # Continuă execuția
```

---

## 💡 Exerciții Practice {#exercitii}

### Nivel 1: Beginner (Înțelegere Cod)

#### Exercițiul 1: Modifică Pragurile

**Obiectiv**: Învață să modifici configurația

```rust
// SARCINĂ: Modifică aceste valori și observă comportamentul
let configuratie = ConfiguratieIDS {
    prag_scanare_porturi: 5,        // Original: 10
    fereastra_timp_secunde: 30,     // Original: 60
    prag_rafala_conexiuni: 20,      // Original: 50
    // ...
};
```

**Întrebări**:
1. Ce se întâmplă dacă scazi `prag_scanare_porturi` la 5?
   - Răspuns: Mai multe alerte (mai sensibil)
   
2. Dacă crești `fereastra_timp_secunde` la 300?
   - Răspuns: Mai puține alerte (interval mai mare)

3. Testează cu script-ul de test și verifică diferențele.

#### Exercițiul 2: Adaugă Logging

**Obiectiv**: Învață să folosești println! pentru debugging

```rust
fn parseaza_linie_syslog(&self, linie: &str) -> Option<IntrareJurnal> {
    // SARCINĂ: Adaugă println! pentru a vedea ce primești
    println!("📥 Linie primită: {}", linie);
    
    let regex_iptables = Regex::new(r"SRC=(\d+\.\d+\.\d+\.\d+).*").ok()?;
    
    if let Some(potriviri) = regex_iptables.captures(linie) {
        let ip_sursa = potriviri.get(1)?.as_str().to_string();
        
        // SARCINĂ: Afișează IP-ul extras
        println!("  ✅ IP extras: {}", ip_sursa);
        
        // ...
    } else {
        // SARCINĂ: Afișează când parsarea eșuează
        println!("  ❌ Parsare eșuată");
    }
    
    None
}
```

**Rulează și observă**: Ce tipuri de linii eșuează la parsare?

#### Exercițiul 3: Adaugă Test Simplu

**Obiectiv**: Scrie primul tău unit test

```rust
#[cfg(test)]
mod teste {
    use super::*;
    
    #[test]
    fn test_parsare_ssh() {
        // SARCINĂ: Completează acest test
        let config = ConfiguratieIDS::default();
        let ids = MotorIDS::nou(config);
        
        let linie = "Jan 26 10:30:45 sshd: Failed password from 1.2.3.4 port 2222";
        let rezultat = ids.parseaza_linie_syslog(linie);
        
        // SARCINĂ: Verifică că parsarea reușește
        assert!(rezultat.is_some());
        
        let intrare = rezultat.unwrap();
        
        // SARCINĂ: Verifică IP-ul
        assert_eq!(intrare.ip_sursa, "1.2.3.4");
        
        // SARCINĂ: Verifică portul (indiciu: e în linie ca "port 2222")
        assert_eq!(intrare.port_destinatie, 2222);
    }
}
```

### Nivel 2: Intermediate (Extindere Funcționalitate)

#### Exercițiul 4: Adaugă Detectare Scanare Verticală

**Obiectiv**: Detectează când un IP scanează același port pe mai multe hosturi

**Pas 1**: Adaugă câmp nou în `ModelScanare`:

```rust
#[derive(Debug, Clone)]
struct ModelScanare {
    ip_sursa: String,
    porturi_unice: Vec<u16>,
    hosturi_tinta: Vec<String>,  // ← NOU: Lista hosturilor țintă
    prima_aparitie: DateTime<Utc>,
    ultima_aparitie: DateTime<Utc>,
    numar_conexiuni: usize,
}
```

**Pas 2**: Modifică `analizeaza_si_detecteaza`:

```rust
self.urmaritor_scanari
    .entry(ip.clone())
    .and_modify(|model| {
        model.numar_conexiuni += 1;
        
        // Adaugă host dacă e nou
        if !model.hosturi_tinta.contains(&intrare.nume_gazda) {
            model.hosturi_tinta.push(intrare.nume_gazda.clone());
        }
        
        // ...
    });

// SARCINĂ: Adaugă detectare scanare verticală
if model.hosturi_tinta.len() >= 5  // 5+ hosturi
    && model.porturi_unice.len() == 1  // Același port
    && diferenta_timp <= 60 {
    
    alerte.push(self.creaza_alerta_cef(
        "SCANARE_VERTICALA",
        "Scanare Verticală Detectată",
        7,
        &format!("sursa={} port={} hosturi={}", 
                 ip, 
                 model.porturi_unice[0],
                 model.hosturi_tinta.len())
    ));
}
```

#### Exercițiul 5: Statistici per Protocoale

**Obiectiv**: Urmărește câte evenimente sunt TCP vs UDP vs SSH

**Pas 1**: Modifică structura statisticilor:

```rust
// În MotorIDS, adaugă:
protocol_stats: Arc<DashMap<String, u64>>,  // protocol -> count
```

**Pas 2**: Actualizează în `analizeaza_si_detecteaza`:

```rust
// După parsare, actualizează statistici
self.protocol_stats
    .entry(intrare.protocol.clone())
    .and_modify(|c| *c += 1)
    .or_insert(1);
```

**Pas 3**: Afișează în `task_statistici`:

```rust
println!("\n📊 === Statistici Protocol ===");
for entry in self.protocol_stats.iter() {
    println!("  {}: {}", entry.key(), entry.value());
}
```

#### Exercițiul 6: Export JSON

**Obiectiv**: Salvează alertele într-un fișier JSON (învață serialization)

**Pas 1**: Adaugă câmp în `MotorIDS`:

```rust
alerte_istorice: Arc<DashMap<String, EvenimentCEF>>,  // timestamp -> alertă
```

**Pas 2**: Salvează alertele:

```rust
async fn trimite_catre_arcsight(&self, alerta: &EvenimentCEF) {
    // Salvează în istoric
    let timestamp = Utc::now().to_rfc3339();
    self.alerte_istorice.insert(timestamp, alerta.clone());
    
    // ...
}
```

**Pas 3**: Exportă periodic într-un task nou:

```rust
async fn task_export_json(&self) {
    let mut interval = time::interval(Duration::from_secs(3600)); // La o oră
    
    loop {
        interval.tick().await;
        
        // Colectează toate alertele
        let alerte: Vec<_> = self.alerte_istorice
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        
        // Serializează în JSON
        let json = serde_json::to_string_pretty(&alerte).unwrap();
        
        // Salvează în fișier
        tokio::fs::write("/var/log/ids-alerte.json", json)
            .await
            .expect("Eroare scriere JSON");
        
        println!("💾 Exportat {} alerte în JSON", alerte.len());
    }
}
```

### Nivel 3: Advanced (Optimizare și Securitate)

#### Exercițiul 7: Implementează Rate Limiting per IP

**Obiectiv**: Previne flood de alerte de la același IP

```rust
struct MotorIDS {
    // ...
    alerte_recente: Arc<DashMap<String, DateTime<Utc>>>,  // IP -> ultima alertă
}

fn analizeaza_si_detecteaza(&self, intrare: IntrareJurnal) -> Option<Vec<EvenimentCEF>> {
    // SARCINĂ: Nu genera alertă dacă ultima a fost în ultimele 60s
    
    if let Some(ultima_alerta) = self.alerte_recente.get(&intrare.ip_sursa) {
        let diferenta = (Utc::now() - *ultima_alerta).num_seconds();
        
        if diferenta < 60 {
            println!("⏳ Alertă suprimată pentru {} (prea recent)", intrare.ip_sursa);
            return None;  // Skip alertă
        }
    }
    
    // Generează alertă normal...
    
    if !alerte.is_empty() {
        // Actualizează timestamp ultima alertă
        self.alerte_recente.insert(intrare.ip_sursa.clone(), Utc::now());
    }
    
    // ...
}
```

#### Exercițiul 8: Geo-IP Lookup

**Obiectiv**: Adaugă țara de origine pentru IP-uri (folosind API extern)

**Pas 1**: Adaugă dependency în `Cargo.toml`:

```toml
geoip2 = "0.4"  # Sau folosește API online
```

**Pas 2**: Creează funcție async pentru lookup:

```rust
async fn obtine_tara_ip(ip: &str) -> Option<String> {
    // SARCINĂ: Interoghează API GeoIP
    // Exemplu cu API gratuit: ip-api.com
    
    let url = format!("http://ip-api.com/json/{}", ip);
    
    let response = reqwest::get(&url).await.ok()?;
    let json: serde_json::Value = response.json().await.ok()?;
    
    json["country"].as_str().map(|s| s.to_string())
}
```

**Pas 3**: Integrează în CEF:

```rust
let tara = obtine_tara_ip(&ip).await.unwrap_or("Necunoscut".to_string());

alerte.push(self.creaza_alerta_cef(
    "SCANARE_PORTURI",
    "Scanare Detectată",
    8,
    &format!("sursa={} tara={} porturi={}", ip, tara, numar_porturi)
));
```

#### Exercițiul 9: Implementează Whitelist

**Obiectiv**: Permite IP-uri de încredere să scaneze fără alerte

```rust
struct ConfiguratieIDS {
    // ...
    ip_uri_whitelist: HashSet<String>,  // IP-uri de încredere
}

impl MotorIDS {
    fn este_ip_whitelist(&self, ip: &str) -> bool {
        self.configuratie.ip_uri_whitelist.contains(ip)
    }
    
    fn analizeaza_si_detecteaza(&self, intrare: IntrareJurnal) -> Option<Vec<EvenimentCEF>> {
        // Check whitelist
        if self.este_ip_whitelist(&intrare.ip_sursa) {
            println!("✅ IP whitelist: {} - ignorat", intrare.ip_sursa);
            return None;
        }
        
        // Continuă normal...
    }
}

// În main:
let configuratie = ConfiguratieIDS {
    ip_uri_whitelist: vec![
        "192.168.1.10".to_string(),  // Scanner de securitate intern
        "10.0.0.50".to_string(),     // Server monitoring
    ].into_iter().collect(),
    // ...
};
```

---

## 📚 Resurse Suplimentare {#resurse}

### Resurse Rust

#### Cărți Online (Gratuite)

1. **The Rust Programming Language** (Cartea Oficială)
   - Link: https://doc.rust-lang.org/book/
   - Cel mai bun punct de plecare pentru Rust
   - Acoperă ownership, borrowing, traits, async

2. **Rust by Example**
   - Link: https://doc.rust-lang.org/rust-by-example/
   - Învățare prin cod practic
   - Exemple scurte și clare

3. **Asynchronous Programming in Rust**
   - Link: https://rust-lang.github.io/async-book/
   - Specific pentru async/await și Tokio
   - Esențial pentru IDS-ul nostru

4. **The Cargo Book**
   - Link: https://doc.rust-lang.org/cargo/
   - Cum să folosești Cargo (build system)

#### Tutoriale Interactive

1. **Rustlings** - Exerciții interactive
   - Link: https://github.com/rust-lang/rustlings
   - `cargo install rustlings`
   - Învață prin rezolvare de puzzle-uri

2. **Exercism Rust Track**
   - Link: https://exercism.org/tracks/rust
   - Exerciții cu mentor feedback

#### Documentație

- **std Library**: https://doc.rust-lang.org/std/
- **Tokio Docs**: https://docs.rs/tokio/latest/tokio/
- **Regex Docs**: https://docs.rs/regex/latest/regex/

### Resurse Securitate Rețea

#### Concepte IDS/IPS

1. **SANS Reading Room** - IDS/IPS Papers
   - Link: https://www.sans.org/white-papers/
   - Articole despre detectare intruziuni

2. **Snort Documentation**
   - Link: https://www.snort.org/documents
   - Snort = IDS clasic, învață reguli și pattern-uri

3. **Suricata User Guide**
   - Link: https://suricata.readthedocs.io/
   - IDS modern, multi-threaded

#### Port Scanning și Nmap

1. **Nmap Network Scanning**
   - Link: https://nmap.org/book/
   - Cartea oficială despre scanare rețea
   - Înțelege ce fac atacatorii

2. **OWASP Testing Guide**
   - Link: https://owasp.org/www-project-web-security-testing-guide/
   - Tehnici de testare securitate

#### CEF și SIEM

1. **ArcSight CEF Format**
   - Link: https://www.microfocus.com/documentation/arcsight/
   - Documentație oficială CEF

2. **Splunk Common Information Model**
   - Link: https://docs.splunk.com/Documentation/CIM/
   - Alternativă la CEF

### Comunități și Forum-uri

1. **r/rust** - Reddit Rust Community
   - Link: https://reddit.com/r/rust
   - Întrebări și discuții

2. **Rust Users Forum**
   - Link: https://users.rust-lang.org/
   - Forum oficial Rust

3. **Discord Server - Rust Programming Language**
   - Link: https://discord.gg/rust-lang
   - Chat real-time

4. **Stack Overflow [rust] tag**
   - Link: https://stackoverflow.com/questions/tagged/rust

### Proiecte Similare (Pentru Inspirație)

1. **Suricata** (C + Rust)
   - Link: https://github.com/OISF/suricata
   - IDS/IPS enterprise

2. **Sniffnet** (Rust)
   - Link: https://github.com/GyulyVGC/sniffnet
   - Network monitoring GUI

3. **Vector** (Rust)
   - Link: https://github.com/vectordotdev/vector
   - Log processing pipeline

---

## 🎓 Plan de Învățare Recomandat

### Săptămâna 1: Rust Fundamentals

**Zi 1-2**: Ownership și Borrowing
- Citește: The Rust Book - Capitolele 4-5
- Exercițiu: Rustlings - exercises/move_semantics

**Zi 3-4**: Structs, Enums, Pattern Matching
- Citește: The Rust Book - Capitolele 6-7
- Exercițiu: Creează propriul struct pentru evenimente

**Zi 5-7**: Result, Option, Error Handling
- Citește: The Rust Book - Capitolul 9
- Exercițiu: Rescrie parsarea cu error handling robust

### Săptămâna 2: Async și Concurrency

**Zi 1-3**: Tokio și Async/Await
- Citește: Async Book - toate capitolele
- Exercițiu: Creează server TCP simplu cu Tokio

**Zi 4-5**: Arc, Mutex, DashMap
- Citește: The Rust Book - Capitolul 16
- Exercițiu: Împărtășește date între 3 task-uri

**Zi 6-7**: Regex și Parsing
- Docs: https://docs.rs/regex/
- Exercițiu: Parsează 5 formate diferite de log-uri

### Săptămâna 3: IDS Project

**Zi 1-2**: Înțelege Arhitectura
- Studiază diagrama de flux din acest ghid
- Desenează propriile diagrame

**Zi 3-4**: Implementează Exercițiile Nivel 1
- Modifică praguri
- Adaugă logging
- Scrie teste

**Zi 5-7**: Implementează Exercițiile Nivel 2
- Scanare verticală
- Statistici protocoale
- Export JSON

### Săptămâna 4: Advanced și Deploy

**Zi 1-3**: Exerciții Nivel 3
- Rate limiting
- Geo-IP
- Whitelist

**Zi 4-5**: Testing și Debugging
- Write unit tests pentru toate funcțiile
- Test cu date reale

**Zi 6-7**: Deploy și Monitoring
- Deploy pe server de test
- Integrează cu rsyslog real
- Monitorizează performanța

---

## 🔧 Troubleshooting Comun

### Problema 1: "Socket not found"

```bash
❌ Socket error: No such file or directory (os error 2)
```

**Cauză**: IDS-ul încearcă să se conecteze la socket înainte ca rsyslog să-l creeze.

**Soluție**:
```bash
# Verifică dacă socket-ul există
ls -la /var/run/ids-personalizat/ids.sock

# Dacă nu există, verifică configurația rsyslog
sudo rsyslogd -N1  # Validează configurația

# Restart rsyslog
sudo systemctl restart rsyslog
```

### Problema 2: Compilare Eșuată - "borrowed value does not live long enough"

```rust
error[E0597]: `temp` does not live long enough
```

**Cauză**: Încerci să returnezi o referință către o variabilă locală.

**Soluție**:
```rust
// ❌ GREȘIT
fn returneaza_string() -> &str {
    let temp = String::from("test");
    &temp  // temp e șters la sfârșitul funcției!
}

// ✅ CORECT - Returnează owned String
fn returneaza_string() -> String {
    String::from("test")
}

// ✅ SAU - Folosește string literal static
fn returneaza_string() -> &'static str {
    "test"  // Există pentru întreaga durată a programului
}
```

### Problema 3: "cannot borrow as mutable"

```rust
error[E0596]: cannot borrow `ids` as mutable, as it is not declared as mutable
```

**Soluție**:
```rust
// ❌ GREȘIT
let ids = MotorIDS::nou(config);
ids.urmaritor_scanari.insert(...);  // Eroare!

// ✅ CORECT - Pentru modificare directă
let mut ids = MotorIDS::nou(config);

// ✅ SAU - Folosește interior mutability (DashMap)
// DashMap permite modificare chiar și prin &self
let ids = MotorIDS::nou(config);  // fără mut
ids.urmaritor_scanari.insert(...);  // Funcționează!
```

### Problema 4: Memoria Crește Continuu

**Cauză**: Task-ul de curățare nu rulează sau pragul e prea mare.

**Diagnostic**:
```bash
# Monitorizează memoria
watch -n 1 'ps aux | grep ids-rsyslog'

# Verifică statistici IDS
# Ar trebui să vezi "IP-uri urmărite active" să scadă periodic
```

**Soluție**:
```rust
// Reduce intervalul de curățare
interval_curatare_secunde: 60,  // Din 300 în 60

// Reduce pragul de memorie
maxim_ip_uri_urmarite: 10_000,  // Din 100_000
```

---

## 🎯 Concluzie

Felicitări! Acum ai:

✅ **Înțeles Rust** - Ownership, borrowing, async/await
✅ **Înțeles IDS** - Port scanning, CEF, SIEM integration
✅ **Proiect Funcțional** - IDS production-ready
✅ **Exerciții Practice** - Pentru aprofundare

### Next Steps

1. **Modifică și Experimentează** - Nu copia-paste, schimbă cod și vezi ce se întâmplă
2. **Citește Documentația** - Apasă pe funcții în IDE și citește docs
3. **Scrie Teste** - Cel mai bun mod de a învăța
4. **Deploy în Producție** - Învățarea adevărată vine din probleme reale

### Resurse Continue

- **Daily Rust**: https://this-week-in-rust.org/ - Newsleter săptămânal
- **Rust Blog**: https://blog.rust-lang.org/ - Anunțuri oficiale
- **Awesome Rust**: https://github.com/rust-unofficial/awesome-rust - Curated list

---

**Mult succes în călătoria ta de învățare Rust! 🦀**

*Documentul creat cu ❤️ pentru învățarea Rust prin practică*