# 🛡️ IDS Scanner - Detector de Scanări de Rețea

Scanner de detectare intruziuni (IDS) educațional în limbaj Rust, cu comentarii în română. Detectează scan-uri de rețea (rapide și lente) din log-uri UDP și trimite alerte către ArcSight SIEM.

## ✨ Caracteristici v2.0

- ✅ **Configurare flexibilă** prin fișier TOML
- ✅ **Detectare scan rapid** (ex: nmap -T4, -T5)
- ✅ **Detectare scan lent** (ex: nmap -T1, -T2, stealth scan)
- ✅ **Parser multi-format** (CEF, CEF Syslog, Raw Syslog)
- ✅ **Alertare automată** către ArcSight SIEM
- ✅ **Thread-safe** și performant (async/await cu Tokio)
- ✅ **Curățare automată** a cache-ului
- ✅ **Filtrare acțiuni** (opțional: procesează doar deny/block)
- ✅ **Cod comentat educațional** în română

## 📋 Cerințe

- **Rust** 1.70+ (instalează de pe [rustup.rs](https://rustup.rs/))
- **ArcSight Forwarder** (opțional, pentru testing)

## 🚀 Instalare & Configurare

### 1. Clonează/Descarcă proiectul

```bash
# Navighează în directorul proiectului
cd ids-scanner
```

### 2. Configurare

Creează fișierul de configurare din template:

```bash
cp config.example.toml config.toml
```

Editează `config.toml` după necesități:

```toml
[network]
# Unde ascultă programul (primește log-uri)
listen_address = "0.0.0.0:5555"

# Unde trimite alertele (ArcSight SIEM)
siem_address = "127.0.0.1:514"

[detection]
# Detectare scan rapid (10 porturi în 60 secunde)
rapid_scan_threshold = 10
rapid_scan_window_sec = 60

# Detectare scan lent (20 porturi în 1 oră)
slow_scan_threshold = 20
slow_scan_window_sec = 3600

# Curățare cache după 2 ore
cache_expiration_sec = 7200

# Opțional: procesează doar anumite acțiuni
# filter_actions = ["deny", "block", "drop"]
```

### 3. Compilare

```bash
# Compilare în modul debug (pentru dezvoltare)
cargo build

# SAU compilare optimizată pentru producție
cargo build --release
```

### 4. Rulare

```bash
# Rulare cu logging detaliat
RUST_LOG=info cargo run

# SAU rulare direct (după compilare)
./target/release/ids-scanner
```

## 📊 Configurare ArcSight Forwarder

### Recomandare: Folosește **CEF Syslog** format

În fișierul de configurare ArcSight Forwarder (`agents.properties` sau `forwarding.xml`):

```properties
# Configurare agent pentru trimitere log-uri către IDS Scanner
agent[0].mode=CEFSyslog
agent[0].type=udp
agent[0].destination.host=127.0.0.1
agent[0].destination.port=5555
```

**De ce CEF Syslog?**
- ✅ Structură CEF (src, dst, dpt) - ușor de parsat
- ✅ Header Syslog cu timestamp și hostname
- ✅ Cel mai complet format pentru detectare
- ✅ Compatibil perfect cu parser-ul din cod

### Alternative de formate suportate:

| Format | Avantaje | Dezavantaje |
|--------|----------|-------------|
| **CEF Syslog** ⭐ | Complet, structurat | Ușor mai verbose |
| CEF File | Simplu, structurat | Fără context syslog |
| Raw Syslog | Flexibil | Nestructurat |

## 📝 Exemple de Log-uri Suportate

### Format CEF Syslog (recomandat):
```
<134>Jan 15 10:30:45 firewall CEF:0|Vendor|Product|1.0|100|Traffic Denied|5|src=192.168.1.100 dst=10.0.0.50 dpt=22 act=deny proto=TCP
```

### Format CEF simplu:
```
CEF:0|Vendor|Product|1.0|100|Traffic Denied|5|src=192.168.1.100 dst=10.0.0.50 dpt=22 act=deny proto=TCP
```

### Format Raw Syslog:
```
Jan 15 10:30:45 firewall kernel: SRC=192.168.1.100 DST=10.0.0.50 DPT=22 ACT=deny
```

## 🧪 Testing

### 1. Test manual cu netcat

```bash
# În terminal 1: Pornește IDS Scanner
RUST_LOG=info cargo run

# În terminal 2: Trimite log-uri de test
echo "CEF:0|Test|Test|1.0|100|Test|5|src=192.168.1.100 dst=10.0.0.50 dpt=22 act=deny" | nc -u 127.0.0.1 5555
echo "CEF:0|Test|Test|1.0|100|Test|5|src=192.168.1.100 dst=10.0.0.50 dpt=23 act=deny" | nc -u 127.0.0.1 5555
# ... trimite 10+ mesaje cu porturi diferite pentru a declanșa alertă
```

### 2. Script de test automat

```bash
#!/bin/bash
# test_scan.sh - Simulează un scan rapid

for port in {22..35}; do
    echo "CEF:0|Test|Test|1.0|100|Test|5|src=192.168.1.100 dst=10.0.0.50 dpt=$port act=deny" | nc -u 127.0.0.1 5555
    sleep 0.5
done
```

Rulează:
```bash
chmod +x test_scan.sh
./test_scan.sh
```

### 3. Verificare alertă

Dacă totul funcționează corect, vei vedea în consolă:

```
⚠️  SCAN DETECTAT: Scan de rețea RAPID_SCAN detectat: IP 192.168.1.100 a accesat 10 porturi unice în ultimele 60 secunde
📤 Alertă trimisă către SIEM (127.0.0.1:514): CEF:0|CustomIDS|NetworkScanner|1.0|RAPID_SCAN|...
```

## 🎛️ Personalizare Configurare

### Configurare pentru securitate maximă (detectare sensibilă):
```toml
rapid_scan_threshold = 5      # 5 porturi
rapid_scan_window_sec = 30    # în 30 secunde
slow_scan_threshold = 10      # 10 porturi
slow_scan_window_sec = 1800   # în 30 minute
```

### Configurare pentru rețele mari (toleranță mare):
```toml
rapid_scan_threshold = 20     # 20 porturi
rapid_scan_window_sec = 120   # în 2 minute
slow_scan_threshold = 50      # 50 porturi
slow_scan_window_sec = 7200   # în 2 ore
```

### Filtrare doar acțiuni blocate:
```toml
filter_actions = ["deny", "block", "drop", "reject"]
```

## 📂 Structura Proiectului

```
ids-scanner/
├── Cargo.toml              # Dependințe Rust
├── config.toml             # Configurare activă (creat de tine)
├── config.example.toml     # Template configurare
├── README.md               # Această documentație
└── src/
    └── main.rs             # Codul principal (cu comentarii în română)
```

## 🐛 Troubleshooting

### Problema: "Nu pot încărca config.toml"

**Soluție:**
```bash
# Verifică dacă fișierul există
ls -l config.toml

# Dacă nu există, creează-l din template
cp config.example.toml config.toml
```

Programul va folosi configurarea default dacă `config.toml` lipsește.

### Problema: "Address already in use"

**Soluție:** Portul 5555 este ocupat de alt proces.

```bash
# Găsește procesul care ocupă portul
sudo lsof -i :5555

# SAU schimbă portul în config.toml
listen_address = "0.0.0.0:5556"  # alt port
```

### Problema: Nu primesc log-uri

**Verificări:**
1. ArcSight Forwarder trimite către IP:PORT corect?
2. Firewall-ul blochează UDP 5555?
3. Rulează IDS Scanner pe aceeași mașină cu Forwarder?

```bash
# Testează conectivitatea
echo "test" | nc -u 127.0.0.1 5555

# Verifică dacă programul ascultă
sudo netstat -tulpn | grep 5555
```

### Problema: Nu detectează scan-uri

**Verificări:**
1. Log-urile conțin `src=` și `dpt=`?
2. Pragurile sunt prea mari? (scade-le în `config.toml`)
3. Filtrul de acțiuni exclude log-urile? (comentează `filter_actions`)

```bash
# Activează logging detaliat
RUST_LOG=debug cargo run
```

## 📚 Resurse de Învățare Rust

- [The Rust Programming Language](https://doc.rust-lang.org/book/) - cartea oficială
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/) - exemple practice
- [Rustlings](https://github.com/rust-lang/rustlings) - exerciții interactive

## 📄 Licență

Acest proiect este destinat scopurilor educaționale.

## 🤝 Contribuții

Pull requests și sugestii sunt binevenite! Scopul este să fie cât mai educațional și ușor de înțeles pentru începători.

## 📧 Contact

Pentru întrebări sau probleme, deschide un Issue în repository.

---

**Nota:** Acest IDS este destinat învățării și testării. Pentru medii de producție, consideră soluții enterprise precum Snort, Suricata, sau Zeek.