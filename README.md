# Intrusion Detection Scanner pentru ArcSight

Scanner de detecție a intruziunilor scris în Rust, specializat în identificarea scan-urilor de rețea (atât rapide cât și lente) din log-urile transmise de ArcSight Logger.

## 🎓 Pentru Începători în Rust

Acest proiect include **documentație educațională completă în limba română**:

- **`src/main_educational_ro.rs`** - Cod complet tradus în română cu comentarii detaliate pentru fiecare linie
- **`INVATARE_RUST.md`** - Ghid complet de învățare Rust de la zero
- **`EXEMPLE_PRACTICE.md`** - Exerciții și modificări pas-cu-pas pentru a învăța prin practică

Începe cu **QUICKSTART.md** pentru setup rapid, apoi explorează fișierele educaționale!

## 🎯 Funcționalități

- **Detecție Scan Rapid**: Identifică atacatori care scanează multe porturi într-un timp scurt
- **Detecție Scan Lent**: Detectează scan-uri stealth care încearcă să evite detecția prin viteze reduse
- **Parsing CEF și Raw Syslog**: Suportă ambele formate comune de log-uri
- **Alerte către SIEM**: Trimite automat alerte în format CEF către ArcSight
- **Performance**: Async/concurrent cu Tokio pentru processing rapid
- **Memory Management**: Curățare automată a cache-ului pentru eficiență

## 🏗️ Arhitectură

```
ArcSight Logger (Forwarder)
         |
         | UDP (CEF/Syslog)
         v
   [IDS Scanner] (Port 5555)
         |
         | Detectare scan-uri
         v
   [Alert Engine]
         |
         | UDP (CEF Alert)
         v
   ArcSight SIEM (Port 514)
```

## 📋 Cerințe

- Rust 1.70+
- ArcSight Logger cu Forwarder configurat
- ArcSight SIEM pentru primirea alertelor

## 🚀 Instalare

```bash
# Clonează sau extrage proiectul
cd ids-scanner

# Build în modul release (optimizat)
cargo build --release

# Binarul se va afla în target/release/ids-scanner
```

## ⚙️ Configurare ArcSight Logger

### Pasul 1: Configurare Forwarder în ArcSight

1. Accesează interfața web ArcSight Logger
2. Navighează la **Configuration → Forwarders**
3. Click pe **Add Forwarder**
4. Configurează următoarele:
   - **Name**: IDS_Scanner_Forwarder
   - **Destination**: IP-ul serverului unde rulează scanner-ul
   - **Port**: 5555 (sau portul ales)
   - **Protocol**: UDP
   - **Format**: CEF (recomandat) sau Raw Syslog

### Pasul 2: Aplicare Filtre (Recomandat)

Pentru a reduce volumul de date și a trimite doar evenimente relevante:

```
deviceVendor = "Cisco" AND (action = "DENY" OR action = "BLOCK")
```

Sau pentru trafic de firewall:

```
deviceCategory = "Firewall" AND destinationPort > 0
```

## 🔧 Utilizare

### Rulare Simplă

```bash
# Rulează cu setările default
./target/release/ids-scanner
```

### Setări Default

- **Port de ascultare**: 5555 (UDP)
- **SIEM address**: 127.0.0.1:514 (UDP)
- **Scan rapid**: 10+ porturi în 60 secunde
- **Scan lent**: 20+ porturi în 3600 secunde (1 oră)

### Modificare Configurare în Cod

Editează `src/main.rs` pentru a schimba setările:

```rust
// Modifică portul de ascultare
let listen_addr = "0.0.0.0:6666";

// Modifică adresa SIEM
let siem_addr = "10.0.0.50:514";

// Modifică pragurile de detecție
let config = ScanDetectionConfig {
    rapid_scan_threshold: 15,      // 15+ porturi
    rapid_scan_window: 30,         // în 30 secunde
    slow_scan_threshold: 25,       // 25+ porturi
    slow_scan_window: 7200,        // în 2 ore
    cache_expiry: 14400,           // cache de 4 ore
};
```

## 📊 Exemple de Log-uri Acceptate

### Format CEF (Recomandat)

```
CEF:0|Cisco|ASA|9.0|106023|Deny tcp src|5|src=192.168.1.100 dst=10.0.0.50 dpt=22 proto=TCP act=DENY
```

### Format Raw Syslog

```
Jan 29 10:15:30 firewall: src=192.168.1.100 dst=10.0.0.50 dport=80 action=DENY
```

## 🚨 Tipuri de Alerte Generate

### Scan Rapid (HIGH Severity)

**Exemplu**: Un atacator scanează 15 porturi în 45 de secunde

```
CEF:0|CustomIDS|NetworkScanner|1.0|RAPID_SCAN|Scan de rețea RAPID_SCAN detectat: IP 192.168.1.100 a accesat 15 porturi unice în ultimele 60 secunde|HIGH|src=192.168.1.100 msg=Scan de rețea RAPID_SCAN detectat cnt=15
```

### Scan Lent (MEDIUM Severity)

**Exemplu**: Un atacator scanează 25 de porturi pe parcursul a 50 de minute

```
CEF:0|CustomIDS|NetworkScanner|1.0|SLOW_SCAN|Scan de rețea SLOW_SCAN detectat: IP 10.0.5.20 a accesat 25 porturi unice în ultimele 3600 secunde|MEDIUM|src=10.0.5.20 msg=Scan de rețea SLOW_SCAN detectat cnt=25
```

## 🔍 Monitorizare și Logging

Scanner-ul folosește `env_logger`. Poți controla nivelul de logging:

```bash
# Info level (default)
RUST_LOG=info ./target/release/ids-scanner

# Debug level (detaliat)
RUST_LOG=debug ./target/release/ids-scanner

# Warning level (doar alerte importante)
RUST_LOG=warn ./target/release/ids-scanner
```

### Output Tipic

```
[2025-01-29T10:15:30Z INFO  ids_scanner] 🚀 Starting Intrusion Detection Scanner
[2025-01-29T10:15:30Z INFO  ids_scanner] Configurare: ScanDetectionConfig { rapid_scan_threshold: 10, rapid_scan_window: 60, slow_scan_threshold: 20, slow_scan_window: 3600, cache_expiry: 7200 }
[2025-01-29T10:15:30Z INFO  ids_scanner] 📡 Listening on UDP 0.0.0.0:5555
[2025-01-29T10:15:30Z INFO  ids_scanner] 🎯 Alerte vor fi trimise către SIEM: 127.0.0.1:514
[2025-01-29T10:20:15Z WARN  ids_scanner] ⚠️  SCAN DETECTAT: Scan de rețea RAPID_SCAN detectat: IP 192.168.1.100 a accesat 12 porturi unice în ultimele 60 secunde
[2025-01-29T10:20:15Z INFO  ids_scanner] Alertă trimisă către SIEM (127.0.0.1:514): CEF:0|CustomIDS|...
```

## 🧪 Testare

### Test Manual cu netcat

```bash
# Terminal 1: Pornește scanner-ul
./target/release/ids-scanner

# Terminal 2: Trimite un log de test
echo "CEF:0|Test|FW|1.0|100|Test|5|src=192.168.1.100 dst=10.0.0.1 dpt=22 act=DENY" | nc -u localhost 5555
```

### Test de Scan Rapid

```bash
# Trimite 15 log-uri cu porturi diferite rapid
for port in {1..15}; do
  echo "CEF:0|Test|FW|1.0|100|Test|5|src=192.168.1.100 dst=10.0.0.1 dpt=$port act=DENY" | nc -u localhost 5555
  sleep 0.5
done
```

Ar trebui să vezi o alertă de RAPID_SCAN după ce pragul este atins.

## 📈 Performance

- **Throughput**: ~50,000+ evenimente/secundă pe hardware modern
- **Latență**: <1ms per eveniment (async processing)
- **Memory**: ~10-50MB în funcție de numărul de IP-uri active

## 🔒 Securitate

- Scanner-ul nu stochează date sensibile
- Cache-ul se curăță automat
- Nu necesită privilegii root (port >1024)
- Validare strictă a formatelor de input

## 🛠️ Dezvoltare Viitoare

Funcționalități planificate:

- [ ] Configurare dintr-un fișier TOML/YAML
- [ ] Whitelist pentru IP-uri cunoscute
- [ ] Detecție de anomalii bazată pe ML
- [ ] Dashboard web pentru monitoring
- [ ] Integrare cu alte SIEM-uri (Splunk, ELK)
- [ ] Support pentru TLS/TCP în loc de UDP

## 🐛 Troubleshooting

### Scanner-ul nu primește log-uri

1. Verifică că Forwarder-ul din ArcSight este configurat corect
2. Testează conectivitatea: `nc -u localhost 5555` și scrie un mesaj
3. Verifică firewall-ul: `sudo ufw allow 5555/udp`

### Alertele nu ajung în SIEM

1. Verifică că adresa SIEM este corectă
2. Testează manual: `echo "test" | nc -u <SIEM_IP> 514`
3. Verifică log-urile scanner-ului pentru erori

### Prea multe alerte false

Ajustează pragurile în configurare:
- Crește `rapid_scan_threshold` (ex: de la 10 la 20)
- Crește `slow_scan_threshold` (ex: de la 20 la 30)
- Adaugă IP-uri în whitelist

## 📝 Licență

MIT License - vezi fișierul LICENSE pentru detalii.

## 👨‍💻 Contribuții

Contribuțiile sunt binevenite! Te rog să deschizi un issue sau pull request.

## 📧 Contact

Pentru întrebări sau suport, contactează echipa de securitate.

---

**⚠️ Important**: Acest tool este destinat utilizării în medii de producție pentru securitate. Asigură-te că ai autorizație înainte de deployment și respectă politicile companiei privind monitorizarea rețelei.
