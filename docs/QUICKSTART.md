# 🚀 Quick Start Guide - Intrusion Detection Scanner

Un scanner de detecție a intruziunilor scris în Rust pentru ArcSight, optimizat pentru detectarea scan-urilor de rețea.

## ⚡ Start Rapid (5 Minute Setup)

### 1. Build Proiectul

```bash
cd ids-scanner
cargo build --release
```

### 2. Rulează Scanner-ul

```bash
./target/release/ids-scanner
```

**Scanner-ul va:**
- Asculta pe portul UDP `5555`
- Detecta scan-uri rapide (10+ porturi în 60 secunde)
- Detecta scan-uri lente (20+ porturi în 1 oră)
- Trimite alerte către ArcSight SIEM pe `127.0.0.1:514`

### 3. Test Rapid

În alt terminal:

```bash
chmod +x test_scanner.sh
./test_scanner.sh
```

Verifică log-urile pentru alerte:

```
⚠️  SCAN DETECTAT: Scan de rețea RAPID_SCAN detectat: IP 192.168.1.100 a accesat 15 porturi unice în ultimele 60 secunde
```

## 📚 Documentație Completă

| Document | Descriere |
|----------|-----------|
| **README.md** | Documentație completă cu toate funcționalitățile |
| **DEPLOYMENT.md** | Ghid pas-cu-pas pentru deployment în producție |
| **EXAMPLES.md** | Exemple de log-uri și scenarii de detecție |
| **config.example.toml** | Template configurare (viitor feature) |

## 🔧 Configurare ArcSight Logger

### Configurare Forwarder

1. **Acces**: ArcSight Logger Web Interface
2. **Navigare**: Configuration → Forwarders
3. **Adaugă nou**:
   - **Destination**: IP-ul serverului cu IDS Scanner
   - **Port**: 5555
   - **Protocol**: UDP
   - **Format**: CEF (recomandat)

### Filtre Recomandate

```
deviceVendor = "Cisco" AND action IN ["DENY", "BLOCK"]
```

sau

```
deviceCategory = "Firewall" AND destinationPort > 0
```

## 📊 Ce Detectează

### ✅ Scan Rapid (HIGH Severity)
- 10+ porturi diferite în 60 secunde
- Tipic: `nmap -F`, scan-uri automate agresive

### ✅ Scan Lent (MEDIUM Severity)
- 20+ porturi diferite în 1 oră
- Tipic: scan-uri stealth, reconnaissance lent

## 🎯 Exemple Log-uri Acceptate

### Format CEF
```
CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=192.168.1.100 dst=10.0.0.50 dpt=22 proto=TCP act=DENY
```

### Format Raw Syslog
```
Jan 29 10:15:30 firewall: src=192.168.1.100 dst=10.0.0.50 dport=80 action=DENY
```

## 🔥 Features

- ⚡ **Async/Concurrent**: Tokio pentru performance ridicat
- 🎯 **Dual Detection**: Scan-uri rapide și lente
- 📝 **Multiple Formats**: CEF și Raw Syslog
- 🔔 **Real-time Alerts**: Trimite alerte imediate către SIEM
- 🧹 **Auto-Cleanup**: Gestionare automată a memoriei
- 🛡️ **Production Ready**: Optimizat pentru deployment

## 📈 Arhitectură Simplificată

```
┌─────────────────────┐
│  ArcSight Logger    │
│    (Forwarder)      │
└──────────┬──────────┘
           │ UDP CEF/Syslog
           │ Port 5555
           ▼
┌─────────────────────┐
│   IDS Scanner       │
│  - Parse Logs       │
│  - Track Activity   │
│  - Detect Scans     │
└──────────┬──────────┘
           │ CEF Alerts
           │ Port 514
           ▼
┌─────────────────────┐
│   ArcSight SIEM     │
│  (Alert Console)    │
└─────────────────────┘
```

## 🛠️ Modificare Setări

Editează `src/main.rs`:

```rust
// Schimbă portul
let listen_addr = "0.0.0.0:6666";

// Schimbă adresa SIEM
let siem_addr = "10.0.0.100:514";

// Ajustează pragurile
let config = ScanDetectionConfig {
    rapid_scan_threshold: 15,    // mai tolerant
    rapid_scan_window: 30,       // mai strict pe timp
    slow_scan_threshold: 25,
    slow_scan_window: 7200,      // 2 ore
    cache_expiry: 14400,
};
```

După modificări:

```bash
cargo build --release
./target/release/ids-scanner
```

## 🐛 Troubleshooting Rapid

### Nu primește log-uri?

```bash
# Test conectivitate
echo "CEF:0|Test|FW|1.0|100|Test|5|src=1.1.1.1 dst=2.2.2.2 dpt=80 act=DENY" | nc -u localhost 5555

# Verifică că portul e deschis
sudo netstat -ulnp | grep 5555

# Verifică firewall
sudo ufw allow 5555/udp
```

### Alertele nu ajung în SIEM?

```bash
# Test către SIEM
echo "test alert" | nc -u <SIEM_IP> 514

# Verifică adresa în cod
grep "siem_addr" src/main.rs
```

## 📝 Logging

```bash
# Debug complet
RUST_LOG=debug ./target/release/ids-scanner

# Doar warnings și erori
RUST_LOG=warn ./target/release/ids-scanner

# Info (default)
RUST_LOG=info ./target/release/ids-scanner
```

## 🚀 Deployment Producție

Vezi **DEPLOYMENT.md** pentru:
- Setup systemd service
- Configurare firewall
- Tuning performance
- Monitoring și alerting
- Rotație log-uri
- Security hardening

## 📞 Support

Pentru probleme:
1. Verifică log-urile cu `RUST_LOG=debug`
2. Rulează `test_scanner.sh` pentru verificare funcționalitate
3. Review documentația completă în README.md
4. Contactează echipa de securitate

## ⚠️ Important

- **Autorizare**: Asigură-te că ai autorizație pentru monitoring
- **Privacy**: Respectă politicile de confidențialitate
- **Testing**: Testează în dev înainte de producție
- **Backup**: Păstrează backup la configurări

---

**✨ Created with Rust 🦀 | Optimized for ArcSight | Production Ready**

Pentru detalii complete, vezi **README.md**
