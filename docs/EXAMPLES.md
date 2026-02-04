# Exemple de Log-uri și Detecție

Acest document conține exemple detaliate de log-uri suportate și scenarii de detecție.

## 📝 Formate Suportate

### 1. Format CEF (Common Event Format)

**Structură generală CEF:**
```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

**Exemplu complet:**
```
CEF:0|Cisco|ASA|9.0|106023|Deny tcp src|5|src=192.168.1.100 dst=10.0.0.50 dpt=22 proto=TCP act=DENY
```

**Câmpuri utilizate de scanner:**
- `src` - Source IP (obligatoriu pentru detecție)
- `dst` - Destination IP (opțional)
- `dpt` - Destination Port (obligatoriu pentru detecție)
- `proto` - Protocol (opțional)
- `act` - Action (opțional pentru filtrare)

### 2. Format Raw Syslog

**Exemplu Cisco ASA:**
```
Jan 29 10:15:30 192.168.1.1 %ASA-4-106023: Deny tcp src inside:192.168.1.100/45000 dst outside:10.0.0.50/22
```

**Exemplu simplificat cu key=value:**
```
Jan 29 10:15:30 firewall: src=192.168.1.100 dst=10.0.0.50 dport=80 action=DENY proto=TCP
```

**Exemplu pfSense:**
```
filterlog: 5,,,1000000103,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,192.168.1.100,10.0.0.50,50000,80
```

## 🎯 Scenarii de Detecție

### Scenario 1: Scan Rapid de Porturi (Port Scan)

**Descriere:** Un atacator scanează rapid multiple porturi pe un host țintă.

**Log-uri simulate:**
```
CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=192.168.1.100 dst=10.0.0.50 dpt=21 proto=TCP act=DENY
CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=192.168.1.100 dst=10.0.0.50 dpt=22 proto=TCP act=DENY
CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=192.168.1.100 dst=10.0.0.50 dpt=23 proto=TCP act=DENY
CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=192.168.1.100 dst=10.0.0.50 dpt=80 proto=TCP act=DENY
CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=192.168.1.100 dst=10.0.0.50 dpt=443 proto=TCP act=DENY
CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=192.168.1.100 dst=10.0.0.50 dpt=3306 proto=TCP act=DENY
CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=192.168.1.100 dst=10.0.0.50 dpt=3389 proto=TCP act=DENY
CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=192.168.1.100 dst=10.0.0.50 dpt=5432 proto=TCP act=DENY
CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=192.168.1.100 dst=10.0.0.50 dpt=8080 proto=TCP act=DENY
CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=192.168.1.100 dst=10.0.0.50 dpt=8443 proto=TCP act=DENY
```

**Detecție:**
- 10+ porturi unice în 60 secunde
- Alertă: `RAPID_SCAN`
- Severitate: `HIGH`

**Alertă generată:**
```
CEF:0|CustomIDS|NetworkScanner|1.0|RAPID_SCAN|Scan de rețea RAPID_SCAN detectat: IP 192.168.1.100 a accesat 10 porturi unice în ultimele 60 secunde|HIGH|src=192.168.1.100 msg=Scan de rețea RAPID_SCAN detectat: IP 192.168.1.100 a accesat 10 porturi unice în ultimele 60 secunde cnt=10
```

### Scenario 2: Scan Lent Stealth (Slow Scan)

**Descriere:** Un atacator încearcă să evite detecția scanând lent de-a lungul unei ore.

**Caracteristici:**
- 1 port la fiecare 2-3 minute
- Distribuție pe o perioadă lungă (1 oră+)
- Total 20+ porturi diferite

**Exemplu timeline:**
```
10:00:00 - Port 21
10:03:00 - Port 22
10:06:00 - Port 23
10:09:00 - Port 25
...
10:57:00 - Port 8080
11:00:00 - Port 9000  <- Alertă generată aici (20+ porturi în 1h)
```

**Detecție:**
- 20+ porturi unice în 3600 secunde (1 oră)
- Alertă: `SLOW_SCAN`
- Severitate: `MEDIUM`

### Scenario 3: Network Sweep (Scanning Multiple Hosts)

**Descriere:** Atacatorul scanează același port pe multiple host-uri.

**Log-uri:**
```
CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=192.168.1.100 dst=10.0.0.1 dpt=445 proto=TCP act=DENY
CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=192.168.1.100 dst=10.0.0.2 dpt=445 proto=TCP act=DENY
CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=192.168.1.100 dst=10.0.0.3 dpt=445 proto=TCP act=DENY
...
CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=192.168.1.100 dst=10.0.0.50 dpt=445 proto=TCP act=DENY
```

**Notă:** Versiunea actuală detectează scanări ale aceluiași IP sursă către **porturi diferite**. Pentru detecție de network sweep (același port, destinații diferite), este nevoie de logică suplimentară.

### Scenario 4: Service Discovery cu Nmap

**Descriere:** Scanare Nmap standard cu `-sS` (SYN scan).

**Porturi comune scanate:**
```
21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS),
80 (HTTP), 110 (POP3), 143 (IMAP), 443 (HTTPS), 445 (SMB),
3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 8080 (HTTP Alt)
```

**Detecție:** Dacă sunt scanate 10+ din aceste porturi în mai puțin de 60 secunde → RAPID_SCAN

### Scenario 5: Vulnerability Scanner (Nessus/OpenVAS)

**Descriere:** Scanner automat de vulnerabilități.

**Caracteristici:**
- Scanare secvențială a multor porturi
- Poate scana sute de porturi
- Viteză moderată (2-5 secunde per port)

**Detecție:**
- Rapid Scan: Dacă scanează >10 porturi în <60s
- Slow Scan: Dacă scanează >20 porturi în <1h

## 🔧 Configurare Praguri pentru Scenarii Specifice

### Configurare 1: Rețea cu multe scanere legitime

```rust
ScanDetectionConfig {
    rapid_scan_threshold: 20,      // Mai tolerant
    rapid_scan_window: 30,         // Fereastră mai scurtă
    slow_scan_threshold: 50,       // Prag mai ridicat
    slow_scan_window: 3600,
    cache_expiry: 7200,
}
```

### Configurare 2: Rețea high-security

```rust
ScanDetectionConfig {
    rapid_scan_threshold: 5,       // Foarte strict
    rapid_scan_window: 120,        // Fereastră mai largă
    slow_scan_threshold: 10,       // Prag scăzut
    slow_scan_window: 1800,        // 30 minute
    cache_expiry: 3600,
}
```

### Configurare 3: Balansată (Recommended)

```rust
ScanDetectionConfig {
    rapid_scan_threshold: 10,
    rapid_scan_window: 60,
    slow_scan_threshold: 20,
    slow_scan_window: 3600,
    cache_expiry: 7200,
}
```

## 📊 Exemple Complete de Testare

### Test 1: Simulare Scan Rapid cu nc

```bash
#!/bin/bash
# test_rapid_scan.sh

SRC_IP="192.168.1.100"
DST_IP="10.0.0.50"
SCANNER_PORT="5555"

echo "Trimitere 15 log-uri pentru scan rapid..."
for port in 21 22 23 25 80 110 143 443 445 3306 3389 5432 8080 8443 9000; do
    echo "CEF:0|Cisco|ASA|9.0|106023|Deny|5|src=$SRC_IP dst=$DST_IP dpt=$port proto=TCP act=DENY" | nc -u localhost $SCANNER_PORT
    echo "Trimis port $port"
    sleep 0.5
done

echo "Test completat. Verifică log-urile pentru alertă RAPID_SCAN"
```

### Test 2: Simulare Diverse Formate

```bash
#!/bin/bash
# test_formats.sh

# Format CEF
echo "CEF:0|Fortinet|FortiGate|6.0|0001|Traffic|5|src=10.0.5.20 dst=172.16.0.10 dpt=22 proto=TCP act=DENY" | nc -u localhost 5555

# Format Syslog simplificat
echo "Jan 29 11:30:00 fw01: src=10.0.5.20 dst=172.16.0.10 dport=80 action=BLOCK" | nc -u localhost 5555

# Format Cisco ASA raw
echo "Jan 29 11:30:05 192.168.1.1 %ASA-4-106023: Deny tcp src inside:10.0.5.20/50000 dst outside:172.16.0.10/443" | nc -u localhost 5555
```

## 🎓 Interpretare Alerte

### Alertă RAPID_SCAN

**Ce înseamnă:**
- Activitate suspectă de scan rapid
- Posibil atacator activ
- Risc ridicat de compromitere

**Acțiuni recomandate:**
1. Verifică IP-ul sursă în threat intelligence
2. Blochează temporar IP-ul dacă este extern
3. Verifică dacă există conexiuni reușite de la același IP
4. Alertează echipa SOC

### Alertă SLOW_SCAN

**Ce înseamnă:**
- Scan stealth în desfășurare
- Atacator caută să evite detecția
- Risc mediu spre ridicat

**Acțiuni recomandate:**
1. Monitorizează activitatea IP-ului
2. Verifică istoric pentru pattern-uri similare
3. Consideră rate-limiting pentru IP-ul sursă
4. Documentează pentru analiză de tendințe

## 📈 Metrici și Statistici

### Normal vs Anomalii

**Trafic Normal:**
- 1-5 porturi accesate per oră
- Porturi comune (80, 443)
- Pattern-uri regulate

**Scan Detectat:**
- 10+ porturi în interval scurt
- Porturi neobișnuite (1-1024)
- Pattern secvențial sau aleatoriu intensiv

### False Positives Comune

1. **Load Balancer Health Checks**
   - Soluție: Whitelist IP-uri load balancer

2. **Monitoring Tools Legitime**
   - Soluție: Ajustează praguri sau whitelist

3. **Service Discovery Intern**
   - Soluție: Filtrează rețele interne de trust

## 🔍 Debugging și Troubleshooting

### Verificare Parsing Log-uri

Rulează cu `RUST_LOG=debug`:

```bash
RUST_LOG=debug ./target/release/ids-scanner
```

Output așteptat:
```
[DEBUG] Parsed CEF event: CefEvent { source_ip: Some("192.168.1.100"), dest_ip: Some("10.0.0.50"), dest_port: Some(22), ... }
[DEBUG] Updated activity for 192.168.1.100: 5 unique ports in 60s window
```

### Verificare Detecție

```bash
# Trimite test
echo "CEF:0|Test|FW|1.0|100|Test|5|src=TEST_IP dst=10.0.0.1 dpt=9999 act=DENY" | nc -u localhost 5555

# Verifică în log
sudo journalctl -u ids-scanner | grep TEST_IP
```

---

**💡 Best Practices:**

1. **Tuning Inițial:** Începe cu praguri conservatoare și ajustează bazat pe false positives
2. **Whitelist:** Menține o listă de IP-uri și servicii legitime
3. **Correlation:** Combină alertele IDS cu alte surse (firewall logs, IPS, threat intel)
4. **Review Periodic:** Analizează alertele săptămânal pentru îmbunătățiri
5. **Documentation:** Documentează toate ajustările și incidentele pentru referință viitoare
