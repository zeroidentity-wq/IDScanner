# Ghid de Deployment în Producție

Acest document descrie pașii pentru deployment-ul scanner-ului IDS în producție pe un server Linux.

## 📋 Prerequisite

- Server Linux (Ubuntu 20.04+, CentOS 8+, sau RHEL 8+)
- Rust toolchain (pentru build)
- Access SSH cu privilegii sudo
- ArcSight Logger funcțional
- ArcSight SIEM pentru primirea alertelor

## 🔧 Pregătire Server

### 1. Instalare Rust (dacă nu este deja instalat)

```bash
# Instalare Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Verificare instalare
rustc --version
cargo --version
```

### 2. Creare User Dedicat

```bash
# Creează user fără privilegii pentru rularea serviciului
sudo useradd -r -s /bin/false -d /opt/ids-scanner idsuser
```

### 3. Pregătire Directoare

```bash
# Creează directorul de instalare
sudo mkdir -p /opt/ids-scanner
sudo mkdir -p /var/log/ids-scanner

# Setează owner-ul
sudo chown -R idsuser:idsuser /opt/ids-scanner
sudo chown -R idsuser:idsuser /var/log/ids-scanner
```

## 📦 Build și Instalare

### 1. Build în Modul Release

```bash
# În directorul proiectului
cd ids-scanner
cargo build --release

# Verifică binarul
ls -lh target/release/ids-scanner
```

### 2. Deployment Binarul

```bash
# Copiază binarul
sudo cp target/release/ids-scanner /opt/ids-scanner/

# Setează permisiuni
sudo chown idsuser:idsuser /opt/ids-scanner/ids-scanner
sudo chmod 755 /opt/ids-scanner/ids-scanner

# Test rapid
sudo -u idsuser /opt/ids-scanner/ids-scanner --help
```

## ⚙️ Configurare Serviciu Systemd

### 1. Instalare Fișier Service

```bash
# Copiază fișierul service
sudo cp ids-scanner.service /etc/systemd/system/

# Editează configurarea (opțional)
sudo nano /etc/systemd/system/ids-scanner.service
```

### 2. Modificare Setări (în fișierul service)

Editează `/etc/systemd/system/ids-scanner.service` pentru:

- **Port de ascultare**: Modifică binarul să citească din ENV sau hardcodează în `src/main.rs`
- **Logging level**: `Environment="RUST_LOG=info"` (opțiuni: debug, info, warn, error)

### 3. Activare Serviciu

```bash
# Reload daemon
sudo systemctl daemon-reload

# Enable la boot
sudo systemctl enable ids-scanner

# Start serviciu
sudo systemctl start ids-scanner

# Verifică status
sudo systemctl status ids-scanner
```

## 🔥 Configurare Firewall

### UFW (Ubuntu/Debian)

```bash
# Permite trafic UDP pe portul 5555
sudo ufw allow 5555/udp comment 'IDS Scanner'

# Verifică reguli
sudo ufw status
```

### Firewalld (CentOS/RHEL)

```bash
# Permite port UDP
sudo firewall-cmd --permanent --add-port=5555/udp
sudo firewall-cmd --reload

# Verifică
sudo firewall-cmd --list-all
```

## 🔗 Configurare ArcSight Logger

### 1. Configurare Forwarder

Accesează interfața ArcSight Logger și configurează un forwarder nou:

```
Destination Host: <IP_SERVER_IDS>
Destination Port: 5555
Protocol: UDP
Format: CEF
```

### 2. Aplicare Filtre

Exemplu de filtru pentru a trimite doar evenimente relevante:

```
deviceVendor = "Cisco" AND action IN ["DENY", "BLOCK", "DROP"]
```

sau

```
deviceCategory = "Firewall" AND destinationPort IS NOT NULL
```

### 3. Test Conectivitate

Din ArcSight Logger, trimite un test event și verifică log-urile:

```bash
sudo journalctl -u ids-scanner -f
```

## 📊 Monitorizare și Logging

### Vizualizare Log-uri Live

```bash
# Toate log-urile
sudo journalctl -u ids-scanner -f

# Doar erori
sudo journalctl -u ids-scanner -p err -f

# Ultimele 100 linii
sudo journalctl -u ids-scanner -n 100
```

### Rotație Log-uri

Journald gestionează automat rotația, dar poți configura:

```bash
# Editează configurarea journald
sudo nano /etc/systemd/journald.conf

# Setări recomandate:
SystemMaxUse=1G
MaxFileSec=1week
MaxRetentionSec=1month
```

După modificări:

```bash
sudo systemctl restart systemd-journald
```

## 🧪 Testare Post-Deployment

### 1. Test Conectivitate UDP

```bash
# Trimite un mesaj de test
echo "CEF:0|Test|FW|1.0|100|Test|5|src=192.168.1.1 dst=10.0.0.1 dpt=80 act=DENY" | nc -u <SERVER_IP> 5555
```

### 2. Verifică Primirea

```bash
sudo journalctl -u ids-scanner -n 20
```

Ar trebui să vezi:

```
📡 Listening on UDP 0.0.0.0:5555
```

### 3. Test Scan Rapid

Rulează scriptul de test:

```bash
./test_scanner.sh
```

Verifică în log-uri pentru:

```
⚠️  SCAN DETECTAT: Scan de rețea RAPID_SCAN detectat...
```

## 🔍 Troubleshooting

### Scanner-ul nu pornește

```bash
# Verifică erori
sudo journalctl -u ids-scanner -n 50

# Verifică permisiuni
ls -l /opt/ids-scanner/ids-scanner

# Test manual
sudo -u idsuser /opt/ids-scanner/ids-scanner
```

### Nu primește log-uri de la ArcSight

1. **Verifică conectivitatea**:
```bash
# Din serverul ArcSight
nc -zvu <IDS_SERVER_IP> 5555
```

2. **Verifică firewall-ul**:
```bash
sudo netstat -ulnp | grep 5555
```

3. **Verifică configurarea Forwarder** în ArcSight Logger

### Alertele nu ajung în SIEM

1. **Test manual trimite către SIEM**:
```bash
echo "CEF:0|Test|Test|1.0|100|Test|5|msg=test" | nc -u <SIEM_IP> 514
```

2. **Verifică că SIEM-ul ascultă**:
```bash
# Pe serverul SIEM
sudo netstat -ulnp | grep 514
```

## 📈 Optimizări Performance

### 1. Ajustare Limită Descriptori Fișiere

```bash
# Editează limits
sudo nano /etc/systemd/system/ids-scanner.service

# Adaugă în secțiunea [Service]
LimitNOFILE=65536
```

### 2. Tuning Kernel pentru UDP

```bash
# Adaugă în /etc/sysctl.conf
sudo nano /etc/sysctl.conf

# Adaugă:
net.core.rmem_max = 134217728
net.core.rmem_default = 67108864
net.ipv4.udp_mem = 65536 131072 262144

# Aplicare
sudo sysctl -p
```

### 3. Ajustare Buffer Size

Modifică în `src/main.rs`:

```rust
let mut buf = vec![0u8; 131072]; // 128KB în loc de 64KB
```

## 🔄 Update și Maintenance

### Update Scanner

```bash
# Build nou
cd ids-scanner
git pull  # sau descarcă noua versiune
cargo build --release

# Stop serviciu
sudo systemctl stop ids-scanner

# Update binar
sudo cp target/release/ids-scanner /opt/ids-scanner/

# Restart serviciu
sudo systemctl start ids-scanner

# Verifică
sudo systemctl status ids-scanner
```

### Backup Configurare

```bash
# Backup service file
sudo cp /etc/systemd/system/ids-scanner.service ~/ids-scanner-backup/

# Backup binar
sudo cp /opt/ids-scanner/ids-scanner ~/ids-scanner-backup/
```

## 🔐 Securitate

### 1. Restricții SELinux (RHEL/CentOS)

```bash
# Verifică status SELinux
getenforce

# Dacă este Enforcing, creează policy
sudo ausearch -c 'ids-scanner' --raw | audit2allow -M ids-scanner
sudo semodule -i ids-scanner.pp
```

### 2. Limitări Resource

În `/etc/systemd/system/ids-scanner.service`:

```ini
[Service]
# Limitări memory
MemoryMax=512M
MemoryHigh=256M

# Limitări CPU
CPUQuota=80%
```

## 📞 Support și Contact

Pentru probleme sau întrebări:
- Verifică log-urile: `sudo journalctl -u ids-scanner`
- Review README.md pentru detalii funcționalitate
- Contactează echipa de securitate

---

**✅ Deployment Checklist**

- [ ] Rust instalat și funcțional
- [ ] User `idsuser` creat
- [ ] Directoare create și permisiuni setate
- [ ] Binar compilat și copiat
- [ ] Service file instalat
- [ ] Firewall configurat (port 5555 UDP)
- [ ] ArcSight Forwarder configurat
- [ ] Test conectivitate reușit
- [ ] Test scan detection reușit
- [ ] Alertele ajung în SIEM
- [ ] Monitorizare activată (journald)
- [ ] Backup efectuat
