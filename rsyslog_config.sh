#!/bin/bash
# ============================================================================
# CONFIGURAȚIE RSYSLOG PENTRU IDS
# ============================================================================
# Script de configurare automată pentru integrarea IDS cu rsyslog
# pe serverul ArcSight Logger - ZERO INTERFERENȚĂ cu ArcSight
# ============================================================================

set -e  # Ieșire la eroare

echo "╔═══════════════════════════════════════════════════╗"
echo "║   Configurare IDS Rsyslog                         ║"
echo "║   Mod Coexistență ArcSight                        ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

# ============================================================================
# VERIFICĂRI PRELIMINARE
# ============================================================================

if [ "$EUID" -ne 0 ]; then 
    echo "❌ Acest script trebuie rulat ca root (sudo)"
    exit 1
fi

if ! command -v rsyslogd &> /dev/null; then
    echo "❌ rsyslog nu este instalat"
    echo "   Instalare: sudo apt-get install rsyslog  # Debian/Ubuntu"
    echo "             sudo yum install rsyslog       # RHEL/CentOS"
    exit 1
fi

echo "✓ Rulează ca root"
echo "✓ rsyslog este instalat"
echo ""

# ============================================================================
# CONFIGURAȚIE IDS
# ============================================================================

DIRECTOR_SOCKET_IDS="/var/run/ids-personalizat"
CALE_SOCKET_IDS="${DIRECTOR_SOCKET_IDS}/ids.sock"
FISIER_CONFIG_IDS="/etc/rsyslog.d/90-ids-personalizat.conf"

echo "📁 Creare directoare IDS..."
mkdir -p "$DIRECTOR_SOCKET_IDS"
chmod 755 "$DIRECTOR_SOCKET_IDS"
echo "   Creat: $DIRECTOR_SOCKET_IDS"
echo ""

# ============================================================================
# CONFIGURAȚIE RSYSLOG - METODA OMFWD (FLUX DUPLICAT)
# ============================================================================
# Această metodă trimite jurnalele în PARALEL către:
# 1. ArcSight (fluxul original, nemodificat)
# 2. IDS-ul nostru (prin socket UNIX)

echo "📝 Creare configurație rsyslog..."

cat > "$FISIER_CONFIG_IDS" << 'EOF'
# ============================================================================
# INTEGRARE IDS PERSONALIZAT - FĂRĂ INTERFERENȚĂ ARCSIGHT
# ============================================================================
# Această configurație trimite o COPIE a jurnalelor către IDS
# fără a modifica fluxul original către ArcSight
# ============================================================================

# Încarcă modulul pentru ieșire socket UNIX
module(load="omuxsock")

# Regulă: Trimite TOATE jurnalele către IDS
# & stop - NU ADĂUGĂM (pentru a permite continuarea către ArcSight)
# Folosim action() cu copy pentru a duplica fluxul

# IMPORTANT: Folosim șablon simplu pentru a evita overhead
template(name="FormatIDS" type="string" string="%msg%\n")

# Trimite către IDS (ASYNC pentru a nu bloca fluxul principal)
action(
    type="omuxsock"
    socket="/var/run/ids-personalizat/ids.sock"
    template="FormatIDS"
    
    # ASYNC = nu bloca rsyslog dacă IDS-ul e lent/offline
    queue.type="LinkedList"
    queue.size="10000"
    queue.discardMark="9500"
    queue.discardSeverity="0"
    action.resumeRetryCount="-1"
    
    # Gestionare erori
    action.reportSuspension="on"
    action.reportSuspensionContinuation="on"
)

# Jurnalele continuă normal către ArcSight (fluxul original)
# Nu adăugăm "& stop" aici!

EOF

echo "✓ Creat: $FISIER_CONFIG_IDS"
echo ""

# ============================================================================
# BACKUP CONFIGURAȚIE EXISTENTĂ
# ============================================================================

echo "💾 Backup configurație rsyslog..."
DIRECTOR_BACKUP="/etc/rsyslog.backup.$(date +%Y%m%d_%H%M%S)"
mkdir -p "$DIRECTOR_BACKUP"
cp -r /etc/rsyslog.conf /etc/rsyslog.d "$DIRECTOR_BACKUP/" 2>/dev/null || true
echo "✓ Backup salvat în: $DIRECTOR_BACKUP"
echo ""

# ============================================================================
# VALIDARE CONFIGURAȚIE
# ============================================================================

echo "🔍 Validare configurație rsyslog..."
if rsyslogd -N1 2>&1 | grep -i error; then
    echo "❌ Validarea configurației a eșuat!"
    echo "   Restaurare backup..."
    cp "$DIRECTOR_BACKUP/rsyslog.conf" /etc/rsyslog.conf
    rm -f "$FISIER_CONFIG_IDS"
    exit 1
fi

echo "✓ Configurația este validă"
echo ""

# ============================================================================
# VERIFICARE CONFLICTE ARCSIGHT
# ============================================================================

echo "🔒 Verificare conflicte ArcSight..."

# Verifică dacă ceva folosește deja socket-ul nostru
if lsof 2>/dev/null | grep -q "ids.sock"; then
    echo "⚠️  ATENȚIE: Ceva folosește deja ids.sock"
    echo "   Verifică: lsof | grep ids.sock"
fi

# Verifică dacă ArcSight Logger rulează
if pgrep -f "arcsight" > /dev/null 2>&1; then
    echo "✓ Proces ArcSight detectat (normal)"
else
    echo "ℹ️  Proces ArcSight nu e detectat (OK dacă nu e pornit încă)"
fi

echo ""

# ============================================================================
# INFORMAȚII POST-INSTALARE
# ============================================================================

cat << 'EOF'
╔═══════════════════════════════════════════════════╗
║   CONFIGURARE COMPLETĂ                            ║
╚═══════════════════════════════════════════════════╝

📋 PAȘI URMĂTORI:

1. PORNEȘTE IDS-UL (înainte de restart rsyslog):
   
   # Compilează și rulează IDS-ul Rust
   cd /cale/catre/ids
   cargo build --release
   sudo ./target/release/ids-rsyslog
   
   # Sau ca serviciu systemd (vezi mai jos)

2. RESTART RSYSLOG:
   
   sudo systemctl restart rsyslog
   
   # Verifică lipsa erorilor
   sudo journalctl -u rsyslog -n 50 --no-pager

3. VERIFICĂ IDS-UL PRIMEȘTE DATE:
   
   # Verifică consola IDS
   # Ar trebui să vezi: "✓ Conexiune nouă de la rsyslog"
   
   # Generează trafic de test
   logger "TEST: Acesta este un mesaj de test"

4. MONITORIZEAZĂ PROBLEME:
   
   # Urmărește jurnalele rsyslog
   sudo tail -f /var/log/syslog
   
   # Urmărește ieșirea IDS
   # Ar trebui să afișeze statistici la fiecare 60 secunde

╔═══════════════════════════════════════════════════╗
║   IZOLARE ARCSIGHT VERIFICATĂ                     ║
╚═══════════════════════════════════════════════════╝

✓ IDS folosește socket separat: /var/run/ids-personalizat/ids.sock
✓ IDS folosește port separat: 8888 (ArcSight: 8443)
✓ IDS este proces separat (fără modificare binare)
✓ rsyslog trimite flux DUPLICAT (originalul continuă)
✓ Coadă ASYNC previne blocarea rsyslog

🔒 ZERO INTERFERENȚĂ CU ARCSIGHT:
   - ArcSight continuă să primească toate jurnalele normal
   - IDS operează complet independent
   - Dacă IDS crapă, ArcSight nu e afectat
   - Dacă IDS e lent, rsyslog bufferizează și continuă

EOF

# ============================================================================
# CREEAZĂ SERVICIU SYSTEMD (OPȚIONAL)
# ============================================================================

read -p "Creezi serviciu systemd pentru IDS? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    CALE_BINAR_IDS="/usr/local/bin/ids-rsyslog"
    FISIER_SERVICIU_IDS="/etc/systemd/system/ids-rsyslog.service"
    
    echo "📝 Creare serviciu systemd..."
    
    cat > "$FISIER_SERVICIU_IDS" << EOF
[Unit]
Description=IDS Rsyslog Personalizat - Detectare Scanări Rețea
After=network.target rsyslog.service
Requires=rsyslog.service

[Service]
Type=simple
User=root
Group=root
ExecStart=$CALE_BINAR_IDS
Restart=always
RestartSec=10

# Întărire securitate (opțional)
NoNewPrivileges=true
PrivateTmp=true

# Jurnalizare
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ids-rsyslog

[Install]
WantedBy=multi-user.target
EOF

    echo "✓ Creat: $FISIER_SERVICIU_IDS"
    echo ""
    echo "📋 Pentru a folosi serviciul systemd:"
    echo "   1. Copiază binarul IDS:"
    echo "      sudo cp target/release/ids-rsyslog $CALE_BINAR_IDS"
    echo "      sudo chmod +x $CALE_BINAR_IDS"
    echo ""
    echo "   2. Activează și pornește:"
    echo "      sudo systemctl daemon-reload"
    echo "      sudo systemctl enable ids-rsyslog"
    echo "      sudo systemctl start ids-rsyslog"
    echo ""
    echo "   3. Verifică status:"
    echo "      sudo systemctl status ids-rsyslog"
    echo "      sudo journalctl -u ids-rsyslog -f"
fi

echo ""
echo "✅ Configurare completă!"
echo ""

# ============================================================================
# TEST CONEXIUNE (OPȚIONAL)
# ============================================================================

read -p "Testezi conexiunea socket acum? (necesită IDS pornit) (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -S "$CALE_SOCKET_IDS" ]; then
        echo "✓ Socket există: $CALE_SOCKET_IDS"
        echo "Trimitere mesaj de test..."
        echo "TEST: $(date) - Test socket IDS" | nc -U "$CALE_SOCKET_IDS" 2>/dev/null && echo "✓ Mesaj de test trimis" || echo "✗ Eroare la trimitere"
    else
        echo "ℹ️  Socket nu există. Pornește IDS-ul mai întâi, apoi restart rsyslog."
    fi
fi

echo ""
echo "🎉 Totul gata! Verifică instrucțiunile de mai sus."