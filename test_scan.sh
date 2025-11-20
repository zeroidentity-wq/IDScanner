#!/bin/bash

# ==============================================================================
# Script pentru a testa PDScanner prin simularea unei scanări de porturi
# sau prin forțarea trimiterii unui e-mail de test.
# ==============================================================================

# --- Configurare implicită ---
TARGET_HOST="localhost"
TARGET_PORT="7878"
SCAN_TYPE="fast"
TEST_EMAIL=false
FORCE_EMAIL=false

# --- Funcție de afișare a utilizării ---
usage() {
  echo "Utilizare: $0 [opțiuni]"
  echo ""
  echo "Opțiuni:"
  echo "  --type <fast|slow>    Tipul de scanare de simulat. Implicit: 'fast'."
  echo "  --with-email          Activează modul de testare pentru e-mail în timpul unei scanări."
  echo "  --force-email         Trimite un singur pachet pentru a forța un e-mail de test."
  echo "                        Această opțiune ignoră --type și --with-email."
  echo "  --help                Afișează acest mesaj de ajutor."
  exit 1
}

# --- Parsarea argumentelor din linia de comandă ---
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --type) SCAN_TYPE="$2"; shift ;;
        --with-email) TEST_EMAIL=true ;;
        --force-email) FORCE_EMAIL=true ;;
        --help) usage ;;
        *) echo "Parametru necunoscut: $1"; usage ;;
    esac
    shift
done

# --- Validare `nc` ---
if ! command -v nc &> /dev/null; then
    echo "Eroare: Comanda 'nc' (netcat) nu a fost găsită. Vă rugăm să o instalați." >&2
    exit 1
fi

# --- Modul de testare forțată a e-mailului ---
if [ "$FORCE_EMAIL" = true ]; then
  echo "**********************************************************************"
  echo "** ATENȚIE: Se va trimite o comandă de testare forțată a e-mailului. **"
  echo "**                                                                  **"
  echo "** Asigurați-vă că în 'config.toml':                                **"
  echo "** 1. 'enabled = true' în secțiunea [smtp].                         **"
  echo "** 2. Detaliile SMTP (server, port, user, pass) sunt corecte.       **"
  echo "**********************************************************************"
  read -p "Apăsați [Enter] pentru a trimite e-mailul de test..."

  echo "Se trimite comanda 'FORCE_EMAIL_TEST' către $TARGET_HOST:$TARGET_PORT..."
  echo "FORCE_EMAIL_TEST" | nc -u -w1 $TARGET_HOST $TARGET_PORT
  
  echo "Comanda a fost trimisă. Verificați consola serverului și inbox-ul."
  exit 0
fi

# --- Modul de simulare a scanării ---
if [ "$SCAN_TYPE" == "fast" ]; then
  PACKET_COUNT=25
  DELAY=0
  ATTACKER_IP="10.1.2.3"
  echo "Se pregătește simularea unei scanări RAPIDE..."
elif [ "$SCAN_TYPE" == "slow" ]; then
  PACKET_COUNT=105
  DELAY=1
  ATTACKER_IP="10.4.5.6"
  echo "Se pregătește simularea unei scanări LENTE... Acest test va dura aproximativ $PACKET_COUNT secunde."
else
  echo "Eroare: Tip de scanare invalid '$SCAN_TYPE'. Folosiți 'fast' sau 'slow'."
  exit 1
fi

if [ "$TEST_EMAIL" = true ]; then
  echo ""
  echo "**********************************************************************"
  echo "** ATENȚIE: Modul de testare a e-mailului este activat.             **"
  echo "** Asigurați-vă că detaliile SMTP sunt corecte în 'config.toml'.    **"
  echo "**********************************************************************"
  read -p "Apăsați [Enter] pentru a continua testul..."
  echo ""
fi

echo "Se inițiază trimiterea a $PACKET_COUNT pachete UDP către $TARGET_HOST:$TARGET_PORT..."
echo "------------------------------------------------------------------"

for i in $(seq 1 $PACKET_COUNT); do
  LOG_MSG="date=2024-05-21 time=10:00:00 devname=\"fortigate\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" vd=\"root\" srcip=$ATTACKER_IP srcport=54321 dstip=192.168.1.100 dstport=$i proto=6 action=deny"
  echo "$LOG_MSG" | nc -u -w1 $TARGET_HOST $TARGET_PORT
  echo "Pachet de test trimis pentru portul $i"
  sleep $DELAY
done

echo "------------------------------------------------------------------"
echo "Test finalizat."
echo "Verificați consola unde rulează PDScanner pentru a vedea mesajul de alertă."
if [ "$TEST_EMAIL" = true ]; then
    echo "De asemenea, verificați inbox-ul destinatarului pentru e-mailul de alertă."
fi
