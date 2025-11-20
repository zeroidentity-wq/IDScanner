#!/bin/bash

# Script pentru a testa PDScanner prin simularea unei scanări rapide de porturi.
#
# Acest script trimite un număr configurabil de pachete UDP false către server,
# fiecare cu un port de destinație diferit, pentru a declanșa alerta de scanare.

# --- Configurare ---
TARGET_HOST="localhost"
TARGET_PORT="7878"
PACKET_COUNT=25 # Trebuie să fie mai mare decât fast_scan_threshold din config.toml
ATTACKER_IP="10.1.2.3"

# --- Validare ---
# Verifică dacă `nc` (netcat) este instalat
if ! command -v nc &> /dev/null
then
    echo "Eroare: Comanda 'nc' (netcat) nu a fost găsită. Vă rugăm să o instalați."
    echo "Pe Red Hat/CentOS, rulați: sudo dnf install nmap-ncat"
    echo "Pe Debian/Ubuntu, rulați: sudo apt-get install netcat"
    exit 1
fi

echo "Se inițiază testul de scanare a porturilor..."
echo "Se vor trimite $PACKET_COUNT pachete UDP către $TARGET_HOST:$TARGET_PORT"
echo "-----------------------------------------------------"

for i in $(seq 1 $PACKET_COUNT); do
  # Creăm un mesaj de jurnal fals, similar cu cel de la FortiGate.
  # IP-ul sursă este fix, iar portul destinație se schimbă la fiecare iterație.
  LOG_MSG="date=2024-05-21 time=10:00:00 devname=\"fortigate\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" vd=\"root\" srcip=$ATTACKER_IP srcport=54321 dstip=192.168.1.100 dstport=$i proto=6 action=deny"
  
  # Trimitem mesajul prin UDP la serverul de monitorizare.
  echo "$LOG_MSG" | nc -u -w1 $TARGET_HOST $TARGET_PORT
  
  echo "Am trimis pachetul de test pentru portul $i"
done

echo "-----------------------------------------------------"
echo "Test finalizat. Verificați consola unde rulează PDScanner pentru a vedea mesajul de alertă."
