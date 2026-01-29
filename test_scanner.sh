#!/bin/bash

# Script de testare pentru Intrusion Detection Scanner
# Simulează diverse tipuri de scan-uri pentru a testa detecția

set -e

SCANNER_HOST="localhost"
SCANNER_PORT="5555"

echo "🧪 Test Suite pentru IDS Scanner"
echo "================================"
echo ""

# Verifică dacă netcat este instalat
if ! command -v nc &> /dev/null; then
    echo "❌ netcat (nc) nu este instalat. Instalează-l cu:"
    echo "   sudo apt-get install netcat (Ubuntu/Debian)"
    echo "   sudo yum install nc (CentOS/RHEL)"
    exit 1
fi

echo "✅ netcat detectat"
echo ""

# Funcție pentru a trimite log CEF
send_cef_log() {
    local src_ip=$1
    local dst_ip=$2
    local dst_port=$3
    local action=$4
    
    local cef_msg="CEF:0|Cisco|ASA|9.0|106023|Deny tcp|5|src=$src_ip dst=$dst_ip dpt=$dst_port proto=TCP act=$action"
    echo "$cef_msg" | nc -u -w1 "$SCANNER_HOST" "$SCANNER_PORT"
}

# Funcție pentru a trimite log Raw Syslog
send_syslog_log() {
    local src_ip=$1
    local dst_ip=$2
    local dst_port=$3
    local action=$4
    
    local syslog_msg="Jan 29 10:15:30 firewall: src=$src_ip dst=$dst_ip dport=$dst_port action=$action"
    echo "$syslog_msg" | nc -u -w1 "$SCANNER_HOST" "$SCANNER_PORT"
}

echo "📋 Test 1: Verificare conectivitate"
echo "-----------------------------------"
echo "Trimitere log de test..."
send_cef_log "192.168.1.200" "10.0.0.1" "80" "DENY"
echo "✅ Log trimis cu succes"
echo ""

sleep 2

echo "🚀 Test 2: Simulare Scan Rapid (RAPID_SCAN)"
echo "-------------------------------------------"
echo "Trimitem 15 conexiuni către porturi diferite în 10 secunde..."
echo "ATENȚIE: Aceasta ar trebui să genereze o alertă RAPID_SCAN!"
echo ""

SRC_IP="192.168.1.100"
DST_IP="10.0.0.50"

for port in {1..15}; do
    echo "  → Port $port"
    send_cef_log "$SRC_IP" "$DST_IP" "$((1000 + port))" "DENY"
    sleep 0.5
done

echo "✅ 15 log-uri trimise"
echo "⏳ Așteaptă 3 secunde pentru procesare..."
sleep 3
echo "📊 Verifică log-urile scanner-ului pentru alerta RAPID_SCAN"
echo ""

sleep 2

echo "🐌 Test 3: Simulare Scan Lent (SLOW_SCAN)"
echo "-----------------------------------------"
echo "Trimitem 12 conexiuni către porturi diferite cu întârziere..."
echo "Nota: Pentru test complet SLOW_SCAN, trebuie 20+ porturi în 1 oră"
echo "      Acest test demonstrează doar mecanismul"
echo ""

SRC_IP="10.0.5.20"
DST_IP="10.0.0.100"

for port in {1..12}; do
    echo "  → Port $port"
    send_cef_log "$SRC_IP" "$DST_IP" "$((2000 + port))" "DENY"
    sleep 1
done

echo "✅ 12 log-uri trimise"
echo "ℹ️  Pentru alertă SLOW_SCAN completă, trimite 20+ porturi"
echo ""

sleep 2

echo "📝 Test 4: Testare format Raw Syslog"
echo "-----------------------------------"
echo "Trimitem log-uri în format Raw Syslog..."
echo ""

SRC_IP="172.16.1.50"
DST_IP="10.0.0.200"

for port in {1..8}; do
    echo "  → Syslog port $port"
    send_syslog_log "$SRC_IP" "$DST_IP" "$((3000 + port))" "DENY"
    sleep 0.5
done

echo "✅ 8 log-uri Syslog trimise"
echo ""

sleep 2

echo "🔄 Test 5: Teste de la IP-uri multiple"
echo "--------------------------------------"
echo "Simulăm trafic de la 3 IP-uri diferite..."
echo ""

for ip_suffix in {101..103}; do
    SRC_IP="192.168.1.$ip_suffix"
    echo "  IP: $SRC_IP"
    for port in {1..5}; do
        send_cef_log "$SRC_IP" "10.0.0.1" "$((4000 + port))" "DENY"
        sleep 0.3
    done
done

echo "✅ Log-uri de la 3 IP-uri diferite trimise"
echo ""

sleep 2

echo ""
echo "================================"
echo "✅ Suite de teste completat!"
echo "================================"
echo ""
echo "📋 Sumar:"
echo "  - Test 1: Conectivitate ✓"
echo "  - Test 2: Scan Rapid (15 porturi) ✓"
echo "  - Test 3: Scan Lent demo (12 porturi) ✓"
echo "  - Test 4: Format Raw Syslog ✓"
echo "  - Test 5: Multiple IP-uri ✓"
echo ""
echo "🔍 Ce să verifici în log-urile scanner-ului:"
echo "  1. Mesaj de primire a log-urilor"
echo "  2. Alertă RAPID_SCAN pentru 192.168.1.100"
echo "  3. Procesare corectă a formatelor CEF și Syslog"
echo ""
echo "💡 Sfat: Rulează cu RUST_LOG=debug pentru detalii complete"
echo "   Exemplu: RUST_LOG=debug ./target/release/ids-scanner"
echo ""
