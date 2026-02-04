#!/bin/bash
# ============================================================================
# Script Avansat de Test - IDS Scanner
# ============================================================================
# Testează toate formatele de log suportate: CEF Syslog, CEF, Raw Syslog
# ============================================================================

# Culori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Configurare
IDS_HOST="${IDS_HOST:-127.0.0.1}"
IDS_PORT="${IDS_PORT:-5555}"

print_header() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
}

print_section() {
    echo ""
    echo -e "${CYAN}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│ $1${NC}"
    echo -e "${CYAN}└──────────────────────────────────────────────────────────────────────────┘${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

send_udp() {
    local message="$1"
    echo "$message" | nc -u -w1 "$IDS_HOST" "$IDS_PORT" 2>/dev/null
    return $?
}

# Test 1: CEF Syslog Format (RECOMANDAT)
test_cef_syslog() {
    print_section "TEST 1: Format CEF Syslog (Recomandat pentru ArcSight)"

    print_info "Trimit 12 log-uri în format CEF Syslog..."
    echo ""

    local source_ip="192.168.1.100"
    local dest_ip="10.0.0.50"
    local timestamp=$(date '+%b %d %H:%M:%S')

    # Porturi comune pentru test
    local ports=(22 23 80 443 3389 8080 21 25 53 3306 1433 5432)

    for port in "${ports[@]}"; do
        # Format CEF Syslog complet cu header
        local message="<134>${timestamp} firewall CEF:0|Cisco|ASA|9.8|106023|Traffic Denied|5|src=${source_ip} dst=${dest_ip} dpt=${port} act=deny proto=TCP spt=54321"

        if send_udp "$message"; then
            print_success "Port ${port} - CEF Syslog trimis"
        else
            print_error "Eroare trimitere port ${port}"
        fi

        sleep 2
    done

    echo ""
    print_warning "Așteaptă detecția... Ar trebui să vezi o alertă RAPID_SCAN în ~25 secunde"
    sleep 3
}

# Test 2: CEF Format Simplu
test_cef_simple() {
    print_section "TEST 2: Format CEF Simplu (fără header Syslog)"

    print_info "Trimit 12 log-uri în format CEF simplu..."
    echo ""

    local source_ip="192.168.2.200"
    local dest_ip="10.0.0.100"

    local ports=(135 139 445 1024 1025 1026 1027 1028 1029 1030 1031 1032)

    for port in "${ports[@]}"; do
        local message="CEF:0|Palo Alto|NGFW|10.0|TRAFFIC|deny|8|src=${source_ip} dst=${dest_ip} dpt=${port} act=deny proto=TCP"

        if send_udp "$message"; then
            print_success "Port ${port} - CEF simplu trimis"
        else
            print_error "Eroare trimitere port ${port}"
        fi

        sleep 2
    done

    echo ""
    print_warning "Așteaptă detecția... Ar trebui să vezi o alertă RAPID_SCAN"
    sleep 3
}

# Test 3: Raw Syslog Format
test_raw_syslog() {
    print_section "TEST 3: Format Raw Syslog"

    print_info "Trimit 12 log-uri în format Raw Syslog..."
    echo ""

    local source_ip="192.168.3.50"
    local dest_ip="10.0.0.200"
    local timestamp=$(date '+%b %d %H:%M:%S')

    local ports=(5000 5001 5002 5003 5004 5005 5006 5007 5008 5009 5010 5011)

    for port in "${ports[@]}"; do
        # Simulare log iptables
        local message="${timestamp} gateway kernel: [UFW BLOCK] IN=eth0 OUT= SRC=${source_ip} DST=${dest_ip} PROTO=TCP SPT=45678 DPT=${port} ACT=DROP"

        if send_udp "$message"; then
            print_success "Port ${port} - Raw Syslog trimis"
        else
            print_error "Eroare trimitere port ${port}"
        fi

        sleep 2
    done

    echo ""
    print_warning "Așteaptă detecția... Ar trebui să vezi o alertă RAPID_SCAN"
    sleep 3
}

# Test 4: Scan Lent (Stealth)
test_stealth_scan() {
    print_section "TEST 4: Scan Lent Stealth (20 porturi în 10 minute)"

    print_warning "ATENȚIE: Acest test durează ~10 minute!"
    print_info "Apasă Ctrl+C pentru a opri"
    echo ""
    read -p "Continui? (y/N): " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Test anulat"
        return
    fi

    local source_ip="192.168.4.100"
    local dest_ip="10.0.0.250"
    local timestamp=$(date '+%b %d %H:%M:%S')

    print_info "Începe scanarea lentă..."

    for port in {6000..6019}; do
        local message="<134>${timestamp} firewall CEF:0|Fortinet|FortiGate|6.4|utm:attack|Intrusion Prevented|6|src=${source_ip} dst=${dest_ip} dpt=${port} act=block proto=TCP"

        if send_udp "$message"; then
            print_success "Port ${port} scanat (stealth)"
        else
            print_error "Eroare port ${port}"
        fi

        # Așteaptă 30 secunde între scanuri (stealth)
        echo -e "${YELLOW}   Așteaptă 30 secunde... (scan stealth)${NC}"
        sleep 30
    done

    echo ""
    print_warning "Scan stealth completat! Verifică pentru alertă SLOW_SCAN"
}

# Test 5: Multiple IP-uri Simultane
test_multiple_sources() {
    print_section "TEST 5: Scan de la Multiple IP-uri Simultane"

    print_info "Testăm detectarea pentru 3 IP-uri diferite simultan..."
    echo ""

    local ips=("192.168.5.10" "192.168.5.20" "192.168.5.30")
    local dest_ip="10.0.0.100"
    local timestamp=$(date '+%b %d %H:%M:%S')

    # Fiecare IP scanează 10 porturi
    for ip in "${ips[@]}"; do
        print_info "Scanare din IP: ${ip}"

        for port in {7000..7009}; do
            local message="<134>${timestamp} firewall CEF:0|Test|IDS|1.0|100|Deny|5|src=${ip} dst=${dest_ip} dpt=${port} act=deny proto=TCP"

            send_udp "$message"
            print_success "  Port ${port}"
            sleep 1.5
        done

        echo ""
    done

    print_warning "Verifică log-urile - ar trebui să vezi 3 alerte RAPID_SCAN (câte una pentru fiecare IP)"
}

# Test 6: Verificare Filtrare Acțiuni
test_action_filtering() {
    print_section "TEST 6: Testare Filtrare Acțiuni (act=allow vs act=deny)"

    print_info "Dacă ai filter_actions=['deny','block'] în config, doar deny/block vor fi detectate"
    echo ""

    local source_ip="192.168.6.100"
    local dest_ip="10.0.0.150"
    local timestamp=$(date '+%b %d %H:%M:%S')

    print_info "Trimit 5 log-uri cu act=allow (NU ar trebui detectate dacă filtrul e activ):"
    for port in {8001..8005}; do
        local message="<134>${timestamp} firewall CEF:0|Test|IDS|1.0|100|Allow|3|src=${source_ip} dst=${dest_ip} dpt=${port} act=allow proto=TCP"
        send_udp "$message"
        print_success "  Port ${port} (allow)"
        sleep 1
    done

    echo ""
    print_info "Trimit 10 log-uri cu act=deny (AR TREBUI detectate):"
    for port in {8006..8015}; do
        local message="<134>${timestamp} firewall CEF:0|Test|IDS|1.0|100|Deny|5|src=${source_ip} dst=${dest_ip} dpt=${port} act=deny proto=TCP"
        send_udp "$message"
        print_success "  Port ${port} (deny)"
        sleep 2
    done

    echo ""
    print_warning "Dacă filtrul e activ, ar trebui să vezi alertă doar pentru log-urile cu act=deny"
}

# Test Conexiune
test_connection() {
    print_section "TEST CONEXIUNE"

    print_info "Verific conectivitatea către ${IDS_HOST}:${IDS_PORT}..."

    if send_udp "TEST CONNECTION"; then
        print_success "Conexiune UDP reușită!"
        return 0
    else
        print_error "Nu pot conecta la IDS!"
        echo ""
        print_warning "Verificări:"
        echo "  1. IDS-ul rulează? (RUST_LOG=info cargo run)"
        echo "  2. Adresa/portul sunt corecte?"
        echo "  3. Firewall-ul blochează portul?"
        echo ""
        echo "Test manual:"
        echo "  echo 'test' | nc -u ${IDS_HOST} ${IDS_PORT}"
        return 1
    fi
}

# Meniu Principal
show_menu() {
    print_header "IDS SCANNER - TEST SUITE COMPLET"

    echo ""
    echo -e "${GREEN}Teste Disponibile:${NC}"
    echo ""
    echo -e "  ${CYAN}1${NC}. Test CEF Syslog Format ${YELLOW}(RECOMANDAT)${NC}"
    echo -e "  ${CYAN}2${NC}. Test CEF Simplu Format"
    echo -e "  ${CYAN}3${NC}. Test Raw Syslog Format"
    echo -e "  ${CYAN}4${NC}. Test Scan Lent Stealth (10 minute)"
    echo -e "  ${CYAN}5${NC}. Test Multiple IP-uri Simultane"
    echo -e "  ${CYAN}6${NC}. Test Filtrare Acțiuni (allow vs deny)"
    echo -e "  ${CYAN}7${NC}. Rulează TOATE testele (fără scan lent)"
    echo -e "  ${CYAN}8${NC}. Test Conexiune"
    echo -e "  ${CYAN}0${NC}. Ieșire"
    echo ""
    echo -e "${YELLOW}Configurare Curentă:${NC}"
    echo -e "  IDS Host: ${IDS_HOST}"
    echo -e "  IDS Port: ${IDS_PORT}"
    echo ""
}

run_all_tests() {
    print_header "RULARE TOATE TESTELE"

    if ! test_connection; then
        print_error "Test conexiune eșuat! Opresc..."
        return 1
    fi

    sleep 2
    test_cef_syslog

    sleep 5
    test_cef_simple

    sleep 5
    test_raw_syslog

    sleep 5
    test_multiple_sources

    sleep 5
    test_action_filtering

    echo ""
    print_header "TOATE TESTELE COMPLETATE"
    print_info "Verifică output-ul IDS-ului pentru alertele detectate"
}

# Main
main() {
    # Verifică netcat
    if ! command -v nc &> /dev/null; then
        print_error "netcat (nc) nu este instalat!"
        print_info "Instalează cu: sudo apt-get install netcat"
        exit 1
    fi

    # Verifică dacă rulează cu argumente
    if [ $# -gt 0 ]; then
        case "$1" in
            connection|conn|test)
                test_connection
                ;;
            cef-syslog|1)
                test_cef_syslog
                ;;
            cef|2)
                test_cef_simple
                ;;
            raw|3)
                test_raw_syslog
                ;;
            stealth|slow|4)
                test_stealth_scan
                ;;
            multi|5)
                test_multiple_sources
                ;;
            filter|6)
                test_action_filtering
                ;;
            all|7)
                run_all_tests
                ;;
            *)
                print_error "Opțiune necunoscută: $1"
                echo ""
                echo "Utilizare: $0 [connection|cef-syslog|cef|raw|stealth|multi|filter|all]"
                exit 1
                ;;
        esac
        exit 0
    fi

    # Meniu interactiv
    while true; do
        show_menu
        read -p "Alege opțiunea (0-8): " choice

        case $choice in
            1)
                test_cef_syslog
                ;;
            2)
                test_cef_simple
                ;;
            3)
                test_raw_syslog
                ;;
            4)
                test_stealth_scan
                ;;
            5)
                test_multiple_sources
                ;;
            6)
                test_action_filtering
                ;;
            7)
                run_all_tests
                ;;
            8)
                test_connection
                ;;
            0)
                print_info "La revedere!"
                exit 0
                ;;
            *)
                print_error "Opțiune invalidă!"
                ;;
        esac

        echo ""
        read -p "Apasă Enter pentru a continua..."
    done
}

main "$@"