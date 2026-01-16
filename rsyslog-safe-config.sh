#!/bin/bash
# ==============================================================================
# CONFIGURARE RSYSLOG - 100% INDEPENDENTĂ DE ARCSIGHT
# ==============================================================================
# Fișier: /etc/rsyslog.d/99-ids-unix-socket.conf
#
# IMPORTANT: Această configurare este COMPLET INDEPENDENTĂ de ArcSight!
# 
# Cum funcționează:
# 1. Rsyslog procesează log-urile normal și le trimite către ArcSight
# 2. DUPĂ ce ArcSight a primit log-urile, rsyslog le COPIAZĂ și către IDS
# 3. Comunicarea cu IDS-ul se face prin UNIX socket (nu FIFO/pipe)
# 4. Dacă IDS-ul pică/se blochează, rsyslog continuă NORMAL către ArcSight
# 
# De ce UNIX socket în loc de FIFO (named pipe)?
# - FIFO poate bloca rsyslog dacă IDS-ul nu citește destul de repede
# - UNIX socket are flow control automat
# - UNIX socket permite comunicare bidirecțională
# - Mai sigur și mai predictibil
# ==============================================================================

# ------------------------------------------------------------------------------
# MODULE: Activează suportul pentru UNIX socket output
# ------------------------------------------------------------------------------
module(load="omuxsock")  # Output Module UNIX Socket

# ------------------------------------------------------------------------------
# TEMPLATE: Format pentru log-urile trimise către IDS
# ------------------------------------------------------------------------------
# Definim un template simplu, ușor de parsat
# Format: TIMESTAMP HOSTNAME TAG MESSAGE
template(name="IDSFormat" type="string"
    string="%timegenerated:::date-rfc3339% %HOSTNAME% %syslogtag%%msg:::drop-last-lf%\n"
)

# ------------------------------------------------------------------------------
# RULESET: Procesare separată pentru IDS (NU afectează ArcSight)
# ------------------------------------------------------------------------------
# Ruleset = un "pipeline" separat de procesare
# Acest ruleset rulează INDEPENDENT de forward-ul către ArcSight

ruleset(name="ids_mirror") {
    # Trimite către UNIX socket
    action(
        type="omuxsock"                      # Output Module: UNIX Socket
        socket="/var/run/ids.sock"           # Calea către socket (creată de IDS)
        template="IDSFormat"                 # Folosește template-ul nostru
        
        # === CONFIGURARE QUEUE (CRITICĂ PENTRU NON-INTERFERENȚĂ) ===
        queue.type="LinkedList"              # Tip: listă înlănțuită (async)
        queue.size="10000"                   # Buffer: 10,000 mesaje în memorie
        queue.discardMark="9000"             # La 9000 mesaje, începe să arunce
        queue.discardSeverity="7"            # Aruncă doar mesajele de low priority
        
        # === POLITICA DE RETRY (CE SE ÎNTÂMPLĂ DACĂ IDS-UL NU RĂSPUNDE) ===
        action.resumeRetryCount="5"          # Încearcă de 5 ori să retrimită
        action.resumeInterval="5"            # Așteaptă 5 sec între retry-uri
        action.reportSuspension="on"         # Raportează dacă se blochează
        
        # === TIMEOUT ===
        action.writeTimeout="1000"           # Timeout 1 secundă per write
    )
    
    # OPREȘTE procesarea aici - NU trimite mai departe
    # Acest "stop" e DOAR pentru ruleset-ul "ids_mirror"
    # Nu afectează flow-ul principal către ArcSight
    stop
}

# ------------------------------------------------------------------------------
# APELARE RULESET: Copiază log-urile către IDS
# ------------------------------------------------------------------------------
# ATENȚIE: Folosim "call" NU "~" (tilda)
# "call" = COPIAZĂ mesajul către ruleset (originalul continuă)
# "~" sau "&" = MUTĂ mesajul (ar opri procesarea)

# Opțiunea 1: TOATE log-urile către IDS (copie completă)
*.* call ids_mirror

# ------------------------------------------------------------------------------
# OPȚIONAL: Filtrare selectivă (dacă vrei doar security events)
# ------------------------------------------------------------------------------
# Comentează linia de mai sus (*.* call ids_mirror) și decomentează următoarele
# pentru a trimite DOAR evenimente de securitate către IDS

# Doar evenimente cu severity warning sau mai mare
# *.warning call ids_mirror

# Doar facilități specifice (auth, security, kernel)
# authpriv.* call ids_mirror
# auth.* call ids_mirror  
# kern.* call ids_mirror

# Doar mesaje care conțin anumite cuvinte cheie
# :msg, contains, "DROP" call ids_mirror
# :msg, contains, "DENY" call ids_mirror
# :msg, contains, "REJECT" call ids_mirror
# :msg, contains, "Failed password" call ids_mirror
# :msg, contains, "authentication failure" call ids_mirror

# Doar de la anumite echipamente (bazat pe hostname sau IP)
# :fromhost-ip, isequal, "192.168.1.1" call ids_mirror
# :hostname, contains, "firewall" call ids_mirror

# ------------------------------------------------------------------------------
# VERIFICARE: Flow-ul COMPLET ar trebui să arate așa
# ------------------------------------------------------------------------------
# 
# Log original
#    │
#    ├─→ [Procesare normală rsyslog]
#    │      │
#    │      ├─→ ArcSight Connector (forward original - NEATINS)
#    │      │
#    │      └─→ Fișiere locale (/var/log/*)
#    │
#    └─→ [Copie pentru IDS via "call ids_mirror"]
#           │
#           └─→ UNIX Socket /var/run/ids.sock
#                  │
#                  └─→ Rust IDS (procesează independent)
#
# ------------------------------------------------------------------------------

# ==============================================================================
# TROUBLESHOOTING ȘI DEBUGGING
# ==============================================================================

# Activează debugging pentru modulul UNIX socket (doar pentru testare)
# $DebugLevel 2
# $DebugFile /var/log/rsyslog-debug.log

# Statistici (vezi câte mesaje procesează fiecare queue)
# module(load="impstats" interval="300" severity="7")
# syslog.=debug action(type="omfile" file="/var/log/rsyslog-stats.log")

# ==============================================================================
# INSTRUCȚIUNI DE INSTALARE
# ==============================================================================
#
# 1. Salvează acest fișier ca /etc/rsyslog.d/99-ids-unix-socket.conf
#
# 2. Verifică sintaxa:
#    sudo rsyslogd -N1 -f /etc/rsyslog.conf
#
# 3. Pornește IDS-ul ÎNAINTE (el creează socket-ul):
#    sudo systemctl start rust-ids
#
# 4. Restart rsyslog:
#    sudo systemctl restart rsyslog
#
# 5. Verifică status:
#    sudo systemctl status rsyslog
#    sudo systemctl status rust-ids
#
# 6. Test manual:
#    logger -p auth.warning "Test message for IDS"
#
# 7. Monitorizează:
#    # Pe server
#    tail -f /var/log/syslog | grep -i "suspended\|error\|IDS"
#    
#    # În IDS
#    journalctl -u rust-ids -f
#
# ==============================================================================
# VERIFICARE NON-INTERFERENȚĂ CU ARCSIGHT
# ==============================================================================
#
# Test 1: Oprește IDS-ul complet
#   sudo systemctl stop rust-ids
#   logger "Test without IDS"
#   # Verifică în ArcSight - mesajul TREBUIE să ajungă
#
# Test 2: Blochează socket-ul
#   sudo chmod 000 /var/run/ids.sock
#   logger "Test with blocked socket"  
#   # rsyslog ar trebui să raporteze eroare DAR să continue către ArcSight
#
# Test 3: Volum mare
#   for i in {1..1000}; do logger "Test $i"; done
#   # Toate 1000 mesaje trebuie în ArcSight, chiar dacă IDS-ul e lent
#
# ==============================================================================
# ÎNTREBĂRI FRECVENTE
# ==============================================================================
#
# Î: Ce se întâmplă dacă IDS-ul pică?
# R: Rsyslog va încerca 5 retry-uri, apoi va arunca mesajele DOAR pentru IDS.
#    ArcSight primește totul NORMAL.
#
# Î: Socket-ul poate bloca rsyslog?
# R: Nu, datorită queue.type="LinkedList" și timeout-urilor.
#    Rsyslog scrie async și continuă imediat.
#
# Î: De ce numărul 99 în numele fișierului?
# R: Rsyslog procesează fișierele în ordine alfabetică.
#    99- asigură că rulează DUPĂ configurația ArcSight (de obicei 50-).
#
# Î: Cum verific că nu interferez cu ArcSight?
# R: Compară numărul de evenimente în ArcSight înainte și după activarea IDS.
#    Ar trebui să fie IDENTIC.
#
# ==============================================================================