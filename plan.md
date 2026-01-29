## Varianta 1: ArcSight Logger "Forwarder" (Recomandată)

**CONFIG:** Configurezi din interfața ArcSight un Forwarder care să trimită log-urile de Firewall (poți aplica filtre, `ex: deviceVendor = Cisco`) către adresa IP și Portul unde ascultă programul tău (`ex: localhost:5555`).

**Format:** Poți alege să le trimită ca **CEF** (**Common Event Format**) sau **Raw Syslog**. **CEF** este foarte ușor de parsat programatic (e un fel de `key=value`).

**Avantaj:** Nu încarci programul tău cu gunoi. Filtrezi din ArcSight doar ce te interesează (ex: doar traficul DENY sau doar anumite subnet-uri) și programul primește doar datele relevante.

> (Forwarder) pe port UDP. Programul tău va asculta pe un port UDP (socket) și va primi pachete text frumos formatate. E cel mai scalabil.

## Varianta 2: "Real-time File Follow" (Dacă poți genera fișiere text)

Dacă configurezi ArcSight sau Rsyslog să scrie log-urile de firewall într-un fișier text rotativ (`ex: firewall.log)`, programul  poate funcționa ca un tail -f.

> (Fișier Text dedicat). Configurează `rsyslog` să pună logurile de **firewall** într-un fișier separat (`/var/log/firewall_analysis.log`) și scrie programul să citească acel fișier.
