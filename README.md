# PDScanner

PDScanner este un instrument de securitate bazat pe Rust, conceput pentru a monitoriza jurnalele de trafic de rețea, în special de la firewall-urile FortiGate. Acesta ascultă jurnalele trimise printr-un server UDP, analizează datele pentru a detecta potențiale scanări de porturi (atât rapide, cât și lente) și trimite alerte prin e-mail atunci când este detectată o activitate suspectă.

## Caracteristici

- **Monitorizare în timp real:** Ascultă pe un server UDP pentru a primi jurnale de trafic de rețea.
- **Detecție de scanare de porturi:** Identifică atât scanările rapide, cât și cele lente, pe baza unor praguri și ferestre de timp configurabile.
- **Alerte prin e-mail:** Trimite notificări detaliate prin e-mail prin SMTP atunci când este detectată o scanare.
- **Configurare flexibilă:** Permite o configurare ușoară printr-un fișier `config.toml`.

## Noțiuni introductive

### Cerințe preliminare

- [Rust](https://www.rust-lang.org/tools/install) (versiunea 2021 sau mai recentă)

### Instalare

1. Clonați depozitul:
   ```sh
   git clone <URL_DEPOZIT>
   cd PDScanner
   ```

2. Construiți proiectul:
   ```sh
   cargo build --release
   ```

## Configurare

Înainte de a rula aplicația, trebuie să configurați setările în fișierul `config.toml`. Acest fișier vă permite să definiți adresa de legare a serverului, pragurile de detecție a scanării și setările serverului SMTP pentru alerte.

Iată un exemplu de fișier `config.toml`:

```toml
# Adresa și portul pe care va asculta serverul UDP
bind_address = "0.0.0.0:7878"

# --- Configurare Detecție Rapidă ---
# Numărul de porturi scanate pentru a declanșa o alertă de scanare rapidă
fast_scan_threshold = 20
# Fereastra de timp în secunde pentru detecția scanării rapide
fast_time_window_secs = 60

# --- Configurare Detecție Lentă ---
# Numărul de porturi scanate pentru a declanșa o alertă de scanare lentă
slow_scan_threshold = 100
# Fereastra de timp în secunde pentru detecția scanării lente
slow_time_window_secs = 86400

# --- Configurare SMTP pentru Alerte Email ---
[smtp]
enabled = true
server = "smtp.example.com"
port = 587
username = "user@example.com"
password = "your_smtp_password"
from = "scanner-detector@example.com"
to = ["admin1@example.com", "security-team@example.com"]
subject = "🚨 Alertă de Securitate: Scanare de Porturi Detectată 🚨"
```

**Notă:** Asigurați-vă că ați configurat firewall-ul FortiGate (sau altă sursă de jurnal) pentru a trimite jurnalele de trafic la adresa și portul specificate în `bind_address`.

## Utilizare

Pentru a porni serverul, rulați următoarea comandă din directorul rădăcină al proiectului:

```sh
cargo run --release
```

Serverul va porni și va începe să asculte jurnalele de intrare pe adresa UDP configurată. Când este detectată o scanare de porturi, o avertizare va fi înregistrată în consolă, iar o alertă va fi trimisă la adresele de e-mail specificate, dacă alertele prin e-mail sunt activate.
