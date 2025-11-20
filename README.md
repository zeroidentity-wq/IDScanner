# PDScanner

PDScanner este un instrument de securitate bazat pe Rust, conceput pentru a monitoriza jurnalele de trafic de rețea, în special de la firewall-urile FortiGate. Acesta ascultă jurnalele trimise printr-un server UDP, analizează datele pentru a detecta potențiale scanări de porturi (atât rapide, cât și lente) și trimite alerte prin e-mail atunci când este detectată o activitate suspectă.

## Caracteristici

- **Monitorizare în timp real:** Ascultă pe un server UDP pentru a primi jurnale de trafic de rețea.
- **Detecție de scanare de porturi:** Identifică atât scanările rapide, cât și cele lente, pe baza unor praguri și ferestre de timp configurabile.
- **Alerte prin e-mail:** Trimite notificări detaliate prin e-mail prin SMTP atunci când este detectată o scanare.
- **Configurare flexibilă:** Permite o configurare ușoară printr-un fișier `config.toml`.

## Compilare

### Opțiunea 1: Compilare standard (necesită Rust pe mașina țintă)

1. **Instalați Rust:** Urmați instrucțiunile de pe [rust-lang.org](https://www.rust-lang.org/tools/install).
2. **Clonați depozitul:**
   ```sh
   git clone <URL_DEPOZIT>
   cd PDScanner
   ```
3. **Construiți proiectul:**
   ```sh
   cargo build --release
   ```
   Executabilul se va găsi la `target/release/pdscanner`.

### Opțiunea 2: Compilare statică (creează un executabil portabil)

Această metodă produce un singur executabil care poate fi rulat pe aproape orice distribuție Linux x86_64, fără a necesita instalarea Rust sau a altor dependențe pe mașina țintă.

#### Pași pentru Red Hat 8.6 / CentOS 8:

1. **Instalați Rust:**
   ```sh
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

2. **Instalați `musl-gcc`:**
   Acest compilator este necesar pentru a crea un executabil legat static.
   ```sh
   sudo dnf install musl-gcc
   ```

3. **Adăugați ținta `musl` pentru Rust:**
   ```sh
   rustup target add x86_64-unknown-linux-musl
   ```

4. **Clonați depozitul și compilați:**
   Proiectul este deja configurat să folosească `musl-gcc` pentru această țintă.
   ```sh
   git clone <URL_DEPOZIT>
   cd PDScanner
   cargo build --release --target x86_64-unknown-linux-musl
   ```

5. **Localizați executabilul:**
   Executabilul static și portabil se va găsi la `target/x86_64-unknown-linux-musl/release/pdscanner`.

## Configurare

Înainte de a rula aplicația, creați un fișier `config.toml` în același director cu executabilul.

Iată un exemplu de conținut:
```toml
# Adresa și portul pe care va asculta serverul UDP
bind_address = "0.0.0.0:7878"

# --- Configurare Detecție Rapidă ---
fast_scan_threshold = 20
fast_time_window_secs = 60

# --- Configurare Detecție Lentă ---
slow_scan_threshold = 100
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

## Utilizare

1. Transferați executabilul `pdscanner` și fișierul `config.toml` pe mașina țintă.
2. Asigurați-vă că executabilul are permisiuni de execuție:
   ```sh
   chmod +x pdscanner
   ```
3. Rulați executabilul:
   ```sh
   ./pdscanner
   ```
Serverul va porni și va începe să asculte jurnalele de intrare pe adresa UDP configurată.
