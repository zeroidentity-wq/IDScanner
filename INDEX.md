# 📖 Index Complet Proiect IDS Scanner

Bine ai venit! Acest document te ghidează prin toată documentația disponibilă.

## 🚀 Start Rapid

Dacă vrei să pornești rapid scanner-ul:

1. **[QUICKSTART.md](QUICKSTART.md)** - Setup în 5 minute
   - Build și rulare
   - Test rapid
   - Configurare minimă ArcSight

## 📚 Pentru Învățare Rust

Dacă ești **începător în Rust** și vrei să înveți:

1. **[INVATARE_RUST.md](INVATARE_RUST.md)** - Ghid complet de învățare
   - Concepte fundamentale (Ownership, Borrowing, etc.)
   - Plan de studiu săptămânal
   - Resurse de învățare
   - Exerciții practice

2. **[src/main_educational_ro.rs](src/main_educational_ro.rs)** - Cod cu comentarii educaționale
   - Fiecare linie explicată în română
   - Explicații despre conceptele Rust folosite
   - Exemple și sfaturi

3. **[EXEMPLE_PRACTICE.md](EXEMPLE_PRACTICE.md)** - Modificări pas-cu-pas
   - Modificări simple pentru începători
   - Exerciții intermediare
   - Challenge-uri avansate
   - Tehnici de debugging

## 📖 Documentație Tehnică

Pentru înțelegerea completă a proiectului:

1. **[README.md](README.md)** - Documentație completă
   - Arhitectură
   - Toate funcționalitățile
   - API și usage
   - Troubleshooting

2. **[DEPLOYMENT.md](DEPLOYMENT.md)** - Deployment în producție
   - Setup server
   - Configurare systemd
   - Firewall și securitate
   - Monitoring și logs
   - Performance tuning

3. **[EXAMPLES.md](EXAMPLES.md)** - Exemple și scenarii
   - Formate de log-uri
   - Scenarii de detecție
   - Testare completă
   - Interpretare alerte

## 🔧 Fișiere de Configurare

1. **[config.example.toml](config.example.toml)** - Template de configurare
2. **[ids-scanner.service](ids-scanner.service)** - Fișier systemd service
3. **[test_scanner.sh](test_scanner.sh)** - Script de testare automată

## 📁 Structura Proiectului

```
ids-scanner/
├── src/
│   ├── main.rs                    # Codul principal (versiunea originală)
│   └── main_educational_ro.rs     # Codul cu comentarii educaționale în română
├── Cargo.toml                      # Dependențe și configurare Rust
├── README.md                       # Documentație completă
├── QUICKSTART.md                   # Ghid de start rapid
├── INVATARE_RUST.md               # Ghid complet de învățare Rust
├── EXEMPLE_PRACTICE.md            # Exerciții și modificări practice
├── DEPLOYMENT.md                   # Ghid de deployment producție
├── EXAMPLES.md                     # Exemple detaliate de scenarii
├── config.example.toml            # Template configurare
├── ids-scanner.service            # Fișier systemd
└── test_scanner.sh                # Script de testare
```

## 🎯 Parcursuri Recomandate

### Pentru Începători Absoluti în Rust

```
1. Citește INVATARE_RUST.md (Secțiunea 1: Concepte Fundamentale)
   ↓
2. Deschide main_educational_ro.rs și urmărește comentariile
   ↓
3. Build proiectul: cargo build
   ↓
4. Rulează: cargo run
   ↓
5. În alt terminal, rulează: ./test_scanner.sh
   ↓
6. Încearcă exercițiile din EXEMPLE_PRACTICE.md (Secțiunea 1)
   ↓
7. Continuă cu INVATARE_RUST.md (planul săptămânal)
```

### Pentru Cei Care Știu Deja Rust

```
1. Citește QUICKSTART.md pentru overview rapid
   ↓
2. Explorează main.rs pentru implementare
   ↓
3. Citește DEPLOYMENT.md pentru deployment
   ↓
4. Încearcă exercițiile avansate din EXEMPLE_PRACTICE.md (Secțiunea 3)
```

### Pentru Deployment în Producție

```
1. QUICKSTART.md - înțelege ce face
   ↓
2. README.md - funcționalități complete
   ↓
3. DEPLOYMENT.md - pas-cu-pas setup server
   ↓
4. EXAMPLES.md - configurare ArcSight și testare
```

## 🔍 Căutare Rapidă

**Vreau să:**

- **Pornesc rapid scanner-ul** → [QUICKSTART.md](QUICKSTART.md)
- **Învăț Rust de la zero** → [INVATARE_RUST.md](INVATARE_RUST.md)
- **Înțeleg codul pas cu pas** → [src/main_educational_ro.rs](src/main_educational_ro.rs)
- **Fac modificări practice** → [EXEMPLE_PRACTICE.md](EXEMPLE_PRACTICE.md)
- **Deployment în producție** → [DEPLOYMENT.md](DEPLOYMENT.md)
- **Înțeleg ce detectează** → [EXAMPLES.md](EXAMPLES.md) (Secțiunea Scenarii)
- **Configurez ArcSight** → [README.md](README.md#configurare-arcsight-logger)
- **Troubleshooting** → [README.md](README.md#troubleshooting)
- **Testez funcționalitatea** → [test_scanner.sh](test_scanner.sh)

## ❓ Întrebări Frecvente

**Î: Trebuie să știu Rust pentru a folosi scanner-ul?**
R: Nu! Pentru deployment simplu, urmează QUICKSTART.md. Pentru a învăța Rust prin proiect, vezi INVATARE_RUST.md.

**Î: Care fișier main.rs să folosesc?**
R: 
- `src/main.rs` - versiunea standard (limba engleză, cod concis)
- `src/main_educational_ro.rs` - versiunea educațională (limba română, comentarii detaliate)

Pentru compilare, redenumește fișierul dorit în `main.rs`.

**Î: Cum modific pragurile de detecție?**
R: Vezi [EXEMPLE_PRACTICE.md - Secțiunea 1](EXEMPLE_PRACTICE.md#11-schimbă-mesajele-de-log)

**Î: Unde găsesc exemple de log-uri?**
R: [EXAMPLES.md - Secțiunea Formate Suportate](EXAMPLES.md#-formate-suportate)

**Î: Cum adaug un whitelist de IP-uri?**
R: [EXEMPLE_PRACTICE.md - Secțiunea 2.1](EXEMPLE_PRACTICE.md#21-implementează-whitelist-de-ip-uri)

**Î: Scanner-ul nu primește log-uri de la ArcSight**
R: [README.md - Troubleshooting](README.md#troubleshooting)

## 📞 Suport

Pentru probleme:
1. Verifică secțiunea **Troubleshooting** din [README.md](README.md#troubleshooting)
2. Rulează cu debug logging: `RUST_LOG=debug cargo run`
3. Testează cu script-ul: `./test_scanner.sh`
4. Verifică log-urile: `sudo journalctl -u ids-scanner -f`

## 🎓 Resurse Externe

**Învățare Rust:**
- [The Rust Book](https://doc.rust-lang.org/book/) - Cartea oficială (gratuită)
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/) - Învățare prin exemple
- [Rustlings](https://github.com/rust-lang/rustlings) - Exerciții interactive

**ArcSight:**
- [ArcSight Logger Documentation](https://www.microfocus.com/documentation/arcsight/arcsight-logger/)
- [CEF Format Guide](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/)

**Securitate Rețea:**
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE ATT&CK](https://attack.mitre.org/) - Framework pentru tehnici de atac

---

## 🚀 Start Imediat

```bash
# 1. Build
cd ids-scanner
cargo build --release

# 2. Rulează
./target/release/ids-scanner

# 3. Test (în alt terminal)
./test_scanner.sh

# 4. Verifică alerte
# Ar trebui să vezi: "⚠️  SCAN DETECTAT: ..."
```

---

**Baftă la învățat și la dezvoltat! 🦀**

*Creat pentru învățare și utilizare în producție*
*MIT License - Vezi LICENSE pentru detalii*
