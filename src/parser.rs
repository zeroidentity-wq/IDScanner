use std::collections::HashMap;

/// Parsează un mesaj de log FortiGate într-un HashMap folosind referințe (&str)
/// pentru a evita alocările de memorie.
///
/// Mesajul este un șir de perechi cheie=valoare separate prin spații.
/// Valorile care sunt între ghilimele vor fi curățate de acestea.
pub fn parse_fortigate_log(log_message: &str) -> HashMap<&str, &str> {
    log_message
        .split_whitespace()
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                // Nu mai alocăm String-uri, doar curățăm ghilimelele
                Some((key, value.trim_matches('"')))
            } else {
                None
            }
        })
        .collect()
}
