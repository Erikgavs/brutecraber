use faster_hex;
use pbkdf2::hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

// Parse a PMKID hash line in Hashcat 22000 text format:
// WPA*01*PMKID*MAC_AP*MAC_STA*ESSID***
// Return the PMKID and MACs as byte arrays, and the ESSID as bytes.
fn parse_pmkid_line(hash_line: &str) -> Option<([u8; 16], [u8; 6], [u8; 6], Vec<u8>)> {
    // Require and remove the trailing marker.
    let hash_line = hash_line.strip_suffix("***")?;

    // Split the remaining line into its six fields.
    let parts: Vec<&str> = hash_line.split('*').collect();

    // Reject missing/extra fields and records that are not PMKID type `01`.
    if parts.len() != 6 || parts[0] != "WPA" || parts[1] != "01" {
        return None;
    };

    // A PMKID is 16 bytes; each MAC address is 6 bytes.
    if parts[2].len() != 32 || parts[3].len() != 12 || parts[4].len() != 12 {
        return None;
    };

    // Decode the PMKID from hex into 16 bytes.
    let mut pmkid = [0u8; 16];
    if faster_hex::hex_decode(parts[2].as_bytes(), &mut pmkid).is_err() {
        return None;
    };

    // Decode the access point's MAC address from hex.
    let mut mac_ap = [0u8; 6];
    if faster_hex::hex_decode(parts[3].as_bytes(), &mut mac_ap).is_err() {
        return None;
    };

    // Decode the station's MAC address from hex.
    let mut mac_sta = [0u8; 6];
    if faster_hex::hex_decode(parts[4].as_bytes(), &mut mac_sta).is_err() {
        return None;
    };

    // The ESSID is hex-encoded and can be up to 32 bytes long.
    let essid_hex = parts[5];
    if essid_hex.len() % 2 != 0 || essid_hex.len() > 64 {
        return None;
    };

    let mut essid = vec![0u8; essid_hex.len() / 2];
    if faster_hex::hex_decode(essid_hex.as_bytes(), &mut essid).is_err() {
        return None;
    };

    // Return all decoded fields together.
    Some((pmkid, mac_ap, mac_sta, essid))
}

pub fn verify_pmkid_line(passphrase: &str, hash_line: &str) -> bool {
    // WPA passphrases must be between 8 and 63 bytes.
    if !(8..=63).contains(&passphrase.len()) {
        return false;
    }

    let (pmkid, mac_ap, mac_sta, essid) = match parse_pmkid_line(hash_line) {
        Some(datos) => datos, // if hash_line is parsed, save data in "datos"
        None => return false, // if hash_line parse fails, return bool -> false
    };

    // pmk = pairwise master key, the key WPA derives from essid and password
    let mut pmk = [0u8; 32];
    // WPA requires PBKDF2-HMAC-SHA1 with 4096 iterations.
    //Create a key from this password guess and the network name.
    pbkdf2_hmac::<Sha1>(passphrase.as_bytes(), &essid, 4096, &mut pmk);

    // Set up HMAC-SHA1 using the derived PMK as its key.
    // (HMAC is a keyed hash used here to calculate the expected PMKID)
    let mut hmac = match Hmac::<Sha1>::new_from_slice(&pmk) {
        Ok(hmac) => hmac,
        Err(_) => return false,
    };

    // Add the fixed label required by the WPA PMKID calculation.
    hmac.update(b"PMK Name");
    // Add the access point's MAC address.
    hmac.update(&mac_ap);
    // Add the connected device's MAC address.
    hmac.update(&mac_sta);

    // Finish the HMAC calculation and store its result as bytes.
    let calculated = hmac.finalize().into_bytes();

    // Compare the first 16 result bytes with the PMKID from the input.
    calculated[..16] == pmkid[..]
}

#[cfg(test)]
mod tests {
    use super::{parse_pmkid_line, verify_pmkid_line};

    #[test]
    fn parses_valid_pmkid_line() {
        let line = "WPA*01*00000000000000000000000000000000*001122334455*aabbccddeeff*74657374***";

        let (pmkid, mac_ap, mac_sta, essid) = parse_pmkid_line(line).expect("valid PMKID line");

        assert_eq!(pmkid, [0u8; 16]);
        assert_eq!(mac_ap, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(mac_sta, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(essid, b"test");
    }

    #[test]
    fn rejects_pmkid_line_without_suffix() {
        let line = "WPA*01*00000000000000000000000000000000*001122334455*aabbccddeeff*74657374";

        assert!(parse_pmkid_line(line).is_none());
    }

    #[test]
    fn rejects_odd_length_ssid_hex() {
        let line = "WPA*01*00000000000000000000000000000000*001122334455*aabbccddeeff*7465737***";

        assert!(parse_pmkid_line(line).is_none());
    }

    #[test]
    fn rejects_ssid_over_32_bytes() {
        let ssid_hex = "00".repeat(33);
        let line = format!(
            "WPA*01*00000000000000000000000000000000*001122334455*aabbccddeeff*{ssid_hex}***"
        );

        assert!(parse_pmkid_line(&line).is_none());
    }

    #[test]
    fn rejects_wrong_prefix_and_version() {
        let wrong_prefix =
            "NOTWPA*01*00000000000000000000000000000000*001122334455*aabbccddeeff*74657374***";
        let wrong_version =
            "WPA*02*00000000000000000000000000000000*001122334455*aabbccddeeff*74657374***";

        assert!(parse_pmkid_line(wrong_prefix).is_none());
        assert!(parse_pmkid_line(wrong_version).is_none());
    }

    #[test]
    fn rejects_invalid_pmkid_and_mac_hex() {
        let valid_ap = "001122334455";
        let valid_sta = "aabbccddeeff";
        let valid_ssid = "74657374";
        let invalid_lines = [
            format!("WPA*01*00*{valid_ap}*{valid_sta}*{valid_ssid}***"),
            format!("WPA*01*{}*{valid_ap}*{valid_sta}*{valid_ssid}***", "gg".repeat(16)),
            format!("WPA*01*{}*0011223344*{valid_sta}*{valid_ssid}***", "00".repeat(16)),
            format!("WPA*01*{}*00112233445g*{valid_sta}*{valid_ssid}***", "00".repeat(16)),
            format!("WPA*01*{}*{valid_ap}*aabbccddeeff00*{valid_ssid}***", "00".repeat(16)),
            format!("WPA*01*{}*{valid_ap}*aabbccddeefg*{valid_ssid}***", "00".repeat(16)),
        ];

        for line in invalid_lines {
            assert!(parse_pmkid_line(&line).is_none(), "accepted invalid line: {line}");
        }
    }

    #[test]
    fn verifies_correct_passphrase() {
        // This expected PMKID was calculated independently using Python's hashlib and hmac.
        let line = "WPA*01*0ad6fdc0a540312a34414dee1ed5bf0c*001122334455*aabbccddeeff*746573742d6e6574776f726b***";

        assert!(verify_pmkid_line("password123", line));
    }

    #[test]
    fn rejects_incorrect_passphrase() {
        let line = "WPA*01*0ad6fdc0a540312a34414dee1ed5bf0c*001122334455*aabbccddeeff*746573742d6e6574776f726b***";

        assert!(!verify_pmkid_line("wrongpassword", line));
    }

    #[test]
    fn rejects_passphrase_shorter_than_wpa_minimum() {
        let line = "WPA*01*0ad6fdc0a540312a34414dee1ed5bf0c*001122334455*aabbccddeeff*746573742d6e6574776f726b***";

        assert!(!verify_pmkid_line("short", line));
    }

    #[test]
    fn rejects_passphrase_longer_than_wpa_maximum() {
        let line = "WPA*01*0ad6fdc0a540312a34414dee1ed5bf0c*001122334455*aabbccddeeff*746573742d6e6574776f726b***";
        let passphrase = "a".repeat(64);

        assert!(!verify_pmkid_line(&passphrase, line));
    }
}
