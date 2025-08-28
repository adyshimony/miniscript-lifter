use miniscript::{
    bitcoin::{
        hashes::{hash160, sha256, Hash}, // for to_byte_array()
        script::{Script, ScriptBuf},
        PublicKey,
    },
    policy::Liftable, // for .lift()
    Miniscript, Segwitv0,
};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        println!("NOT_LIFTABLE: missing hex argument");
        std::process::exit(3);
    }

    let input_hex = &args[0];
    let input_bytes = match hex::decode(input_hex) {
        Ok(b) => b,
        Err(e) => {
            println!("NOT_LIFTABLE: invalid hex - {e}");
            std::process::exit(3);
        }
    };
    let input = ScriptBuf::from_bytes(input_bytes);

    match classify_script_pubkey(input.as_bytes()) {
        None => {
            // Treat as redeem/witness script and test liftability
            print_liftability(input.as_script());
        }
        Some(kind) => {
            if args.len() >= 2 {
                let inner_hex = &args[1];
                let inner_bytes = match hex::decode(inner_hex) {
                    Ok(b) => b,
                    Err(e) => {
                        println!("NOT_LIFTABLE: inner script invalid hex - {e}");
                        std::process::exit(3);
                    }
                };
                let inner = ScriptBuf::from_bytes(inner_bytes);
                match verify_spk_matches_inner(input.as_bytes(), inner.as_script()) {
                    Ok(_) => print_liftability(inner.as_script()),
                    Err(msg) => {
                        println!("NOT_LIFTABLE: {msg}");
                        std::process::exit(3);
                    }
                }
            } else {
                println!("NOT_LIFTABLE: input is a scriptPubKey ({kind}); provide inner redeem/witness script hex as second argument");
                std::process::exit(3);
            }
        }
    }
}

fn print_liftability(script: &Script) -> ! {
    match Miniscript::<PublicKey, Segwitv0>::parse_insane(script) {
        Ok(ms) => {
            println!("LIFTABLE: SAFE");
            println!("Miniscript: {}", ms);
            match ms.lift() {
                Ok(policy) => println!("Policy: {}", policy),
                Err(e) => println!("Policy: <error: {e}>"),
            }
            std::process::exit(0);
        }
        Err(insane_err) => match Miniscript::<PublicKey, Segwitv0>::parse(script) {
            Ok(ms_unchecked) => {
                println!("LIFTABLE: UNSAFE - {insane_err}");
                println!("Miniscript (unchecked): {}", ms_unchecked);
                match ms_unchecked.lift() {
                    Ok(policy) => println!("Policy (from unchecked): {}", policy),
                    Err(e) => println!("Policy (from unchecked): <error: {e}>"),
                }
                std::process::exit(1);
            }
            Err(parse_err) => {
                println!("NOT_LIFTABLE: {parse_err}");
                std::process::exit(3);
            }
        },
    }
}

/// Detect common scriptPubKey patterns from raw bytes.
fn classify_script_pubkey(b: &[u8]) -> Option<&'static str> {
    // v0 P2WPKH: OP_0 0x14 <20>
    if b.len() == 22 && b[0] == 0x00 && b[1] == 0x14 {
        return Some("P2WPKH v0");
    }
    // v0 P2WSH: OP_0 0x20 <32>
    if b.len() == 34 && b[0] == 0x00 && b[1] == 0x20 {
        return Some("P2WSH v0");
    }
    // P2SH: OP_HASH160 OP_PUSHBYTES_20 <20> OP_EQUAL
    if b.len() == 23 && b[0] == 0xa9 && b[1] == 0x14 && b[22] == 0x87 {
        return Some("P2SH");
    }
    // Taproot (v1): OP_1 0x20 <32>
    if b.len() == 34 && b[0] == 0x51 && b[1] == 0x20 {
        return Some("P2TR v1");
    }
    None
}

/// For P2WSH/P2SH spks, verify the provided inner script matches the hash in the spk.
fn verify_spk_matches_inner(spk: &[u8], inner: &Script) -> Result<(), String> {
    // P2WSH: OP_0 0x20 <32=sha256(inner)>
    if spk.len() == 34 && spk[0] == 0x00 && spk[1] == 0x20 {
        let expected_prog = &spk[2..34]; // &[u8]
        let got_arr = sha256::Hash::hash(inner.as_bytes()).to_byte_array(); // [u8;32]
        if expected_prog == got_arr.as_slice() {
            return Ok(());
        } else {
            return Err("inner script does not match P2WSH witness program (expected sha256(inner))".to_string());
        }
    }
    // P2SH: OP_HASH160 OP_PUSHBYTES_20 <20=h160(inner)> OP_EQUAL
    if spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87 {
        let expected_h160 = &spk[2..22]; // &[u8]
        let got_arr = hash160::Hash::hash(inner.as_bytes()).to_byte_array(); // [u8;20]
        if expected_h160 == got_arr.as_slice() {
            return Ok(());
        } else {
            return Err("inner script does not match P2SH redeem hash (expected hash160(inner))".to_string());
        }
    }
    Err("unsupported scriptPubKey type for inner-script verification (expected P2WSH or P2SH)".to_string())
}
