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
    let spk_or_script = ScriptBuf::from_bytes(input_bytes);

    match classify_script_pubkey(spk_or_script.as_bytes()) {
        None => {
            // Treat as redeem/witness/tapscript (i.e., an executable script) and test liftability
            print_liftability(spk_or_script.as_script());
        }
        Some(SpkKind::P2WSH) => {
            // Needs witnessScript to check/verify
            if args.len() < 2 {
                println!("NOT_LIFTABLE: input is a P2WSH scriptPubKey; provide the witnessScript hex as the second argument");
                std::process::exit(3);
            }
            let ws_hex = &args[1];
            let ws = match hex_to_script(ws_hex) {
                Ok(s) => s,
                Err(e) => {
                    println!("NOT_LIFTABLE: witnessScript invalid hex - {e}");
                    std::process::exit(3);
                }
            };
            match verify_p2wsh_matches(&spk_or_script, &ws) {
                Ok(_) => print_liftability(ws.as_script()),
                Err(msg) => {
                    println!("NOT_LIFTABLE: {msg}");
                    std::process::exit(3);
                }
            }
        }
        Some(SpkKind::P2SH) => {
            // Needs redeemScript to check/verify
            if args.len() < 2 {
                println!("NOT_LIFTABLE: input is a P2SH scriptPubKey; provide the redeemScript hex as the second argument");
                std::process::exit(3);
            }
            let rs_hex = &args[1];
            let rs = match hex_to_script(rs_hex) {
                Ok(s) => s,
                Err(e) => {
                    println!("NOT_LIFTABLE: redeemScript invalid hex - {e}");
                    std::process::exit(3);
                }
            };
            match verify_p2sh_matches(&spk_or_script, &rs) {
                Ok(_) => print_liftability(rs.as_script()),
                Err(msg) => {
                    println!("NOT_LIFTABLE: {msg}");
                    std::process::exit(3);
                }
            }
        }
        Some(SpkKind::P2WPKH) => {
            // No separate witnessScript exists
            println!("NOT_LIFTABLE: input is a P2WPKH scriptPubKey; there is no separate witnessScript. Provide the actual script you want to analyze, not the scriptPubKey");
            std::process::exit(3);
        }
        Some(SpkKind::P2TR) => {
            // Optional: accept tapscript as second arg; verification not implemented
            if args.len() < 2 {
                println!("NOT_LIFTABLE: input is a P2TR (Taproot) scriptPubKey; provide the tapscript (tapleaf) hex as the second argument (SPK↔tapscript verification not implemented)");
                std::process::exit(3);
            }
            let ts_hex = &args[1];
            let ts = match hex_to_script(ts_hex) {
                Ok(s) => s,
                Err(e) => {
                    println!("NOT_LIFTABLE: tapscript invalid hex - {e}");
                    std::process::exit(3);
                }
            };
            // We skip verifying the tapleaf against the SPK+control block; just check liftability.
            print_liftability(ts.as_script());
        }
    }
}

fn hex_to_script(hex: &str) -> Result<ScriptBuf, String> {
    let bytes = hex::decode(hex).map_err(|e| format!("invalid hex: {e}"))?;
    Ok(ScriptBuf::from_bytes(bytes))
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

#[derive(Clone, Copy)]
enum SpkKind {
    P2WPKH,
    P2WSH,
    P2SH,
    P2TR,
}

/// Detect common scriptPubKey patterns from raw bytes.
fn classify_script_pubkey(b: &[u8]) -> Option<SpkKind> {
    // v0 P2WPKH: OP_0 0x14 <20>
    if b.len() == 22 && b[0] == 0x00 && b[1] == 0x14 {
        return Some(SpkKind::P2WPKH);
    }
    // v0 P2WSH: OP_0 0x20 <32>
    if b.len() == 34 && b[0] == 0x00 && b[1] == 0x20 {
        return Some(SpkKind::P2WSH);
    }
    // P2SH: OP_HASH160 OP_PUSHBYTES_20 <20> OP_EQUAL
    if b.len() == 23 && b[0] == 0xa9 && b[1] == 0x14 && b[22] == 0x87 {
        return Some(SpkKind::P2SH);
    }
    // Taproot (v1): OP_1 0x20 <32>
    if b.len() == 34 && b[0] == 0x51 && b[1] == 0x20 {
        return Some(SpkKind::P2TR);
    }
    None
}

/// Verify that `witness_script` matches the given P2WSH scriptPubKey.
fn verify_p2wsh_matches(spk: &ScriptBuf, witness_script: &ScriptBuf) -> Result<(), String> {
    let b = spk.as_bytes();
    if b.len() != 34 || b[0] != 0x00 || b[1] != 0x20 {
        return Err("not a P2WSH scriptPubKey".to_string());
    }
    let expected_prog = &b[2..34];
    let got = sha256::Hash::hash(witness_script.as_bytes()).to_byte_array(); // [u8;32]
    if expected_prog == got.as_slice() {
        Ok(())
    } else {
        Err("witnessScript does not match P2WSH witness program (expected sha256(witnessScript))".to_string())
    }
}

/// Verify that `redeem_script` matches the given P2SH scriptPubKey.
fn verify_p2sh_matches(spk: &ScriptBuf, redeem_script: &ScriptBuf) -> Result<(), String> {
    let b = spk.as_bytes();
    if !(b.len() == 23 && b[0] == 0xa9 && b[1] == 0x14 && b[22] == 0x87) {
        return Err("not a P2SH scriptPubKey".to_string());
    }
    let expected_h160 = &b[2..22];
    let got = hash160::Hash::hash(redeem_script.as_bytes()).to_byte_array(); // [u8;20]
    if expected_h160 == got.as_slice() {
        Ok(())
    } else {
        Err("redeemScript does not match P2SH redeem hash (expected hash160(redeemScript))".to_string())
    }
}
