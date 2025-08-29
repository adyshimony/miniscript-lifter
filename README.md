# Miniscript Lifter

A command-line tool for analyzing Bitcoin **scripts** and determining their liftability to **Miniscript**, plus a derived **Policy**.

---

## What it does

`lift` accepts a Bitcoin **script hex** and reports whether it can be lifted to Miniscript.  
If liftable, it prints:

- **Miniscript** (script-level form, e.g., `pk_k(...)`, `and_v(...)`, `older(...)`)
- **Policy** (high-level form, e.g., `pk(...)`, `thresh(...)`, `or(...)`)

This is useful for:

- Understanding spending conditions  
- Converting complex scripts into human-readable policies  
- Checking whether a script is safely inside Miniscript’s analyzable subset  

---

## Installation

```bash
cargo build --release
```

The binary will be at:

```
target/release/lift
```

> Ensure your crate/bin is named `lift` so the path matches.

---

## Usage

### 1) Direct **spending script**

A “spending script” is the actual script that executes (e.g., a **redeemScript** for P2SH, **witnessScript** for P2WSH, or **tapscript** for Taproot).

```bash
./lift <script_hex>
```

### 2) **scriptPubKey + spending script**

When the first argument is a **scriptPubKey**, pass the committed spending script as the second argument:

```bash
./lift <scriptpubkey_hex> <spending_script_hex>
```

- **P2WSH** (BIP141): second arg is the **witnessScript**  
  The tool verifies the witness program equals `sha256(witnessScript)`.
- **P2SH** (BIP16): second arg is the **redeemScript**  
  The tool verifies the redeem hash equals `hash160(redeemScript)`.
- **P2TR** (Taproot, BIP341/342): second arg is the **tapscript** (tapleaf)  
  *Note: the tool only checks tapscript liftability; it does **not** verify the control block/path.*
- **P2WPKH**: **not supported** here (no separate spending script exists to analyze).

---

## Examples

### A) Direct spending script

This script encodes: `pk1 CHECKSIGVERIFY; pk2 CHECKSIG`, which lifts to
`and_v(v:pk_k(pk1), pk_k(pk2))`:

```bash
./lift 2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ad2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac
```

**Output:**
```
LIFTABLE: SAFE
Miniscript: and_v(v:pk_k(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9),pk_k(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))
Policy: and(pk(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9),pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))
```

---

### B) P2WSH scriptPubKey + witnessScript (2-of-3 multisig)

- **witnessScript** (2-of-3 multisig):  
  ```
  522102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
  2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd
  2103defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34
  53ae
  ```

- **scriptPubKey** (OP_0 <sha256(witnessScript)>):  
  ```
  002060b665d87f99f11647a951457422794037e020d4d88da1421b5a8c31428067ba
  ```

Run:
```bash
./lift "002060b665d87f99f11647a951457422794037e020d4d88da1421b5a8c31428067ba" \
       "522102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9\
2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd\
2103defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34\
53ae"
```

The tool verifies the SPK’s witness program equals `sha256(witnessScript)`, then lifts the witnessScript (expect `multi(2, ...)` or `thresh(2, ...)`).

---

## Output & exit codes

The first line is always decisive:

- `LIFTABLE: SAFE` — analysis passed (**exit 0**)  
- `LIFTABLE: UNSAFE - <reason>` — parsed but analysis failed (**exit 1**)  
- `NOT_LIFTABLE: <reason>` — invalid/unsupported input or cannot be lifted (**exit 3**)  

When liftable, the program also prints **Miniscript** and **Policy**.

---

## Supported inputs

- Direct **spending scripts**: **redeemScript**, **witnessScript**, **tapscript**  
- **P2WSH** scriptPubKey + **witnessScript** (hash verified)  
- **P2SH** scriptPubKey + **redeemScript** (hash verified)  
- **P2TR** scriptPubKey + **tapscript** (liftability only; no control-block verification)  

**Not supported**: **P2WPKH** scriptPubKeys (no separate spending script to analyze).  

---

## Why scriptPubKeys can’t be lifted by themselves

A **scriptPubKey** only contains (or commits to) a hash/program of the actual **spending script**.  
Without the corresponding **redeemScript** / **witnessScript** / **tapscript**, the tool cannot analyze spending conditions for liftability.

---

## Miniscript refresher

Miniscript is a structured language for expressing Bitcoin Script that enables:

- Automatic safety analysis (standardness, malleability, timelocks, etc.)  
- Round-tripping between Script ⇄ Miniscript for the supported fragment set  
- Derivation of a readable **Policy** form such as `thresh(2, pk(A), pk(B), pk(C))`  

---

## Dependencies

- `miniscript` — Miniscript and re-exported `bitcoin` types  
- `hex` — hex parsing  
