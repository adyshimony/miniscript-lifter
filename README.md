# Miniscript Lifter

A command-line tool for analyzing Bitcoin scripts and determining their liftability to Miniscript policies.

## What it does

The `lift` program takes a Bitcoin script (in hex format) and determines whether it can be "lifted" to a Miniscript policy. This is useful for:

- Analyzing Bitcoin scripts to understand their spending conditions
- Converting complex scripts to human-readable policy representations
- Verifying script security and liftability

## Installation

```bash
cargo build --release
```

The binary will be available at `target/release/lift`.

## Usage

### Basic usage with a redeem/witness script

```bash
./lift <script_hex>
```

### Usage with a scriptPubKey and executable script

```bash
./lift <scriptpubkey_hex> <executable_script_hex>
```

This is needed when the first argument is a scriptPubKey rather than a direct executable script. The second argument depends on the scriptPubKey type:

- **P2WSH**: Provide the `witnessScript` as the second argument
- **P2SH**: Provide the `redeemScript` as the second argument  
- **P2TR**: Provide the `tapscript` as the second argument
- **P2WPKH**: Cannot be lifted (no separate witness script exists)

## Examples

### Basic example with an executable script

```bash
./lift 2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ad2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac
```

**Output:**
```
LIFTABLE: SAFE
Miniscript: and_v(v:pk(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9),pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))
Policy: and(pk(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9),pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))
```

### Why scriptPubKeys can't be lifted directly

When you have a scriptPubKey, it only contains a hash of the actual spending script, not the script itself. Without the corresponding executable script, the program cannot analyze the spending conditions for liftability.

**Note:** P2WPKH scriptPubKeys cannot be lifted at all since they don't have a separate witness script - the public key hash itself is the spending condition.

**Example with P2WSH scriptPubKey:**
```bash
./lift "002060b665d87f99f11647a951457422794037e020d4d88da1421b5a8c31428067ba" "522102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f92103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd2103defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a3453ae"
```

**What this does:**
- First argument: P2WSH scriptPubKey (`002060b665d87f99f11647a951457422794037e020d4d88da1421b5a8c31428067ba`)
- Second argument: The `witnessScript` (3-of-3 multisig)
- Program verifies the scriptPubKey hash matches the witnessScript, then analyzes liftability

## Exit codes

- `0`: Script is liftable and safe
- `1`: Script is liftable but unsafe (contains potential security issues)
- `3`: Script is not liftable or invalid input

## Supported script types

The program can analyze:
- Direct executable scripts (redeem/witness/tapscript)
- P2WSH (Pay-to-Witness-Script-Hash) scripts with their `witnessScript`
- P2SH (Pay-to-Script-Hash) scripts with their `redeemScript`
- P2TR (Pay-to-Taproot) scripts with their `tapscript`

**Note:** P2WPKH (Pay-to-Witness-Public-Key-Hash) scriptPubKeys cannot be lifted since they don't have a separate witness script.

## What is Miniscript?

Miniscript is a language for writing Bitcoin scripts in a structured way that allows for:
- Automatic analysis of spending conditions
- Policy composition and decomposition
- Security analysis and verification
- Human-readable representation of complex scripts

## Dependencies

- `miniscript`: Core Miniscript functionality
- `hex`: Hex string parsing
- `bitcoin`: Bitcoin script and cryptographic primitives 