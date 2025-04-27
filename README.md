# Cryptography and Quantum Attack Simulations

## Overview
This project explores the implementation and comparison of two cryptographic systems:
- **Lattice-based Encryption** (Crypto1)
- **ECC-based Encryption** (Crypto2)

It also simulates **quantum attacks** on both systems using placeholder circuits, and performs a comparative analysis of encryption time, decryption time, cipher sizes, entropy, and bit-flip resilience.

## Project Structure
- **Crypto1.py** → Lattice-based encryption using Learning With Errors (LWE) principles.
- **Crypto2.py** → ECC-based encryption using Elliptic Curve Diffie-Hellman (ECDH) key exchange and AES encryption.
- **Attack1.py** → Simulated quantum attack on Lattice encryption using Qiskit.
- **Attack2.py** → Simulated quantum attack on ECC encryption (Shor’s algorithm inspired).
- **CompareCrypto.py** → Script to benchmark and compare both encryption schemes based on multiple security parameters.

## How It Works

### Crypto1 (Lattice-Based Encryption)
- Uses a public matrix **A**, a private secret vector **s**, and a small noise vector **e**.
- Encrypts a message by creating a ciphertext tuple (c1, c2).
- Decryption uses modular arithmetic to recover the original message.

### Crypto2 (ECC-Based Encryption)
- Generates ECC key pairs over the **P-256** curve.
- Derives a shared AES key using ECDH.
- Encrypts the message with AES-CBC using the derived key.

### Attack Simulations
- **Attack1.py**: Simulates a quantum attack on lattice encryption by creating superposition and random guesses.
- **Attack2.py**: Simulates a quantum circuit attack for ECC (e.g., Shor's algorithm behavior).

### Cryptographic Comparison
- **CompareCrypto.py** benchmarks both systems by:
  - Measuring encryption and decryption time.
  - Checking ciphertext size.
  - Calculating Shannon entropy.
  - Testing bit-flip resilience.

## Hardware & Software Requirements
- Python 3.8+
- Libraries:
  - `numpy`
  - `pycryptodome`
  - `qiskit`
  - `qiskit-aer`
- Install with:
  ```bash
  pip install numpy pycryptodome qiskit qiskit-aer


#Outputs
  ```
🔹 Crypto1.py
Original Message: 7
Decrypted Message: 7

🔹 Crypto2.py
Original Message: 10
Decrypted Message: 10
Ciphertext (hex): 9f9e8bc9...

🔹 CompareCrypto.py
🔍 Comparison Results:
✅ Original Message: 10
🛡️ Lattice Decrypted: 10 | ECC Decrypted: 10
⏱️ Lattice Encryption Time: 0.0001s | ECC Encryption Time: 0.00005s
📦 Lattice Cipher Size: 80 bytes | ECC Cipher Size: 2
🎲 Lattice Cipher Entropy: 3.95 | ECC Cipher Entropy: 7.95
🛡️ Lattice Bitflip Resilience: True | ECC Bitflip Resilience: True


