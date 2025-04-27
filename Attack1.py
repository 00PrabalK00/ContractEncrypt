import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from qiskit import transpile

# Parameters
n = 10  # Security parameter (dimension)
q = 1031  # Large prime modulus
sigma = 1  # Noise standard deviation
message_space = 16  # Allow messages 0-15 (4-bit messages)

# Key Generation
def keygen():
    A = np.random.randint(0, q, (n, n))  # Public random matrix
    s = np.random.randint(0, q, (n, 1))  # Secret key
    e = np.round(np.random.normal(0, sigma, (n, 1))).astype(int)  # Small noise, rounded properly
    b = (A @ s + e) % q  # Compute b = As + e (mod q)
    return (A, b), s  # Public key (A, b), private key s

# Encryption
def encrypt(public_key, message):
    A, b = public_key
    m = np.array([[message % message_space]])  # Keep message in range
    r = np.random.randint(0, 2, (n, 1))  # Small random vector
    c1 = (A.T @ r) % q  # First ciphertext component
    c2 = (b.T @ r).item() + (m * (q // message_space)) % q  # Scale message properly
    return c1, c2

# Decryption
def decrypt(secret_key, ciphertext):
    c1, c2 = ciphertext
    decrypted = (c2 - (secret_key.T @ c1).item()) % q  # Recover message
    # Scale back and round properly
    return int(np.round(decrypted * message_space / q) % message_space)

# Quantum Attack Simulation (a simple placeholder for Shor's-style attack)
def quantum_attack(A, b):
    """Simulate a quantum attack to recover the secret key."""
    print("\n🔹 Running Simulated Quantum Attack...")

    # Placeholder: Create a simple quantum circuit that could simulate a brute force attack
    qubits = n  # Number of qubits based on the dimension of the lattice
    qc = QuantumCircuit(qubits, qubits)

    qc.h(range(qubits))  # Apply Hadamard gates to all qubits for superposition
    qc.measure(range(qubits), range(qubits))  # Measurement step

    # Simulate the quantum circuit using AerSimulator's run method
    backend = AerSimulator()
    compiled_circuit = transpile(qc, backend)
    
    # Run the simulation using 'run' instead of 'execute'
    result = backend.run(compiled_circuit, shots=1024).result()
    counts = result.get_counts()

    print("\n🔹 Quantum Measurement Results:", counts)

    # Simulate the attack success (this is just a placeholder)
    # In reality, the quantum attack would attempt to recover the secret key (s)
    # For now, we simulate it by printing a random key guess
    guess = np.random.randint(0, q, (n, 1))  # Random guess of the secret key
    print("\n🔹 Simulated Quantum Attack Guess: ", guess.T)
    return guess

# Testing the scheme
public_key, secret_key = keygen()
message = np.random.randint(0, 16)  # Random message (0-15)
ciphertext = encrypt(public_key, message)
decrypted_message = decrypt(secret_key, ciphertext)

print(f"Original Message: {message}")
print(f"Decrypted Message: {decrypted_message}")

# Run Quantum Attack on the public key
quantum_attack(public_key[0], public_key[1])  # Simulating the attack
