
🛡️ pqwallet – Post-Quantum Wallet Generator (Dilithium5)
Welcome to pqwallet, a lightweight, offline-first wallet generator built in Rust using Dilithium5, a post-quantum cryptographic algorithm. This is my first project in Rust and serves as a foundational component for a larger initiative currently in development.
⚠️ Disclaimer
This is an experimental project and my first app written in Rust. But its fully functional.
pqwallet is a simple but powerful tool that generates:

🗝️ A Post-Quantum Safe Private Key

🔓 A Corresponding Public Key

🏷️ A Human-Friendly Wallet Address (e.g. PQx0847474747447...)

The wallet address acts as a unique, user-friendly identity identifier, designed to replace the unwieldy public key in practical applications. It enables secure, pseudonymous identity handling in a post-quantum world.

🔐 Why Post-Quantum?
Current cryptographic standards are vulnerable to quantum computing. pqwallet uses Dilithium5, a NIST-approved post-quantum digital signature algorithm, to ensure that:

Your identity remains secure, even in the age of quantum computers.

Your private key cannot be reverse-engineered from the public key—even with theoretical quantum computing capabilities.

✍️ Use Cases
The generated private key can be used to sign messages and documents offline, offering:

A lightweight proof of authenticity system.

A secure way to verify authorship for digital art, legal documents, identity claims, and more.

Full anonymity and consent-based disclosure, since identity is not inherently tied to the public key.

Even in the event of a quantum breakthrough, your data and identity remain protected.

🛠️ Tech Stack
Language: Rust 🦀

Crypto: CRYSTALS-Dilithium5 (Post-Quantum Digital Signatures)

Security Model: Offline-first, quantum-resilient

📦 Coming Soon
This tool is part of a broader project I’m building. Stay tuned for:

Integration into a full identity/authentication framework

User interface for key management

Extended features like multi-signature wallets and encrypted key storage

🤝 Contribute
If you're interested in post-quantum cryptography, Rust, or identity systems, feel free to fork, open issues, or submit PRs!

📜 License
This project is open-source and available under the MIT License.
