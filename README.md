# Advanced Blockchain Governance Platform

A full-featured blockchain platform with **Decentralized Identity (DID), Staking, Poll Management, and Governance**. This project combines blockchain mechanics, cryptography, and a REST API backend for interactive decentralized voting and identity management.

---

## Features

* **Decentralized Identities (DID):**
  * Register identities with unique blockchain-based addresses.
  * Track reputation and credentials.
  * JSON serialization for easy API consumption.

* **Staking Mechanism:**
  * Lock tokens for a defined period to participate in governance.
  * Earn rewards proportional to stake and time.
  * View stake status and rewards via API.

* **Polls & Governance:**
  * Owners can create polls with options, duration, and requirements.
  * Reputation and stake-based voting validation.
  * Real-time vote tracking and results calculation.

* **Blockchain Core:**
  * Proof-of-work mining with adjustable difficulty.
  * Merkle Tree transaction verification.
  * Multiple-threaded mining for performance.
  * Fully auditable blocks and transaction hashes.

* **REST API Server (via `httplib`):**
  * Endpoints for identity, staking, voting, polls, and blockchain inspection.
  * Supports CORS and JSON responses for integration with frontends.

* **Security & Integrity:**
  * SHA-256 hashing for transaction and block integrity.
  * Signature verification for all transactions.
  * Ensures blockchain validity and immutability.

---

## Prerequisites

* **C++ Compiler:** C++17 compatible (e.g., MSVC, GCC, Clang)  
* **Libraries:**
  * [OpenSSL](https://www.openssl.org/) (for SHA-256 hashing)  
  * [httplib.h](https://github.com/yhirose/cpp-httplib) (single-header HTTP server)  
* **CMake** (optional but recommended for cross-platform builds)

---

## Building

### 1. Clone the repository

```bash
git clone <repository-url>
cd <repository-folder>
