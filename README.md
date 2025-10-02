


# Advanced Blockchain Governance Platform

```

DID Registration → Staking → Poll Creation → Voting → Mining → Results

````

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
  * Multi-threaded mining for performance.
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

* **C++ Compiler:** C++17 compatible (MSVC, GCC, Clang)  
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
````

### 2. Setup Dependencies

* **OpenSSL:**

  * Install via your package manager or download binaries.
  * Ensure headers and libraries are accessible to your compiler.

* **httplib:**

  * Include `httplib.h` in your project folder.

### 3. Using Visual Studio

1. Create a new **Console Application** project.
2. Add all `.cpp` and `.h` files to the project.
3. Add include directories for:

   * OpenSSL headers
   * `httplib.h`
4. Link against OpenSSL libraries (`libssl.lib` and `libcrypto.lib`).
5. Set C++17 standard in project properties.
6. Build the project.

### 4. Using CMake

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

> Make sure OpenSSL paths are correctly set in your `CMakeLists.txt`.

---

## Running

Run the executable:

```bash
./BlockchainGovernancePlatform
```

The server will start and expose API endpoints on **[http://localhost:8080](http://localhost:8080)** (default).

---

## API Endpoints

* **Identity Management**

  * `POST /identity/register` — Register a new identity
  * `GET /identity/{address}` — Fetch identity by address
  * `GET /identities` — List all identities

* **Staking**

  * `POST /stake` — Stake tokens
  * `POST /unstake` — Unstake tokens
  * `GET /stake/{address}` — Get stake status
  * `GET /balance/{address}` — Get token balance

* **Polls & Voting**

  * `POST /poll/create` — Create a poll
  * `POST /poll/vote` — Cast a vote
  * `GET /polls` — List all polls
  * `GET /poll/{id}` — Get poll details

* **Blockchain Inspection**

  * `GET /chain` — Get full blockchain data
  * `GET /block/{index}` — Get specific block
  * `GET /merkle-proof/{blockIndex}/{txIndex}` — Get transaction Merkle proof
  * `GET /status` — Check blockchain health and stats

* **Candidates**

  * `GET /candidates` — List allowed candidates

---

## How to Impress with this Project

* **Live Demo:** Register identities, stake tokens, create polls, and vote via API or frontend.
* **Multi-threaded Mining:** Show how votes and transactions are mined efficiently.
* **Blockchain Integrity:** Demonstrate `isChainValid()` before and after tampering a transaction.
* **Merkle Proofs:** Show verification of individual votes using Merkle proofs.
* **Dynamic Difficulty:** Show how mining difficulty adjusts automatically based on block times.

---

## Future Enhancements

* Web frontend with real-time dashboard for votes and stakes.
* Support for multiple miners and peer-to-peer networking.
* Enhanced governance rules (quadratic voting, multi-poll participation).

---

## License

MIT License


