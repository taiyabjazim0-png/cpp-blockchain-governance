#include "httplib/httplib.h"
#include <iostream>
#include <vector>
#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <fstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <memory>
#include <chrono>
#include <random>
#include <algorithm>

// JSON helpers
std::string escapeJson(const std::string& str) {
	std::string result;
	for (char c : str) {
		if (c == '"') result += "\\\"";
		else if (c == '\\') result += "\\\\";
		else if (c == '\n') result += "\\n";
		else if (c == '\r') result += "\\r";
		else if (c == '\t') result += "\\t";
		else result += c;
	}
	return result;
}

// SHA256
std::string sha256(const std::string& data) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256((unsigned char*)data.c_str(), data.size(), hash);
	std::stringstream ss;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
	}
	return ss.str();
}

// Generate random key
std::string generateKey() {
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 255);
	std::stringstream ss;
	for (int i = 0; i < 32; i++) {
		ss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
	}
	return ss.str();
}

// Decentralized Identity (DID)
struct DecentralizedIdentity {
	std::string did;
	std::string publicKey;
	std::string address;
	long registrationTime;
	int reputation;
	std::vector<std::string> credentials;
	bool verified;

	DecentralizedIdentity() : reputation(0), verified(false), registrationTime(0) {}

	DecentralizedIdentity(const std::string& name)
		: reputation(100), verified(false), registrationTime(time(0)) {
		publicKey = generateKey();
		address = sha256(name + publicKey).substr(0, 42);
		did = "did:blockchain:" + address;
	}

	void addCredential(const std::string& cred) {
		credentials.push_back(cred);
	}

	void updateReputation(int delta) {
		reputation += delta;
		if (reputation < 0) reputation = 0;
		if (reputation > 1000) reputation = 1000;
	}

	std::string toJson() const {
		std::stringstream ss;
		ss << "{\"did\":\"" << escapeJson(did)
			<< "\",\"address\":\"" << escapeJson(address)
			<< "\",\"publicKey\":\"" << escapeJson(publicKey.substr(0, 16)) << "...\""
			<< ",\"reputation\":" << reputation
			<< ",\"verified\":" << (verified ? "true" : "false")
			<< ",\"registrationTime\":" << registrationTime
			<< ",\"credentials\":[";
		for (size_t i = 0; i < credentials.size(); i++) {
			ss << "\"" << escapeJson(credentials[i]) << "\"";
			if (i < credentials.size() - 1) ss << ",";
		}
		ss << "]}";
		return ss.str();
	}
};

// Staking System
struct StakePosition {
	std::string staker;
	double amount;
	long lockTime;
	long unlockTime;
	double rewards;
	bool active;

	StakePosition() : amount(0), lockTime(0), unlockTime(0), rewards(0), active(false) {}

	StakePosition(const std::string& s, double amt, long lock)
		: staker(s), amount(amt), lockTime(lock), active(true), rewards(0) {
		unlockTime = time(0) + lock;
	}

	void calculateRewards() {
		if (!active) return;
		long currentTime = time(0);
		long elapsed = currentTime - (unlockTime - lockTime);
		double rate = 0.05;
		rewards = amount * rate * (elapsed / 31536000.0);
	}

	bool canUnstake() const {
		return time(0) >= unlockTime;
	}

	std::string toJson() const {
		std::stringstream ss;
		ss << "{\"staker\":\"" << escapeJson(staker)
			<< "\",\"amount\":" << std::fixed << std::setprecision(2) << amount
			<< ",\"lockTime\":" << lockTime
			<< ",\"unlockTime\":" << unlockTime
			<< ",\"rewards\":" << rewards
			<< ",\"active\":" << (active ? "true" : "false")
			<< ",\"canUnstake\":" << (canUnstake() ? "true" : "false") << "}";
		return ss.str();
	}
};

// Poll structure
struct Poll {
	std::string id;
	std::string title;
	std::string description;
	std::string creator;
	std::vector<std::string> options;
	long startTime;
	long endTime;
	bool active;
	int minReputation;
	double minStake;
	std::map<std::string, std::string> votes;
	std::string pollType;

	Poll() : startTime(0), endTime(0), active(false), minReputation(0), minStake(0), pollType("simple") {}

	Poll(const std::string& t, const std::string& desc, const std::string& c,
		const std::vector<std::string>& opts, long duration, int minRep = 0,
		double minStk = 0, const std::string& type = "simple")
		: title(t), description(desc), creator(c), options(opts),
		minReputation(minRep), minStake(minStk), pollType(type), active(true) {
		id = sha256(t + c + std::to_string(time(0))).substr(0, 16);
		startTime = time(0);
		endTime = startTime + duration;
	}

	bool isActive() const {
		long now = time(0);
		return active && now >= startTime && now < endTime;
	}

	bool hasVoted(const std::string& voter) const {
		return votes.find(voter) != votes.end();
	}

	void addVote(const std::string& voter, const std::string& choice) {
		if (!isActive()) return;
		votes[voter] = choice;
	}

	std::map<std::string, int> getResults() const {
		std::map<std::string, int> results;
		for (const auto& opt : options) {
			results[opt] = 0;
		}
		for (const auto& vote : votes) {
			results[vote.second]++;
		}
		return results;
	}

	std::string toJson() const {
		std::stringstream ss;
		ss << "{\"id\":\"" << escapeJson(id)
			<< "\",\"title\":\"" << escapeJson(title)
			<< "\",\"description\":\"" << escapeJson(description)
			<< "\",\"creator\":\"" << escapeJson(creator)
			<< "\",\"pollType\":\"" << escapeJson(pollType)
			<< "\",\"options\":[";
		for (size_t i = 0; i < options.size(); i++) {
			ss << "\"" << escapeJson(options[i]) << "\"";
			if (i < options.size() - 1) ss << ",";
		}
		ss << "],\"startTime\":" << startTime
			<< ",\"endTime\":" << endTime
			<< ",\"active\":" << (isActive() ? "true" : "false")
			<< ",\"minReputation\":" << minReputation
			<< ",\"minStake\":" << minStake
			<< ",\"totalVotes\":" << votes.size()
			<< ",\"results\":{";

		auto results = getResults();
		size_t i = 0;
		for (const auto& result : results) {
			ss << "\"" << escapeJson(result.first) << "\":" << result.second;
			if (++i < results.size()) ss << ",";
		}
		ss << "}}";
		return ss.str();
	}
};

// Merkle tree
class MerkleTree {
public:
	static std::string computeRoot(const std::vector<std::string>& txHashes) {
		if (txHashes.empty()) return sha256("empty");
		if (txHashes.size() == 1) return txHashes[0];

		std::vector<std::string> current = txHashes;
		while (current.size() > 1) {
			std::vector<std::string> next;
			for (size_t i = 0; i < current.size(); i += 2) {
				if (i + 1 < current.size())
					next.push_back(sha256(current[i] + current[i + 1]));
				else
					next.push_back(current[i]);
			}
			current = next;
		}
		return current[0];
	}

	static std::vector<std::string> generateProof(const std::vector<std::string>& txHashes, size_t index) {
		std::vector<std::string> proof;
		std::vector<std::string> current = txHashes;
		size_t idx = index;

		while (current.size() > 1) {
			if (idx % 2 == 0) {
				if (idx + 1 < current.size())
					proof.push_back(current[idx + 1]);
			}
			else {
				proof.push_back(current[idx - 1]);
			}

			std::vector<std::string> next;
			for (size_t i = 0; i < current.size(); i += 2) {
				if (i + 1 < current.size())
					next.push_back(sha256(current[i] + current[i + 1]));
				else
					next.push_back(current[i]);
			}
			current = next;
			idx /= 2;
		}
		return proof;
	}
};

// Transaction
struct Transaction {
	std::string sender, receiver, signature, txType;
	std::string data;
	double amount;
	long timestamp;

	Transaction(const std::string& s, const std::string& r, const std::string& type = "vote",
		double amt = 0, const std::string& d = "")
		: sender(s), receiver(r), txType(type), amount(amt), data(d), timestamp(time(0)) {
		signature = generateSignature();
	}

	std::string generateSignature() const {
		return sha256(sender + receiver + data + std::to_string(timestamp)).substr(0, 16);
	}

	std::string getHash() const {
		return sha256(sender + receiver + data + std::to_string(timestamp) + std::to_string(amount));
	}

	bool verify() const {
		return signature == generateSignature();
	}

	std::string toJson() const {
		return "{\"sender\":\"" + escapeJson(sender) +
			"\",\"receiver\":\"" + escapeJson(receiver) +
			"\",\"txType\":\"" + escapeJson(txType) +
			"\",\"data\":\"" + escapeJson(data) +
			"\",\"amount\":" + std::to_string(amount) +
			",\"signature\":\"" + escapeJson(signature) +
			"\",\"timestamp\":" + std::to_string(timestamp) + "}";
	}
};

// Block
struct Block {
	int index, nonce, difficulty;
	long timestamp;
	std::string prevHash, hash, merkleRoot;
	std::vector<Transaction> transactions;
	double miningTime;
	std::string miner;
	double blockReward;

	Block(int idx, const std::string& prev, const std::vector<Transaction>& txs, int diff, const std::string& m = "system")
		: index(idx), prevHash(prev), transactions(txs), difficulty(diff), nonce(0),
		miningTime(0), miner(m), blockReward(10.0) {
		timestamp = time(0);
		merkleRoot = calculateMerkleRoot();
		hash = calculateHash();
	}

	std::string calculateMerkleRoot() const {
		std::vector<std::string> txHashes;
		for (const auto& tx : transactions)
			txHashes.push_back(tx.getHash());
		return MerkleTree::computeRoot(txHashes);
	}

	std::string calculateHash() const {
		std::stringstream ss;
		ss << index << timestamp << prevHash << merkleRoot << nonce << difficulty << miner;
		return sha256(ss.str());
	}

	void mineBlock(int threadCount = 4) {
		std::string target(difficulty, '0');
		std::atomic<bool> found(false);
		std::atomic<int> bestNonce(0);
		std::string bestHash;
		std::mutex hashMutex;
		auto start = std::chrono::high_resolution_clock::now();

		std::cout << "[*] Mining block " << index << " (miner: " << miner << ")...\n";

		std::vector<std::thread> threads;
		for (int t = 0; t < threadCount; t++) {
			threads.emplace_back([&, t]() {
				Block temp = *this;
				temp.nonce = t;
				while (!found) {
					temp.hash = temp.calculateHash();
					if (temp.hash.substr(0, difficulty) == target) {
						std::lock_guard<std::mutex> lock(hashMutex);
						if (!found) {
							found = true;
							bestNonce = temp.nonce;
							bestHash = temp.hash;
						}
						break;
					}
					temp.nonce += threadCount;
				}
			});
		}

		for (auto& th : threads) th.join();
		nonce = bestNonce;
		hash = bestHash;
		auto end = std::chrono::high_resolution_clock::now();
		miningTime = std::chrono::duration<double>(end - start).count();
		std::cout << "[+] Mined! Hash: " << hash.substr(0, 20) << "... (nonce: " << nonce
			<< ", time: " << std::fixed << std::setprecision(2) << miningTime << "s)\n";
	}

	std::string toJson() const {
		std::stringstream ss;
		ss << "{\"index\":" << index
			<< ",\"timestamp\":" << timestamp
			<< ",\"prevHash\":\"" << prevHash
			<< "\",\"hash\":\"" << hash
			<< "\",\"nonce\":" << nonce
			<< ",\"merkleRoot\":\"" << merkleRoot
			<< "\",\"difficulty\":" << difficulty
			<< ",\"miner\":\"" << miner
			<< "\",\"blockReward\":" << blockReward
			<< ",\"miningTime\":" << std::fixed << std::setprecision(3) << miningTime
			<< ",\"transactions\":[";
		for (size_t i = 0; i < transactions.size(); i++) {
			ss << transactions[i].toJson();
			if (i < transactions.size() - 1) ss << ",";
		}
		ss << "]}";
		return ss.str();
	}
};

// Smart contract
class GovernanceContract {
	std::map<std::string, bool> authorizedOwners;
	std::vector<std::string> allowedCandidates;
	std::map<std::string, DecentralizedIdentity> identities;
	std::map<std::string, StakePosition> stakes;
	std::map<std::string, double> balances;
	std::mutex contractMutex;

public:
	GovernanceContract(const std::vector<std::string>& c, const std::vector<std::string>& owners)
		: allowedCandidates(c) {
		for (const auto& owner : owners) {
			authorizedOwners[owner] = true;
		}
	}

	bool isOwner(const std::string& address) const {
		return authorizedOwners.find(address) != authorizedOwners.end();
	}

	bool registerIdentity(const std::string& name, const std::string& address) {
		std::lock_guard<std::mutex> lock(contractMutex);
		if (identities.find(address) != identities.end()) {
			std::cout << "[-] Identity already registered for: " << address << "\n";
			return false;
		}
		identities[address] = DecentralizedIdentity(name);
		balances[address] = 1000.0;
		std::cout << "[+] DID registered: " << identities[address].did << "\n";
		return true;
	}

	DecentralizedIdentity* getIdentity(const std::string& address) {
		auto it = identities.find(address);
		if (it == identities.end()) return nullptr;
		return &it->second;
	}

	bool stake(const std::string& staker, double amount, long lockTime) {
		std::lock_guard<std::mutex> lock(contractMutex);
		if (balances[staker] < amount) {
			std::cout << "[-] Insufficient balance for staking\n";
			return false;
		}
		balances[staker] -= amount;
		stakes[staker] = StakePosition(staker, amount, lockTime);
		std::cout << "[+] Staked " << amount << " tokens (lock: " << lockTime << "s)\n";
		return true;
	}

	bool unstake(const std::string& staker) {
		std::lock_guard<std::mutex> lock(contractMutex);
		auto it = stakes.find(staker);
		if (it == stakes.end()) {
			std::cout << "[-] No stake found\n";
			return false;
		}
		StakePosition& pos = it->second;
		if (!pos.canUnstake()) {
			std::cout << "[-] Stake still locked\n";
			return false;
		}
		pos.calculateRewards();
		balances[staker] += pos.amount + pos.rewards;
		pos.active = false;
		std::cout << "[+] Unstaked " << pos.amount << " + " << pos.rewards << " rewards\n";
		return true;
	}

	StakePosition* getStake(const std::string& staker) {
		auto it = stakes.find(staker);
		if (it == stakes.end()) return nullptr;
		it->second.calculateRewards();
		return &it->second;
	}

	double getBalance(const std::string& address) const {
		auto it = balances.find(address);
		return it != balances.end() ? it->second : 0.0;
	}

	bool hasMinimumStake(const std::string& address, double minStake) const {
		auto it = stakes.find(address);
		return it != stakes.end() && it->second.active && it->second.amount >= minStake;
	}

	std::vector<std::string> getCandidates() const {
		return allowedCandidates;
	}

	std::map<std::string, DecentralizedIdentity> getAllIdentities() const {
		return identities;
	}

	std::map<std::string, StakePosition> getAllStakes() const {
		return stakes;
	}
};

// Blockchain
class Blockchain {
public:
	std::vector<Block> chain;
	std::vector<Transaction> pendingTransactions;
	std::map<std::string, Poll> polls;
	int difficulty;
	std::unique_ptr<GovernanceContract> contract;
	std::mutex chainMutex;
	std::string ownerAddress;

	Blockchain(const std::vector<std::string>& candidates, const std::string& owner, int diff = 3)
		: difficulty(diff), ownerAddress(owner) {
		std::vector<std::string> owners = { owner };
		contract = std::make_unique<GovernanceContract>(candidates, owners);

		std::cout << "[*] Initializing blockchain...\n";
		std::cout << "[*] Owner: " << owner << "\n";

		std::vector<Transaction> genesisTxs = {
			Transaction("system", "genesis", "genesis", 0, "genesis_block")
		};
		Block genesis(0, "0", genesisTxs, difficulty, "system");
		genesis.mineBlock(4);
		chain.push_back(genesis);
		std::cout << "\n";
	}

	Block getLatestBlock() const {
		return chain.back();
	}

	bool createPoll(const std::string& creator, const std::string& title,
		const std::string& description, const std::vector<std::string>& options,
		long duration, int minReputation = 0, double minStake = 0,
		const std::string& pollType = "simple") {
		std::lock_guard<std::mutex> lock(chainMutex);

		if (!contract->isOwner(creator)) {
			std::cout << "[-] Only owners can create polls\n";
			return false;
		}

		Poll poll(title, description, creator, options, duration, minReputation, minStake, pollType);
		polls[poll.id] = poll;

		Transaction tx(creator, "poll_contract", "poll_creation", 0, poll.id);
		pendingTransactions.push_back(tx);

		std::cout << "[+] Poll created: " << title << " (ID: " << poll.id << ")\n";
		return true;
	}

	bool voteInPoll(const std::string& pollId, const std::string& voter, const std::string& choice) {
		std::lock_guard<std::mutex> lock(chainMutex);

		auto pollIt = polls.find(pollId);
		if (pollIt == polls.end()) {
			std::cout << "[-] Poll not found\n";
			return false;
		}

		Poll& poll = pollIt->second;

		if (!poll.isActive()) {
			std::cout << "[-] Poll is not active\n";
			return false;
		}

		if (poll.hasVoted(voter)) {
			std::cout << "[-] Already voted in this poll\n";
			return false;
		}

		auto identity = contract->getIdentity(voter);
		if (!identity) {
			std::cout << "[-] Identity not registered\n";
			return false;
		}

		if (identity->reputation < poll.minReputation) {
			std::cout << "[-] Insufficient reputation\n";
			return false;
		}

		if (poll.minStake > 0 && !contract->hasMinimumStake(voter, poll.minStake)) {
			std::cout << "[-] Insufficient stake\n";
			return false;
		}

		poll.addVote(voter, choice);
		Transaction tx(voter, pollId, "poll_vote", 0, choice);
		pendingTransactions.push_back(tx);

		identity->updateReputation(5);

		std::cout << "[+] Vote recorded: " << voter << " -> " << choice << " (Poll: " << poll.title << ")\n";
		return true;
	}

	void minePendingTransactions(const std::string& miner = "system") {
		std::lock_guard<std::mutex> lock(chainMutex);
		if (pendingTransactions.empty()) {
			std::cout << "[!] No pending transactions\n";
			return;
		}
		Block newBlock((int)chain.size(), getLatestBlock().hash, pendingTransactions, difficulty, miner);
		newBlock.mineBlock(4);
		chain.push_back(newBlock);

		contract->registerIdentity(miner, miner);
		std::cout << "[+] Miner reward: " << newBlock.blockReward << " tokens\n";

		pendingTransactions.clear();
		adjustDifficulty();
		std::cout << "\n";
	}

	void adjustDifficulty() {
		if (chain.size() < 3) return;
		double avg = 0;
		for (size_t i = chain.size() - 2; i < chain.size(); i++)
			avg += chain[i].miningTime;
		avg /= 2;

		if (avg < 3 && difficulty < 6) {
			difficulty++;
			std::cout << "[+] Difficulty -> " << difficulty << "\n";
		}
		else if (avg > 10 && difficulty > 1) {
			difficulty--;
			std::cout << "[-] Difficulty -> " << difficulty << "\n";
		}
	}

	bool isChainValid() const {
		for (size_t i = 1; i < chain.size(); i++) {
			if (chain[i].hash != chain[i].calculateHash()) return false;
			if (chain[i].prevHash != chain[i - 1].hash) return false;
			if (chain[i].merkleRoot != chain[i].calculateMerkleRoot()) return false;
			for (const auto& tx : chain[i].transactions)
				if (!tx.verify()) return false;
		}
		return true;
	}

	std::string getPollsJson() const {
		std::stringstream ss;
		ss << "{\"polls\":[";
		size_t i = 0;
		for (const auto& pollEntry : polls) {
			ss << pollEntry.second.toJson();
			if (++i < polls.size()) ss << ",";
		}
		ss << "],\"totalPolls\":" << polls.size() << "}";
		return ss.str();
	}

	std::string getChainJson() const {
		std::stringstream ss;
		ss << "{\"chain\":[";
		for (size_t i = 0; i < chain.size(); i++) {
			ss << chain[i].toJson();
			if (i < chain.size() - 1) ss << ",";
		}
		ss << "],\"difficulty\":" << difficulty
			<< ",\"totalBlocks\":" << chain.size()
			<< ",\"valid\":" << (isChainValid() ? "true" : "false") << "}";
		return ss.str();
	}
};

int main() {
	std::cout << R"(
+===================================================+
|  ADVANCED BLOCKCHAIN GOVERNANCE PLATFORM         |
|  With DID, Staking & Poll Management             |
+===================================================+
)" << "\n";

	std::string ownerAddr = "owner_" + generateKey().substr(0, 16);
	std::vector<std::string> candidates = { "Alice", "Bob", "Charlie" };
	Blockchain voteChain(candidates, ownerAddr, 3);

	voteChain.contract->registerIdentity("Owner", ownerAddr);
	voteChain.contract->registerIdentity("Voter1", "voter_001");
	voteChain.contract->registerIdentity("Voter2", "voter_002");

	httplib::Server svr;

	svr.set_default_headers({
		{ "Access-Control-Allow-Origin", "*" },
		{ "Access-Control-Allow-Methods", "GET, POST, OPTIONS" },
		{ "Access-Control-Allow-Headers", "Content-Type" }
		});

	svr.Post("/identity/register", [&](const httplib::Request& req, httplib::Response& res) {
		std::string name = req.get_param_value("name");
		std::string address = req.get_param_value("address");
		if (name.empty() || address.empty()) {
			res.set_content("{\"status\":\"error\",\"message\":\"Missing name or address\"}", "application/json");
			return;
		}
		if (voteChain.contract->registerIdentity(name, address)) {
			auto identity = voteChain.contract->getIdentity(address);
			res.set_content("{\"status\":\"success\",\"identity\":" + identity->toJson() + "}", "application/json");
		}
		else {
			res.set_content("{\"status\":\"error\",\"message\":\"Registration failed\"}", "application/json");
		}
	});

	svr.Get(R"(/identity/(.+))", [&](const httplib::Request& req, httplib::Response& res) {
		std::string address = req.matches[1];
		auto identity = voteChain.contract->getIdentity(address);
		if (identity) {
			res.set_content("{\"status\":\"success\",\"identity\":" + identity->toJson() + "}", "application/json");
		}
		else {
			res.set_content("{\"status\":\"error\",\"message\":\"Identity not found\"}", "application/json");
		}
	});

	svr.Post("/stake", [&](const httplib::Request& req, httplib::Response& res) {
		std::string staker = req.get_param_value("address");
		std::string amountStr = req.get_param_value("amount");
		std::string lockTimeStr = req.get_param_value("lockTime");
		if (staker.empty() || amountStr.empty() || lockTimeStr.empty()) {
			res.set_content("{\"status\":\"error\",\"message\":\"Missing parameters\"}", "application/json");
			return;
		}
		double amount = std::stod(amountStr);
		long lockTime = std::stol(lockTimeStr);
		if (voteChain.contract->stake(staker, amount, lockTime)) {
			res.set_content("{\"status\":\"success\",\"message\":\"Staked successfully\"}", "application/json");
		}
		else {
			res.set_content("{\"status\":\"error\",\"message\":\"Staking failed\"}", "application/json");
		}
	});

	svr.Post("/unstake", [&](const httplib::Request& req, httplib::Response& res) {
		std::string staker = req.get_param_value("address");
		if (staker.empty()) {
			res.set_content("{\"status\":\"error\",\"message\":\"Missing address\"}", "application/json");
			return;
		}
		if (voteChain.contract->unstake(staker)) {
			res.set_content("{\"status\":\"success\",\"message\":\"Unstaked successfully\"}", "application/json");
		}
		else {
			res.set_content("{\"status\":\"error\",\"message\":\"Unstaking failed\"}", "application/json");
		}
	});

	svr.Get(R"(/stake/(.+))", [&](const httplib::Request& req, httplib::Response& res) {
		std::string address = req.matches[1];
		auto stake = voteChain.contract->getStake(address);
		if (stake) {
			res.set_content("{\"status\":\"success\",\"stake\":" + stake->toJson() + "}", "application/json");
		}
		else {
			res.set_content("{\"status\":\"error\",\"message\":\"No stake found\"}", "application/json");
		}
	});

	svr.Get(R"(/balance/(.+))", [&](const httplib::Request& req, httplib::Response& res) {
		std::string address = req.matches[1];
		double balance = voteChain.contract->getBalance(address);
		std::stringstream ss;
		ss << "{\"status\":\"success\",\"address\":\"" << escapeJson(address)
			<< "\",\"balance\":" << std::fixed << std::setprecision(2) << balance << "}";
		res.set_content(ss.str(), "application/json");
	});

	svr.Post("/poll/create", [&](const httplib::Request& req, httplib::Response& res) {
		std::string creator = req.get_param_value("creator");
		std::string title = req.get_param_value("title");
		std::string description = req.get_param_value("description");
		std::string optionsStr = req.get_param_value("options");
		std::string durationStr = req.get_param_value("duration");
		std::string minRepStr = req.get_param_value("minReputation");
		std::string minStakeStr = req.get_param_value("minStake");
		std::string pollType = req.get_param_value("pollType");
		if (creator.empty() || title.empty() || optionsStr.empty() || durationStr.empty()) {
			res.set_content("{\"status\":\"error\",\"message\":\"Missing required parameters\"}", "application/json");
			return;
		}
		std::vector<std::string> options;
		std::stringstream ss(optionsStr);
		std::string option;
		while (std::getline(ss, option, ',')) {
			options.push_back(option);
		}
		long duration = std::stol(durationStr);
		int minRep = minRepStr.empty() ? 0 : std::stoi(minRepStr);
		double minStake = minStakeStr.empty() ? 0 : std::stod(minStakeStr);
		if (pollType.empty()) pollType = "simple";
		if (voteChain.createPoll(creator, title, description, options, duration, minRep, minStake, pollType)) {
			res.set_content("{\"status\":\"success\",\"message\":\"Poll created successfully\"}", "application/json");
		}
		else {
			res.set_content("{\"status\":\"error\",\"message\":\"Poll creation failed\"}", "application/json");
		}
	});

	svr.Post("/poll/vote", [&](const httplib::Request& req, httplib::Response& res) {
		std::string pollId = req.get_param_value("pollId");
		std::string voter = req.get_param_value("voter");
		std::string choice = req.get_param_value("choice");
		if (pollId.empty() || voter.empty() || choice.empty()) {
			res.set_content("{\"status\":\"error\",\"message\":\"Missing parameters\"}", "application/json");
			return;
		}
		if (voteChain.voteInPoll(pollId, voter, choice)) {
			std::thread([&voteChain, voter]() {
				voteChain.minePendingTransactions(voter);
			}).detach();
			res.set_content("{\"status\":\"success\",\"message\":\"Vote recorded and mining started\"}", "application/json");
		}
		else {
			res.set_content("{\"status\":\"error\",\"message\":\"Vote rejected\"}", "application/json");
		}
	});

	svr.Get("/polls", [&](const httplib::Request&, httplib::Response& res) {
		res.set_content(voteChain.getPollsJson(), "application/json");
	});

	svr.Get(R"(/poll/(.+))", [&](const httplib::Request& req, httplib::Response& res) {
		std::string pollId = req.matches[1];
		auto it = voteChain.polls.find(pollId);
		if (it != voteChain.polls.end()) {
			res.set_content("{\"status\":\"success\",\"poll\":" + it->second.toJson() + "}", "application/json");
		}
		else {
			res.set_content("{\"status\":\"error\",\"message\":\"Poll not found\"}", "application/json");
		}
	});

	svr.Get("/chain", [&](const httplib::Request&, httplib::Response& res) {
		res.set_content(voteChain.getChainJson(), "application/json");
	});

	svr.Get("/candidates", [&](const httplib::Request&, httplib::Response& res) {
		auto candidates = voteChain.contract->getCandidates();
		std::stringstream ss;
		ss << "{\"candidates\":[";
		for (size_t i = 0; i < candidates.size(); i++) {
			ss << "\"" << escapeJson(candidates[i]) << "\"";
			if (i < candidates.size() - 1) ss << ",";
		}
		ss << "]}";
		res.set_content(ss.str(), "application/json");
	});

	svr.Get("/status", [&](const httplib::Request&, httplib::Response& res) {
		std::stringstream ss;
		ss << "{\"totalBlocks\":" << voteChain.chain.size()
			<< ",\"pendingTransactions\":" << voteChain.pendingTransactions.size()
			<< ",\"difficulty\":" << voteChain.difficulty
			<< ",\"chainValid\":" << (voteChain.isChainValid() ? "true" : "false")
			<< ",\"latestBlockHash\":\"" << voteChain.getLatestBlock().hash.substr(0, 16) << "...\""
			<< ",\"owner\":\"" << escapeJson(voteChain.ownerAddress) << "\""
			<< ",\"totalPolls\":" << voteChain.polls.size() << "}";
		res.set_content(ss.str(), "application/json");
	});

	svr.Get("/identities", [&](const httplib::Request&, httplib::Response& res) {
		auto identities = voteChain.contract->getAllIdentities();
		std::stringstream ss;
		ss << "{\"identities\":[";
		size_t i = 0;
		for (const auto& identity : identities) {
			ss << identity.second.toJson();
			if (++i < identities.size()) ss << ",";
		}
		ss << "],\"total\":" << identities.size() << "}";
		res.set_content(ss.str(), "application/json");
	});

	svr.Get("/stakes", [&](const httplib::Request&, httplib::Response& res) {
		auto stakes = voteChain.contract->getAllStakes();
		std::stringstream ss;
		ss << "{\"stakes\":[";
		size_t activeCount = 0;
		for (const auto& stakeEntry : stakes) {
			if (stakeEntry.second.active) {
				if (activeCount > 0) ss << ",";
				StakePosition temp = stakeEntry.second;
				temp.calculateRewards();
				ss << temp.toJson();
				activeCount++;
			}
		}
		ss << "],\"totalActive\":" << activeCount << "}";
		res.set_content(ss.str(), "application/json");
	});

	svr.Post("/mine", [&](const httplib::Request& req, httplib::Response& res) {
		std::string miner = req.get_param_value("miner");
		if (miner.empty()) miner = "system";
		std::thread([&voteChain, miner]() {
			voteChain.minePendingTransactions(miner);
		}).detach();
		res.set_content("{\"status\":\"success\",\"message\":\"Mining started\"}", "application/json");
	});

	svr.Get(R"(/block/(\d+))", [&](const httplib::Request& req, httplib::Response& res) {
		int index = std::stoi(req.matches[1].str());
		if (index >= 0 && index < (int)voteChain.chain.size()) {
			res.set_content("{\"status\":\"success\",\"block\":" + voteChain.chain[index].toJson() + "}", "application/json");
		}
		else {
			res.set_content("{\"status\":\"error\",\"message\":\"Block not found\"}", "application/json");
		}
	});

	svr.Get(R"(/merkle-proof/(\d+)/(\d+))", [&](const httplib::Request& req, httplib::Response& res) {
		int blockIndex = std::stoi(req.matches[1].str());
		int txIndex = std::stoi(req.matches[2].str());
		if (blockIndex < 0 || blockIndex >= (int)voteChain.chain.size()) {
			res.set_content("{\"status\":\"error\",\"message\":\"Block not found\"}", "application/json");
			return;
		}
		const Block& block = voteChain.chain[blockIndex];
		if (txIndex < 0 || txIndex >= (int)block.transactions.size()) {
			res.set_content("{\"status\":\"error\",\"message\":\"Transaction not found\"}", "application/json");
			return;
		}
		std::vector<std::string> txHashes;
		for (const auto& tx : block.transactions) {
			txHashes.push_back(tx.getHash());
		}
		auto proof = MerkleTree::generateProof(txHashes, txIndex);
		std::stringstream ss;
		ss << "{\"status\":\"success\",\"proof\":[";
		for (size_t i = 0; i < proof.size(); i++) {
			ss << "\"" << proof[i] << "\"";
			if (i < proof.size() - 1) ss << ",";
		}
		ss << "],\"merkleRoot\":\"" << block.merkleRoot << "\"}";
		res.set_content(ss.str(), "application/json");
	});

	svr.Get("/analytics", [&](const httplib::Request&, httplib::Response& res) {
		double totalStaked = 0;
		int activeStakes = 0;
		double totalRewards = 0;
		int totalVoters = 0;
		int verifiedIdentities = 0;
		auto stakes = voteChain.contract->getAllStakes();
		for (const auto& stakeEntry : stakes) {
			if (stakeEntry.second.active) {
				activeStakes++;
				totalStaked += stakeEntry.second.amount;
				StakePosition temp = stakeEntry.second;
				temp.calculateRewards();
				totalRewards += temp.rewards;
			}
		}
		auto identities = voteChain.contract->getAllIdentities();
		totalVoters = (int)identities.size();
		for (const auto& identity : identities) {
			if (identity.second.verified) verifiedIdentities++;
		}
		int totalTransactions = 0;
		for (const auto& block : voteChain.chain) {
			totalTransactions += (int)block.transactions.size();
		}
		double avgBlockTime = 0;
		if (voteChain.chain.size() > 1) {
			for (size_t i = 1; i < voteChain.chain.size(); i++) {
				avgBlockTime += voteChain.chain[i].miningTime;
			}
			avgBlockTime /= (voteChain.chain.size() - 1);
		}
		std::stringstream ss;
		ss << "{\"totalBlocks\":" << voteChain.chain.size()
			<< ",\"totalTransactions\":" << totalTransactions
			<< ",\"totalStaked\":" << std::fixed << std::setprecision(2) << totalStaked
			<< ",\"activeStakes\":" << activeStakes
			<< ",\"totalRewards\":" << totalRewards
			<< ",\"totalVoters\":" << totalVoters
			<< ",\"verifiedIdentities\":" << verifiedIdentities
			<< ",\"totalPolls\":" << voteChain.polls.size()
			<< ",\"difficulty\":" << voteChain.difficulty
			<< ",\"avgBlockTime\":" << avgBlockTime
			<< ",\"chainValid\":" << (voteChain.isChainValid() ? "true" : "false") << "}";
		res.set_content(ss.str(), "application/json");
	});

	std::cout << R"(
[*] Server is LIVE on http://localhost:8080
[*] Owner Address: )" << ownerAddr << R"(

API ENDPOINTS:
==============
IDENTITY (Decentralized ID):
  POST /identity/register -> Register DID
  GET  /identity/:address -> Get identity
  GET  /identities        -> List all identities

STAKING:
  POST /stake            -> Stake tokens
  POST /unstake          -> Unstake tokens
  GET  /stake/:address   -> Get stake info
  GET  /stakes           -> List stakes
  GET  /balance/:address -> Get balance

POLLS (Owner-controlled):
  POST /poll/create -> Create poll
  POST /poll/vote   -> Vote in poll
  GET  /polls       -> List polls
  GET  /poll/:id    -> Poll details

BLOCKCHAIN:
  GET  /chain        -> Full blockchain
  GET  /block/:index -> Get block
  GET  /candidates   -> Valid candidates
  GET  /status       -> Status
  POST /mine         -> Trigger mining
  GET  /merkle-proof/:blockIndex/:txIndex -> Merkle proof

ANALYTICS:
  GET /analytics -> Statistics

EXAMPLES:
curl -X POST "http://localhost:8080/identity/register?name=Alice&address=alice_addr"
curl -X POST "http://localhost:8080/stake?address=alice_addr&amount=100&lockTime=86400"
curl -X POST "http://localhost:8080/poll/create?creator=)" << ownerAddr << R"(&title=TestPoll&description=Test&options=Yes,No&duration=3600"
)" << "\n";

	svr.listen("0.0.0.0", 8080);
	return 0;
}