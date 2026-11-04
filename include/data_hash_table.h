#pragma once

#include <cstdint>
#include <cstddef>

// PacketInfo is defined in pcapHandler.h.
// A forward declaration keeps this header independent from PcapPlusPlus.
struct PacketInfo;

//Data packet key
//The key identifies one bidirectional flow. It never stores packet direction.
struct dataKey {
    uint32_t sideA_IP = 0;
    uint32_t sideB_IP = 0;

    uint16_t sideA_Port = 0;
    uint16_t sideB_Port = 0;

    uint8_t protocol = 0;
};

enum class Direction {
    A_to_B,
    B_to_A
};

//The canonical key identifies the flow; direction describes only the current packet.
struct CanonicalDirectionKey {
    dataKey key{};
    Direction direction = Direction::A_to_B; 
};

//In TCP, both directions of the same 5-tuple are tracked as one flow.
enum class TCPStates {
    NONE,
    SYN_SENT,
    ESTABLISHED,
    FIN_WAIT,
    CLOSED
};

struct ConnectionInfo {
    //Total traffic in this flow
    uint64_t packetCount = 0;
    uint64_t byteCount = 0;

    //Directional traffic statistics
    uint64_t packetAtoB = 0;
    uint64_t packetBtoA = 0;
    uint64_t byteAtoB = 0;
    uint64_t byteBtoA = 0;

    //Timestamps are in microseconds. They remain zero if no timestamp is supplied.
    uint64_t firstSeen = 0;
    uint64_t lastSeen = 0;

    //Number of TCP conversations completed for this 5-tuple.
    //This value is preserved when a closed connection is restarted.
    uint64_t totalFinishedConversations = 0;

    TCPStates state = TCPStates::NONE;

    //The direction that sent the first SYN (without ACK).
    Direction initiatorDirection = Direction::A_to_B;
    bool initiatorKnown = false;
    bool synAckReceived = false;

    //TCP Flags
    uint64_t synAtoB = 0;
    uint64_t synBtoA = 0;

    uint64_t ackAtoB = 0;
    uint64_t ackBtoA = 0;

    uint64_t finAtoB = 0;
    uint64_t finBtoA = 0;

    uint64_t rstAtoB = 0;
    uint64_t rstBtoA = 0;

    //Used by the simplified TCP close-state logic.
    bool finAtoBSeen = false;
    bool finBtoASeen = false;
};

struct Node {
    dataKey key;
    ConnectionInfo info;
    Node* next = nullptr;

    Node(const dataKey& k, const ConnectionInfo& i): key(k), info(i), next(nullptr) {}
};

class HashTable {
    Node** bucket = nullptr;

    size_t capacity = 0; //total capacity of hash table
    size_t size = 0;     //current number of stored flows
    static constexpr double LOAD_FACTOR = 0.75; // Max load factor for resizing

    bool keysEqual(const dataKey& a, const dataKey& b) const;

    uint64_t HashValue(const dataKey& key) const;
    uint64_t HashFunction(const dataKey& key) const;
    void reSizeHash();

    void updateTCPState(ConnectionInfo& info, const PacketInfo& packet, Direction direction);

public:
    HashTable(size_t cap = 128);
    ~HashTable();

    void clear();

    //Rule of Three: deep copy constructor and copy assignment operator.
    HashTable(const HashTable& other);
    HashTable& operator=(const HashTable& other);

    //Canonicalize packet endpoints and preserve this packet's direction separately.
    CanonicalDirectionKey makeCanonicalKey(const PacketInfo& packet) const;

    //Insert creates a new node. If the key already exists, the existing info is returned unchanged.
    ConnectionInfo* insertKey(const dataKey& key, const ConnectionInfo& info);

    //Delete
    void remove(const dataKey& key);

    //Find
    ConnectionInfo* find(const dataKey& key);
    const ConnectionInfo* find(const dataKey& key) const;

    //Process one parsed TCP/UDP packet and update its flow history.
    //timestampUs is optional and must be expressed in microseconds.
    //Returns false for protocols other than TCP (6) and UDP (17).
    bool processPacket(const PacketInfo& packet, uint64_t timestampUs = 0);

    size_t getSize() const;
    size_t getCapacity() const;
};
