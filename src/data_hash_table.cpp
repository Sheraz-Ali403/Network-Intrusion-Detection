#include "data_hash_table.h"
#include "pcapHandler.h"

#include <limits>
#include <stdexcept>
#include <utility>

//Fixed protocol numbers from the IPv4 Protocol field.
namespace {
    constexpr uint8_t TCP_PROTOCOL = 6;
    constexpr uint8_t UDP_PROTOCOL = 17;

    //Compare endpoints consistently: first IP, then port.
    bool endpointIsBefore(uint32_t firstIP, uint16_t firstPort,
                          uint32_t secondIP, uint16_t secondPort)
    {
        if (firstIP != secondIP) {
            return firstIP < secondIP;
        }

        return firstPort <= secondPort;
    }
}

HashTable::HashTable(size_t cap) : capacity(cap), size(0){
    if(capacity == 0) {
        throw std::invalid_argument("HashTable capacity must be greater than zero");
    }

    bucket = new Node*[capacity]{}; //curly braces for all init to null
}

//Destructor
HashTable::~HashTable(){
    clear();
    delete[] bucket;
    bucket = nullptr;
}

//Delete all nodes but keep the current bucket array and capacity.
void HashTable::clear() {
    for (size_t i = 0; i < capacity; ++i) {
        Node* current = bucket[i];

        //for cleaning up the list in each bucket in separate chaining
        while (current) {
            Node* toDelete = current;
            current = current->next;
            delete toDelete;
        }

        bucket[i] = nullptr;
    }

    size = 0;
}

//Deep copy constructor
HashTable::HashTable(const HashTable& other): capacity(other.capacity), size(0){
    bucket = new Node*[capacity]{};

    try {
        //Copy every node, including all nodes in collision chains.
        for (size_t i = 0; i < other.capacity; ++i) {
            Node* current = other.bucket[i];

            while (current) {
                uint64_t index = HashValue(current->key) % capacity;

                Node* newNode = new Node(current->key, current->info);
                newNode->next = bucket[index];
                bucket[index] = newNode;

                ++size;
                current = current->next;
            }
        }
    }
    catch (...) {
        clear();
        delete[] bucket;
        bucket = nullptr;
        capacity = 0;
        throw;
    }
}

//Copy assignment operator
HashTable& HashTable::operator=(const HashTable& other) {
    if (this != &other) {
        HashTable temp(other); //does deep copy utilizing copy constructor

        //swap gives O(1) ownership exchange; temp cleans up the old table.
        std::swap(capacity, temp.capacity);
        std::swap(size, temp.size);
        std::swap(bucket, temp.bucket);
    }

    return *this;
}

bool HashTable::keysEqual(const dataKey& a, const dataKey& b) const {
    return (a.sideA_IP == b.sideA_IP &&
            a.sideB_IP == b.sideB_IP &&
            a.sideA_Port == b.sideA_Port &&
            a.sideB_Port == b.sideB_Port &&
            a.protocol == b.protocol);
}

//FNV-1a hash value. Each field is processed byte-by-byte, not as one whole integer.
uint64_t HashTable::HashValue(const dataKey& key) const {
    constexpr uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
    constexpr uint64_t FNV_PRIME = 1099511628211ULL;

    uint64_t hash = FNV_OFFSET_BASIS;

    auto processByte = [&hash](uint8_t byte) {
        hash ^= byte;
        hash *= FNV_PRIME;
    };

    for (int i = 0; i < 4; ++i) {
        processByte(static_cast<uint8_t>((key.sideA_IP >> (i * 8)) & 0xFFU));
    }

    for (int i = 0; i < 4; ++i) {
        processByte(static_cast<uint8_t>((key.sideB_IP >> (i * 8)) & 0xFFU));
    }

    for (int i = 0; i < 2; ++i) {
        processByte(static_cast<uint8_t>((key.sideA_Port >> (i * 8)) & 0xFFU));
    }

    for (int i = 0; i < 2; ++i) {
        processByte(static_cast<uint8_t>((key.sideB_Port >> (i * 8)) & 0xFFU));
    }

    processByte(key.protocol);

    return hash;
}

//Return the bucket index for the current table capacity.
uint64_t HashTable::HashFunction(const dataKey& key) const {
    return HashValue(key) % capacity;
}

void HashTable::reSizeHash() {
    //Resize before inserting the next node if it would exceed the load factor.
    if (static_cast<double>(size + 1) / static_cast<double>(capacity) <= LOAD_FACTOR) {
        return;
    }

    if (capacity > std::numeric_limits<size_t>::max() / 2) {
        throw std::length_error("HashTable capacity cannot be doubled");
    }
    //std::numeric_limits<size_t>::max() checks for overflow when doubling the capacity. If the current capacity is greater than half of the maximum value for size_t, doubling it would exceed the maximum representable value, leading to undefined behavior or wraparound. Therefore, we throw a length_error exception to prevent this situation.

    const size_t newCapacity = capacity * 2;
    Node** newBucket = new Node*[newCapacity]{};

    //Move existing nodes into the new bucket array. Node objects are not copied.
    for (size_t i = 0; i < capacity; ++i) {
        Node* current = bucket[i];

        while (current) {
            Node* nextNode = current->next;
            uint64_t index = HashValue(current->key) % newCapacity;

            //Insert the existing node at the head of its new collision chain.
            current->next = newBucket[index];
            newBucket[index] = current;

            current = nextNode;
        }
    }

    delete[] bucket;
    bucket = newBucket;
    capacity = newCapacity;
}

CanonicalDirectionKey HashTable::makeCanonicalKey(const PacketInfo& packet) const {
    CanonicalDirectionKey result{};

    bool sourceIsA = endpointIsBefore(packet.srcIP, packet.srcPort, packet.dstIP, packet.dstPort);

    if (sourceIsA) {
        result.key.sideA_IP = packet.srcIP;
        result.key.sideB_IP = packet.dstIP;

        result.key.sideA_Port = packet.srcPort;
        result.key.sideB_Port = packet.dstPort;

        result.direction = Direction::A_to_B;
    }
    else {
        result.key.sideA_IP = packet.dstIP;
        result.key.sideB_IP = packet.srcIP;

        result.key.sideA_Port = packet.dstPort;
        result.key.sideB_Port = packet.srcPort;

        result.direction = Direction::B_to_A;
    }

    result.key.protocol = packet.protocol;

    return result;
}

//Insert
ConnectionInfo* HashTable::insertKey(const dataKey& key, const ConnectionInfo& info) {
    //Do not create a duplicate node for an existing key.
    uint64_t index = HashFunction(key);
    Node* current = bucket[index];

    while (current) {
        if (keysEqual(current->key, key)) {
            return &current->info;
        }

        current = current->next;
    }

    //Resize before insertion so an allocation failure does not leave a half completed insert.
    reSizeHash();

    index = HashFunction(key);

    Node* newNode = new Node(key, info);
    newNode->next = bucket[index];
    bucket[index] = newNode;

    ++size;

    return &newNode->info;
}

//Delete
void HashTable::remove(const dataKey& key) {
    uint64_t index = HashFunction(key);
    Node* current = bucket[index];
    Node* prev = nullptr;

    while (current) {
        if (keysEqual(current->key, key)) {
            if (prev) {
                prev->next = current->next;
            }
            else {
                bucket[index] = current->next;
            }

            delete current;
            --size;
            return;
        }

        prev = current;
        current = current->next;
    }
}

//Find
ConnectionInfo* HashTable::find(const dataKey& key) {
    uint64_t index = HashFunction(key);
    Node* current = bucket[index];

    while (current) {
        if (keysEqual(current->key, key)) {
            return &current->info;
        }

        current = current->next;
    }

    return nullptr;
}

const ConnectionInfo* HashTable::find(const dataKey& key) const {
    uint64_t index = HashFunction(key);
    Node* current = bucket[index];

    while (current) {
        if (keysEqual(current->key, key)) {
            return &current->info;
        }

        current = current->next;
    }

    return nullptr;
}

void HashTable::updateTCPState(ConnectionInfo& info, const PacketInfo& packet, Direction direction)
{
    //RST terminates the tracked TCP conversation immediately.
    if (packet.rst) {
        if (info.state != TCPStates::CLOSED) {
            info.state = TCPStates::CLOSED;
            ++info.totalFinishedConversations;
        }

        return;
    }

    //First SYN (without ACK) identifies the initiator.
    if (packet.syn && !packet.ack) {
        if (info.state == TCPStates::NONE) {
            info.initiatorDirection = direction;
            info.initiatorKnown = true;
            info.state = TCPStates::SYN_SENT;
        }

        //A repeated SYN in the same state is treated as a retransmission.
        return;
    }

    //The SYN+ACK must travel in the opposite direction to the initial SYN.
    if (packet.syn && packet.ack) {
        if (info.state == TCPStates::SYN_SENT &&
            info.initiatorKnown &&
            direction != info.initiatorDirection) {
            info.synAckReceived = true;
        }

        return;
    }

    //The final ACK must travel in the original initiator direction.
    if (info.state == TCPStates::SYN_SENT &&
        info.synAckReceived &&
        packet.ack &&
        !packet.syn &&
        direction == info.initiatorDirection) {
        info.state = TCPStates::ESTABLISHED;
    }

    //This is a simplified close model. It marks CLOSED after both sides send FIN.
    if (packet.fin &&
        (info.state == TCPStates::ESTABLISHED || info.state == TCPStates::FIN_WAIT)) {

        if (direction == Direction::A_to_B) {
            info.finAtoBSeen = true;
        }
        else {
            info.finBtoASeen = true;
        }

        info.state = TCPStates::FIN_WAIT;

        if (info.finAtoBSeen && info.finBtoASeen) {
            info.state = TCPStates::CLOSED;
            ++info.totalFinishedConversations;
        }
    }
}

//Process one parsed TCP/UDP packet and update its flow history.
bool HashTable::processPacket(const PacketInfo& packet, uint64_t timestampUs) {
    if (packet.protocol != TCP_PROTOCOL && packet.protocol != UDP_PROTOCOL) {
        return false;
    }

    CanonicalDirectionKey flow = makeCanonicalKey(packet);

    ConnectionInfo* info = find(flow.key);

    if (info == nullptr) {
        ConnectionInfo newInfo{};
        info = insertKey(flow.key, newInfo);
    }
    else if (packet.protocol == TCP_PROTOCOL &&
             info->state == TCPStates::CLOSED &&
             packet.syn && !packet.ack) {

        //The same 5-tuple can be reused after a TCP conversation has closed.
        //Reset per-conversation statistics but preserve the completed-conversation total.
        uint64_t finishedCount = info->totalFinishedConversations;
        *info = ConnectionInfo{};
        info->totalFinishedConversations = finishedCount;
    }

    //Update overall and directional traffic counters.
    ++info->packetCount;
    info->byteCount += packet.packetSize;

    if (flow.direction == Direction::A_to_B) {
        ++info->packetAtoB;
        info->byteAtoB += packet.packetSize;

        if(packet.protocol == TCP_PROTOCOL){
            if(packet.syn) ++info->synAtoB;
            if(packet.ack) ++info->ackAtoB;
            if(packet.fin) ++info->finAtoB;
            if(packet.rst) ++info->rstAtoB;
        }
    }
    else{
        ++info->packetBtoA;
        info->byteBtoA += packet.packetSize;

        if(packet.protocol == TCP_PROTOCOL) {
            if(packet.syn) ++info->synBtoA;
            if(packet.ack) ++info->ackBtoA;
            if(packet.fin) ++info->finBtoA;
            if(packet.rst) ++info->rstBtoA;
        }
    }

    if (timestampUs != 0) {
        if (info->firstSeen == 0) {
            info->firstSeen = timestampUs;
        }

        info->lastSeen = timestampUs;
    }

    //UDP has flow statistics but no TCP handshake/close state.
    if (packet.protocol == TCP_PROTOCOL) {
        updateTCPState(*info, packet, flow.direction);
    }

    return true;
}

size_t HashTable::getSize() const {
    return size;
}

size_t HashTable::getCapacity() const {
    return capacity;
}
