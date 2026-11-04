#include "pcapHandler.h"
#include "data_hash_table.h"
#include <cassert>
#include <cstdint>
#include <iostream>

static PacketInfo pkt(uint32_t sIP, uint16_t sPort, uint32_t dIP, uint16_t dPort,
                      uint8_t proto, uint32_t bytes = 100,
                      bool syn = false, bool ack = false,
                      bool fin = false, bool rst = false) {
    PacketInfo p{};
    p.srcIP = sIP; p.srcPort = sPort;
    p.dstIP = dIP; p.dstPort = dPort;
    p.protocol = proto; p.packetSize = bytes;
    p.syn = syn; p.ack = ack; p.fin = fin; p.rst = rst;
    return p;
}

int main() {
    constexpr uint32_t client = 0x0A000001;
    constexpr uint32_t server = 0x0A000002;

    // Canonicalization: reverse packets must produce the same key but opposite directions.
    HashTable table(128);
    auto forward = table.makeCanonicalKey(pkt(client, 50000, server, 443, 6, 60, true, false));
    auto reverse = table.makeCanonicalKey(pkt(server, 443, client, 50000, 6, 60, true, true));
    assert(forward.key.sideA_IP == reverse.key.sideA_IP);
    assert(forward.key.sideB_IP == reverse.key.sideB_IP);
    assert(forward.key.sideA_Port == reverse.key.sideA_Port);
    assert(forward.key.sideB_Port == reverse.key.sideB_Port);
    assert(forward.direction != reverse.direction);

    // Interleaved connections remain separate; TCP three-way handshake is tracked.
    assert(table.processPacket(pkt(client, 50000, server, 443, 6, 60, true, false), 1000));
    assert(table.processPacket(pkt(client, 51000, server, 443, 6, 70, true, false), 1100));
    assert(table.processPacket(pkt(server, 443, client, 50000, 6, 60, true, true), 1200));
    assert(table.processPacket(pkt(client, 50000, server, 443, 6, 52, false, true), 1300));

    auto firstKey = table.makeCanonicalKey(pkt(client, 50000, server, 443, 6)).key;
    auto secondKey = table.makeCanonicalKey(pkt(client, 51000, server, 443, 6)).key;
    auto* first = table.find(firstKey);
    auto* second = table.find(secondKey);
    assert(first && second && first != second);
    assert(first->state == TCPStates::ESTABLISHED);
    assert(first->packetCount == 3);
    assert(first->packetAtoB == 2);
    assert(first->packetBtoA == 1);
    assert(first->synAtoB == 1 && first->synBtoA == 1);
    assert(first->ackBtoA == 1);
    assert(first->firstSeen == 1000 && first->lastSeen == 1300);
    assert(second->state == TCPStates::SYN_SENT);

    // Both FIN directions close the simplified TCP flow.
    table.processPacket(pkt(client, 50000, server, 443, 6, 50, false, true, true), 1400);
    table.processPacket(pkt(server, 443, client, 50000, 6, 50, false, true, true), 1500);
    assert(first->state == TCPStates::CLOSED);
    assert(first->totalFinishedConversations == 1);

    // A fresh SYN on the same 5-tuple resets per-conversation counters, retaining finished count.
    table.processPacket(pkt(client, 50000, server, 443, 6, 60, true, false), 2000);
    assert(first->state == TCPStates::SYN_SENT);
    assert(first->packetCount == 1);
    assert(first->packetAtoB == 1 && first->packetBtoA == 0);
    assert(first->totalFinishedConversations == 1);
    assert(first->firstSeen == 2000 && first->lastSeen == 2000);

    // UDP tracks bidirectional flow stats but does not enter TCP states or count TCP flags.
    table.processPacket(pkt(client, 53000, server, 53, 17, 80), 3000);
    table.processPacket(pkt(server, 53, client, 53000, 17, 120), 3100);
    auto udpKey = table.makeCanonicalKey(pkt(client, 53000, server, 53, 17)).key;
    auto* udp = table.find(udpKey);
    assert(udp && udp->packetCount == 2 && udp->byteCount == 200);
    assert(udp->packetAtoB == 1 && udp->packetBtoA == 1);
    assert(udp->state == TCPStates::NONE);
    assert(udp->synAtoB == 0 && udp->ackBtoA == 0);

    // Unsupported protocols are ignored.
    assert(!table.processPacket(pkt(client, 1, server, 2, 1)));

    // Two different keys that hash to the same bucket exercise separate chaining.
    HashTable collisions(128);
    auto collisionPacket1 = pkt(0x0A000001, 1001, 0x0B000001, 443, 17, 64);
    auto collisionPacket2 = pkt(0x0A000009, 1009, 0x0B000001, 443, 17, 64);
    auto collisionKey1 = collisions.makeCanonicalKey(collisionPacket1).key;
    auto collisionKey2 = collisions.makeCanonicalKey(collisionPacket2).key;
    collisions.processPacket(collisionPacket1);
    collisions.processPacket(collisionPacket2);
    assert(collisions.getSize() == 2);
    assert(collisions.find(collisionKey1) != nullptr);
    assert(collisions.find(collisionKey2) != nullptr);
    collisions.remove(collisionKey1);
    assert(collisions.find(collisionKey1) == nullptr);
    assert(collisions.find(collisionKey2) != nullptr);

    // Force growth and verify all entries remain findable.
    HashTable many(8);
    for (uint32_t i = 1; i <= 200; ++i) {
        auto p = pkt(0x0A000000 + i, static_cast<uint16_t>(1000 + i),
                     0x0B000001, 443, 17, 64);
        assert(many.processPacket(p));
    }
    assert(many.getSize() == 200);
    assert(many.getCapacity() >= 256);
    for (uint32_t i = 1; i <= 200; ++i) {
        auto key = many.makeCanonicalKey(pkt(0x0A000000 + i,
                                 static_cast<uint16_t>(1000 + i),
                                 0x0B000001, 443, 17)).key;
        auto* entry = many.find(key);
        assert(entry && entry->packetCount == 1);
    }

    // Copy constructor and copy assignment must be deep copies.
    HashTable copied(many);
    assert(copied.getSize() == many.getSize());
    auto copyKey = copied.makeCanonicalKey(pkt(0x0A000001, 1001, 0x0B000001, 443, 17)).key;
    copied.find(copyKey)->byteCount = 9999;
    assert(many.find(copyKey)->byteCount == 64);

    HashTable assigned(2);
    assigned = many;
    assert(assigned.getSize() == many.getSize());
    assigned.find(copyKey)->byteCount = 777;
    assert(many.find(copyKey)->byteCount == 64);
    assigned = assigned; // self assignment
    assert(assigned.getSize() == many.getSize());

    // Remove and clear.
    assigned.remove(copyKey);
    assert(assigned.find(copyKey) == nullptr);
    assigned.clear();
    assert(assigned.getSize() == 0);

    std::cout << "All HashTable tests passed.\n";
}
