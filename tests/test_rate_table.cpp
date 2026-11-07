#include "rate_table.h"
#include "pcapHandler.h"

#include <cassert>
#include <cstdint>
#include <iostream>

// These tests use synthetic PacketInfo objects. They do not require a PCAP file.
// Timestamps are supplied in microseconds, just as RateTable::processPacket()
// expects them.

namespace {
constexpr std::uint64_t SECOND = 1'000'000ULL;

PacketInfo makePacket(
    std::uint32_t sourceIP,
    std::uint8_t protocol,
    std::uint32_t packetSize,
    bool syn = false,
    bool ack = false
) {
    PacketInfo packet{};

    packet.srcIP = sourceIP;
    packet.dstIP = 0x0A000001; // 10.0.0.1
    packet.srcPort = 12345;
    packet.dstPort = 80;
    packet.protocol = protocol;
    packet.packetSize = packetSize;
    packet.syn = syn;
    packet.ack = ack;

    return packet;
}

void testPacketAndByteCounting() {
    RateThresholds limits{};
    limits.maxPacketsPerWindow = 100;
    limits.maxSynPerWindow = 100;
    limits.maxUdpPerWindow = 100;
    limits.maxIcmpPerWindow = 100;

    RateTable table(128, limits);

    PacketInfo first = makePacket(0xC0A8010A, 6, 100, true, false);
    PacketInfo second = makePacket(0xC0A8010A, 6, 200, false, true);

    RateResult result = table.processPacket(first, 1 * SECOND);
    result = table.processPacket(second, 2 * SECOND);

    assert(table.getSize() == 1);
    assert(result.rates.packetCount == 2);
    assert(result.rates.totalBytes == 300);
    assert(result.rates.tcpSynCount == 1);

    std::cout << "[PASS] Packet and byte counting\n";
}

void testProtocolCounters() {
    RateThresholds limits{};
    limits.maxPacketsPerWindow = 100;
    limits.maxSynPerWindow = 100;
    limits.maxUdpPerWindow = 100;
    limits.maxIcmpPerWindow = 100;

    RateTable table(128, limits);
    const std::uint32_t sourceIP = 0xC0A80114;

    table.processPacket(makePacket(sourceIP, 6, 60, true, false), 1 * SECOND);
    table.processPacket(makePacket(sourceIP, 17, 70), 2 * SECOND);
    RateResult result =
        table.processPacket(makePacket(sourceIP, 1, 80), 3 * SECOND);

    assert(result.rates.packetCount == 3);
    assert(result.rates.tcpSynCount == 1);
    assert(result.rates.udpCount == 1);
    assert(result.rates.icmpCount == 1);
    assert(result.rates.totalBytes == 210);

    std::cout << "[PASS] TCP SYN, UDP and ICMP counters\n";
}

void testSourcesAreTrackedSeparately() {
    RateThresholds limits{};
    limits.maxPacketsPerWindow = 100;
    limits.maxSynPerWindow = 100;
    limits.maxUdpPerWindow = 100;
    limits.maxIcmpPerWindow = 100;

    RateTable table(128, limits);

    const std::uint32_t sourceA = 0xC0A8010A;
    const std::uint32_t sourceB = 0xC0A8010B;

    table.processPacket(makePacket(sourceA, 17, 100), 1 * SECOND);
    RateResult result =
        table.processPacket(makePacket(sourceB, 17, 200), 1 * SECOND);

    const RateInfo* infoA = table.find(sourceA);
    const RateInfo* infoB = table.find(sourceB);

    assert(infoA != nullptr);
    assert(infoB != nullptr);
    assert(table.getSize() == 2);
    assert(result.rates.packetCount == 1);
    assert(result.rates.totalBytes == 200);

    std::cout << "[PASS] Separate source-IP entries\n";
}

void testThresholdAlertsAndSuppression() {
    RateThresholds limits{};
    limits.maxPacketsPerWindow = 2;
    limits.maxSynPerWindow = 1;
    limits.maxUdpPerWindow = 100;
    limits.maxIcmpPerWindow = 100;

    RateTable table(128, limits);
    const std::uint32_t sourceIP = 0xC0A8011E;

    RateResult first =
        table.processPacket(makePacket(sourceIP, 6, 60, true, false), 1 * SECOND);
    assert(!first.highPacketRate);
    assert(!first.possibleSynFlood);

    RateResult second =
        table.processPacket(makePacket(sourceIP, 6, 60, true, false), 2 * SECOND);
    assert(!second.highPacketRate);
    assert(first.possibleSynFlood == false);
    assert(second.possibleSynFlood);

    RateResult third =
        table.processPacket(makePacket(sourceIP, 6, 60, true, false), 3 * SECOND);
    assert(third.highPacketRate);
    assert(!third.possibleSynFlood); // SYN alert is already active; no duplicate.

    RateResult fourth =
        table.processPacket(makePacket(sourceIP, 6, 60, true, false), 4 * SECOND);
    assert(!fourth.highPacketRate);
    assert(!fourth.possibleSynFlood);

    std::cout << "[PASS] Threshold triggering and repeated-alert suppression\n";
}

void testSlidingWindowDropsOldBuckets() {
    RateThresholds limits{};
    limits.maxPacketsPerWindow = 100;
    limits.maxSynPerWindow = 100;
    limits.maxUdpPerWindow = 100;
    limits.maxIcmpPerWindow = 100;

    RateTable table(128, limits);
    const std::uint32_t sourceIP = 0xC0A80128;

    table.processPacket(makePacket(sourceIP, 17, 100), 1 * SECOND);
    table.processPacket(makePacket(sourceIP, 17, 100), 2 * SECOND);

    // At second 12, seconds 1 and 2 are outside the 10-second window.
    RateResult result =
        table.processPacket(makePacket(sourceIP, 17, 50), 12 * SECOND);

    assert(result.rates.packetCount == 1);
    assert(result.rates.totalBytes == 50);
    assert(result.rates.udpCount == 1);

    std::cout << "[PASS] Sliding-window expiration\n";
}

void testRingBucketReuse() {
    RateThresholds limits{};
    limits.maxPacketsPerWindow = 100;
    limits.maxSynPerWindow = 100;
    limits.maxUdpPerWindow = 100;
    limits.maxIcmpPerWindow = 100;

    RateTable table(128, limits);
    const std::uint32_t sourceIP = 0xC0A80132;

    table.processPacket(makePacket(sourceIP, 17, 100), 1 * SECOND);
    // Second 11 maps to the same ring-bucket index as second 1.
    RateResult result =
        table.processPacket(makePacket(sourceIP, 17, 40), 11 * SECOND);

    assert(result.rates.packetCount == 1);
    assert(result.rates.totalBytes == 40);

    std::cout << "[PASS] Ring-bucket reuse and reset\n";
}

void testResizeAndExpiration() {
    RateThresholds limits{};
    limits.maxPacketsPerWindow = 100;
    limits.maxSynPerWindow = 100;
    limits.maxUdpPerWindow = 100;
    limits.maxIcmpPerWindow = 100;

    RateTable table(2, limits);

    table.processPacket(makePacket(0xC0A80101, 17, 60), 1 * SECOND);
    table.processPacket(makePacket(0xC0A80102, 17, 60), 1 * SECOND);
    table.processPacket(makePacket(0xC0A80103, 17, 60), 1 * SECOND);

    assert(table.getSize() == 3);
    assert(table.getCapacity() == 4);
    assert(table.find(0xC0A80101) != nullptr);
    assert(table.find(0xC0A80102) != nullptr);
    assert(table.find(0xC0A80103) != nullptr);

    const std::size_t removed = table.removeExpired(12 * SECOND, 5 * SECOND);

    assert(removed == 3);
    assert(table.getSize() == 0);
    assert(table.find(0xC0A80101) == nullptr);

    std::cout << "[PASS] Resizing and inactive-entry removal\n";
}

void testClear() {
    RateTable table;

    table.processPacket(
        makePacket(0xC0A80140, 17, 100),
        1 * SECOND
    );
    table.processPacket(
        makePacket(0xC0A80141, 17, 100),
        1 * SECOND
    );

    table.clear();

    assert(table.getSize() == 0);
    assert(table.find(0xC0A80140) == nullptr);
    assert(table.find(0xC0A80141) == nullptr);

    std::cout << "[PASS] Clear operation\n";
}
} // namespace

int main() {
    testPacketAndByteCounting();
    testProtocolCounters();
    testSourcesAreTrackedSeparately();
    testThresholdAlertsAndSuppression();
    testSlidingWindowDropsOldBuckets();
    testRingBucketReuse();
    testResizeAndExpiration();
    testClear();

    std::cout << "\nAll RateTable tests passed.\n";
    return 0;
}
