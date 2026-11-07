#include "rate_table.h"

#include "pcapHandler.h"

#include <limits>






namespace {
constexpr std::uint64_t MICROSECONDS_PER_SECOND = 1'000'000ULL;
constexpr std::uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
constexpr std::uint64_t FNV_PRIME = 1099511628211ULL;

void resetBucket(RateBucket& bucket, std::uint64_t second) {
    bucket = RateBucket{};
    bucket.second = second;
    bucket.initialized = true;
}
} // namespace

RateTable::RateTable(std::size_t initialCapacity, const RateThresholds& limits)
    : bucket(nullptr),
      capacity(initialCapacity == 0 ? 128 : initialCapacity),
      size(0),
      thresholds(limits) {
    bucket = new RateNode*[capacity]{};
}

RateTable::~RateTable() {
    clear();
    delete[] bucket;
}

//hash function FNV-1a algorithem
std::size_t RateTable::hashIP(
    std::uint32_t sourceIP,
    std::size_t tableCapacity
) const {
    // Hash the four IPv4 address bytes in a consistent order.
    std::uint64_t hash = FNV_OFFSET_BASIS;

    //hash making
    for (int shift = 24; shift >= 0; shift -= 8) {
        const auto byte = static_cast<std::uint8_t>((sourceIP >> shift) & 0xFFU);
        hash ^= byte;
        hash *= FNV_PRIME;
    }

    return static_cast<std::size_t>(hash % tableCapacity);
}

RateNode* RateTable::findNode(std::uint32_t sourceIP) {
    const std::size_t index = hashIP(sourceIP, capacity);
    RateNode* current = bucket[index];

    while (current != nullptr) {
        if (current->sourceIP == sourceIP) {
            return current;
        }
        current = current->next;
    }

    return nullptr;
}

const RateNode* RateTable::findNode(std::uint32_t sourceIP) const {
    const std::size_t index = hashIP(sourceIP, capacity);
    const RateNode* current = bucket[index];

    while (current != nullptr) {
        if (current->sourceIP == sourceIP) {
            return current;
        }
        current = current->next;
    }

    return nullptr;
}

RateNode* RateTable::createNode(std::uint32_t sourceIP) {
    const std::size_t index = hashIP(sourceIP, capacity);
    RateNode* newNode = new RateNode{};

    newNode->sourceIP = sourceIP;
    newNode->next = bucket[index];
    bucket[index] = newNode;
    ++size;

    if (static_cast<double>(size) / static_cast<double>(capacity) > LOAD_FACTOR) {
        resizeTable();
    }

    return newNode;
}

void RateTable::resizeTable() {
    if (capacity > std::numeric_limits<std::size_t>::max() / 2) {
        return;
    }

    const std::size_t newCapacity = capacity * 2;
    RateNode** newBucket = new RateNode*[newCapacity]{};

    for (std::size_t i = 0; i < capacity; ++i) {
        RateNode* current = bucket[i];

        while (current != nullptr) {
            RateNode* nextNode = current->next;
            const std::size_t newIndex = hashIP(current->sourceIP, newCapacity);

            current->next = newBucket[newIndex];
            newBucket[newIndex] = current;
            current = nextNode;
        }
    }

    delete[] bucket;
    bucket = newBucket;
    capacity = newCapacity;
}

//Linked to the PacketInfo
void RateTable::updateBucket(
    RateInfo& info,
    const PacketInfo& packet,
    //timespec timestampUs = rawPacket.getPacketTimeStamp(); from pcapHandler.h (pcapPlusPlus)
    std::uint64_t timestampUs
) {
    //convert timestamp to seconds for the rate window
    const std::uint64_t currentSecond = timestampUs / MICROSECONDS_PER_SECOND;

    if (!info.hasTimestamp || currentSecond > info.latestSecond) {
        info.latestSecond = currentSecond;
    }
    info.hasTimestamp = true;

    // Ignore packets that are older than the active window. This also protects
    // the ring buffer if a PCAP contains out-of-order packet timestamps.
    if (info.latestSecond >= currentSecond &&
        info.latestSecond - currentSecond >= RATE_WINDOW_SECONDS) {
        return;
    }

    const std::size_t index = static_cast<std::size_t>(
        currentSecond % RATE_WINDOW_SECONDS
    );
    RateBucket& currentBucket = info.buckets[index];

    if (!currentBucket.initialized || currentBucket.second != currentSecond) {
        resetBucket(currentBucket, currentSecond);
    }

    ++currentBucket.packetCount;
    currentBucket.totalBytes += static_cast<std::uint64_t>(packet.packetSize);

    // TCP protocol number is 6. Count connection-opening SYNs, not SYN-ACKs.
    if (packet.protocol == 6 && packet.syn && !packet.ack) {
        ++currentBucket.tcpSynCount;
    }

    // IPv4 protocol numbers: UDP = 17, ICMP = 1.
    if (packet.protocol == 17) {
        ++currentBucket.udpCount;
    } else if (packet.protocol == 1) {
        ++currentBucket.icmpCount;
    }
}


//finds the rates for a given source IP and returns a RateSnapshot containing the calculated rates.
RateSnapshot RateTable::calculateRates(const RateInfo& info) const {
    RateSnapshot result{};

    if (!info.hasTimestamp) {
        return result;
    }

    result.windowEndSecond = info.latestSecond;
    result.windowStartSecond =
        info.latestSecond >= RATE_WINDOW_SECONDS - 1
            ? info.latestSecond - (RATE_WINDOW_SECONDS - 1)
            : 0;

    for (const RateBucket& currentBucket : info.buckets) {
        if (!currentBucket.initialized ||
            currentBucket.second > info.latestSecond) {
            continue;
        }

        const std::uint64_t age = info.latestSecond - currentBucket.second;
        if (age >= RATE_WINDOW_SECONDS) {
            continue;
        }

        result.packetCount += currentBucket.packetCount;
        result.totalBytes += currentBucket.totalBytes;
        result.tcpSynCount += currentBucket.tcpSynCount;
        result.udpCount += currentBucket.udpCount;
        result.icmpCount += currentBucket.icmpCount;
    }

    return result;
}

//alert logic if the threshold exceeds (generalized)
void RateTable::evaluateThreshold(
    std::uint64_t count,
    std::uint64_t threshold,
    bool& alertActive,
    bool& newAlert
) const {
    if (threshold == 0) {
        alertActive = false;
        return;
    }

    if (count > threshold) {
        if (!alertActive) {
            newAlert = true;
        }
        alertActive = true;
    } else {
        // Allow a new alert if the count later rises above the threshold again.
        alertActive = false;
    }
}

//main function that processes a packet and returns a RateResult containing the calculated rates and any triggered alerts.
RateResult RateTable::processPacket(
    const PacketInfo& packet,
    std::uint64_t timestampUs
) {
    RateNode* node = findNode(packet.srcIP);

    if (node == nullptr) {
        node = createNode(packet.srcIP);
    }

    updateBucket(node->info, packet, timestampUs);

    if (!node->info.hasTimestamp || timestampUs > node->info.lastSeenUs) {
        node->info.lastSeenUs = timestampUs;
    }

    RateResult result{};
    result.sourceIP = packet.srcIP;
    result.rates = calculateRates(node->info);

    evaluateThreshold(
        result.rates.packetCount,
        thresholds.maxPacketsPerWindow,
        node->info.packetAlertActive,
        result.highPacketRate
    );
    evaluateThreshold(
        result.rates.tcpSynCount,
        thresholds.maxSynPerWindow,
        node->info.synAlertActive,
        result.possibleSynFlood
    );
    evaluateThreshold(
        result.rates.udpCount,
        thresholds.maxUdpPerWindow,
        node->info.udpAlertActive,
        result.possibleUdpFlood
    );
    evaluateThreshold(
        result.rates.icmpCount,
        thresholds.maxIcmpPerWindow,
        node->info.icmpAlertActive,
        result.possibleIcmpFlood
    );

    return result;
}

RateInfo* RateTable::find(std::uint32_t sourceIP) {
    RateNode* node = findNode(sourceIP);
    return node == nullptr ? nullptr : &node->info;
}

const RateInfo* RateTable::find(std::uint32_t sourceIP) const {
    const RateNode* node = findNode(sourceIP);
    return node == nullptr ? nullptr : &node->info;
}

std::size_t RateTable::removeExpired(
    std::uint64_t currentTimeUs,
    std::uint64_t idleTimeoutUs
) {
    std::size_t removedCount = 0;

    for (std::size_t i = 0; i < capacity; ++i) {
        RateNode** currentLink = &bucket[i];

        while (*currentLink != nullptr) {
            RateNode* current = *currentLink;
            const bool timeIsForward = currentTimeUs >= current->info.lastSeenUs;
            const bool isExpired = current->info.hasTimestamp &&
                timeIsForward &&
                (currentTimeUs - current->info.lastSeenUs > idleTimeoutUs);

            if (isExpired) {
                *currentLink = current->next;
                delete current;
                --size;
                ++removedCount;
            } else {
                currentLink = &current->next;
            }
        }
    }

    return removedCount;
}

void RateTable::clear() {
    for (std::size_t i = 0; i < capacity; ++i) {
        RateNode* current = bucket[i];

        while (current != nullptr) {
            RateNode* nextNode = current->next;
            delete current;
            current = nextNode;
        }

        bucket[i] = nullptr;
    }

    size = 0;
}

std::size_t RateTable::getSize() const {
    return size;
}

std::size_t RateTable::getCapacity() const {
    return capacity;
}
