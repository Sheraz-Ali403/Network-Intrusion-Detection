#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

//One bucket represents one second 
//ten buckets form the rate window.
inline constexpr std::size_t RATE_WINDOW_SECONDS = 10;

struct PacketInfo;  //from pcapHandler.h

struct RateBucket {
    std::uint64_t second = 0;

    std::uint64_t packetCount = 0;
    std::uint64_t totalBytes = 0;

    std::uint64_t tcpSynCount = 0;
    std::uint64_t udpCount = 0;
    //not implemented yet, but can be added in the future
    std::uint64_t icmpCount = 0;

    bool initialized = false;
};

struct RateInfo {
    std::array<RateBucket, RATE_WINDOW_SECONDS> buckets{}; //size 10

    //latestSecond is the newest packet timestamp seen for this source
    std::uint64_t latestSecond = 0;
    std::uint64_t lastSeenUs = 0;
    //time tracking 
    bool hasTimestamp = false;

    //flags or exceeding thresholds
    //Checks and remembers already flagged so no again same alert
    bool packetAlertActive = false;
    bool synAlertActive = false;
    bool udpAlertActive = false;
    //not implemented yet
    bool icmpAlertActive = false;
};

struct RateNode {
    std::uint32_t sourceIP = 0;
    RateInfo info;  
    RateNode* next = nullptr;
};

struct RateThresholds {
    //Thresholds
    //These are starter values for testing, not universal
    std::uint64_t maxPacketsPerWindow = 500;
    std::uint64_t maxSynPerWindow = 100;
    std::uint64_t maxUdpPerWindow = 300;
    std::uint64_t maxIcmpPerWindow = 100;
};


//snapshots of current rate
struct RateSnapshot {
    std::uint64_t windowStartSecond = 0;
    std::uint64_t windowEndSecond = 0;

    std::uint64_t packetCount = 0;
    std::uint64_t totalBytes = 0;

    std::uint64_t tcpSynCount = 0;
    std::uint64_t udpCount = 0;
    //
    std::uint64_t icmpCount = 0;
};

struct RateResult {
    std::uint32_t sourceIP = 0;
    RateSnapshot rates;

    //gets true only when a new alert is triggered by this packet
    bool highPacketRate = false;
    bool possibleSynFlood = false;
    bool possibleUdpFlood = false;
    bool possibleIcmpFlood = false;
};

class RateTable {
private:
    RateNode** bucket;
    std::size_t capacity;
    std::size_t size;

    RateThresholds thresholds;

    static constexpr double LOAD_FACTOR = 0.75;

    std::size_t hashIP(std::uint32_t sourceIP, std::size_t tableCapacity) const;

    RateNode* findNode(std::uint32_t sourceIP);
    const RateNode* findNode(std::uint32_t sourceIP) const;
    RateNode* createNode(std::uint32_t sourceIP);

    void resizeTable();

    void updateBucket(
        RateInfo& info,
        const PacketInfo& packet,
        std::uint64_t timestampUs
    );

    RateSnapshot calculateRates(const RateInfo& info) const;

    void evaluateThreshold(
        std::uint64_t count,
        std::uint64_t threshold,
        bool& alertActive,
        bool& newAlert
    ) const;

public:
    explicit RateTable(
        std::size_t initialCapacity = 128,
        const RateThresholds& limits = RateThresholds{}
    );

    ~RateTable();

    // RateTable owns raw linked-list nodes, so copying is intentionally disabled.
    RateTable(const RateTable&) = delete;
    RateTable& operator=(const RateTable&) = delete;

    RateResult processPacket(const PacketInfo& packet, std::uint64_t timestampUs);

    RateInfo* find(std::uint32_t sourceIP);
    const RateInfo* find(std::uint32_t sourceIP) const;

    // Removes entries that have been inactive for longer than idleTimeoutUs.
    // Returns the number of entries removed.
    std::size_t removeExpired(
        std::uint64_t currentTimeUs,
        std::uint64_t idleTimeoutUs
    );

    void clear();

    std::size_t getSize() const;
    std::size_t getCapacity() const;
};
