#include "pcapHandler.h"
#include "data_hash_table.h"
#include "rate_table.h"
#include "aho_corasick.h"
#include "cidr_blacklist.h"

#include <csignal>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
volatile std::sig_atomic_t stopRequested = 0;
void stopCapture(int) { stopRequested = 1; }

std::string detectionTime() {
    const std::time_t now = std::time(nullptr);
    const std::tm* utc = std::gmtime(&now);
    if (!utc) return "unavailable";
    std::ostringstream text;
    text << std::put_time(utc, "%Y-%m-%dT%H:%M:%SZ");
    return text.str();
}

//Each append is flushed and closed before another component writes.
void logAlert(const std::string& path, const std::string& entry) {
    std::cout << entry << '\n' << std::flush;
    std::ofstream log(path, std::ios::app);
    if (!log) throw std::runtime_error("Cannot open alert log");
    log << entry << '\n';
    log.flush();
    if (!log) throw std::runtime_error("Cannot write alert log");
}

std::string endpoint(uint32_t ip, uint16_t port) {
    return pcpp::IPv4Address(ip).toString() + ":" + std::to_string(port);
}

std::filesystem::path inputPath(const char* supplied, const char* fallback,
                                const char* executable) {
    if (supplied) return supplied;
    std::filesystem::path path = fallback;
    if (!std::filesystem::exists(path))
        path = std::filesystem::path(executable).parent_path() / ".." / fallback;
    return path;
}
}

int main(int argc, char* argv[]) {
    if (argc > 4 || (argc == 2 && std::string(argv[1]) == "--help")) {
        std::cout << "Usage: " << argv[0]
                  << " [capture.pcap] [ahoRules.txt] [cidrBlacklist.txt]\n"
                  << "Defaults: captures/sample.pcap, rules/ahoRules.txt, rules/cidrBlacklist.txt\n";
        return argc > 4 ? 1 : 0;
    }
    try {
        const auto path = inputPath(argc > 1 ? argv[1] : nullptr, "captures/sample.pcap", argv[0]);
        const auto rulesPath = inputPath(argc > 2 ? argv[2] : nullptr, "rules/ahoRules.txt", argv[0]);
        const auto cidrPath = inputPath(argc > 3 ? argv[3] : nullptr, "rules/cidrBlacklist.txt", argv[0]);
        if (!std::filesystem::is_regular_file(path)) {
            std::cerr << "Capture file not found: " << path << '\n';
            return 1;
        }
        PcapHandler handler;
        if (!handler.openPcapFile(path.string())) return 1;

        //Trie nodes point into patterns; keep this storage alive and unchanged.
        std::vector<patternInfo> patterns;
        AhoCorasick ac;
        if (!std::ifstream(rulesPath).good()) {
            std::cerr << "Cannot read signature rules: " << rulesPath << '\n';
            return 1;
        }
        ac.openRules(patterns, rulesPath.string()); //also builds failure/output links
        bool usable = false;
        for (const auto& pattern : patterns)
            if (!pattern.pattern.empty()) usable = true;
        if (!usable) {
            std::cerr << "No nonempty signatures loaded from " << rulesPath << '\n';
            return 1;
        }
        CidrBlacklist blacklist;
        if (blacklist.openBlacklist(cidrPath.string()) == 0)
            std::cerr << "Warning: no CIDR entries loaded from " << cidrPath << '\n';

        HashTable flows;
        RateTable rates;
        std::filesystem::create_directories("output");
        const std::string logPath = "output/alerts.log";
        {
            std::ofstream log(logPath, std::ios::app);
            if (!log) throw std::runtime_error("Cannot open output/alerts.log");
        }
        if (std::signal(SIGINT, stopCapture) == SIG_ERR)
            throw std::runtime_error("Cannot install Ctrl+C handler");

        uint64_t watermark = 0, lastCleanup = 0;
        bool clockStarted = false;
        uint64_t readCount = 0, accepted = 0, skipped = 0, backwards = 0;
        uint64_t bytes = 0, tcp = 0, udp = 0, syn = 0, ack = 0;
        uint64_t expiredFlows = 0, expiredSources = 0;
        uint64_t rateAlerts = 0, payloadAlerts = 0, blacklistAlerts = 0;
        size_t nextFlowAlert = 0;
        PacketInfo packet;
        std::cout << "Reading: " << std::filesystem::absolute(path).lexically_normal()
                  << "\nTCP/UDP only. Press Ctrl+C to stop.\n";

        auto lastStatus = std::chrono::steady_clock::now();
        uint64_t lastStatusPackets = 0;
        auto status = [&](const char* state, bool force = false) {
            const auto now = std::chrono::steady_clock::now();
            const double seconds = std::chrono::duration<double>(now - lastStatus).count();
            if (!force && seconds < 1.0) return;
            const double speed = seconds > 0 ? (readCount - lastStatusPackets) / seconds : 0;
            std::ostringstream line;
            line << "[OFFLINE PCAP] " << state << " | processed=" << readCount
                 << " accepted=" << accepted << " skipped=" << skipped
                 << " TCP=" << tcp << " UDP=" << udp
                 << " speed=" << std::fixed << std::setprecision(1) << speed << " pkt/s";
            std::cout << line.str() << '\n' << std::flush;
            lastStatus = now;
            lastStatusPackets = readCount;
        };
        status("Starting", true);

        while (!stopRequested && handler.readNextPacket(packet)) {
            ++readCount;
            //Only cleanup uses the watermark. Detectors get original timestamps.
            if (!clockStarted) {
                watermark = lastCleanup = packet.timestampUs;
                clockStarted = true;
            } else if (packet.timestampUs < watermark) {
                ++backwards;
            } else {
                watermark = packet.timestampUs;
            }
            if (watermark - lastCleanup >= 1000000ULL) {
                expiredFlows += flows.expireFlows(watermark);
                expiredSources += rates.removeExpired(watermark, 60000000ULL);
                lastCleanup = watermark;
            }
            if (!packet.valid || (packet.protocol != 6 && packet.protocol != 17)) {
                ++skipped;
                status("Processing");
                continue;
            }
            const std::string src = pcpp::IPv4Address(packet.srcIP).toString();
            const std::string dst = pcpp::IPv4Address(packet.dstIP).toString();
            const std::string flow = std::string(packet.protocol == 6 ? "TCP " : "UDP ")
                + endpoint(packet.srcIP, packet.srcPort) + " -> "
                + endpoint(packet.dstIP, packet.dstPort)
                + " | captureTimestampUs=" + std::to_string(packet.timestampUs);

            if (!flows.processPacket(packet, packet.timestampUs))
                throw std::runtime_error("HashTable rejected a supported packet");
            const auto& alerts = flows.getAlerts();
            while (nextFlowAlert < alerts.size()) {
                const auto& alert = alerts[nextFlowAlert];
                std::ostringstream entry;
                entry << "[FLOW] " << alert.id << " | " << alert.description
                          << " | canonicalA=" << endpoint(alert.flowKey.sideA_IP, alert.flowKey.sideA_Port)
                          << " canonicalB=" << endpoint(alert.flowKey.sideB_IP, alert.flowKey.sideB_Port)
                          << " | protocol=" << static_cast<unsigned>(alert.flowKey.protocol)
                          << " | captureTimestampUs=" << alert.timestampUs
                          << " | observed=" << alert.observedValue
                          << " threshold=" << alert.threshold
                          << " | trigger=" << flow
                          << " | detectedUtc=" << detectionTime();
                logAlert(logPath, entry.str());
                ++nextFlowAlert;
            }
            const RateResult result = rates.processPacket(packet, packet.timestampUs);
            auto printRate = [&](bool triggered, const char* name, uint64_t count) {
                if (!triggered) return;
                ++rateAlerts;
                std::ostringstream entry;
                entry << "[RATE] " << name << " | count=" << count
                          << " | windowSeconds=" << result.rates.windowStartSecond
                          << ".." << result.rates.windowEndSecond
                          << " | source=" << pcpp::IPv4Address(result.sourceIP).toString()
                          << " | " << flow << " | detectedUtc=" << detectionTime();
                logAlert(logPath, entry.str());
            };
            printRate(result.highPacketRate, "High packet rate", result.rates.packetCount);
            printRate(result.possibleSynFlood, "Possible SYN flood", result.rates.tcpSynCount);
            printRate(result.possibleUdpFlood, "Possible UDP flood", result.rates.udpCount);

            if (!packet.payload.empty()) {
                const auto matches = ac.scanPattern(packet.payload.data(), packet.payload.size());
                const std::string context = matches.empty() ? flow
                    : flow + " | detectedUtc=" + detectionTime();
                for (const auto& hit : matches) {
                    if (!hit.info) continue;
                    ++payloadAlerts;
                    std::cout << "[PAYLOAD] " << hit.info->id << " " << hit.info->name
                              << " (" << hit.info->severity << ") | " << context
                              << " | endOffsetExclusive=" << hit.endOffset << '\n' << std::flush;
                }
                if (!matches.empty()) ac.writeAlerts(logPath, matches, context);
            }
            auto checkBlacklist = [&](uint32_t ip, const std::string& text, const char* side) {
                const cidrEntry* hit = blacklist.checkNetOrder(ip);
                if (!hit) return;
                ++blacklistAlerts;
                const std::string context = flow + " | detectedUtc=" + detectionTime();
                std::cout << "[BLACKLIST] " << side << " " << text
                          << " matched " << hit->text << " | " << context << '\n' << std::flush;
                blacklist.writeAlert(logPath, text, side, *hit, context);
            };
            checkBlacklist(packet.srcIP, src, "SRC");
            checkBlacklist(packet.dstIP, dst, "DST");
            ++accepted;
            bytes += packet.packetSize;
            tcp += packet.protocol == 6;
            udp += packet.protocol == 17;
            syn += packet.syn;
            ack += packet.ack;
            status("Processing");
        }
        status(stopRequested ? "Stopped by user" : "Reading ended", true);
        std::cout << (stopRequested ? "\nStopped by user.\n" : "\nPacket reading ended.\n")
                  << "Packets read: " << readCount << "\nAccepted: " << accepted
                  << "\nSkipped invalid/unsupported: " << skipped
                  << "\nTCP packets: " << tcp << "\nUDP packets: " << udp
                  << "\nAccepted captured bytes: " << bytes
                  << "\nSYN flags: " << syn << "\nACK flags: " << ack
                  << "\nStored flows: " << flows.getSize()
                  << "\nStored rate sources: " << rates.getSize()
                  << "\nExpired flows: " << expiredFlows
                  << "\nExpired rate sources: " << expiredSources
                  << "\nFlow alerts: " << nextFlowAlert << "\nRate alerts: " << rateAlerts
                  << "\nPayload alerts: " << payloadAlerts
                  << "\nBlacklist alerts: " << blacklistAlerts
                  << "\nTimestamps behind watermark: " << backwards << '\n';
        if (backwards)
            std::cerr << "Warning: out-of-order timestamps can affect flow timing; "
                      << "original timestamps were preserved.\n";
        std::cout << "Reader limitation: EOF and read errors share the same return value.\n";
        return stopRequested ? 130 : 0;
    } catch (const std::exception& error) {
        std::cerr << "Analysis failed: " << error.what() << '\n';
        return 1;
    }
}
