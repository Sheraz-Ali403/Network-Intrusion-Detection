#include "pcapHandler.h"
#include "data_hash_table.h"
#include "aho_corasick.h"
#include "cidr_blacklist.h"

#include <exception>
#include <filesystem>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc > 2 || (argc == 2 && std::string(argv[1]) == "--help")) {
        std::cout << "Usage: " << argv[0] << " [capture.pcap]\n"
                  << "Default: captures/sample.pcap\n";
        return argc > 2 ? 1 : 0;
    }

    try {
        std::filesystem::path path = argc == 2 ? argv[1] : "captures/sample.pcap";
        // Also find the bundled capture when launched from the build directory.
        if (argc == 1 && !std::filesystem::exists(path)) {
            path = std::filesystem::path(argv[0]).parent_path()
                 / ".." / "captures" / "sample.pcap";
        }
        if (!std::filesystem::is_regular_file(path)) {
            std::cerr << "Capture file not found: " << path << '\n'
                      << "Pass the full path to an existing .pcap file.\n";
            return 1;
        }

        PcapHandler handler;
        if (!handler.openPcapFile(path.string())) {
            return 1;
        }

        HashTable flows;
        uint64_t readCount = 0, accepted = 0, skipped = 0;
        uint64_t uniqueFlows = 0, bytes = 0, tcp = 0, udp = 0;
        uint64_t syn = 0, ack = 0;
        PacketInfo packet;

        std::filesystem::create_directories("output"); //so alert files can be created

        //loading ahocorasick
        AhoCorasick ac;
        std::vector<patternInfo> patterns; //must remain unchanged and alive
        ac.openRules(patterns, "rules/ahoRules.txt"); //adding keywords
        if (patterns.empty())
        {    // guard clause
            std::cerr << "No rules loaded from ahoRules.txt\n";
            return 1;
        }

        //loading cidr blacklist
        CidrBlacklist blacklist;
        if (blacklist.openBlacklist("rules/cidrBlacklist.txt") == 0)
        {
            std::cerr << "Warning: no CIDR entries loaded from cidrBlacklist.txt\n";
        }

        uint64_t PayloadAlertCount = 0; //for payload alets only
        uint64_t BlacklistAlertCount = 0; //for cidr blacklist alerts only

        std::cout << "Reading: " << std::filesystem::absolute(path).lexically_normal()
                  << "\nFirst 10 accepted packets (directional flows):\n";

        while (handler.readNextPacket(packet)) {
            ++readCount;
            if (!packet.valid) {
                ++skipped;
                continue;
            }

            const std::string srcText = pcpp::IPv4Address(packet.srcIP).toString();
            const std::string dstText = pcpp::IPv4Address(packet.dstIP).toString();
            const std::string flow = srcText + ":" + std::to_string(packet.srcPort)
                                   + " -> " + dstText + ":" + std::to_string(packet.dstPort);

            //cidr blacklist check, either end of the flow can be blacklisted
            if (const cidrEntry* hit = blacklist.checkNetOrder(packet.srcIP))
            {
                BlacklistAlertCount++;
                std::cout << "[BLACKLIST] SRC " << srcText << " matched " << hit->text
                          << " | " << flow << '\n';
                blacklist.writeAlert("output/alerts.log", srcText, "SRC", *hit, flow);
            }
            if (const cidrEntry* hit = blacklist.checkNetOrder(packet.dstIP))
            {
                BlacklistAlertCount++;
                std::cout << "[BLACKLIST] DST " << dstText << " matched " << hit->text
                          << " | " << flow << '\n';
                blacklist.writeAlert("output/alerts.log", dstText, "DST", *hit, flow);
            }

            if(!packet.payload.empty())
            {
                std::vector<match> alerts = ac.scanPattern(packet.payload.data(),packet.payload.size());

                for(size_t i=0; i<alerts.size();i++)
                {
                    PayloadAlertCount++;

                    std::cout << "[ALERT] " << alerts[i].info->id << " " << alerts[i].info->name
                            << " (" << alerts[i].info->severity << ") "
                            << flow
                            << " offset=" << alerts[i].endOffset << '\n';
                }
                if(!alerts.empty())
                {
                    ac.writeAlerts("output/alerts.log", alerts, flow);
                }
            }

            const dataKey key{packet.srcIP, packet.dstIP, packet.srcPort,
                              packet.dstPort, packet.protocol};
            const bool newFlow = flows.find(key) == nullptr;
            const keyInfo delta{1, packet.packetSize,
                                static_cast<uint64_t>(packet.syn),
                                static_cast<uint64_t>(packet.ack)};
            flows.insertKey(key, delta);
            uniqueFlows += newFlow;
            ++accepted;
            bytes += packet.packetSize;
            tcp += packet.protocol == 6;
            udp += packet.protocol == 17;
            syn += packet.syn;
            ack += packet.ack;

            if (accepted <= 10) {
                const keyInfo* history = flows.find(key);
                std::cout << (packet.protocol == 6 ? "TCP " : "UDP ")
                          << flow
                          << " | flow packets=" << history->packetCount
                          << " bytes=" << history->byteCount << '\n';
            }
        }

        std::cout << "\nPackets read: " << readCount
                  << "\nAccepted IPv4 TCP/UDP packets: " << accepted
                  << "\nSkipped unsupported/zero-port packets: " << skipped
                  << "\nUnique directional flows: " << uniqueFlows
                  << "\nTCP packets: " << tcp << "\nUDP packets: " << udp
                  << "\nAccepted captured bytes: " << bytes
                  << "\nSYN flags: " << syn << "\nACK flags: " << ack << '\n';
        // PcapHandler currently reports both EOF and read errors as false.

        std::cout << "Payload Alerts: " << PayloadAlertCount << '\n';
        std::cout << "Blacklist Alerts: " << BlacklistAlertCount << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Analysis failed: " << error.what() << '\n';
        return 1;
    }
}