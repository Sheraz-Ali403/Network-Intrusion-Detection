#pragma once
#include <iostream>
#include <stdio.h>
#include <cstdint>  //unit16_t, uint32_t
#include <string>

#include "PcapLiveDeviceList.h" //For live capture for v2

//pcap releed header files
#include "PcapFileDevice.h" //For reading pcap files
#include "RawPacket.h" // Packets before parsing
#include "Packet.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"




// Packets Info Storer
struct PacketInfo {
    std::string srcIP;
    std::string dstIP;
    std::string protocol;

    //0-65,535 port so 16 bits are enough
    uint16_t srcPort;  
    uint16_t dstPort;

    uint32_t packetSize;
    std::string timestamp;

    //if TCP, store the flags
    bool syn = false;
    bool ack = false;
    bool fin = false;
    bool rst = false;

    /*Latter can be added
    timestamp already added
    MAC addresses
    payload pointer/data
    TTL
    ICMP information
    TCP sequence/acknowledgment numbers
    */
};


class PcapHandler {
private:
    pcpp::PcapFileReaderDevice reader;
    pcpp::RawPacket rawPacket;
    PacketInfo info;
public:
    bool openPcapFile(const std::string& fileName);
    PacketInfo getPacketInfo(pcpp::RawPacket& rawPacket);
    // bool readNextPacket();
};






