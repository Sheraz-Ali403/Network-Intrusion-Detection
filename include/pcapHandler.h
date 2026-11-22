#pragma once
#include <iostream>
#include <stdio.h>
#include <cstdint>  //unit16_t, uint32_t
#include <string>
#include <vector>

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
    uint32_t srcIP=0;
    uint32_t dstIP=0;
    uint8_t protocol=0;

    //0-65,535 port so 16 bits are enough
    uint16_t srcPort=0;  
    uint16_t dstPort=0;

    uint32_t packetSize=0;
    uint64_t timestampUs = 0; // capture timestamp in microseconds
    //std::string timestamp;

    //if TCP, store the flags
    bool syn = false;
    bool ack = false;
    bool fin = false;
    bool rst = false;
    uint32_t sequenceNumber = 0;
    uint32_t acknowledgmentNumber = 0;

    bool valid = false; //if the packet is valid or not, if not valid then we can skip it

    std::vector<uint8_t> payload;   // copy of the data inside the packet byte by byte

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
    pcpp::PcapFileReaderDevice* reader; 
    std::string fileName;
    //pcpp::RawPacket rawPacket;
    //PacketInfo info;

    PacketInfo getPacketInfo(pcpp::RawPacket& rawPacket);
public:
    PcapHandler();
    ~PcapHandler();
    //ban copying objects
    PcapHandler(const PcapHandler&)=delete;
    PcapHandler& operator=(const PcapHandler&)=delete;

    bool openPcapFile(const std::string& fileName);


    bool readNextPacket(PacketInfo& info);
};

