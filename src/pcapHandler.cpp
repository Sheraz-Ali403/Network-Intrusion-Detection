#include <iostream>
#include <stdio.h>
#include <cstdint>  //unit16_t, uint32_t
#include <string>
#include <algorithm> //for std::swap
#include <utility> 

#include "pcapHandler.h"  

#include "PcapLiveDeviceList.h" //For live capture for v2

//pcap releed header files
#include "PcapFileDevice.h" //For reading pcap files
#include "RawPacket.h" // Packets before parsing
#include "Packet.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"

PcapHandler::PcapHandler() : reader(nullptr) { }
PcapHandler::~PcapHandler(){
    if (reader){
        reader->close();
        delete reader;
        reader = nullptr;
    }
}

bool PcapHandler::openPcapFile(const std::string& filename) {
    if (reader){
        reader->close();
        delete reader;
        reader = nullptr;
    }
        reader = new pcpp::PcapFileReaderDevice(filename);
    if (!reader->open()) {
        std::cerr << "Error opening the pcap file: " << filename << std::endl;
        //reader->close();
        delete reader;
        reader = nullptr;
        return false;
    }
    fileName = filename;
    return true;
}

PacketInfo PcapHandler::getPacketInfo(pcpp::RawPacket& rawPacket) {
    pcpp::Packet packet(&rawPacket);

    PacketInfo info;
    auto* ipv4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (ipv4Layer != nullptr){
        info.srcIP = ipv4Layer->getSrcIPv4Address().toInt();
        info.dstIP = ipv4Layer->getDstIPv4Address().toInt();

        //We are limiting to TCP and UDP for now, but we can add more protocols later

        //pcpp::ProtocolType protocol = ipv4Layer->getProtocol(); 
        info.protocol = ipv4Layer->getIPv4Header()->protocol;

        //pcpp::TCP = 6 
        //pcpp::UDP = 17 in pcap its enum is 5 but
        // according  IANA Internet protocol assignment
        if(info.protocol == 6) {
            auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();

            if (tcpLayer != nullptr) {
                info.srcPort = tcpLayer->getSrcPort();
                info.dstPort = tcpLayer->getDstPort();

                info.syn = tcpLayer->getTcpHeader()->synFlag;
                info.ack = tcpLayer->getTcpHeader()->ackFlag;
                info.fin = tcpLayer->getTcpHeader()->finFlag;
                info.rst = tcpLayer->getTcpHeader()->rstFlag;
            }
        } 
        else if (info.protocol == 17) { // pcpp::UDP = 17
            //info.protocol = "UDP";

            auto* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
            if (udpLayer != nullptr) {
                info.srcPort = udpLayer->getSrcPort();
                info.dstPort = udpLayer->getDstPort();
            }
        } 
        else {
            info.protocol = 100000; //Unknown/unset protocol
        }

        info.valid = true;
    }

    info.packetSize = rawPacket.getRawDataLen();
    // Timestamp handling can be added here

    return info;
}
bool PcapHandler::readNextPacket(PacketInfo& info){
    if(!reader) return false;
    pcpp::RawPacket rawPacket;
    if(!reader->getNextPacket(rawPacket)){
        return false; // No more packets or error
    }
    info = getPacketInfo(rawPacket);
    return true;
}