#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

struct cidrEntry
{
    uint32_t network;   // already masked, host byte order
    uint32_t mask;
    int prefix;
    std::string text;   // original "a.b.c.d/n" text, used in alerts

    cidrEntry() : network(0), mask(0), prefix(0) {}
};

class CidrBlacklist
{
    std::vector<cidrEntry> entries;

    static bool parseIPv4(const std::string& s, uint32_t& out);
    static bool parseCidr(const std::string& s, cidrEntry& out);

public:
    CidrBlacklist() {}

    // one CIDR per line, '#' comments and blank lines ignored.
    // a bare IP with no "/n" is treated as /32. returns number of entries loaded
    size_t openBlacklist(const std::string& path);

    // host byte order IP
    const cidrEntry* check(uint32_t ip) const;
    // text IP like "10.1.2.3"
    const cidrEntry* check(const std::string& ip) const;
    // IP as stored in PacketInfo (pcpp toInt(), network byte order)
    const cidrEntry* checkNetOrder(uint32_t ipNet) const;

    size_t size() const { return entries.size(); }

    // side is "SRC" or "DST" so the log says which end of the flow was blacklisted
    void writeAlert(const std::string& path, const std::string& ip, const std::string& side,
                    const cidrEntry& hit, const std::string& flow) const;
};