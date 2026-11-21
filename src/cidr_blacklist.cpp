#include "cidr_blacklist.h"
#include <fstream>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h> //ntohl
#endif

using std::string;
using std::ifstream;
using std::ofstream;
using std::getline;

bool CidrBlacklist::parseIPv4(const string& s, uint32_t& out)
{
    uint32_t result = 0;
    size_t pos = 0;

    for (int part = 0; part < 4; part++)
    {
        if (pos >= s.size()) return false;

        size_t digits = 0;
        uint32_t val = 0;
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9')
        {
            val = val * 10 + (s[pos] - '0');
            if (val > 255) return false;
            pos++;
            digits++;
        }
        if (digits == 0) return false;

        result = (result << 8) | val;

        if (part < 3)
        {
            if (pos >= s.size() || s[pos] != '.') return false;
            pos++; //skip dot
        }
    }

    if (pos != s.size()) return false; //trailing garbage
    out = result;
    return true;
}

bool CidrBlacklist::parseCidr(const string& s, cidrEntry& out)
{
    string ipPart = s;
    int prefix = 32;

    size_t slash = s.find('/');
    if (slash != string::npos)
    {
        ipPart = s.substr(0, slash);
        string pre = s.substr(slash + 1);
        if (pre.empty() || pre.size() > 2) return false;
        for (char c : pre) if (c < '0' || c > '9') return false;
        prefix = std::stoi(pre);
        if (prefix > 32) return false;
    }

    uint32_t ip;
    if (!parseIPv4(ipPart, ip)) return false;

    out.mask = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix)); //avoid shift by 32 (UB)
    out.network = ip & out.mask;
    out.prefix = prefix;
    out.text = s;
    return true;
}

size_t CidrBlacklist::openBlacklist(const string& path)
{
    ifstream file(path);
    if (!file.is_open()) return 0;

    string line;
    while (getline(file, line))
    {
        if (!line.empty() && line.back() == '\r') line.pop_back(); //windows \r

        size_t hash = line.find('#'); //strip comments
        if (hash != string::npos) line.erase(hash);

        size_t b = line.find_first_not_of(" \t");
        if (b == string::npos) continue; //empty
        size_t e = line.find_last_not_of(" \t");
        line = line.substr(b, e - b + 1);

        cidrEntry entry;
        if (parseCidr(line, entry)) entries.push_back(entry);
    }

    return entries.size();
}

const cidrEntry* CidrBlacklist::check(uint32_t ip) const
{
    for (size_t i = 0; i < entries.size(); i++)
    {
        if ((ip & entries[i].mask) == entries[i].network) return &entries[i];
    }
    return nullptr;
}

const cidrEntry* CidrBlacklist::check(const string& ip) const
{
    uint32_t value;
    if (!parseIPv4(ip, value)) return nullptr;
    return check(value);
}

const cidrEntry* CidrBlacklist::checkNetOrder(uint32_t ipNet) const
{
    return check(ntohl(ipNet)); //pcpp toInt() is network order, entries are host order
}

void CidrBlacklist::writeAlert(const string& path, const string& ip, const string& side,
                               const cidrEntry& hit, const string& flow) const
{
    ofstream file(path, std::ios::app);
    if (!file.is_open()) return;

    file << "[BLACKLIST] " << side << ": " << ip
         << " | Matched CIDR: " << hit.text
         << " | Flow: " << flow << "\n";
}