#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

using std::string;

struct patternInfo
{
    string name;
    int id;
    string severity;
    string pattern;

    patternInfo(string n, int i, string s, string p): name(n), id(i), severity(s), pattern(p) {};
};

struct match // store alerts
{
    size_t endOffset;
    patternInfo* info;

    match() : endOffset(0), info(NULL) {}
    match(size_t off, patternInfo* i) : endOffset(off), info(i) {}
};


struct node // trieNode carrying the letter
{
    char letter;
    node *children[256];
    node *failureLink;
    node *outputLink;
    patternInfo* info; // indication for pattern

    node(char input);
};

class AhoCorasick
{
    node *root;

    uint8_t lower(char c);
    void insertUtil(node* cur, const std::string& word, size_t index, patternInfo& pInfo);
    void buildFailAndOutputLinkUtil();
    std::vector<match> scanPatternUtil(const uint8_t* data, size_t len);
    void destroy(node *cur);

public:
    AhoCorasick();
    ~AhoCorasick();

    void buildTrie(std::vector<patternInfo>& patterns);
    void buildFailAndOutputLink();
    void openRules(std::vector<patternInfo>& patterns, const std::string& path);
    std::vector<match> scanPattern(const uint8_t* data, size_t len);
    void writeAlerts(const std::string& path, std::vector<match> alerts, const std::string& flow);

    // to prevent accidental copy of Aho-Corasick
    AhoCorasick(const AhoCorasick &) = delete;
    AhoCorasick &operator=(const AhoCorasick &) = delete;

};