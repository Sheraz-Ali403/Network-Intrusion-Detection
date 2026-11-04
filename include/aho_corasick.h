#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

struct match // store alerts
{
    size_t endOffset;
    int patternID;

    match() : endOffset(0), patternID(-1) {}
    match(size_t off, int id) : endOffset(off), patternID(id) {}
};

struct node // trieNode carrying the letter
{
    char letter;
    node *children[256];
    node *failureLink;
    node *outputLink;
    int patternID; // indication for pattern

    node(char input);
};

class AhoCorasick
{
    node *root;

    uint8_t lower(char c);
    void insertUtil(node *cur, const std::string &word, size_t index, int id);
    void buildFailAndOutputLinkUtil();
    std::vector<match> scanPatternUtil(const uint8_t *data, size_t len);
    void destroy(node *cur);

public:
    AhoCorasick();
    ~AhoCorasick();

    void buildTrie(const std::vector<std::string> &pattern);
    void buildFailAndOutputLink();
    std::vector<match> scanPattern(const uint8_t *data, size_t len);

    // to prevent accidental copy of Aho-Corasick
    AhoCorasick(const AhoCorasick &) = delete;
    AhoCorasick &operator=(const AhoCorasick &) = delete;
};