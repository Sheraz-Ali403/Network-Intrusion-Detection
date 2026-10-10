#pragma once

#include <iostream>
#include <string>

#include <cstdint>
#include <cstddef>


/* 
Hash Table
Constructer, Destructor - Done
KeysEqual - Done




*/


//Data packet key
struct dataKey {
    uint32_t srcIP;
    uint32_t destIP;

    uint16_t srcPort;
    uint16_t destPort;

    uint64_t protocol;
};

//If next same on the same IP and port, then increment the count and byte count
struct keyInfo {
    uint64_t packetCount =0;
    uint64_t byteCount=0;
    uint64_t synCount=0;
    uint64_t ackCount=0;
};

struct Node {
    dataKey key;
    keyInfo info;
    Node* next = nullptr;
    Node(const dataKey& k, const keyInfo& i) : key(k), info(i), next(nullptr) {}
};


class HashTable {
    Node** bucket;

    size_t capacity; //total capacity of hash table 
    size_t size;     //current size 
    static constexpr double LOAD_FACTOR = 0.75; // Max load factor for resizing
    //constexpr cz we already know the value and it is a constant expression

    bool keysEqual(const dataKey& a, const dataKey& b) const;

    uint64_t HashFunction(const dataKey& key) const;
    void reSizeHash();
public:
    HashTable(size_t cap = 128);
    ~HashTable();

    //Insert
    void insertKey(const dataKey& key, const keyInfo& info);
    //Delete
    void remove(const dataKey& key);
    //Find
    keyInfo* find(const dataKey& key);
};