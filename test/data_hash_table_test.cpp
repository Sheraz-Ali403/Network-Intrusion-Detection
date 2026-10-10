#include "../include/data_hash_table.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

static uint64_t testHash(const dataKey& key) {
    uint64_t hash = 14695981039346656037ULL;
    for (int i = 0; i < 4; ++i) {
        hash ^= (key.srcIP >> (i * 8)) & 0xFF;
        hash *= 1099511628211ULL;
    }
    for (int i = 0; i < 4; ++i) {
        hash ^= (key.destIP >> (i * 8)) & 0xFF;
        hash *= 1099511628211ULL;
    }
    for (int i = 0; i < 2; ++i) {
        hash ^= (key.srcPort >> (i * 8)) & 0xFF;
        hash *= 1099511628211ULL;
    }
    for (int i = 0; i < 2; ++i) {
        hash ^= (key.destPort >> (i * 8)) & 0xFF;
        hash *= 1099511628211ULL;
    }
    for (int i = 0; i < 8; ++i) {
        hash ^= (key.protocol >> (i * 8)) & 0xFF;
        hash *= 1099511628211ULL;
    }
    return hash;
}

static dataKey makeKey(uint32_t srcIP) {
    return {srcIP, 0x0A000002, 1234, 443, 6};
}

static void testInsertFindAndAggregate() {
    HashTable table(128);
    const dataKey key = makeKey(0x0A000001);

    table.insertKey(key, {1, 100, 1, 0});
    table.insertKey(key, {2, 200, 0, 2});

    keyInfo* result = table.find(key);
    assert(result != nullptr);
    assert(result->packetCount == 3);
    assert(result->byteCount == 300);
    assert(result->synCount == 1);
    assert(result->ackCount == 2);
    assert(table.find(makeKey(99)) == nullptr);
}

static void testSeparateChainingRemoval() {
    HashTable table(1024);
    std::vector<dataKey> collidingKeys;
    const uint64_t targetBucket = testHash(makeKey(0)) % 1024;

    for (uint32_t srcIP = 0; collidingKeys.size() < 3; ++srcIP) {
        dataKey key = makeKey(srcIP);
        if (testHash(key) % 1024 == targetBucket) {
            collidingKeys.push_back(key);
        }
    }

    for (const dataKey& key : collidingKeys) {
        table.insertKey(key, {1, 10, 0, 0});
    }

    table.remove(collidingKeys[2]);
    assert(table.find(collidingKeys[2]) == nullptr);
    assert(table.find(collidingKeys[0]) != nullptr);
    assert(table.find(collidingKeys[1]) != nullptr);

    table.remove(collidingKeys[1]);
    assert(table.find(collidingKeys[1]) == nullptr);
    assert(table.find(collidingKeys[0]) != nullptr);

    table.remove(collidingKeys[0]);
    assert(table.find(collidingKeys[0]) == nullptr);
    table.remove(collidingKeys[0]);
}

static void testResizeAndRemoval() {
    HashTable table(2);
    std::vector<dataKey> keys;
    keys.reserve(300);

    for (uint32_t i = 0; i < 300; ++i) {
        keys.push_back(makeKey(i + 1));
        table.insertKey(keys.back(), {1, i, 0, 0});
    }

    for (uint32_t i = 0; i < keys.size(); ++i) {
        keyInfo* result = table.find(keys[i]);
        assert(result != nullptr);
        assert(result->packetCount == 1);
        assert(result->byteCount == i);
    }

    for (size_t i = 0; i < keys.size(); i += 2) {
        table.remove(keys[i]);
    }
    for (size_t i = 0; i < keys.size(); ++i) {
        assert((table.find(keys[i]) != nullptr) == (i % 2 == 1));
    }
}

int main() {
    testInsertFindAndAggregate();
    testSeparateChainingRemoval();
    testResizeAndRemoval();
    std::cout << "All hash-table tests passed.\n";
}
