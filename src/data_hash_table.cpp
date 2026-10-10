#include "data_hash_table.h"

#include <iostream>
#include <string>

#include <cstdint>
#include <cstddef>
#include <stdexcept>


HashTable::HashTable(size_t cap) : capacity(cap), size(0){
    if(capacity == 0){
        throw std::invalid_argument("HashTable capacity must be greater than zero");
    }
    bucket = new Node*[capacity];
    for(size_t i = 0; i < capacity; ++i) {
        bucket[i] = nullptr;
    }
}

//Destructor
HashTable::~HashTable() {
    for(size_t i = 0; i < capacity; ++i) {
        Node* current = bucket[i];
        //for cleaning up the list in each bucket in separate chaining
        while(current) {
            Node* toDelete = current;
            current = current->next;
            delete toDelete;
        }
    }
    delete[] bucket;
}

//Need to implement copy constructer and copy assignmet operator

HashTable::HashTable(const HashTable& other){
    //size_t capacity = new size_t(other.capacity;
    this->capacity = other.capacity;
    this->size = 0;
    this->bucket = new Node*[other.capacity];
    for(size_t i = 0; i < capacity; ++i) {
        bucket[i] = nullptr;
    }
    for(size_t i = 0; i < other.capacity; ++i) {
        Node* current = other.bucket[i];
        while(current) {
            insertKey(current->key, current->info);
            current = current->next;
        }
    }
}
HashTable& HashTable::operator =(const HashTable& other){
    if(this != &other) {
        // Implementation for assignment operator
        for(size_t i = 0; i < capacity; ++i) {
            Node* current = bucket[i];
            while(current) {
                Node* toDelete = current;
                current = current->next;
                delete toDelete;
            }
        }
        delete[] bucket; 
        this->capacity = other.capacity;
        this->size = 0;
        this->bucket = new Node*[other.capacity];
        for(size_t i = 0; i < capacity; ++i) {
            bucket[i] = nullptr;
        }
        for(size_t i = 0; i < other.capacity; ++i) {
            Node* current = other.bucket[i];
            while(current) {
                insertKey(current->key, current->info);
                current = current->next;
            }
        }
    }
    return *this;
}

bool HashTable::keysEqual(const dataKey& a, const dataKey& b) const {
    return (a.srcIP == b.srcIP && a.destIP == b.destIP && a.srcPort == b.srcPort && a.destPort == b.destPort && a.protocol == b.protocol);
}

uint64_t HashTable::HashFunction(const dataKey& key) const {
    //Fixed FNV Constants
    // constexpr uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
    // constexpr uint64_t FNV_PRIME         = 1099511628211ULL;
    uint64_t hash = 14695981039346656037ULL;
    for(int i=0; i<4; ++i) {
        hash ^= (key.srcIP >> (i * 8)) & 0xFF;
        hash *= 1099511628211ULL;
    }
    for(int i=0; i<4; ++i) {
        hash ^= (key.destIP >> (i * 8)) & 0xFF;
        hash *= 1099511628211ULL;
    }
    for(int i=0; i<2; ++i) {
        hash ^= (key.srcPort >> (i * 8)) & 0xFF;
        hash *= 1099511628211ULL;
    }
    for(int i=0; i<2; ++i) {
        hash ^= (key.destPort >> (i * 8)) & 0xFF;
        hash *= 1099511628211ULL;
    }
    //fixed one protocol
    for(int i=0; i<8; ++i) {
        hash ^= (key.protocol >> (i * 8)) & 0xFF;
        hash *= 1099511628211ULL;
    }

    return hash % capacity;

}

void HashTable::reSizeHash() {
    //Fixed load factor of 0.75, if the current size exceeds 75% of the capacity, we resize the hash table
    if( (size/static_cast<double>(capacity)) > LOAD_FACTOR) {
        capacity *= 2;
        Node** newBucket = new Node*[capacity];
        for(size_t i = 0; i < capacity; ++i) {
            newBucket[i] = nullptr;
        }
        for(size_t i = 0; i < capacity / 2; ++i) {
            Node* current = bucket[i];
            while(current) {
                Node* nextNode = current->next;
                uint64_t index = HashFunction(current->key);
                //Insert newNode at head in separate chaining
                current->next = newBucket[index];
                newBucket[index] = current;
                current = nextNode;
            }
        }
        delete[] bucket;
        bucket = newBucket;
        return;
    }
    return;
}

void HashTable::insertKey(const dataKey& key, const keyInfo& info) {
    uint64_t index = HashFunction(key);
    Node* current = bucket[index];
    while(current) {
        if(keysEqual(current->key, key)) {
            current->info.packetCount += info.packetCount;
            current->info.byteCount += info.byteCount;
            current->info.synCount += info.synCount;
            current->info.ackCount += info.ackCount;
            return;
        }
        current = current->next;
    }
    Node* newNode = new Node(key, info);
    newNode->next = bucket[index];
    bucket[index] = newNode;
    ++size;

    reSizeHash();
}

void HashTable::remove(const dataKey& key) {
    uint64_t index = HashFunction(key);
    Node* current = bucket[index];
    Node* prev = nullptr;

    while(current) {
        if(keysEqual(current->key, key)) {
            if(prev) {
                prev->next = current->next;
            } else {
                bucket[index] = current->next;
            }
            delete current;
            --size;
            return;
        }
        prev = current;
        current = current->next;
    }
}

keyInfo* HashTable::find(const dataKey& key) {
    uint64_t index = HashFunction(key);
    Node* current = bucket[index];
    while(current) {
        if(keysEqual(current->key, key)) {
            return &(current->info);
        }
        current = current->next;
    }
    return nullptr;
}

