# NIDS Project Design Decisions & Architecture Architecture

This document establishes the foundational design decisions, structural blueprints, and computational complexities for our C++ Network Intrusion Detection System (NIDS).

---

## 1. Rule Memory Storage

### In-Depth Analysis
When the NIDS initializes, it processes rules from a configuration file and parses them into memory objects. Storing these rules sequentially in a flat list forces every incoming packet to iterate through *every single rule*. This leads to an inefficient runtime complexity of $O(M)$ per packet, where $M$ is the total number of rules.

### Implementation Blueprint
* **Data Structure:** A Hash Map of Groups (`std::unordered_map<std::string, std::vector<Rule>>`).
* **Execution Strategy:** Group the compiled rule objects natively by their layer-4 operational protocol field (`tcp` or `udp`). When an inbound packet is identified as a UDP stream, the engine queries the map in $O(1)$ constant time to fetch only the UDP-bound rule array. It completely skips the evaluation of all TCP rules.

---

## 2. Payload Inspection Engine

### In-Depth Analysis
Validating packet payload data for signature strings like `"/bin/sh"` or `"OR 1=1"` using standard sequential search operations like `std::string::find` uses a brute-force approach. For $M$ different content patterns and an incoming packet payload string of length $N$, this results in an inefficient worst-case execution time of $O(M \times N)$ per packet.

### Implementation Blueprint
* **Data Structure:** A Custom Trie (Prefix Tree) or an Aho-Corasick Automaton.
* **Execution Strategy:** Treat the custom Trie structure as a unified dictionary of malicious content signatures. During the parsing stage, insert every string from your configuration rules directly into the Trie matrix. For every incoming packet, stream the payload bytes down the Trie nodes in a single pass. This consolidates multi-pattern evaluations into an efficient linear time complexity of $O(N)$.

---

## 3. Threading Architecture

### In-Depth Analysis
Network packets arrive rapidly. In a single-threaded configuration, if your application's detection logic takes 5 milliseconds to analyze a packet payload against your rules, the packet capture component is frozen during that time window. This structural stall causes the underlying operating system buffer to overflow and drop incoming network traffic.

### Implementation Blueprint
* **Data Structure:** A Multi-Threaded Producer-Consumer Pipeline using a Thread-Safe FIFO Queue.
* **Execution Strategy:** Divide the system logic into two distinct concurrent execution threads:
  * **Thread 1 (Producer):** Dedicated exclusively to running the PcapPlusPlus/Npcap live capture loop. Its sole job is to grab raw packets from the wire and push them directly onto a safe FIFO queue wrapper.
  * **Thread 2 (Consumer):** Dedicated exclusively to your detection engine. It continuously pops packets off the queue and runs rule verification. Use a `std::mutex` and a `std::condition_variable` to prevent data races and race conditions.

---

## 4. CIDR Range Matching

### In-Depth Analysis
A Classless Inter-Domain Routing (CIDR) block notation (like `/24`) specifies that the first 24 bits of an IP address identify the network prefix, while the remaining 8 bits target unique hosts. Re-parsing string representations of IP addresses inside the evaluation loop introduces severe runtime bottlenecks.

### Implementation Blueprint
* **Data Structure:** Direct 32-bit Integer Bit-Masking.
* **Execution Strategy:** Convert all incoming IPv4 text strings into unsigned 32-bit network-byte-order integers (`uint32_t`) immediately upon capture via helper functions like `inet_pton`. When parsing a CIDR target rule, pre-calculate the bitmask. For example, a `/24` subnet converts to `0xFFFFFF00`. This allows your code to verify network inclusions in a single CPU cycle using a bitwise AND operator:
  ```cpp
  if ((packet_ip & rule_mask) == rule_network_ip) {
      // Subnet Match Verified Natively
  }
  ```

---

## 5. Threshold & State Tracking

### In-Depth Analysis
Detecting rate-based anomalies like automated TCP SYN floods or brute-force SSH port scans (e.g., *100 connection attempts within 5 seconds*) requires the NIDS to maintain historical state tracking. It must monitor connection frequency per unique source IP address.

### Implementation Blueprint
* **Data Structure:** A Sliding Window Log utilizing a Hash Map paired with a Double-Ended Queue (`std::unordered_map<uint32_t, std::deque<double>>`).
* **Execution Strategy:** Maintain a global lookup map where the key is the 32-bit source IP address, and the value is a `std::deque` containing high-precision timestamps (in seconds). When a new packet is intercepted:
  1. Append the current capture timestamp to the back of that specific IP's deque.
  2. Check the front element of the deque and continuously pop out any old timestamps that fall outside the active sliding time window (`current_time - window_seconds`).
  3. Evaluate the remaining size of the deque. If the count exceeds the configured rule limit, trigger an immediate anomaly alert.

---

## 6. Packet Memory Management

### In-Depth Analysis
Performing deep allocations or memory copies of raw network byte arrays (`new char[]`) across thread spaces inside your processing queue creates high memory overhead. It puts unnecessary stress on the system's heap allocator. Conversely, standard raw pointers risk data corruption if one thread attempts to delete memory while another is actively analyzing it.

### Implementation Blueprint
* **Data Structure:** Zero-Copy wrappers utilizing move semantics via Smart Pointers (`std::unique_ptr`).
* **Execution Strategy:** Encapsulate raw packet buffer pointers immediately into a smart unique container block (`std::unique_ptr<RawPacketData>`). When the producer thread forwards the captured packet onto your FIFO queue, use `std::move()` to pass ownership safely to the consumer thread. Once the consumer finishes evaluating the rules, the packet object goes out of scope and automatically frees its memory securely without manual resource cleanup.
