# NIDS Project — Design Decisions (Corrected & Explained Simply)

This document explains the six core design decisions behind our Network Intrusion Detection System (NIDS). Each section is written in two layers: a **plain-language explanation** anyone can follow, then the **technical detail** for implementation.

**One rule applies throughout this whole project:** every structure listed as "Custom" below must be built from scratch — no built-in library containers (like C++'s `std::unordered_map`, `std::map`, or `std::deque`) for these core pieces. Simple helper types like `std::string` or thread-safety tools like `std::mutex` are fine to use as supporting plumbing; they're not what's being graded.

---

## 1. Rule Storage — Sorting Rules Into the Right Bins First

**In plain words:** Imagine a security guard with a thousand rules to check, but most of those rules only apply to cars, and most don't apply to pedestrians. A smart guard sorts the rulebook into two piles — "car rules" and "pedestrian rules" — ahead of time, so when a car shows up, they only flip through the car pile. That's what this does: rules get sorted by network protocol (TCP or UDP) in advance, so each incoming packet only gets checked against the rules that could actually apply to it.

**Technical detail:**
- **Structure:** A custom-built hash table, where the key is the protocol name (`"tcp"` or `"udp"`) and each entry holds a list of the rules for that protocol.
- **Effect:** Without this, a packet gets compared against all M rules — O(M) every time. With protocol grouping, it only checks the relevant subset, cutting wasted comparisons significantly.
- **Correction from earlier draft:** This must use our own custom hash table implementation (separate chaining, FNV-1a hash, 0.75 load factor — same one used for connection tracking), not `std::unordered_map`.

---

## 2. Payload Inspection — Checking a Message for Many Warning Words at Once

**In plain words:** Imagine you're scanning a letter for any of 50 different suspicious phrases. Checking the letter 50 separate times — once per phrase — is slow. Instead, imagine a smart highlighter that's been pre-loaded with all 50 phrases at once, so you only need to read the letter **one time**, and it lights up every match as you go. That's the structure we're building.

**Technical detail:**
- **Structure:** A custom Trie (a tree built from the known malicious patterns) **with failure links added** — this combination is specifically called an Aho-Corasick automaton.
- **Correction from earlier draft:** A plain Trie *alone* does not give single-pass scanning — it only recognizes a pattern if it starts matching from the exact beginning of where you happen to be looking. The failure links are what let the scan continue smoothly from anywhere in the message without restarting, which is what actually makes the "read the payload once" claim true. Build the plain Trie first, confirm it works, then add failure links.
- **Effect:** One pass through the payload (length N) catches matches against all M patterns at once, instead of M separate passes.

---

## 3. Threading — Two Workers, One Safe Handoff Point, With a Size Limit

**In plain words:** One worker's job is to grab incoming mail as fast as it arrives (packet capture). A second worker's job is to read each piece of mail carefully and check it against the rules (detection). If the second worker is slower than the first, mail piles up in a tray between them. That tray needs a **maximum size** — otherwise, during a flood of mail (which is exactly when an attack happens), the pile grows forever and the whole system runs out of room and crashes. So the tray has a cap, and a clear rule for what happens when it's full: the oldest unread piece gets thrown out to make room for the newest one, and we keep count of how many we had to discard.

**Technical detail:**
- **Structure:** A custom-built, fixed-capacity ring buffer (circular queue) shared between a producer thread (packet capture) and a consumer thread (detection engine), synchronized with a mutex and condition variable to prevent race conditions.
- **Correction from earlier draft:** The original description left the queue's size unbounded. A security tool specifically needs a bounded queue with a defined overflow policy (drop-oldest, with a dropped-packet counter), because an attacker flooding the system is a realistic scenario this tool must survive, not just handle at normal traffic levels.

---

## 4. Subnet (CIDR) Matching — Fast Bit Comparison, Inside a Smart Lookup Tree

**In plain words:** A subnet rule like "/24" means "the first part of this address defines a whole neighborhood, not one specific house." Checking "is this address inside this neighborhood?" can be done almost instantly using a basic math trick on the address's numeric form. But if there are many different neighborhood rules to check, doing that quick trick separately for every single rule, one at a time, is still slower than it needs to be. So we use a tree structure that narrows down to the right neighborhood in a handful of steps, no matter how many rules exist — and inside that tree, each step uses the fast bit-comparison trick to move efficiently.

**Technical detail:**
- **Structure:** A custom Radix Trie (binary tree keyed on the IP address's bits), with the fast bitmask-and-compare technique used internally at each node to test individual bits.
- **Correction from earlier draft:** The previous version replaced the Radix Trie with a flat bitmask check against each rule individually — this brings back an O(R) scan across R subnet rules per packet, which is exactly the inefficiency the rest of the design avoids elsewhere. The fix is not to choose one technique over the other — it's to combine them: the trie gives you the "don't check every rule" speed, and the bitmask trick makes each individual step inside the trie fast.
- **Effect:** A single tree walk (bounded by the address's 32 bits) finds the right match, regardless of how many subnet rules are loaded.

---

## 5. Repeated-Behavior Detection (Rate / Threshold Alerts) — Watching for "Too Many, Too Fast"

**In plain words:** To catch something like a port scan or a flood of connection attempts, the system needs to remember recent activity per source — basically a running list of "when did this address do something" for each sender, so it can check "has this address done this more than N times in the last few seconds?" Old entries that fall outside the time window being watched get dropped off the list automatically as new ones come in.

**Technical detail:**
- **Structure:** A custom hash table keyed by source IP, where each entry holds a custom-built, simple timestamp list (a small circular buffer or linked list works), not a built-in container.
- **Correction from earlier draft:** The sliding-window *logic* described (append new timestamp, drop expired ones from the front, check the count) is correct and worth keeping exactly as designed — only the underlying containers need to change, from `std::unordered_map` and `std::deque` to our own custom hash table and a small custom list/buffer structure.
- **Effect:** O(1) average lookup per source IP, and each timestamp is only ever added and removed once overall, keeping the running cost low even under heavy traffic.

---

## 6. Packet Memory Handling — Passing Packets Safely Between Workers

**In plain words:** When one worker hands a packet off to another worker, we need to make sure two things never happen: the packet accidentally gets copied unnecessarily (wasting memory and time), and the packet never gets deleted by one worker while the other is still reading it (which would cause a crash or corrupted data). Modern C++ has a built-in safety tool for exactly this handoff, which automatically cleans up the packet's memory once nobody needs it anymore — no manual cleanup required, and no risk of a worker deleting something the other worker is still using.

**Technical detail:**
- **Structure:** `std::unique_ptr` with move semantics, used to transfer ownership of each captured packet from the producer thread to the consumer thread through the ring buffer.
- **No correction needed** — this is standard, correct, and appropriate. It's a memory-safety tool, not one of the graded custom data structures, so it's fine to use the built-in version here, the same way `std::string` or `std::mutex` are fine as supporting infrastructure.

---

## Summary of Corrections Made

| Section | Issue Found | Fix Applied |
|---      |--          -|          ---|
| 1. Rule Storage | Used `std::unordered_map` (a forbidden built-in structure) | Replaced with the project's custom hash table |
| 2. Payload Inspection | Presented plain Trie and Aho-Corasick as equal options, with a complexity claim only true for the second one | Clarified that failure links are required, not optional, for the single-pass claim to hold |
| 3. Threading | Queue had no size limit or overflow rule | Added fixed capacity and a drop-oldest policy with a dropped-packet counter |
| 4. CIDR Matching | Replaced the required Radix Trie with a flat per-rule bitmask scan | Combined both: Radix Trie structure, using the bitmask technique at each internal step |
| 5. Threshold Tracking | Used `std::unordered_map` and `std::deque` (forbidden built-in structures) | Kept the sliding-window logic, replaced containers with custom equivalents |
| 6. Packet Memory | None | Kept as-is — correctly scoped as supporting infrastructure, not a graded structure |
