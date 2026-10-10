# Network Traffic Monitor + Rule-Based IDS — Semester Roadmap (V1)

**Scope:** This roadmap covers **V1 only** — offline `.pcap` file analysis with a rule-based detection engine. This is the full semester deliverable, not a partial version of something bigger due this term.

**Live capture, multithreading, and the producer-consumer pipeline are explicitly out of scope here.** They become a separate, later personal project ("Project 2") once this one is submitted — see the note at the end of this file.

**Total duration:** 16 weeks.

---

##  Environment — Already Confirmed Working

No setup phase needed — this is done and verified:

- [x] Windows, 64-bit, personal machine
- [x] MSYS2 UCRT64 toolchain (GCC/G++)
- [x] CMake installed and working
- [x] Npcap + Npcap SDK 1.16 installed
- [x] PcapPlusPlus built specifically against the UCRT64/MinGW toolchain
- [x] `Packet++Test.exe` — 264/264 tests passed
- [x] VS Code configured (IntelliSense + correct compiler path)
- [x] **Real smoke test passed:** a test program reading `test.pcap` compiles, links, and runs correctly through your own CMake build (not just IntelliSense resolution)

You can start Phase 1 immediately once the learning phase below is underway.

---

## Phase 0 — Foundational Learning (Weeks 1–3)

**Goal:** Close the gap between Array/LinkedList/Stack/Queue/recursion and what the project actually needs. This phase runs in parallel with nothing else — it comes first, deliberately, because every later phase assumes this knowledge is solid.

### Week 1
- [ ] Hashing & hash tables (collision resolution, load factor, resizing)
- [ ] Amortized analysis (why resizing doesn't break the O(1) average claim)
- [ ] Bit manipulation basics (binary/hex arithmetic, AND/OR/shift operations)

### Week 2
- [ ] Tries (insertion, search, prefix matching)
- [ ] KMP algorithm (failure function concept — this is the prerequisite Aho-Corasick is built on, don't skip it)
- [ ] Begin Aho-Corasick (cp-algorithms.com reference, read slowly)

### Week 3
- [ ] Finish Aho-Corasick (failure links + output links, until it's intuitive, not memorized)
- [ ] Heaps / priority queues (insert, extract-min, heapify)
- [ ] Sliding window technique (as a general pattern, before applying it to timestamps)

### Ongoing, parallel to all three weeks above
- [ ] C++ pointers, stack vs. heap memory, dynamic allocation
- [*] Classes, constructors/destructors, RAII
- [ ] Smart pointers (`std::unique_ptr`) and move semantics

### Right before Phase 2 starts
- [*] Networking refresh: TCP three-way handshake and flags in detail, IPv4 header byte layout, PCAP file format spec — do this close to Phase 2, not weeks early, so it's fresh

**Exit criteria:** You can explain, without notes, what a load factor is and why resizing is still O(1) amortized; you can trace how a failure link redirects a mismatched trie walk; you understand why Dijkstra/heap "decrease-key" problems and connection-expiry "lazy invalidation" are the same underlying issue (this one will matter directly in Phase 6).

---

## Phase 1 — Design Lock (Week 4)

**Goal:** No ambiguity left before detection logic is written.

- [ ] Decide rule syntax — Snort-inspired, 3 rule types: `content`, `cidr`, `threshold`
- [ ] Write `RULE_FORMAT.md` with 5 worked example rules
- [ ] Write `DESIGN_SPEC.md` answering every item below, in writing

### Design-lock checklist
- [ ] Hash table: separate chaining, FNV-1a hash function, 0.75 max load factor, 2× resize policy — built fully from scratch, no `std::unordered_map`
- [ ] **Connection key normalization:** canonical ordering rule so `A→B` and `B→A` packets hash to the same connection entry
- [ ] Aho-Corasick: case-insensitive matching by default (attackers routinely evade case-sensitive matchers); payload treated as `(pointer, length)`, never null-terminated string, so embedded null bytes don't silently truncate scanning
- [ ] Radix trie for CIDR matching: built from scratch, using bitmask-and-compare internally at each node — **not** a flat per-rule bitmask scan (that reintroduces O(R) rule scanning, which defeats the trie's purpose)
- [ ] Connection-expiry heap: **lazy invalidation**, not in-place key update — push a new `(timestamp, key)` entry on every update, treat the hash table's stored timestamp as authoritative, discard stale heap entries on pop
- [ ] TCP state machine scope: explicitly simplified — `NONE → SYN_SENT → ESTABLISHED → FIN_WAIT → CLOSED` only. State this as a deliberate scope decision in the final report, not an oversight.
- [ ] Rule syntax scope: one `content` match per rule for V1 (no AND/OR logic within a single rule)
- [ ] "No match" / "no connection found" semantics: consistent result-struct pattern (`{bool found; ...}`) across every subsystem — no nulls, no magic sentinel values

**Exit criteria:** You can explain every item above out loud, without checking notes.

---

## Phase 2 — Packet Parsing Foundation (Weeks 5–6)

**Goal:** Read a real `.pcap` file and print fully decoded packets. No detection logic yet.

- [ ] `PCAPReader`: parse global header, iterate per-packet records (timestamp, captured length, original length, raw bytes)
- [ ] `EthernetParser`: src/dst MAC, EtherType
- [ ] `IPv4Parser`: src/dst IP, protocol field, **handle variable-length IHL/options correctly**, TTL
- [ ] `TCPParser` + `UDPParser`: ports, flags (SYN/ACK/FIN/RST), sequence numbers, payload offset/length
- [ ] Unit tests against 3–4 known sample `.pcap` files (Wireshark's public sample captures)
- [ ] **Validate output against Wireshark's decode of the same file**

**Exit criteria:** Tool output matches Wireshark's decode for the same sample file.

**Risk flag:** Variable-length IPv4 headers and TCP options are the #1 source of silent off-by-one bugs. Budget real time here.

---

## Phase 3 — Connection Tracking (Weeks 7–8)

**Goal:** Stateful TCP session tracking via your own hash table.

- [ ] `CustomHashTable`: unit-tested standalone, independent of networking code
- [ ] `ConnectionKey` struct with the canonical ordering rule from Phase 1 applied before hashing
- [ ] `ConnectionTracker`: hash-table lookup/insert per packet, update the simplified TCP state machine
- [ ] Print "N active connections" + per-connection state after processing a `.pcap`
- [ ] Benchmark: naive linear-scan lookup vs. custom hash table, across 100 / 1,000 / 10,000 synthetic connections — measured numbers in `benchmarks/`

**Exit criteria:** A `.pcap` with a known number of distinct TCP sessions produces the correct session count and correct final states.

---

## Phase 4 — Signature Matching Engine (Weeks 9–11) — Core Deliverable

**Goal:** Aho-Corasick multi-pattern matching over packet payloads. Do not rush this phase.

- [ ] Build a plain **Trie** of signature strings first — fully tested before adding failure links
- [ ] Add failure links (BFS-based construction) and output links
- [ ] Adversarial test cases for **overlapping patterns** (e.g., `"SHE"`, `"HE"`, `"HERS"` against `"SHERS"`)
- [ ] `RuleParser`: parse the rule file, route `content:"..."` patterns into the automaton at load time
- [ ] Wire automaton into the packet pipeline: every TCP/UDP payload scanned once, `Alert` raised on match
- [ ] Benchmark: naive per-rule substring search vs. Aho-Corasick, scaling rule count 10 → 500

**Exit criteria:** A test `.pcap` with 5 planted signatures (including overlapping ones) produces exactly the 5 expected alerts.

**Risk flag:** A buggy failure-link implementation still produces plausible-looking output. The overlapping-pattern test above is mandatory.

---

## Phase 5 — CIDR / IP Rule Matching (Week 12)

**Goal:** Radix trie for subnet-based rules, using bitmask comparisons internally.

- [ ] `RadixTrie` over 32-bit IP keys, insert by prefix length
- [ ] Unit tests: insert `10.0.0.0/8` and `10.1.0.0/16`, confirm correct **longest-prefix match**
- [ ] Route `cidr`-type rules from the rule file into the trie at load time
- [ ] Wire into pipeline: check src/dst IP of every packet against the trie

**Exit criteria:** Correct longest-prefix-match behavior with overlapping CIDR rules.

---

## Phase 6 — Expiry & Rate-Based Detection (Weeks 13–14)

**Goal:** Behavioral detection — what makes this an IDS, not a signature grep tool.

- [ ] `CustomMinHeap` keyed on last-seen timestamp for connection eviction
- [ ] **Lazy invalidation** exactly as locked in Phase 1 — push new timestamp entries, never update in place; hash table holds the authoritative value
- [ ] Confirm O(log C) per eviction via benchmark
- [ ] Sliding-window rate counters per source IP, using a custom hash table + a small custom list/circular buffer (no `std::deque`)
- [ ] Explicitly test bucket/window rollover logic — off-by-one bugs here are common
- [ ] `AlertEngine`: unify signature, CIDR, and rate alerts into one consistent output format

**Exit criteria:** A single `.pcap` run simultaneously triggers a signature alert, a blacklisted-subnet alert, and a rate-based alert — three mechanisms, one unified alert stream. **V1 feature-complete.**

---

## Phase 7 — Hardening, Benchmarking & Report (Week 15)

**Goal:** Polish, document, generate experimental evidence.

- [ ] Handle edge cases without crashing: empty `.pcap`, truncated packets, malformed headers, non-TCP/UDP protocols
- [ ] Full benchmark suite run and graphed (hash table, Aho-Corasick, heap — naive vs. structured, across increasing input sizes)
- [ ] `benchmarks/results.md` with tables/graphs
- [ ] README + architecture diagram + complexity table, written with precise, defensible language (collision strategy, hash function, load factor, worst case — not just "O(1)")
- [ ] `SCOPE_DECISIONS.md`: one sentence each for every deliberate scope cut (simplified TCP state machine, IPv4-only CIDR, single-pattern rules) — turns limitations into evidence of judgment

**Note:** This is a safe, complete submission state. Everything through here is required scope.

---

## Phase 8 — Evasion Test Suite (Week 16)

**Goal:** The offensive-security differentiator — since V2 is no longer competing for time this semester, this is real, achievable scope now, not a stretch goal.

- [ ] Build a small script that deliberately tries to evade your own detection: fragment payloads, split signatures across packet boundaries, encode/obfuscate payloads, throttle scan rate below your rate-detection window
- [ ] Document which techniques succeeded and why
- [ ] `EVASION_FINDINGS.md`: what you'd add to catch each evasion (e.g., stream reassembly, adaptive rate windows)

This is the single strongest interview differentiator in the whole project — it shows attacker-mindset thinking applied against your own defensive tool.

---

## Milestone Summary

| Milestone | Week | What's demonstrably working |
|---|---|---|
| M0: Core DSA + C++ fundamentals solid | 3 | Ready for implementation |
| M1: Design spec locked, no open decisions | 4 | Ready to code |
| M2: Packet decode matches Wireshark | 6 | Parsing correctness baseline |
| M3: Hash-table connection tracking | 8 | First custom DS proven + benchmarked |
| M4: Aho-Corasick detects planted signatures | 11 | Core DSA + security deliverable |
| M5: CIDR + rate detection live | 14 | **V1 feature-complete** |
| M6: V1 polished, benchmarked, documented | 15 | **Submission-ready** |
| M7: Evasion findings documented | 16 | Offensive-security differentiator |

---

## Weekly Discipline Rule

At the end of every week, you should be able to run the tool against a known `.pcap` and get a deterministic, verifiable result. If you can't, don't start the next phase.

---

## Looking Ahead — "Project 2" (Not Part of This Roadmap)

Once V1 is submitted, live capture becomes its own project, picking up where this leaves off:

- Live capture via PcapPlusPlus's live-device APIs
- Custom bounded ring buffer (producer/consumer), with an explicit overflow policy
- Thread synchronization (mutex + condition variable first; lock-free SPSC as an optional stretch comparison)
- Resolving the Windows Device Guard/App Control block for running a live-capture executable (or developing in WSL2/Linux instead, if the block turns out to be policy-enforced rather than user-configurable)
- Administrator-privilege requirements for live interface access

None of this needs attention until V1 is done.
