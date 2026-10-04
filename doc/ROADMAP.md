# Network Traffic Monitor + Rule-Based IDS — Semester Roadmap

**Total duration:** 16 weeks
**Structure:** V1 (offline `.pcap` analysis) is feature-complete and submittable on its own by Week 12. V2 (live capture) and the evasion test suite are additive, not required for a complete grade.

---

## Phase 0 — Setup & Design Lock (Week 1)

**Goal:** Remove every ambiguity before detection logic is written.

- [ ] Choose language, repo structure, build system (CMake/Makefile or Python venv)
- [ ] Study PCAP file format (global header, per-packet record header)
- [ ] Study Ethernet / IPv4 / TCP / UDP header formats (RFC 791, RFC 793, RFC 768)
- [ ] Decide rule syntax — Snort-inspired, 3 rule types: `content`, `cidr`, `threshold`
- [ ] Write `RULE_FORMAT.md` with 5 worked example rules
- [ ] Write `DESIGN_SPEC.md` answering every item below, in writing

### Design-lock checklist (must be answered before Phase 1)
- [ ] Hash table: chaining strategy, hash function (FNV-1a), max load factor (0.75), resize policy (2×)
- [ ] **Connection key normalization:** canonical ordering rule so `A→B` and `B→A` hash to the same entry (e.g., always place the numerically lower `(IP, port)` pair first before hashing)
- [ ] Aho-Corasick: case-sensitive or normalized? binary-safe or text-only payloads?
- [ ] Radix trie: IPv4 only for V1 (IPv6 is stretch-only, explicitly out of scope)
- [ ] Ring buffer (V2): capacity, overflow policy (drop-oldest vs. drop-newest + dropped-packet counter)
- [ ] Ring buffer synchronization mechanism: mutex + condition variable, or lock-free single-producer/single-consumer atomics — pick one now, don't decide mid-Phase-7
- [ ] Connection-expiry heap: **lazy invalidation**, not in-place key update (see Phase 5 notes)
- [ ] TCP state machine scope: explicitly simplified — `NONE → SYN_SENT → ESTABLISHED → FIN_WAIT → CLOSED` only; no `SYN_RECEIVED`, no simultaneous close, no mid-session RST handling. State this as a deliberate scope decision in the final report.
- [ ] Rule syntax scope: one `content` match per rule for V1 (no AND/OR logic across multiple patterns) — explicit scope limit
- [ ] "No match" / "no connection found" semantics defined for each subsystem (signature engine, CIDR matcher, connection tracker)

**Exit criteria:** You can explain every item above out loud, without checking notes.

---

## Phase 1 — Packet Parsing Foundation (Weeks 2–3)

**Goal:** Read a real `.pcap` file and print fully decoded packets. No detection logic yet.

- [ ] `PCAPReader`: parse global header (magic number, version, snaplen), iterate per-packet records (timestamp, captured length, original length, raw bytes)
- [ ] `EthernetParser`: extract src/dst MAC, EtherType
- [ ] `IPv4Parser`: extract src/dst IP, protocol field, **handle variable-length IHL/options correctly**, TTL
- [ ] `TCPParser` + `UDPParser`: ports, flags (SYN/ACK/FIN/RST), sequence numbers, payload offset/length
- [ ] Unit tests against 3–4 known sample `.pcap` files (Wireshark's public sample captures)
- [ ] **Validate output against Wireshark's decode of the same file** — this is your ground truth

**Exit criteria:** Tool output matches Wireshark's decode (src→dst, ports, protocol, flags) for the same sample file.

**Risk flag:** Variable-length IPv4 headers and TCP options are the #1 source of silent off-by-one bugs. Budget real time here.

---

## Phase 2 — Connection Tracking (Weeks 4–5)

**Goal:** Stateful TCP session tracking via a custom hash table.

- [ ] `CustomHashTable`: separate chaining, FNV-1a hash over concatenated 5-tuple bytes, 0.75 load factor, 2× resize — unit-tested standalone, independent of networking code
- [ ] `ConnectionKey` struct: `(src_ip, dst_ip, src_port, dst_port, protocol)` with the **canonical ordering rule locked in Phase 0** applied before hashing
- [ ] `ConnectionTracker`: hash-table lookup/insert per packet, update simplified TCP state machine
- [ ] Print "N active connections" + per-connection state after processing a `.pcap`
- [ ] Benchmark: naive linear-scan lookup vs. custom hash table, across 100 / 1,000 / 10,000 synthetic connections — real measured numbers in `benchmarks/`

**Exit criteria:** A `.pcap` with a known number of distinct TCP sessions produces the correct session count and correct final states (completed handshakes vs. incomplete scan attempts).

---

## Phase 3 — Signature Matching Engine (Weeks 6–8) — Core Deliverable

**Goal:** Aho-Corasick multi-pattern matching over packet payloads. Do not rush this phase.

- [ ] Build a plain **Trie** of signature strings first — insertion + exact/prefix lookup, fully tested before adding failure links
- [ ] Add **failure links** (BFS-based construction) and **output links** (a node's own match plus any pattern reachable via its failure chain)
- [ ] Adversarial test cases for **overlapping patterns** (e.g., `"SHE"`, `"HE"`, `"HERS"` against text `"SHERS"`) before trusting it on real traffic
- [ ] `RuleParser`: parse the rule file, route `content:"..."` patterns into the automaton at load time, map pattern → rule metadata (msg, sid)
- [ ] Wire automaton into the packet pipeline: every TCP/UDP payload scanned once, `Alert` raised on match
- [ ] Benchmark: naive per-rule substring search vs. Aho-Corasick, scaling rule count 10 → 500 — gap should visibly widen as rule count grows

**Exit criteria:** A test `.pcap` with 5 planted signatures (including overlapping ones) produces exactly the 5 expected alerts — no false positives, no missed matches.

**Risk flag:** A buggy failure-link implementation still produces *plausible-looking* output. The overlapping-pattern test above is mandatory, not optional.

---

## Phase 4 — CIDR / IP Rule Matching (Week 9)

**Goal:** Radix trie for subnet-based rules.

- [ ] `RadixTrie` over 32-bit IP keys, insert by prefix length
- [ ] Unit tests: insert `10.0.0.0/8` and `10.1.0.0/16`, confirm correct **longest-prefix match** for various test IPs
- [ ] Route `cidr`-type rules from the rule file into the trie at load time
- [ ] Wire into pipeline: check src/dst IP of every packet against the trie

**Exit criteria:** Correct longest-prefix-match behavior with overlapping CIDR rules (e.g., a `/24` alert rule nested inside a `/8`).

---

## Phase 5 — Expiry & Rate-Based Detection (Weeks 10–11)

**Goal:** Behavioral detection — what makes this an IDS, not a signature grep tool.

- [ ] `CustomMinHeap` keyed on last-seen timestamp for connection eviction
- [ ] **Lazy invalidation pattern (not in-place key update):** on every packet, push a new `(timestamp, connection_key)` entry; the hash table entry holds the authoritative last-seen time. On pop, compare the popped timestamp against the hash table's current value — if stale, discard and pop again. This mirrors the same decrease-key problem solved via lazy deletion in the Dijkstra implementation; same fix, same justification.
- [ ] Confirm O(log C) per eviction via benchmark (not a full table scan)
- [ ] Sliding-window rate counters: circular buffer of time buckets per source IP, for `threshold:` rules
- [ ] **Explicitly test bucket rollover/reset logic** (off-by-one bugs in circular time-bucket indexing are a common failure mode — don't assume it's correct without a dedicated test)
- [ ] `AlertEngine`: unify signature, CIDR, and rate alerts into one consistent output format (console + JSON log)

**Exit criteria:** A single `.pcap` run simultaneously triggers a signature alert, a blacklisted-subnet alert, and a port-scan (rate-based) alert — three detection mechanisms, one unified alert stream. **This is the V1 feature-complete milestone.**

---

## Phase 6 — V1 Hardening & Report Prep (Week 12)

**Goal:** Polish, document, generate experimental evidence. Safe stopping point.

- [ ] Handle edge cases without crashing: empty `.pcap`, truncated packets, malformed headers, non-TCP/UDP protocols (ICMP, etc.)
- [ ] Full benchmark suite run and graphed (hash table, Aho-Corasick, heap — naive vs. structured, across increasing input sizes)
- [ ] `benchmarks/results.md` with tables/graphs
- [ ] README + architecture diagram + complexity table, written with precise, defensible language (not "O(1) lookup" — the full specified version: collision strategy, hash function, load factor, worst case)

**Note:** If time runs short, V1 alone — fully correct, benchmarked, documented — is a complete and gradable project. Do not sacrifice Phase 1–5 quality to rush Phase 7.

---

## Phase 7 — V2: Live Capture (Weeks 13–15)

**Goal:** Swap file-based input for live traffic, without modifying the detection engine.

- [ ] Integrate libpcap (Linux) or Npcap (Windows) — thin binding only, not a custom capture implementation
- [ ] Confirm raw packet count prints correctly from a live interface
- [ ] `CustomRingBuffer`: bounded circular buffer, producer (capture thread) / consumer (detection engine), using the synchronization mechanism and overflow policy locked in Phase 0
- [ ] Unit-test the ring buffer in isolation: simulate a fast producer + slow consumer, confirm the overflow policy triggers correctly
- [ ] Wire capture → ring buffer → **existing, unmodified** `PacketParser` + detection engine
- [ ] Live test: run `nmap` against a test VM while the tool listens; confirm the port-scan alert fires in real time

**Exit criteria:** A live port scan against a test machine produces a live alert within a second or two, using the exact same detection engine validated in Phases 1–5.

**Risk flag:** This phase bundles three independent hard problems (new library API, thread synchronization, live-traffic testing) — budget the full 3 weeks; don't compress it.

---

## Phase 8 — Offensive-Angle Addition (Week 16, Stretch)

**Goal:** Add a red-team differentiator on top of the defensive tool.

- [ ] Build a small evasion test script: fragment payloads, split signatures across packet boundaries, encode payloads, throttle scan rate below the detection window threshold
- [ ] Document which techniques successfully evaded detection and why
- [ ] `EVASION_FINDINGS.md`: what you'd add to catch each evasion (e.g., TCP stream reassembly, adaptive rate windows)

This is the strongest interview differentiator in the whole project — it demonstrates attacker-mindset thinking applied against your own defensive control, not just the control itself.

---

## Milestone Summary

| Milestone | Week | What's demonstrably working |
|---|---|---|
| M1: Packet decode matches Wireshark | 3 | Parsing correctness baseline |
| M2: Hash-table connection tracking | 5 | First custom DS proven + benchmarked |
| M3: Aho-Corasick detects planted signatures | 8 | Core DSA + security deliverable |
| M4: CIDR + rate detection live | 11 | V1 feature-complete |
| M5: V1 polished, benchmarked, documented | 12 | Safe fallback submission state |
| M6: Live capture detects a real scan | 15 | Full project complete |
| M7 (stretch): Evasion findings documented | 16 | Offensive-security differentiator |

---

## Weekly Discipline Rule

At the end of every week, you should be able to run the tool against a known `.pcap` and get a deterministic, verifiable result. If you can't, don't start the next phase — in a layered pipeline like this, debugging compounds badly if a lower layer is silently wrong.
