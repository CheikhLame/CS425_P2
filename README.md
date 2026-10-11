# Project 2:    

- Name: Cheikh Lame
- Email: cheikhlame@u.boisestate.edu
- Class: CS425-001


## Known Bugs or Issues

No known issues remain in the current implementation. The project compiles cleanly in the release, debug, and test configurations and passes the Unity test suite via `make check`.

## Experience

This assignment was really confusing in terms of execution. I had to heavily rely on AI to complete it. Even after completing the assignment, I am not 100% sure what it is expected to do. The textbook has helped in me understanding the specifics of what exactly the project is supposed to do.
## Analysis

The reliable transfer works because each packet carries a checksum, a sequence number, and a cumulative ACK. The checksum lets the receiver discard corrupted data silently, which makes corruption behave like a loss. Sequence numbers allow the receiver to detect duplicates or out-of-order packets and keep the logic simple by acking only the next expected value. The sender then uses cumulative acknowledgments and a timer to recover from missed packets by retransmitting from the oldest unacknowledged point.

The Go-Back-N window matters because it improves throughput by allowing multiple packets to be in flight at once. With a small window, the sender spends more time idle waiting for ACKs, while a larger window keeps the channel busy and amortizes the propagation delay. The timer is essential because loss is silent; without a timeout, the sender would never know to retransmit a dropped or corrupted packet.

Overall, the exercise demonstrates why TCP uses checksums, sequence numbers, cumulative ACKs, timeouts, and sliding windows: these mechanisms turn an unreliable datagram service into a reliable, ordered byte stream.

## Results

Each configuration transferred a 1 MiB random file three times through the relay with `--delay 50` and the default 250 ms retransmission timeout. Every received copy was checked against the source with `cmp`; all 12 comparisons were identical.

| Window | Loss | Mean time (s) | Throughput (KiB/s) |
|-------:|-----:|--------------:|-------------------:|
| 1 | 0% | 103.835 | 9.86 |
| 16 | 0% | 6.708 | 152.66 |
| 1 | 5% | 128.055 | 8.00 |
| 16 | 5% | 25.853 | 39.61 |

For window 1 with no loss, the sender took an average of 103.835 seconds for 1,025 packets, or about **101.3 ms per round trip** (`103.835 / 1,025`). The relay contributes 100 ms, leaving roughly 1.3 ms for endpoint work: packet encoding and checksum calculation, socket and kernel processing, scheduling, polling, and timer granularity.

Increasing the window to 16 reduced the no-loss mean from 103.835 seconds to 6.708 seconds, a **15.5× speedup**, close to the ideal 16×. Multiple packets can now be in flight during each round trip, so the sender spends much less time waiting. The remaining difference from 16× comes from protocol and operating-system overhead, the finite transfer/window boundaries, and cumulative ACK timing.

With 5% loss, window 1 increased from 103.835 to 128.055 seconds (about 1.23×); window 16 increased from 6.708 to 25.853 seconds (about 3.85×). A stop-and-wait timeout retransmits only its one outstanding packet. With Go-Back-N, a lost packet holds back the cumulative ACK, and a timeout retransmits the whole outstanding window, including packets that may already have arrived. That wastes more transmission work for a larger window, so loss erodes its throughput advantage.
