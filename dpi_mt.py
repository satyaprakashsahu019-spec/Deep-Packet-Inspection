#!/usr/bin/env python3
"""
Multi-Threaded DPI Engine with Consistent Flow Hashing.
Direct Python conversion of src/dpi_mt.cpp.
"""

from __future__ import annotations
import sys
import threading
import time
from typing import Dict, List, Optional
from dpi.types import (
    FiveTuple,
    AppType,
    app_type_to_string,
    sni_to_app_type,
)
from dpi.pcap import PcapReader, PcapWriter, RawPacket
from dpi.parser import PacketParser
from dpi.extractors import SNIExtractor, HTTPHostExtractor
from dpi.rules import BlockingRules
from dpi.queue import ThreadSafeQueue


class PacketJobMT:
    def __init__(
        self,
        job_id: int,
        tuple_: FiveTuple,
        data: bytes,
        payload_offset: int,
        payload_length: int,
        ts_sec: int,
        ts_usec: int,
    ) -> None:
        self.id = job_id
        self.tuple = tuple_
        self.data = data
        self.payload_offset = payload_offset
        self.payload_length = payload_length
        self.ts_sec = ts_sec
        self.ts_usec = ts_usec

    @property
    def payload(self) -> bytes:
        if self.payload_length > 0:
            return self.data[self.payload_offset: self.payload_offset + self.payload_length]
        return b""


class FlowEntryMT:
    def __init__(self, tuple_: FiveTuple) -> None:
        self.tuple = tuple_
        self.app_type: AppType = AppType.UNKNOWN
        self.sni: str = ""
        self.packets: int = 0
        self.bytes: int = 0
        self.blocked: bool = False
        self.classified: bool = False


class StatsMT:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.forwarded: int = 0
        self.dropped: int = 0
        self.tcp_packets: int = 0
        self.udp_packets: int = 0
        self.app_counts: Dict[AppType, int] = {}
        self.detected_snis: Dict[str, AppType] = {}

    def record_app(self, app: AppType, sni: str) -> None:
        with self._lock:
            self.app_counts[app] = self.app_counts.get(app, 0) + 1
            if sni:
                if sni not in self.detected_snis or self.detected_snis[sni] in (AppType.DNS, AppType.HTTPS, AppType.HTTP, AppType.UNKNOWN):
                    self.detected_snis[sni] = app


class FastPathWorker:
    def __init__(
        self,
        fp_id: int,
        rules: BlockingRules,
        stats: StatsMT,
        output_queue: ThreadSafeQueue[PacketJobMT],
    ) -> None:
        self.id = fp_id
        self.rules = rules
        self.stats = stats
        self.output_queue = output_queue
        self.input_queue: ThreadSafeQueue[PacketJobMT] = ThreadSafeQueue(10000)
        self.flows: Dict[FiveTuple, FlowEntryMT] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.processed: int = 0

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, name=f"FP-{self.id}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self.input_queue.shutdown()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while self._running:
            pkt = self.input_queue.pop_with_timeout(0.1)
            if pkt is None:
                continue

            self.processed += 1
            flow = self.flows.get(pkt.tuple)
            if flow is None:
                flow = FlowEntryMT(pkt.tuple)
                self.flows[pkt.tuple] = flow

            flow.packets += 1
            flow.bytes += len(pkt.data)

            if not flow.classified:
                self._classify_flow(pkt, flow)

            if not flow.blocked:
                flow.blocked = self.rules.is_blocked(pkt.tuple.src_ip, flow.app_type, flow.sni)

            self.stats.record_app(flow.app_type, flow.sni)

            if flow.blocked:
                self.stats.dropped += 1
            else:
                self.stats.forwarded += 1
                self.output_queue.push(pkt)

    def _classify_flow(self, pkt: PacketJobMT, flow: FlowEntryMT) -> None:
        if pkt.tuple.dst_port == 443 and pkt.payload_length > 5:
            sni = SNIExtractor.extract(pkt.payload)
            if sni:
                flow.sni = sni
                flow.app_type = sni_to_app_type(sni)
                flow.classified = True
                return

        if pkt.tuple.dst_port == 80 and pkt.payload_length > 10:
            host = HTTPHostExtractor.extract(pkt.payload)
            if host:
                flow.sni = host
                flow.app_type = sni_to_app_type(host)
                flow.classified = True
                return

        if pkt.tuple.dst_port == 53 or pkt.tuple.src_port == 53:
            flow.app_type = AppType.DNS
            flow.classified = True
            return

        if pkt.tuple.dst_port == 443:
            flow.app_type = AppType.HTTPS
        elif pkt.tuple.dst_port == 80:
            flow.app_type = AppType.HTTP


class LoadBalancerWorker:
    def __init__(
        self,
        lb_id: int,
        fp_workers: List[FastPathWorker],
    ) -> None:
        self.id = lb_id
        self.fps = fp_workers
        self.input_queue: ThreadSafeQueue[PacketJobMT] = ThreadSafeQueue(10000)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.dispatched: int = 0

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, name=f"LB-{self.id}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self.input_queue.shutdown()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while self._running:
            pkt = self.input_queue.pop_with_timeout(0.1)
            if pkt is None:
                continue

            h = abs(hash((pkt.tuple.src_ip, pkt.tuple.dst_ip, pkt.tuple.src_port, pkt.tuple.dst_port, pkt.tuple.protocol)))
            fp_idx = h % len(self.fps)
            self.fps[fp_idx].input_queue.push(pkt)
            self.dispatched += 1


def main() -> int:
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.pcap> <output.pcap> [--block-ip <ip>] [--block-app <app>] [--block-domain <dom>]")
        return 1

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    rules = BlockingRules()
    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--block-ip" and i + 1 < len(sys.argv):
            i += 1
            rules.block_ip(sys.argv[i])
        elif arg == "--block-app" and i + 1 < len(sys.argv):
            i += 1
            rules.block_app(sys.argv[i])
        elif arg == "--block-domain" and i + 1 < len(sys.argv):
            i += 1
            rules.block_domain(sys.argv[i])
        i += 1

    print("\n"
          "+==============================================================+\n"
          "|               MULTI-THREADED DPI ENGINE v1.0                 |\n"
          "+==============================================================+\n")

    reader = PcapReader()
    if not reader.open(input_file):
        return 1

    writer = PcapWriter(output_file, reader.global_header)
    output_queue: ThreadSafeQueue[PacketJobMT] = ThreadSafeQueue(20000)
    stats = StatsMT()

    # 4 Fast Path workers, 2 Load Balancers (2 FPs each)
    num_fps = 4
    num_lbs = 2
    fps = [FastPathWorker(idx, rules, stats, output_queue) for idx in range(num_fps)]
    lbs = [
        LoadBalancerWorker(0, fps[0:2]),
        LoadBalancerWorker(1, fps[2:4]),
    ]

    # Start Output Writer Thread
    writer_running = threading.Event()
    writer_running.set()

    def output_writer_func():
        while writer_running.is_set() or not output_queue.empty():
            pkt = output_queue.pop_with_timeout(0.1)
            if pkt:
                writer.write_packet(pkt.data, pkt.ts_sec, pkt.ts_usec)

    out_thread = threading.Thread(target=output_writer_func, name="OutputWriter", daemon=True)
    out_thread.start()

    # Start FP and LB threads
    for fp in fps:
        fp.start()
    for lb in lbs:
        lb.start()

    print("[Reader] Reading packets...")
    job_id = 0
    start_time = time.time()

    for raw in reader:
        parsed = PacketParser.parse(raw)
        if not parsed or not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
            continue

        tuple_ = FiveTuple(
            src_ip=parsed.src_ip,
            dst_ip=parsed.dest_ip,
            src_port=parsed.src_port,
            dst_port=parsed.dest_port,
            protocol=parsed.protocol,
        )

        job = PacketJobMT(
            job_id=job_id,
            tuple_=tuple_,
            data=raw.data,
            payload_offset=parsed.payload_offset,
            payload_length=parsed.payload_length,
            ts_sec=raw.header.ts_sec,
            ts_usec=raw.header.ts_usec,
        )
        job_id += 1
        stats.total_packets += 1
        stats.total_bytes += len(raw.data)
        if parsed.has_tcp:
            stats.tcp_packets += 1
        elif parsed.has_udp:
            stats.udp_packets += 1

        # Route to LB
        h = abs(hash((tuple_.src_ip, tuple_.dst_ip, tuple_.src_port, tuple_.dst_port, tuple_.protocol)))
        lb_idx = h % num_lbs
        lbs[lb_idx].input_queue.push(job)

    reader.close()
    print(f"[Reader] Finished reading {job_id} packets")

    # Drain queues
    time.sleep(0.3)

    for lb in lbs:
        lb.stop()
    for fp in fps:
        fp.stop()

    writer_running.clear()
    output_queue.shutdown()
    out_thread.join(timeout=2.0)
    writer.close()

    elapsed = max(time.time() - start_time, 0.001)

    print("\n"
          "+==============================================================+\n"
          "|                      PROCESSING REPORT                       |\n"
          "+==============================================================+\n"
          f"| Total Packets:      {stats.total_packets:>10}                             |\n"
          f"| Forwarded:          {stats.forwarded:>10}                             |\n"
          f"| Dropped:            {stats.dropped:>10}                             |\n"
          f"| TCP Packets:        {stats.tcp_packets:>10}                             |\n"
          f"| UDP Packets:        {stats.udp_packets:>10}                             |\n"
          f"| Elapsed Time:       {elapsed:>9.2f}s                             |\n"
          "+==============================================================+\n"
          "|                    APPLICATION BREAKDOWN                     |\n"
          "+==============================================================+")

    sorted_apps = sorted(stats.app_counts.items(), key=lambda kv: kv[1], reverse=True)
    for app, count in sorted_apps:
        pct = (100.0 * count / stats.total_packets) if stats.total_packets > 0 else 0.0
        bar = "#" * int(pct / 5)
        print(f"| {app_type_to_string(app):<15}{count:>8} {pct:>5.1f}% {bar:<20}  |")

    print("+==============================================================+")

    if stats.detected_snis:
        print("\n[Detected Applications/Domains]")
        for sni, app in sorted(stats.detected_snis.items(), key=lambda kv: kv[0]):
            print(f"  - {sni} -> {app_type_to_string(app)}")

    print(f"\nOutput written to: {output_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
