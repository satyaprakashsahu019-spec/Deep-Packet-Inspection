"""
DPI Engine - Main multi-threaded orchestrator.
Corresponds to include/dpi_engine.h and src/dpi_engine.cpp.
"""

from __future__ import annotations
import threading
import time
from dataclasses import dataclass
from typing import Optional
from .types import (
    FiveTuple,
    PacketJob,
    PacketAction,
    DPIStats,
    AppType,
)
from .pcap import PcapReader, PcapWriter, RawPacket
from .parser import PacketParser, ParsedPacket, Protocol
from .queue import ThreadSafeQueue
from .rules import RuleManager
from .connection_tracker import GlobalConnectionTable
from .fast_path import FPManager
from .load_balancer import LBManager


@dataclass
class DPIConfig:
    num_load_balancers: int = 2
    fps_per_lb: int = 2
    queue_size: int = 10000
    rules_file: str = ""
    verbose: bool = False


class DPIEngine:
    """
    Main DPI Engine orchestrator.
    Pipelines packets: Reader -> LB threads -> FP threads -> Output Writer thread.
    """

    def __init__(self, config: Optional[DPIConfig] = None) -> None:
        self.config = config or DPIConfig()
        self.stats = DPIStats()

        total_fps = self.config.num_load_balancers * self.config.fps_per_lb
        print("\n"
              "+==============================================================+\n"
              "|                    DPI ENGINE v1.0                           |\n"
              "|               Deep Packet Inspection System                  |\n"
              "+==============================================================+\n"
              "| Configuration:                                               |\n"
              f"|   Load Balancers:    {self.config.num_load_balancers:>3}                                     |\n"
              f"|   FPs per LB:        {self.config.fps_per_lb:>3}                                     |\n"
              f"|   Total FP threads:  {total_fps:>3}                                     |\n"
              "+==============================================================+")

        self.rule_manager = RuleManager()
        self.global_conn_table: Optional[GlobalConnectionTable] = None
        self.fp_manager: Optional[FPManager] = None
        self.lb_manager: Optional[LBManager] = None

        self.output_queue: ThreadSafeQueue[PacketJob] = ThreadSafeQueue(self.config.queue_size)
        self.output_writer: Optional[PcapWriter] = None

        self._running = False
        self._reader_thread: Optional[threading.Thread] = None
        self._output_thread: Optional[threading.Thread] = None

    def initialize(self) -> bool:
        if self.config.rules_file:
            self.rule_manager.load_rules(self.config.rules_file)

        total_fps = self.config.num_load_balancers * self.config.fps_per_lb

        # Callback invoked when an FP worker processes a packet
        def output_cb(job: PacketJob, action: PacketAction) -> None:
            if action == PacketAction.FORWARD:
                self.output_queue.push(job)
                self.stats.record_forward()
            else:
                self.stats.record_drop()

        # Create FP Manager
        self.fp_manager = FPManager(
            num_fps=total_fps,
            rule_manager=self.rule_manager,
            output_callback=output_cb,
            queue_size=self.config.queue_size,
        )

        # Create LB Manager
        self.lb_manager = LBManager(
            num_lbs=self.config.num_load_balancers,
            fps_per_lb=self.config.fps_per_lb,
            fp_queues=self.fp_manager.get_queue_ptrs(),
            queue_size=self.config.queue_size,
        )

        # Register trackers with global table
        self.global_conn_table = GlobalConnectionTable(total_fps)
        for i in range(total_fps):
            self.global_conn_table.register_tracker(i, self.fp_manager.get_fp(i).conn_tracker)

        print("[DPIEngine] Initialized successfully")
        return True

    def start(self) -> None:
        if self._running:
            return
        self._running = True

        # Start output writer thread
        self._output_thread = threading.Thread(target=self._output_thread_func, name="OutputWriter", daemon=True)
        self._output_thread.start()

        # Start FP workers
        if self.fp_manager:
            self.fp_manager.start_all()

        # Start LB threads
        if self.lb_manager:
            self.lb_manager.start_all()

        print("[DPIEngine] All threads started")

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False

        # Stop LBs first
        if self.lb_manager:
            self.lb_manager.stop_all()

        # Stop FPs
        if self.fp_manager:
            self.fp_manager.stop_all()

        # Shutdown and stop output thread
        self.output_queue.shutdown()
        if self._output_thread and self._output_thread.is_alive():
            self._output_thread.join(timeout=2.0)

        if self.output_writer:
            self.output_writer.close()
            self.output_writer = None

        print("[DPIEngine] All threads stopped")

    def process_file(self, input_file: str, output_file: str) -> bool:
        print(f"\n[DPIEngine] Processing: {input_file}")
        print(f"[DPIEngine] Output to:  {output_file}\n")

        if self.fp_manager is None:
            if not self.initialize():
                return False

        # Open output file
        self.output_writer = PcapWriter(output_file)

        # Start workers
        self.start()

        # Run reader
        self._reader_thread = threading.Thread(
            target=self._reader_thread_func, args=(input_file,), name="PcapReader", daemon=True
        )
        self._reader_thread.start()
        self._reader_thread.join()

        # Allow pipelines to drain
        time.sleep(0.3)

        # Stop all threads
        self.stop()

        # Print final reports
        print(self.generate_report())
        if self.fp_manager:
            print(self.fp_manager.generate_classification_report())

        return True

    def _reader_thread_func(self, input_file: str) -> None:
        reader = PcapReader()
        if not reader.open(input_file):
            print(f"[Reader] Error: Cannot open input file {input_file}")
            return

        # Initialize output writer global header from input
        if self.output_writer and reader.global_header:
            self.output_writer.open(self.output_writer.filename, reader.global_header)

        print("[Reader] Starting packet processing...")
        packet_id = 0

        for raw in reader:
            parsed = PacketParser.parse(raw)
            if not parsed:
                continue

            # Only process IPv4 TCP/UDP
            if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
                continue

            tuple_ = FiveTuple(
                src_ip=parsed.src_ip,
                dst_ip=parsed.dest_ip,
                src_port=parsed.src_port,
                dst_port=parsed.dest_port,
                protocol=parsed.protocol,
            )

            job = PacketJob(
                packet_id=packet_id,
                tuple=tuple_,
                data=raw.data,
                eth_offset=0,
                ip_offset=14,
                payload_offset=parsed.payload_offset,
                payload_length=parsed.payload_length,
                tcp_flags=parsed.tcp_flags,
                ts_sec=raw.header.ts_sec,
                ts_usec=raw.header.ts_usec,
            )
            packet_id += 1

            self.stats.add_packet(len(raw.data), parsed.has_tcp, parsed.has_udp)

            if self.lb_manager:
                lb = self.lb_manager.get_lb_for_packet(tuple_)
                lb.input_queue.push(job)

        print(f"[Reader] Finished reading {packet_id} packets")
        reader.close()

    def _output_thread_func(self) -> None:
        while self._running or not self.output_queue.empty():
            job = self.output_queue.pop_with_timeout(0.1)
            if job is None:
                continue
            if self.output_writer:
                self.output_writer.write_packet(
                    data=job.data,
                    ts_sec=job.ts_sec,
                    ts_usec=job.ts_usec,
                )

    # ================= Rule Delegation =================
    def block_ip(self, ip: str) -> None:
        self.rule_manager.block_ip(ip)

    def unblock_ip(self, ip: str) -> None:
        self.rule_manager.unblock_ip(ip)

    def block_app(self, app: AppType | str) -> None:
        self.rule_manager.block_app(app)

    def unblock_app(self, app: AppType | str) -> None:
        self.rule_manager.unblock_app(app)

    def block_domain(self, domain: str) -> None:
        self.rule_manager.block_domain(domain)

    def unblock_domain(self, domain: str) -> None:
        self.rule_manager.unblock_domain(domain)

    def block_port(self, port: int) -> None:
        self.rule_manager.block_port(port)

    def unblock_port(self, port: int) -> None:
        self.rule_manager.unblock_port(port)

    def load_rules(self, filename: str) -> bool:
        return self.rule_manager.load_rules(filename)

    def save_rules(self, filename: str) -> bool:
        return self.rule_manager.save_rules(filename)

    # ================= Reporting =================
    def generate_report(self) -> str:
        s = self.stats.to_dict()
        lines = [
            "",
            "+==============================================================+",
            "|                      PROCESSING REPORT                       |",
            "+==============================================================+",
            f"| Total Packets:      {s['total_packets']:>10}                             |",
            f"| Forwarded:          {s['forwarded_packets']:>10}                             |",
            f"| Dropped:            {s['dropped_packets']:>10}                             |",
            f"| TCP Packets:        {s['tcp_packets']:>10}                             |",
            f"| UDP Packets:        {s['udp_packets']:>10}                             |",
            "+==============================================================+",
        ]
        if self.global_conn_table:
            lines.append(self.global_conn_table.generate_report())
        return "\n".join(lines) + "\n"
