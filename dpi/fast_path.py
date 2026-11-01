"""
Fast Path (FP) processor thread implementation.
Corresponds to include/fast_path.h and src/fast_path.cpp.
"""

from __future__ import annotations
import threading
import time
from typing import Callable, Dict, List, Optional
from .types import (
    FiveTuple,
    PacketJob,
    PacketAction,
    ConnectionState,
    AppType,
    sni_to_app_type,
    app_type_to_string,
    Connection,
)
from .queue import ThreadSafeQueue
from .connection_tracker import ConnectionTracker
from .rules import RuleManager
from .extractors import SNIExtractor, HTTPHostExtractor, DNSExtractor
from .parser import TCPFlags

PacketOutputCallback = Callable[[PacketJob, PacketAction], None]


class FastPathProcessor:
    """
    Worker thread that performs:
      1. Flow tracking
      2. Deep Packet Inspection (TLS SNI, HTTP Host, DNS)
      3. Rule matching (blocking decisions)
      4. Forwarding or dropping packets
    """

    def __init__(
        self,
        fp_id: int,
        rule_manager: Optional[RuleManager],
        output_callback: Optional[PacketOutputCallback],
        queue_size: int = 10000,
    ) -> None:
        self.fp_id = fp_id
        self.input_queue: ThreadSafeQueue[PacketJob] = ThreadSafeQueue(queue_size)
        self.conn_tracker = ConnectionTracker(fp_id=fp_id)
        self.rule_manager = rule_manager
        self.output_callback = output_callback

        # Statistics
        self.packets_processed: int = 0
        self.packets_forwarded: int = 0
        self.packets_dropped: int = 0
        self.sni_extractions: int = 0
        self.classification_hits: int = 0

        # Thread management
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, name=f"FP-{self.fp_id}", daemon=True)
        self._thread.start()
        print(f"[FP{self.fp_id}] Started")

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self.input_queue.shutdown()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        print(f"[FP{self.fp_id}] Stopped (processed {self.packets_processed} packets)")

    def is_running(self) -> bool:
        return self._running

    def _run(self) -> None:
        while self._running:
            job = self.input_queue.pop_with_timeout(0.1)
            if job is None:
                # Periodic stale flow cleanup
                self.conn_tracker.cleanup_stale(300.0)
                continue

            self.packets_processed += 1
            action = self.process_packet(job)

            if self.output_callback:
                self.output_callback(job, action)

            if action == PacketAction.DROP:
                self.packets_dropped += 1
            else:
                self.packets_forwarded += 1

    def process_packet(self, job: PacketJob) -> PacketAction:
        conn = self.conn_tracker.get_or_create_connection(job.tuple)

        # Update stats
        self.conn_tracker.update_connection(conn, len(job.data), is_outbound=True)

        # TCP state tracking
        if job.tuple.protocol == 6:
            self._update_tcp_state(conn, job.tcp_flags)

        # If already blocked, drop immediately
        if conn.state == ConnectionState.BLOCKED:
            return PacketAction.DROP

        # If connection is not yet fully classified and payload is present, inspect payload
        if conn.state != ConnectionState.CLASSIFIED and job.payload_length > 0:
            self._inspect_payload(job, conn)

        # Evaluate rules
        return self._check_rules(job, conn)

    def _inspect_payload(self, job: PacketJob, conn: Connection) -> None:
        if job.payload_length == 0:
            return

        payload = job.payload_data

        # 1. TLS SNI extraction
        if self._try_extract_sni(job, conn):
            return

        # 2. HTTP Host extraction
        if self._try_extract_http_host(job, conn):
            return

        # 3. DNS extraction
        if job.tuple.dst_port == 53 or job.tuple.src_port == 53:
            domain = DNSExtractor.extract_query(payload)
            if domain:
                self.conn_tracker.classify_connection(conn, AppType.DNS, domain)
                return

        # 4. Fallback port classification
        if job.tuple.dst_port == 80:
            self.conn_tracker.classify_connection(conn, AppType.HTTP, "")
        elif job.tuple.dst_port == 443:
            self.conn_tracker.classify_connection(conn, AppType.HTTPS, "")

    def _try_extract_sni(self, job: PacketJob, conn: Connection) -> bool:
        if job.tuple.dst_port != 443 and job.payload_length < 50:
            return False

        sni = SNIExtractor.extract(job.payload_data)
        if sni:
            self.sni_extractions += 1
            app = sni_to_app_type(sni)
            self.conn_tracker.classify_connection(conn, app, sni)
            if app not in (AppType.UNKNOWN, AppType.HTTPS):
                self.classification_hits += 1
            return True
        return False

    def _try_extract_http_host(self, job: PacketJob, conn: Connection) -> bool:
        if job.tuple.dst_port != 80:
            return False

        host = HTTPHostExtractor.extract(job.payload_data)
        if host:
            app = sni_to_app_type(host)
            self.conn_tracker.classify_connection(conn, app, host)
            if app not in (AppType.UNKNOWN, AppType.HTTP):
                self.classification_hits += 1
            return True
        return False

    def _check_rules(self, job: PacketJob, conn: Connection) -> PacketAction:
        if not self.rule_manager:
            return PacketAction.FORWARD

        block_reason = self.rule_manager.should_block(
            src_ip=job.tuple.src_ip,
            dst_port=job.tuple.dst_port,
            app=conn.app_type,
            domain=conn.sni,
        )

        if block_reason:
            print(f"[FP{self.fp_id}] BLOCKED packet: {block_reason.reason_type} {block_reason.detail}")
            self.conn_tracker.block_connection(conn)
            return PacketAction.DROP

        return PacketAction.FORWARD

    def _update_tcp_state(self, conn: Connection, flags: int) -> None:
        if flags & TCPFlags.SYN:
            if flags & TCPFlags.ACK:
                conn.syn_ack_seen = True
            else:
                conn.syn_seen = True

        if conn.syn_seen and conn.syn_ack_seen and (flags & TCPFlags.ACK):
            if conn.state == ConnectionState.NEW:
                conn.state = ConnectionState.ESTABLISHED

        if flags & TCPFlags.FIN:
            conn.fin_seen = True

        if flags & TCPFlags.RST:
            conn.state = ConnectionState.CLOSED

        if conn.fin_seen and (flags & TCPFlags.ACK):
            conn.state = ConnectionState.CLOSED

    def get_stats(self) -> dict:
        return {
            "packets_processed": self.packets_processed,
            "packets_forwarded": self.packets_forwarded,
            "packets_dropped": self.packets_dropped,
            "connections_tracked": self.conn_tracker.get_active_count(),
            "sni_extractions": self.sni_extractions,
            "classification_hits": self.classification_hits,
        }


class FPManager:
    """Manages pool of Fast Path processors."""

    def __init__(
        self,
        num_fps: int,
        rule_manager: Optional[RuleManager],
        output_callback: Optional[PacketOutputCallback],
        queue_size: int = 10000,
    ) -> None:
        self.num_fps = num_fps
        self.fps: List[FastPathProcessor] = [
            FastPathProcessor(i, rule_manager, output_callback, queue_size)
            for i in range(num_fps)
        ]

    def start_all(self) -> None:
        for fp in self.fps:
            fp.start()

    def stop_all(self) -> None:
        for fp in self.fps:
            fp.stop()

    def get_fp(self, idx: int) -> FastPathProcessor:
        return self.fps[idx]

    def get_fp_queue(self, idx: int) -> ThreadSafeQueue[PacketJob]:
        return self.fps[idx].input_queue

    def get_queue_ptrs(self) -> List[ThreadSafeQueue[PacketJob]]:
        return [fp.input_queue for fp in self.fps]

    def generate_classification_report(self) -> str:
        """Aggregate classification results across all FPs."""
        app_counts: Dict[AppType, int] = {}
        unique_snis: Dict[str, AppType] = {}

        for fp in self.fps:
            for conn in fp.conn_tracker.get_all_connections():
                app_counts[conn.app_type] = app_counts.get(conn.app_type, 0) + conn.packets_in + conn.packets_out
                if conn.sni:
                    if conn.sni not in unique_snis or unique_snis[conn.sni] in (AppType.DNS, AppType.HTTPS, AppType.HTTP, AppType.UNKNOWN):
                        unique_snis[conn.sni] = conn.app_type

        lines: List[str] = [
            "",
            "+==============================================================+",
            "|                    APPLICATION BREAKDOWN                     |",
            "+==============================================================+",
        ]

        total = sum(app_counts.values())
        sorted_apps = sorted(app_counts.items(), key=lambda kv: kv[1], reverse=True)
        for app, count in sorted_apps:
            pct = (100.0 * count / total) if total > 0 else 0.0
            bar_len = int(pct / 5)
            bar = "#" * bar_len
            app_str = app_type_to_string(app)
            lines.append(f"| {app_str:<15}{count:>8} {pct:>5.1f}% {bar:<20}  |")

        lines.append("+==============================================================+")

        if unique_snis:
            lines.append("\n[Detected Applications/Domains]")
            for sni, app in sorted(unique_snis.items(), key=lambda kv: kv[0]):
                lines.append(f"  - {sni} -> {app_type_to_string(app)}")

        return "\n".join(lines) + "\n"
