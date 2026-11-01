"""
Connection tracking and flow state management.
Corresponds to include/connection_tracker.h and src/connection_tracker.cpp.
"""

from __future__ import annotations
import time
import threading
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple
from .types import (
    FiveTuple,
    Connection,
    ConnectionState,
    PacketAction,
    AppType,
    app_type_to_string,
)


@dataclass
class Flow:
    """Lightweight flow tracking structure used in simple DPI mode."""
    tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False


class ConnectionTracker:
    """
    Maintains flow table for active connections on a specific worker thread.
    Each Fast Path processor has its own ConnectionTracker instance.
    """

    def __init__(self, fp_id: int = 0, max_connections: int = 100000) -> None:
        self.fp_id = fp_id
        self.max_connections = max_connections
        self._connections: Dict[FiveTuple, Connection] = {}
        self._lock = threading.RLock()
        self.total_seen: int = 0
        self.classified_count: int = 0
        self.blocked_count: int = 0

    def get_or_create_connection(self, tuple_: FiveTuple) -> Connection:
        with self._lock:
            # Check direct or reverse tuple
            if tuple_ in self._connections:
                return self._connections[tuple_]
            rev = tuple_.reverse()
            if rev in self._connections:
                return self._connections[rev]

            # Check capacity
            if len(self._connections) >= self.max_connections:
                self.evict_oldest()

            now = time.time()
            conn = Connection(
                tuple=tuple_,
                state=ConnectionState.NEW,
                first_seen=now,
                last_seen=now,
            )
            self._connections[tuple_] = conn
            self.total_seen += 1
            return conn

    def get_connection(self, tuple_: FiveTuple) -> Optional[Connection]:
        with self._lock:
            if tuple_ in self._connections:
                return self._connections[tuple_]
            rev = tuple_.reverse()
            if rev in self._connections:
                return self._connections[rev]
            return None

    def update_connection(self, conn: Connection, packet_size: int, is_outbound: bool) -> None:
        with self._lock:
            conn.last_seen = time.time()
            if is_outbound:
                conn.packets_out += 1
                conn.bytes_out += packet_size
            else:
                conn.packets_in += 1
                conn.bytes_in += packet_size

    def classify_connection(self, conn: Connection, app: AppType, sni: str) -> None:
        with self._lock:
            if conn.state != ConnectionState.CLASSIFIED:
                conn.app_type = app
                conn.sni = sni
                conn.state = ConnectionState.CLASSIFIED
                self.classified_count += 1

    def block_connection(self, conn: Connection) -> None:
        with self._lock:
            conn.state = ConnectionState.BLOCKED
            conn.action = PacketAction.DROP
            self.blocked_count += 1

    def close_connection(self, tuple_: FiveTuple) -> None:
        with self._lock:
            conn = self.get_connection(tuple_)
            if conn:
                conn.state = ConnectionState.CLOSED

    def cleanup_stale(self, timeout_seconds: float = 300.0) -> int:
        now = time.time()
        removed = 0
        with self._lock:
            keys_to_remove = [
                k for k, c in self._connections.items()
                if (now - c.last_seen > timeout_seconds) or (c.state == ConnectionState.CLOSED)
            ]
            for k in keys_to_remove:
                del self._connections[k]
                removed += 1
        return removed

    def evict_oldest(self) -> None:
        with self._lock:
            if not self._connections:
                return
            oldest_key = min(self._connections.keys(), key=lambda k: self._connections[k].last_seen)
            del self._connections[oldest_key]

    def get_all_connections(self) -> List[Connection]:
        with self._lock:
            return list(self._connections.values())

    def get_active_count(self) -> int:
        with self._lock:
            return len(self._connections)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "active_connections": len(self._connections),
                "total_connections_seen": self.total_seen,
                "classified_connections": self.classified_count,
                "blocked_connections": self.blocked_count,
            }

    def clear(self) -> None:
        with self._lock:
            self._connections.clear()

    def for_each(self, callback: Callable[[Connection], None]) -> None:
        with self._lock:
            for conn in list(self._connections.values()):
                callback(conn)


class GlobalConnectionTable:
    """
    Aggregates statistics and reporting across all Fast Path connection trackers.
    """

    def __init__(self, num_fps: int) -> None:
        self.num_fps = num_fps
        self._trackers: List[Optional[ConnectionTracker]] = [None] * num_fps
        self._lock = threading.RLock()

    def register_tracker(self, fp_id: int, tracker: ConnectionTracker) -> None:
        with self._lock:
            if 0 <= fp_id < len(self._trackers):
                self._trackers[fp_id] = tracker

    def get_global_stats(self) -> dict:
        with self._lock:
            total_active = 0
            total_seen = 0
            app_distribution: Dict[AppType, int] = {}
            domain_counts: Dict[str, int] = {}

            for tracker in self._trackers:
                if tracker is None:
                    continue
                stats = tracker.get_stats()
                total_active += stats["active_connections"]
                total_seen += stats["total_connections_seen"]

                def count_entry(conn: Connection) -> None:
                    app_distribution[conn.app_type] = app_distribution.get(conn.app_type, 0) + 1
                    if conn.sni:
                        domain_counts[conn.sni] = domain_counts.get(conn.sni, 0) + 1

                tracker.for_each(count_entry)

            # Top 20 domains sorted descending
            sorted_domains = sorted(domain_counts.items(), key=lambda kv: kv[1], reverse=True)[:20]

            return {
                "total_active_connections": total_active,
                "total_connections_seen": total_seen,
                "app_distribution": app_distribution,
                "top_domains": sorted_domains,
            }

    def generate_report(self) -> str:
        stats = self.get_global_stats()
        lines: List[str] = [
            "",
            "+==============================================================+",
            "|               CONNECTION STATISTICS REPORT                   |",
            "+==============================================================+",
            f"| Active Connections:     {stats['total_active_connections']:>10}                          |",
            f"| Total Connections Seen: {stats['total_connections_seen']:>10}                          |",
            "+==============================================================+",
            "|                    APPLICATION BREAKDOWN                     |",
            "+==============================================================+",
        ]

        app_dist: Dict[AppType, int] = stats["app_distribution"]
        total_classified = sum(app_dist.values())

        sorted_apps = sorted(app_dist.items(), key=lambda kv: kv[1], reverse=True)
        for app, count in sorted_apps:
            pct = (100.0 * count / total_classified) if total_classified > 0 else 0.0
            app_str = app_type_to_string(app)
            lines.append(f"| {app_str:<20}{count:>10} ({pct:>5.1f}%)                       |")

        top_domains: List[Tuple[str, int]] = stats["top_domains"]
        if top_domains:
            lines.extend([
                "+==============================================================+",
                "|                      TOP DOMAINS                             |",
                "+==============================================================+",
            ])
            for domain, count in top_domains:
                d = domain if len(domain) <= 35 else domain[:32] + "..."
                lines.append(f"| {d:<40}{count:>10}          |")

        lines.append("+==============================================================+")
        return "\n".join(lines) + "\n"
