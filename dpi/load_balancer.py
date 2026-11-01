"""
Load Balancer (LB) thread implementation for consistent flow dispatching.
Corresponds to include/load_balancer.h and src/load_balancer.cpp.
"""

from __future__ import annotations
import threading
from typing import List, Optional
from .types import FiveTuple, PacketJob
from .queue import ThreadSafeQueue


def five_tuple_hash(tuple_: FiveTuple) -> int:
    """Consistent hash combining five-tuple fields."""
    return hash((
        tuple_.src_ip,
        tuple_.dst_ip,
        tuple_.src_port,
        tuple_.dst_port,
        tuple_.protocol,
    ))


class LoadBalancer:
    """
    Load Balancer thread:
      1. Receives packets from Reader
      2. Hashes the 5-tuple
      3. Forwards packet to the target Fast Path processor's queue
    """

    def __init__(
        self,
        lb_id: int,
        fp_queues: List[ThreadSafeQueue[PacketJob]],
        fp_start_id: int,
        queue_size: int = 10000,
    ) -> None:
        self.lb_id = lb_id
        self.fp_start_id = fp_start_id
        self.fp_queues = fp_queues
        self.num_fps = len(fp_queues)
        self.input_queue: ThreadSafeQueue[PacketJob] = ThreadSafeQueue(queue_size)

        # Statistics
        self.packets_received: int = 0
        self.packets_dispatched: int = 0
        self.per_fp_counts: List[int] = [0] * self.num_fps

        # Thread management
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, name=f"LB-{self.lb_id}", daemon=True)
        self._thread.start()
        end_fp = self.fp_start_id + self.num_fps - 1
        print(f"[LB{self.lb_id}] Started (serving FP{self.fp_start_id}-FP{end_fp})")

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self.input_queue.shutdown()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        print(f"[LB{self.lb_id}] Stopped")

    def is_running(self) -> bool:
        return self._running

    def _run(self) -> None:
        while self._running:
            job = self.input_queue.pop_with_timeout(0.1)
            if job is None:
                continue

            self.packets_received += 1
            fp_index = self.select_fp(job.tuple)

            self.fp_queues[fp_index].push(job)
            self.packets_dispatched += 1
            self.per_fp_counts[fp_index] += 1

    def select_fp(self, tuple_: FiveTuple) -> int:
        """Map 5-tuple to one of our assigned FPs using consistent hashing."""
        h = abs(five_tuple_hash(tuple_))
        return h % self.num_fps

    def get_stats(self) -> dict:
        return {
            "packets_received": self.packets_received,
            "packets_dispatched": self.packets_dispatched,
            "per_fp_packets": list(self.per_fp_counts),
        }


class LBManager:
    """Manages pool of Load Balancer threads."""

    def __init__(
        self,
        num_lbs: int,
        fps_per_lb: int,
        fp_queues: List[ThreadSafeQueue[PacketJob]],
        queue_size: int = 10000,
    ) -> None:
        self.num_lbs = num_lbs
        self.fps_per_lb = fps_per_lb
        self.lbs: List[LoadBalancer] = []

        for lb_id in range(num_lbs):
            fp_start = lb_id * fps_per_lb
            lb_fp_queues = fp_queues[fp_start: fp_start + fps_per_lb]
            lb = LoadBalancer(lb_id, lb_fp_queues, fp_start, queue_size)
            self.lbs.append(lb)

        print(f"[LBManager] Created {num_lbs} load balancers, {fps_per_lb} FPs each")

    def start_all(self) -> None:
        for lb in self.lbs:
            lb.start()

    def stop_all(self) -> None:
        for lb in self.lbs:
            lb.stop()

    def get_lb_for_packet(self, tuple_: FiveTuple) -> LoadBalancer:
        """First-level routing: pick Load Balancer based on 5-tuple hash."""
        h = abs(five_tuple_hash(tuple_))
        idx = h % len(self.lbs)
        return self.lbs[idx]

    def get_aggregated_stats(self) -> dict:
        total_recv = sum(lb.packets_received for lb in self.lbs)
        total_disp = sum(lb.packets_dispatched for lb in self.lbs)
        return {
            "total_received": total_recv,
            "total_dispatched": total_disp,
        }
