"""
Rule management and traffic filtering for IP, application, domain, and port.
Corresponds to include/rule_manager.h and src/rule_manager.cpp.
"""

from __future__ import annotations
import fnmatch
import threading
from dataclasses import dataclass
from typing import List, Optional, Set
from .types import AppType, app_type_to_string, string_to_app_type


@dataclass
class BlockReason:
    """Explains why a packet/flow was dropped."""
    reason_type: str  # 'IP', 'APP', 'DOMAIN', 'PORT'
    detail: str


@dataclass
class RuleStats:
    blocked_ips: int
    blocked_apps: int
    blocked_domains: int
    blocked_ports: int


class RuleManager:
    """
    Thread-safe rule manager for filtering network traffic by:
      1. Source IP
      2. Application Type
      3. Domain name (with wildcard and exact matching)
      4. Destination Port
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._blocked_ips: Set[str] = set()
        self._blocked_apps: Set[AppType] = set()
        self._blocked_domains: Set[str] = set()
        self._domain_patterns: List[str] = []
        self._blocked_ports: Set[int] = set()

    # ==================== IP Blocking ====================
    def block_ip(self, ip: str) -> None:
        with self._lock:
            self._blocked_ips.add(ip.strip())
            print(f"[RuleManager] Blocked IP: {ip.strip()}")

    def unblock_ip(self, ip: str) -> None:
        with self._lock:
            self._blocked_ips.discard(ip.strip())
            print(f"[RuleManager] Unblocked IP: {ip.strip()}")

    def is_ip_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked_ips

    def get_blocked_ips(self) -> List[str]:
        with self._lock:
            return sorted(self._blocked_ips)

    # ================= Application Blocking =================
    def block_app(self, app: AppType | str) -> None:
        if isinstance(app, str):
            app = string_to_app_type(app)
        with self._lock:
            self._blocked_apps.add(app)
            print(f"[RuleManager] Blocked app: {app_type_to_string(app)}")

    def unblock_app(self, app: AppType | str) -> None:
        if isinstance(app, str):
            app = string_to_app_type(app)
        with self._lock:
            self._blocked_apps.discard(app)
            print(f"[RuleManager] Unblocked app: {app_type_to_string(app)}")

    def is_app_blocked(self, app: AppType) -> bool:
        with self._lock:
            return app in self._blocked_apps

    def get_blocked_apps(self) -> List[AppType]:
        with self._lock:
            return sorted(self._blocked_apps, key=lambda a: a.value)

    # ================= Domain Blocking =================
    def block_domain(self, domain: str) -> None:
        domain = domain.strip().lower()
        with self._lock:
            if "*" in domain:
                if domain not in self._domain_patterns:
                    self._domain_patterns.append(domain)
            else:
                self._blocked_domains.add(domain)
            print(f"[RuleManager] Blocked domain: {domain}")

    def unblock_domain(self, domain: str) -> None:
        domain = domain.strip().lower()
        with self._lock:
            if "*" in domain:
                if domain in self._domain_patterns:
                    self._domain_patterns.remove(domain)
            else:
                self._blocked_domains.discard(domain)
            print(f"[RuleManager] Unblocked domain: {domain}")

    @staticmethod
    def domain_matches_pattern(domain: str, pattern: str) -> bool:
        """
        Check if domain matches pattern.
        Supports *.example.com matching sub.example.com and example.com.
        """
        domain = domain.lower()
        pattern = pattern.lower()

        if pattern.startswith("*."):
            suffix = pattern[1:]  # .example.com
            bare = pattern[2:]    # example.com
            if domain == bare or domain.endswith(suffix):
                return True

        if fnmatch.fnmatch(domain, pattern):
            return True

        # Also support substring matching if pattern has no wildcard
        if pattern in domain:
            return True

        return False

    def is_domain_blocked(self, domain: str) -> bool:
        if not domain:
            return False
        domain = domain.strip().lower()
        with self._lock:
            if domain in self._blocked_domains:
                return True
            for d in self._blocked_domains:
                if d in domain:
                    return True
            for pattern in self._domain_patterns:
                if self.domain_matches_pattern(domain, pattern):
                    return True
        return False

    def get_blocked_domains(self) -> List[str]:
        with self._lock:
            return sorted(self._blocked_domains.union(self._domain_patterns))

    # ================= Port Blocking =================
    def block_port(self, port: int) -> None:
        with self._lock:
            self._blocked_ports.add(port)
            print(f"[RuleManager] Blocked port: {port}")

    def unblock_port(self, port: int) -> None:
        with self._lock:
            self._blocked_ports.discard(port)

    def is_port_blocked(self, port: int) -> bool:
        with self._lock:
            return port in self._blocked_ports

    def get_blocked_ports(self) -> List[int]:
        with self._lock:
            return sorted(self._blocked_ports)

    # ================= Combined Checking =================
    def should_block(
        self,
        src_ip: str,
        dst_port: int,
        app: AppType,
        domain: str = "",
    ) -> Optional[BlockReason]:
        """
        Evaluate all blocking rules against the given flow parameters.
        Returns BlockReason if blocked, or None if allowed.
        """
        with self._lock:
            # 1. IP Check
            if src_ip in self._blocked_ips:
                return BlockReason("IP", src_ip)

            # 2. Port Check
            if dst_port in self._blocked_ports:
                return BlockReason("PORT", str(dst_port))

            # 3. Application Check
            if app != AppType.UNKNOWN and app in self._blocked_apps:
                return BlockReason("APP", app_type_to_string(app))

            # 4. Domain Check
            if domain and self.is_domain_blocked(domain):
                return BlockReason("DOMAIN", domain)

        return None

    # ================= Rule Persistence =================
    def save_rules(self, filename: str) -> bool:
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("[BLOCKED_IPS]\n")
                for ip in self.get_blocked_ips():
                    f.write(f"{ip}\n")

                f.write("\n[BLOCKED_APPS]\n")
                for app in self.get_blocked_apps():
                    f.write(f"{app_type_to_string(app)}\n")

                f.write("\n[BLOCKED_DOMAINS]\n")
                for dom in self.get_blocked_domains():
                    f.write(f"{dom}\n")

                f.write("\n[BLOCKED_PORTS]\n")
                for port in self.get_blocked_ports():
                    f.write(f"{port}\n")
            print(f"[RuleManager] Rules saved to: {filename}")
            return True
        except OSError as e:
            print(f"Error saving rules: {e}")
            return False

    def load_rules(self, filename: str) -> bool:
        try:
            with open(filename, "r", encoding="utf-8") as f:
                current_section = ""
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("[") and line.endswith("]"):
                        current_section = line
                        continue
                    if current_section == "[BLOCKED_IPS]":
                        self.block_ip(line)
                    elif current_section == "[BLOCKED_APPS]":
                        self.block_app(line)
                    elif current_section == "[BLOCKED_DOMAINS]":
                        self.block_domain(line)
                    elif current_section == "[BLOCKED_PORTS]":
                        self.block_port(int(line))
            print(f"[RuleManager] Rules loaded from: {filename}")
            return True
        except OSError as e:
            print(f"Error loading rules: {e}")
            return False

    def clear_all(self) -> None:
        with self._lock:
            self._blocked_ips.clear()
            self._blocked_apps.clear()
            self._blocked_domains.clear()
            self._domain_patterns.clear()
            self._blocked_ports.clear()
            print("[RuleManager] All rules cleared")

    def get_stats(self) -> RuleStats:
        with self._lock:
            return RuleStats(
                blocked_ips=len(self._blocked_ips),
                blocked_apps=len(self._blocked_apps),
                blocked_domains=len(self._blocked_domains) + len(self._domain_patterns),
                blocked_ports=len(self._blocked_ports),
            )


class BlockingRules:
    """
    Lightweight blocking rules container, compatible with main_working.cpp.
    """

    def __init__(self) -> None:
        self.blocked_ips: Set[str] = set()
        self.blocked_apps: Set[AppType] = set()
        self.blocked_domains: List[str] = []

    def block_ip(self, ip: str) -> None:
        self.blocked_ips.add(ip.strip())
        print(f"[Rules] Blocked IP: {ip.strip()}")

    # Alias for C++ method name compatibility
    blockIP = block_ip

    def block_app(self, app_name: str) -> None:
        app = string_to_app_type(app_name)
        if app != AppType.UNKNOWN:
            self.blocked_apps.add(app)
            print(f"[Rules] Blocked app: {app_type_to_string(app)}")
        else:
            print(f"[Rules] Unknown app: {app_name}")

    # Alias for C++ method name compatibility
    blockApp = block_app

    def block_domain(self, domain: str) -> None:
        self.blocked_domains.append(domain.strip().lower())
        print(f"[Rules] Blocked domain: {domain.strip()}")

    # Alias for C++ method name compatibility
    blockDomain = block_domain

    def is_blocked(self, src_ip: str, app: AppType, sni: str) -> bool:
        if src_ip in self.blocked_ips:
            return True
        if app in self.blocked_apps:
            return True
        lower_sni = sni.lower()
        for dom in self.blocked_domains:
            if dom in lower_sni:
                return True
        return False

    # Alias for C++ method name compatibility
    isBlocked = is_blocked
