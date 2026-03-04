#!/usr/bin/env python3

"""
NoDPI with SOCKS5 Support
=========================

NoDPI is a utility for bypassing the DPI (Deep Packet Inspection) system
Extended with SOCKS5 proxy support for universal client connectivity
"""

import argparse
import asyncio
import base64
import json
import logging
import os
import random
import socket
import ssl
import struct
import subprocess
import sys
import textwrap
import time
import traceback

from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from urllib.error import URLError
from urllib.request import urlopen, Request

if sys.platform == "win32":
    import winreg

__version__ = "2.3-socks5"

os.system("")


class DNSResolver:
    """Async DNS resolver using DNS over HTTPS (DoH) to bypass DNS blocking"""

    # DNS over HTTPS endpoints (port 443, harder to block)
    DOH_SERVERS = [
        "https://cloudflare-dns.com/dns-query",  # Cloudflare DoH
        "https://dns.google/resolve",             # Google DoH
        "https://dns.quad9.net/dns-query",        # Quad9 DoH
        "https://doh.opendns.com/dns-query",      # OpenDNS DoH
        "https://dns.adguard-dns.com/dns-query",  # AdGuard DoH
    ]

    def __init__(self):
        self.cache: Dict[str, str] = {}
        self.cache_lock = asyncio.Lock()
        self._ssl_context = None

    def _get_ssl_context(self):
        """Get or create SSL context"""
        if self._ssl_context is None:
            self._ssl_context = ssl.create_default_context()
        return self._ssl_context

    async def _resolve_doh_cloudflare(self, domain: str, timeout: float = 5.0) -> Optional[str]:
        """Resolve using Cloudflare DoH (binary format, RFC 8484)"""
        try:
            # Build DNS query
            query = self._build_dns_query(domain)

            # Make HTTPS request
            url = "https://cloudflare-dns.com/dns-query"

            # Use urllib in executor for async
            loop = asyncio.get_event_loop()

            def do_request():
                try:
                    import urllib.request
                    req = urllib.request.Request(
                        url,
                        data=query,
                        headers={
                            "Content-Type": "application/dns-message",
                            "Accept": "application/dns-message",
                        },
                        method="POST"
                    )
                    ctx = ssl.create_default_context()
                    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                        if response.status == 200:
                            return response.read()
                except Exception:
                    pass
                return None

            response_data = await loop.run_in_executor(None, do_request)
            if response_data:
                return self._parse_dns_response(response_data)

        except Exception:
            pass
        return None

    async def _resolve_doh_google(self, domain: str, timeout: float = 5.0) -> Optional[str]:
        """Resolve using Google DoH (JSON format)"""
        try:
            loop = asyncio.get_event_loop()

            def do_request():
                try:
                    import urllib.request
                    from urllib.parse import urlencode

                    params = urlencode({"name": domain, "type": "A"})
                    url = f"https://dns.google/resolve?{params}"

                    req = urllib.request.Request(
                        url,
                        headers={"Accept": "application/json"}
                    )
                    ctx = ssl.create_default_context()
                    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                        if response.status == 200:
                            import json
                            data = json.loads(response.read().decode())
                            # Parse Answer section
                            if "Answer" in data:
                                for answer in data["Answer"]:
                                    if answer.get("type") == 1:  # A record
                                        return answer.get("data")
                except Exception:
                    pass
                return None

            result = await loop.run_in_executor(None, do_request)
            return result

        except Exception:
            pass
        return None

    async def _resolve_doh_quad9(self, domain: str, timeout: float = 5.0) -> Optional[str]:
        """Resolve using Quad9 DoH (binary format)"""
        try:
            query = self._build_dns_query(domain)
            url = "https://dns.quad9.net/dns-query"

            loop = asyncio.get_event_loop()

            def do_request():
                try:
                    import urllib.request
                    req = urllib.request.Request(
                        url,
                        data=query,
                        headers={
                            "Content-Type": "application/dns-message",
                            "Accept": "application/dns-message",
                        },
                        method="POST"
                    )
                    ctx = ssl.create_default_context()
                    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                        if response.status == 200:
                            return response.read()
                except Exception:
                    pass
                return None

            response_data = await loop.run_in_executor(None, do_request)
            if response_data:
                return self._parse_dns_response(response_data)

        except Exception:
            pass
        return None

    def _build_dns_query(self, domain: str) -> bytes:
        """Build DNS query packet for A record"""
        # Transaction ID (2 bytes)
        transaction_id = random.randint(0, 65535)

        # Flags: standard query with recursion desired
        flags = 0x0100

        # Questions: 1, Answers: 0, Authority: 0, Additional: 0
        questions = 1
        answers = 0
        authority = 0
        additional = 0

        # Header
        header = struct.pack(">HHHHHH", transaction_id, flags, questions, answers, authority, additional)

        # Question section
        question = b""
        for part in domain.split("."):
            part_bytes = part.encode("idna")  # Support IDN domains
            question += bytes([len(part_bytes)]) + part_bytes
        question += b"\x00"  # End of domain name

        # Query type (A = 1) and class (IN = 1)
        question += struct.pack(">HH", 1, 1)

        return header + question

    def _parse_dns_response(self, response: bytes) -> Optional[str]:
        """Parse DNS response and extract IP address"""
        try:
            if len(response) < 12:
                return None

            transaction_id, flags, questions, answers, authority, additional = struct.unpack(
                ">HHHHHH", response[:12]
            )

            # Check if response is valid
            if not (flags & 0x8000):  # QR bit should be 1 (response)
                return None

            if answers == 0:
                return None

            # Skip question section
            offset = 12
            for _ in range(questions):
                while offset < len(response) and response[offset] != 0:
                    offset += response[offset] + 1
                offset += 5  # Skip null terminator, type and class

            # Parse answer section
            for _ in range(answers):
                if offset >= len(response):
                    break

                # Check for compression pointer
                if response[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while offset < len(response) and response[offset] != 0:
                        offset += response[offset] + 1
                    offset += 1

                if offset + 10 > len(response):
                    break

                rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", response[offset:offset + 10])
                offset += 10

                if rtype == 1 and rdlength == 4:  # A record
                    ip = ".".join(str(b) for b in response[offset:offset + 4])
                    return ip

                offset += rdlength

            return None

        except Exception:
            return None

    async def resolve(self, domain: str, timeout: float = 5.0) -> Optional[str]:
        """Resolve domain to IP address using DNS over HTTPS"""

        # Check cache first
        async with self.cache_lock:
            if domain in self.cache:
                return self.cache[domain]

        # Try DoH servers in order
        # 1. Google DoH (JSON format - simpler and more reliable)
        ip = await self._resolve_doh_google(domain, timeout)
        if ip:
            async with self.cache_lock:
                self.cache[domain] = ip
            return ip

        # 2. Cloudflare DoH (binary format)
        ip = await self._resolve_doh_cloudflare(domain, timeout)
        if ip:
            async with self.cache_lock:
                self.cache[domain] = ip
            return ip

        # 3. Quad9 DoH (binary format)
        ip = await self._resolve_doh_quad9(domain, timeout)
        if ip:
            async with self.cache_lock:
                self.cache[domain] = ip
            return ip

        # Fallback: try system resolver (likely won't work for blocked domains)
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(domain, None)
            if result:
                ip = result[0][4][0]
                async with self.cache_lock:
                    self.cache[domain] = ip
                return ip
        except Exception:
            pass

        return None


# Global DNS resolver instance
_dns_resolver: Optional[DNSResolver] = None


def get_dns_resolver() -> DNSResolver:
    """Get or create the global DNS resolver"""
    global _dns_resolver
    if _dns_resolver is None:
        _dns_resolver = DNSResolver()
    return _dns_resolver


def set_dns_resolver(dns_servers) -> DNSResolver:
    """Set the global DNS resolver (DoH doesn't need server config)"""
    global _dns_resolver
    _dns_resolver = DNSResolver()
    return _dns_resolver


async def resolve_host(host: str) -> Optional[str]:
    """Resolve hostname to IP address"""
    # Check if already an IP address
    try:
        socket.inet_aton(host)
        return host
    except socket.error:
        pass

    # Try IPv6
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except (socket.error, AttributeError):
        pass

    # Resolve using DNS resolver
    resolver = get_dns_resolver()
    return await resolver.resolve(host)


class ConnectionInfo:
    """Class to store connection information"""

    def __init__(self, src_ip: str, dst_domain: str, method: str, proxy_type: str = "http"):

        self.src_ip = src_ip
        self.dst_domain = dst_domain
        self.method = method
        self.proxy_type = proxy_type  # "http" or "socks5"
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.traffic_in = 0
        self.traffic_out = 0


class ProxyConfig:
    """Configuration container for proxy settings"""

    def __init__(self):

        # HTTP Proxy settings
        self.host = "127.0.0.1"
        self.port = 8881

        # SOCKS5 Proxy settings
        self.socks5_host = None
        self.socks5_port = None

        self.out_host = None
        self.username = None
        self.password = None
        self.blacklist_file = "blacklist.txt"
        self.fragment_method = "random"
        self.domain_matching = "strict"
        self.log_access_file = None
        self.log_error_file = None
        self.no_blacklist = False
        self.auto_blacklist = False
        self.quiet = False


class IBlacklistManager(ABC):
    """Interface for blacklist management"""

    @abstractmethod
    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""

    @abstractmethod
    async def check_domain(self, domain: bytes) -> None:
        """Automatically check if domain is blocked"""


class ILogger(ABC):
    """Interface for logging"""

    @abstractmethod
    def log_access(self, message: str) -> None:
        """Log access message"""

    @abstractmethod
    def log_error(self, message: str) -> None:
        """Log error message"""

    @abstractmethod
    def info(self, message: str) -> None:
        """Print info message if not quiet"""

    @abstractmethod
    def error(self, message: str) -> None:
        """Print error message if not quiet"""


class IStatistics(ABC):
    """Interface for statistics tracking"""

    @abstractmethod
    def increment_total_connections(self, proxy_type: str = "http") -> None:
        """Increment total connections counter"""

    @abstractmethod
    def increment_allowed_connections(self, proxy_type: str = "http") -> None:
        """Increment allowed connections counter"""

    @abstractmethod
    def increment_blocked_connections(self, proxy_type: str = "http") -> None:
        """Increment blocked connections counter"""

    @abstractmethod
    def increment_error_connections(self, proxy_type: str = "http") -> None:
        """Increment error connections counter"""

    @abstractmethod
    def update_traffic(self, incoming: int, outgoing: int, proxy_type: str = "http") -> None:
        """Update traffic counters"""

    @abstractmethod
    def update_speeds(self) -> None:
        """Update speed calculations"""

    @abstractmethod
    def get_stats_display(self) -> str:
        """Get statistics display string"""


class IConnectionHandler(ABC):
    """Interface for connection handling"""

    @abstractmethod
    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming connection"""


class IAutostartManager(ABC):
    """Interface for autostart management"""

    @staticmethod
    @abstractmethod
    def manage_autostart(action: str) -> None:
        """Manage autostart"""


class FileBlacklistManager(IBlacklistManager):
    """Blacklist manager that uses file-based blacklist"""

    def __init__(self, config: ProxyConfig):

        self.config = config
        self.blacklist_file = self.config.blacklist_file
        self.blocked: List[str] = []
        self.load_blacklist()

    def load_blacklist(self) -> None:
        """Load blacklist from file"""

        if not os.path.exists(self.blacklist_file):
            raise FileNotFoundError(f"File {self.blacklist_file} not found")

        with open(self.blacklist_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if len(line.strip()) < 2 or line.strip()[0] == "#":
                    continue
                self.blocked.append(line.strip().lower().replace("www.", ""))

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""

        domain = domain.replace("www.", "")

        if self.config.domain_matching == "loose":
            for blocked_domain in self.blocked:
                if blocked_domain in domain:
                    return True

        if domain in self.blocked:
            return True

        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent_domain = ".".join(parts[i:])
            if parent_domain in self.blocked:
                return True

        return False

    async def check_domain(self, domain: bytes) -> None:
        """Not used in file-based mode"""


class AutoBlacklistManager(IBlacklistManager):
    """Blacklist manager that automatically detects blocked domains"""

    def __init__(
        self,
        config: ProxyConfig,
    ):

        self.blacklist_file = config.blacklist_file
        self.blocked: List[str] = []
        self.whitelist: List[str] = []

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""

        if domain in self.blocked:
            return True

        return False

    async def check_domain(self, domain: bytes) -> None:
        """Automatically check if domain is blocked"""

        if domain.decode() in self.blocked or domain in self.whitelist:
            return

        try:
            req = Request(
                f"https://{domain.decode()}", headers={"User-Agent": "Mozilla/5.0"}
            )
            context = ssl._create_unverified_context()

            with urlopen(req, timeout=4, context=context):
                self.whitelist.append(domain.decode())
        except URLError as e:
            reason = str(e.reason)
            if "handshake operation timed out" in reason:
                self.blocked.append(domain.decode())
                with open(self.blacklist_file, "a", encoding="utf-8") as f:
                    f.write(domain.decode() + "\n")


class NoBlacklistManager(IBlacklistManager):
    """Blacklist manager that doesn't block anything"""

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""
        return True

    async def check_domain(self, domain: bytes) -> None:
        """Not used in no-blacklist mode"""


class ProxyLogger(ILogger):
    """Logger implementation for proxy server"""

    def __init__(
        self,
        log_access_file: Optional[str],
        log_error_file: Optional[str],
        quiet: bool = False,
    ):

        self.quiet = quiet
        self.logger = logging.getLogger(__name__)
        self.error_counter_callback = None
        self.setup_logging(log_access_file, log_error_file)

    def setup_logging(
        self, log_access_file: Optional[str], log_error_file: Optional[str]
    ) -> None:
        """Setup logging configuration"""

        class ErrorCounterHandler(logging.FileHandler):
            def __init__(self, counter_callback, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.counter_callback = counter_callback

            def emit(self, record):
                if record.levelno >= logging.ERROR:
                    self.counter_callback()
                super().emit(record)

        if log_error_file:
            error_handler = ErrorCounterHandler(
                self.increment_errors, log_error_file, encoding="utf-8"
            )
            error_handler.setFormatter(
                logging.Formatter(
                    "[%(asctime)s][%(levelname)s]: %(message)s", "%Y-%m-%d %H:%M:%S"
                )
            )
            error_handler.setLevel(logging.ERROR)
            error_handler.addFilter(
                lambda record: record.levelno == logging.ERROR)
        else:
            error_handler = logging.NullHandler()

        if log_access_file:
            access_handler = logging.FileHandler(
                log_access_file, encoding="utf-8")
            access_handler.setFormatter(logging.Formatter("%(message)s"))
            access_handler.setLevel(logging.INFO)
            access_handler.addFilter(
                lambda record: record.levelno == logging.INFO)
        else:
            access_handler = logging.NullHandler()

        self.logger.propagate = False
        self.logger.handlers = []
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(error_handler)
        self.logger.addHandler(access_handler)

    def set_error_counter_callback(self, callback):
        """Set callback for error counting"""
        self.error_counter_callback = callback

    def increment_errors(self) -> None:
        """Increment error counter"""

        if self.error_counter_callback:
            self.error_counter_callback()

    def log_access(self, message: str) -> None:
        """Log access message"""
        self.logger.info(message)

    def log_error(self, message: str) -> None:
        """Log error message"""
        self.logger.error(message)

    def info(self, *args, **kwargs) -> None:
        """Print info message if not quiet"""

        if not self.quiet:
            print(*args, **kwargs)

    def error(self, *args, **kwargs) -> None:
        """Print error message if not quiet"""

        if not self.quiet:
            print(*args, **kwargs)


class ProxyTypeStatistics:
    """Statistics for a single proxy type"""

    def __init__(self):
        self.total_connections = 0
        self.allowed_connections = 0
        self.blocked_connections = 0
        self.errors_connections = 0
        self.traffic_in = 0
        self.traffic_out = 0
        self.last_traffic_in = 0
        self.last_traffic_out = 0
        self.speed_in = 0
        self.speed_out = 0
        self.average_speed_in = (0, 1)
        self.average_speed_out = (0, 1)

    def increment_total(self) -> None:
        self.total_connections += 1

    def increment_allowed(self) -> None:
        self.allowed_connections += 1

    def increment_blocked(self) -> None:
        self.blocked_connections += 1

    def increment_errors(self) -> None:
        self.errors_connections += 1

    def update_traffic(self, incoming: int, outgoing: int) -> None:
        self.traffic_in += incoming
        self.traffic_out += outgoing

    def update_speeds(self, time_diff: float) -> None:
        if time_diff > 0:
            self.speed_in = (self.traffic_in - self.last_traffic_in) * 8 / time_diff
            self.speed_out = (self.traffic_out - self.last_traffic_out) * 8 / time_diff

            if self.speed_in > 0:
                self.average_speed_in = (
                    self.average_speed_in[0] + self.speed_in,
                    self.average_speed_in[1] + 1,
                )
            if self.speed_out > 0:
                self.average_speed_out = (
                    self.average_speed_out[0] + self.speed_out,
                    self.average_speed_out[1] + 1,
                )

        self.last_traffic_in = self.traffic_in
        self.last_traffic_out = self.traffic_out


class Statistics(IStatistics):
    """Statistics tracker for both HTTP and SOCKS5 proxy servers"""

    def __init__(self):
        self.http = ProxyTypeStatistics()
        self.socks5 = ProxyTypeStatistics()
        self.last_time = None

    def increment_total_connections(self, proxy_type: str = "http") -> None:
        """Increment total connections counter"""
        if proxy_type == "socks5":
            self.socks5.increment_total()
        else:
            self.http.increment_total()

    def increment_allowed_connections(self, proxy_type: str = "http") -> None:
        """Increment allowed connections counter"""
        if proxy_type == "socks5":
            self.socks5.increment_allowed()
        else:
            self.http.increment_allowed()

    def increment_blocked_connections(self, proxy_type: str = "http") -> None:
        """Increment blocked connections counter"""
        if proxy_type == "socks5":
            self.socks5.increment_blocked()
        else:
            self.http.increment_blocked()

    def increment_error_connections(self, proxy_type: str = "http") -> None:
        """Increment error connections counter"""
        if proxy_type == "socks5":
            self.socks5.increment_errors()
        else:
            self.http.increment_errors()

    def update_traffic(self, incoming: int, outgoing: int, proxy_type: str = "http") -> None:
        """Update traffic counters"""
        if proxy_type == "socks5":
            self.socks5.update_traffic(incoming, outgoing)
        else:
            self.http.update_traffic(incoming, outgoing)

    def update_speeds(self) -> None:
        """Update speed calculations"""
        current_time = time.time()

        if self.last_time is not None:
            time_diff = current_time - self.last_time
            self.http.update_speeds(time_diff)
            self.socks5.update_speeds(time_diff)

        self.last_time = current_time

    def get_stats_display(self) -> str:
        """Get formatted statistics display"""

        col_width = 22

        # HTTP Stats
        http_conns = (
            f"\033[97mHTTP - Total: \033[93m{self.http.total_connections}\033[0m".ljust(col_width)
            + f"\033[97mMiss: \033[96m{self.http.allowed_connections}\033[0m".ljust(col_width)
            + f"\033[97mUnblock: \033[92m{self.http.blocked_connections}\033[0m".ljust(col_width)
            + f"\033[97mErrors: \033[91m{self.http.errors_connections}\033[0m"
        )

        # SOCKS5 Stats
        socks5_conns = (
            f"\033[97mSOCKS5 - Total: \033[93m{self.socks5.total_connections}\033[0m".ljust(col_width)
            + f"\033[97mMiss: \033[96m{self.socks5.allowed_connections}\033[0m".ljust(col_width)
            + f"\033[97mUnblock: \033[92m{self.socks5.blocked_connections}\033[0m".ljust(col_width)
            + f"\033[97mErrors: \033[91m{self.socks5.errors_connections}\033[0m"
        )

        # Combined Traffic
        total_in = self.http.traffic_in + self.socks5.traffic_in
        total_out = self.http.traffic_out + self.socks5.traffic_out

        traffic_stat = (
            f"\033[97mTotal: \033[96m{self.format_size(total_in + total_out)}\033[0m".ljust(col_width)
            + f"\033[97mHTTP DL: \033[96m{self.format_size(self.http.traffic_in)}\033[0m".ljust(col_width)
            + f"\033[97mSOCKS5 DL: \033[96m{self.format_size(self.socks5.traffic_in)}\033[0m".ljust(col_width)
        )

        # Combined Speed
        total_speed_in = self.http.speed_in + self.socks5.speed_in
        total_speed_out = self.http.speed_out + self.socks5.speed_out

        speed_stat = (
            f"\033[97mDL: \033[96m{self.format_speed(total_speed_in)}\033[0m".ljust(col_width)
            + f"\033[97mUL: \033[96m{self.format_speed(total_speed_out)}\033[0m".ljust(col_width)
            + f"\033[97mHTTP: \033[96m{self.format_speed(self.http.speed_in)}\033[0m".ljust(col_width)
            + f"\033[97mSOCKS5: \033[96m{self.format_speed(self.socks5.speed_in)}\033[0m"
        )

        title = "STATISTICS (HTTP + SOCKS5)"

        top_border = f"\033[92m{'═' * 40} {title} {'═' * 40}\033[0m"
        line_http_conns = f"\033[92m   {'HTTP'.ljust(8)}:\033[0m {http_conns}"
        line_socks5_conns = f"\033[92m   {'SOCKS5'.ljust(8)}:\033[0m {socks5_conns}"
        line_traffic = f"\033[92m   {'Traffic'.ljust(8)}:\033[0m {traffic_stat}"
        line_speed = f"\033[92m   {'Speed'.ljust(8)}:\033[0m {speed_stat}"
        bottom_border = f"\033[92m{'═' * (40*2+len(title)+2)}\033[0m"

        return (
            f"\r\033[K{top_border}\n\r\033[K{line_http_conns}\n\r\033[K{line_socks5_conns}\n\r\033[K{line_traffic}\n\r\033[K{line_speed}\n\r\033[K{bottom_border}"
        )

    @staticmethod
    def format_size(size: int) -> str:
        """Convert size to human readable format"""

        units = ["B", "KB", "MB", "GB"]
        unit = 0
        size_float = float(size)
        while size_float >= 1024 and unit < len(units) - 1:
            size_float /= 1024
            unit += 1
        return f"{size_float:.1f} {units[unit]}"

    @staticmethod
    def format_speed(speed_bps: float) -> str:
        """Convert speed to human readable format"""

        if speed_bps <= 0:
            return "0 b/s"

        units = ["b/s", "Kb/s", "Mb/s", "Gb/s"]
        unit = 0
        speed = speed_bps
        while speed >= 1000 and unit < len(units) - 1:
            speed /= 1000
            unit += 1
        return f"{speed:.0f} {units[unit]}"


class ConnectionHandler(IConnectionHandler):
    """Handles individual HTTP client connections"""

    def __init__(
        self,
        config: ProxyConfig,
        blacklist_manager: IBlacklistManager,
        statistics: IStatistics,
        logger: ILogger,
    ):

        self.config = config
        self.blacklist_manager = blacklist_manager
        self.statistics = statistics
        self.logger = logger
        self.out_host = self.config.out_host
        self.auth_enabled = config.username is not None and config.password is not None
        self.active_connections: Dict[Tuple, ConnectionInfo] = {}
        self.connections_lock = asyncio.Lock()
        self.tasks: List[asyncio.Task] = []
        self.tasks_lock = asyncio.Lock()

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming client connection"""

        try:
            client_ip, client_port = writer.get_extra_info("peername")
            http_data = await reader.read(1500)

            if not http_data:
                writer.close()
                return

            method, host, port = self._parse_http_request(http_data)
            conn_key = (client_ip, client_port)
            conn_info = ConnectionInfo(
                client_ip, host.decode(), method.decode(), "http")

            if method == b"CONNECT" and isinstance(
                self.blacklist_manager, AutoBlacklistManager
            ):
                await self.blacklist_manager.check_domain(host)

            async with self.connections_lock:
                self.active_connections[conn_key] = conn_info

            self.statistics.update_traffic(0, len(http_data), "http")
            conn_info.traffic_out += len(http_data)

            if not await self._check_proxy_authorization(http_data, writer):
                return

            if method == b"CONNECT":
                await self._handle_https_connection(
                    reader, writer, host, port, conn_key, conn_info
                )
            else:
                await self._handle_http_connection(
                    reader, writer, http_data, host, port, conn_key
                )

        except Exception:
            await self._handle_connection_error(writer, conn_key)

    def _parse_http_request(self, http_data: bytes) -> Tuple[bytes, bytes, int]:
        """Parse HTTP request to extract method, host and port"""

        headers = http_data.split(b"\r\n")
        first_line = headers[0].split(b" ")
        method = first_line[0]
        url = first_line[1]

        if method == b"CONNECT":
            host_port = url.split(b":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
        else:
            host_header = next(
                (h for h in headers if h.startswith(b"Host: ")), None)
            if not host_header:
                raise ValueError("Missing Host header")

            host_port = host_header[6:].split(b":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 80

        return method, host, port

    async def _check_proxy_authorization(
        self, http_data: bytes, writer: asyncio.StreamWriter
    ) -> bool:
        """Check proxy authorization"""

        if not self.auth_enabled:
            return True

        headers = http_data.split(b"\r\n")
        auth_header = None
        for line in headers:
            if line.lower().startswith(b"proxy-authorization:"):
                auth_header = line
                break

        if auth_header is None:
            await self._send_407_response(writer)
            return False

        parts = auth_header.split(b" ", 2)
        if len(parts) != 3 or parts[1].lower() != b"basic":
            await self._send_407_response(writer)
            return False

        try:
            decoded = base64.b64decode(parts[2].strip()).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:
            await self._send_407_response(writer)
            return False

        if username != self.config.username or password != self.config.password:
            await self._send_407_response(writer)
            return False

        return True

    async def _send_407_response(self, writer: asyncio.StreamWriter):
        """Send 407 Proxy Authentication Required response"""

        response = (
            "HTTP/1.1 407 Proxy Authentication Required\r\n"
            'Proxy-Authenticate: Basic realm="NoDPI Proxy"\r\n'
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(response.encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def _handle_https_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: bytes,
        port: int,
        conn_key: Tuple,
        conn_info: ConnectionInfo,
    ) -> None:
        """Handle HTTPS CONNECT request"""

        response_size = len(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.statistics.update_traffic(response_size, 0, "http")
        conn_info.traffic_in += response_size

        host_str = host.decode()

        # Resolve host using external DNS if needed
        resolved_ip = await resolve_host(host_str)
        if not resolved_ip:
            self.logger.log_error(f"Failed to resolve {host_str}")
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        remote_reader, remote_writer = await asyncio.open_connection(
            resolved_ip,
            port,
            local_addr=(self.out_host, 0) if self.out_host else None,
        )

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        await self._handle_initial_tls_data(reader, remote_writer, host, conn_info)

        await self._setup_piping(reader, writer, remote_reader, remote_writer, conn_key)

    async def _handle_http_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        http_data: bytes,
        host: bytes,
        port: int,
        conn_key: Tuple,
    ) -> None:
        """Handle HTTP request"""

        host_str = host.decode()

        # Resolve host using external DNS if needed
        resolved_ip = await resolve_host(host_str)
        if not resolved_ip:
            self.logger.log_error(f"Failed to resolve {host_str}")
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        remote_reader, remote_writer = await asyncio.open_connection(
            resolved_ip,
            port,
            local_addr=(self.out_host, 0) if self.out_host else None,
        )

        remote_writer.write(http_data)
        await remote_writer.drain()

        self.statistics.increment_total_connections("http")
        self.statistics.increment_allowed_connections("http")

        await self._setup_piping(reader, writer, remote_reader, remote_writer, conn_key)

    def _extract_sni_position(self, data):
        i = 0
        while i < len(data) - 8:
            if all(data[i + j] == 0x00 for j in [0, 1, 2, 4, 6, 7]):
                ext_len = data[i + 3]
                server_name_list_len = data[i + 5]
                server_name_len = data[i + 8]
                if (
                    ext_len - server_name_list_len == 2
                    and server_name_list_len - server_name_len == 3
                ):
                    sni_start = i + 9
                    sni_end = sni_start + server_name_len
                    return sni_start, sni_end
            i += 1
        return None

    async def _handle_initial_tls_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: bytes,
        conn_info: ConnectionInfo,
    ) -> None:
        """Handle initial TLS data and fragmentation"""

        try:
            head = await reader.read(5)
            data = await reader.read(2048)
        except Exception:
            self.logger.log_error(
                f"{host.decode()} : {traceback.format_exc()}")
            return

        should_fragment = True
        if not isinstance(self.blacklist_manager, NoBlacklistManager):
            should_fragment = self.blacklist_manager.is_blocked(
                conn_info.dst_domain)

        if not should_fragment:
            self.statistics.increment_total_connections("http")
            self.statistics.increment_allowed_connections("http")
            combined_data = head + data
            writer.write(combined_data)
            await writer.drain()

            self.statistics.update_traffic(0, len(combined_data), "http")
            conn_info.traffic_out += len(combined_data)
            return

        self.statistics.increment_total_connections("http")
        self.statistics.increment_blocked_connections("http")

        parts = []

        if self.config.fragment_method == "sni":
            sni_pos = self._extract_sni_position(data)

            if sni_pos:
                part_start = data[: sni_pos[0]]
                sni_data = data[sni_pos[0]: sni_pos[1]]
                part_end = data[sni_pos[1]:]
                middle = (len(sni_data) + 1) // 2

                parts.append(
                    bytes.fromhex("160304")
                    + len(part_start).to_bytes(2, "big")
                    + part_start
                )
                parts.append(
                    bytes.fromhex("160304")
                    + len(sni_data[:middle]).to_bytes(2, "big")
                    + sni_data[:middle]
                )
                parts.append(
                    bytes.fromhex("160304")
                    + len(sni_data[middle:]).to_bytes(2, "big")
                    + sni_data[middle:]
                )
                parts.append(
                    bytes.fromhex("160304")
                    + len(part_end).to_bytes(2, "big")
                    + part_end
                )

        elif self.config.fragment_method == "random":
            host_end = data.find(b"\x00")
            if host_end != -1:
                part_data = (
                    bytes.fromhex("160304")
                    + (host_end + 1).to_bytes(2, "big")
                    + data[: host_end + 1]
                )
                parts.append(part_data)
                data = data[host_end + 1:]

            while data:
                chunk_len = random.randint(1, len(data))
                part_data = (
                    bytes.fromhex("160304")
                    + chunk_len.to_bytes(2, "big")
                    + data[:chunk_len]
                )
                parts.append(part_data)
                data = data[chunk_len:]

        combined_parts = b"".join(parts)
        writer.write(combined_parts)
        await writer.drain()

        self.statistics.update_traffic(0, len(combined_parts), "http")
        conn_info.traffic_out += len(combined_parts)

    async def _setup_piping(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        conn_key: Tuple,
    ) -> None:
        """Setup bidirectional piping between client and remote"""

        async with self.tasks_lock:
            self.tasks.extend(
                [
                    asyncio.create_task(
                        self._pipe_data(
                            client_reader, remote_writer, "out", conn_key)
                    ),
                    asyncio.create_task(
                        self._pipe_data(
                            remote_reader, client_writer, "in", conn_key)
                    ),
                ]
            )

    async def _pipe_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        direction: str,
        conn_key: Tuple,
    ) -> None:
        """Pipe data between reader and writer"""

        conn_info = None
        try:
            while not reader.at_eof() and not writer.is_closing():
                data = await reader.read(1500)
                if not data:
                    break

                if direction == "out":
                    self.statistics.update_traffic(0, len(data), "http")
                else:
                    self.statistics.update_traffic(len(data), 0, "http")

                async with self.connections_lock:
                    conn_info = self.active_connections.get(conn_key)
                    if conn_info:
                        if direction == "out":
                            conn_info.traffic_out += len(data)
                        else:
                            conn_info.traffic_in += len(data)

                writer.write(data)
                await writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception:
            if conn_info:
                self.logger.log_error(
                    f"{conn_info.dst_domain} : {traceback.format_exc()}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

            async with self.connections_lock:
                conn_info = self.active_connections.pop(conn_key, None)
                if conn_info:
                    self.logger.log_access(
                        f"[HTTP] {conn_info.start_time} {conn_info.src_ip} {conn_info.method} {conn_info.dst_domain} {conn_info.traffic_in} {conn_info.traffic_out}"
                    )

    async def _handle_connection_error(
        self, writer: asyncio.StreamWriter, conn_key: Tuple
    ) -> None:
        """Handle connection errors"""

        try:
            error_response = b"HTTP/1.1 500 Internal Server Error\r\n\r\n"
            writer.write(error_response)
            await writer.drain()

            self.statistics.update_traffic(len(error_response), 0, "http")
        except Exception:
            pass

        async with self.connections_lock:
            conn_info = self.active_connections.pop(conn_key, None)

        self.statistics.increment_total_connections("http")
        self.statistics.increment_error_connections("http")
        if conn_info:
            self.logger.log_error(
                f"{conn_info.dst_domain} : {traceback.format_exc()}")

        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

    async def cleanup_tasks(self) -> None:
        """Clean up completed tasks"""

        while True:
            await asyncio.sleep(60)
            async with self.tasks_lock:
                self.tasks = [t for t in self.tasks if not t.done()]


class SOCKS5ConnectionHandler(IConnectionHandler):
    """Handles individual SOCKS5 client connections with DPI bypass"""

    # SOCKS5 constants
    SOCKS_VERSION = 5
    AUTH_NO_AUTH = 0
    AUTH_PASSWORD = 2
    AUTH_NO_ACCEPTABLE = 0xFF

    CMD_CONNECT = 1
    CMD_UDP_ASSOCIATE = 3

    ATYP_IPV4 = 1
    ATYP_DOMAIN = 3
    ATYP_IPV6 = 4

    REP_SUCCESS = 0
    REP_GENERAL_FAILURE = 1
    REP_CONNECTION_NOT_ALLOWED = 2
    REP_NETWORK_UNREACHABLE = 3
    REP_HOST_UNREACHABLE = 4
    REP_CONNECTION_REFUSED = 5
    REP_TTL_EXPIRED = 6
    REP_COMMAND_NOT_SUPPORTED = 7
    REP_ADDRESS_TYPE_NOT_SUPPORTED = 8

    def __init__(
        self,
        config: ProxyConfig,
        blacklist_manager: IBlacklistManager,
        statistics: IStatistics,
        logger: ILogger,
    ):

        self.config = config
        self.blacklist_manager = blacklist_manager
        self.statistics = statistics
        self.logger = logger
        self.out_host = self.config.out_host
        self.auth_enabled = config.username is not None and config.password is not None
        self.active_connections: Dict[Tuple, ConnectionInfo] = {}
        self.connections_lock = asyncio.Lock()
        self.tasks: List[asyncio.Task] = []
        self.tasks_lock = asyncio.Lock()

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming SOCKS5 client connection"""

        client_ip, client_port = writer.get_extra_info("peername")
        conn_key = (client_ip, client_port)

        try:
            # Step 1: Negotiate authentication method
            if not await self._negotiate_auth(reader, writer):
                return

            # Step 2: Handle the request
            await self._handle_request(reader, writer, conn_key)

        except Exception as e:
            self.logger.log_error(f"SOCKS5 connection error: {traceback.format_exc()}")
            await self._handle_connection_error(writer, conn_key)

    async def _negotiate_auth(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> bool:
        """Negotiate authentication method with client"""

        try:
            # Read client greeting
            data = await reader.read(2)
            if len(data) < 2:
                return False

            socks_version, nmethods = data[0], data[1]
            if socks_version != self.SOCKS_VERSION:
                return False

            # Read authentication methods offered by client
            methods = await reader.read(nmethods)
            if len(methods) < nmethods:
                return False

            # Select authentication method
            if not self.auth_enabled:
                # No authentication required
                if self.AUTH_NO_AUTH in methods:
                    selected_method = self.AUTH_NO_AUTH
                else:
                    selected_method = self.AUTH_NO_ACCEPTABLE
            else:
                # Authentication required
                if self.AUTH_PASSWORD in methods:
                    selected_method = self.AUTH_PASSWORD
                elif self.AUTH_NO_AUTH in methods:
                    # Client offered no auth but we require auth
                    selected_method = self.AUTH_NO_ACCEPTABLE
                else:
                    selected_method = self.AUTH_NO_ACCEPTABLE

            # Send method selection response
            writer.write(bytes([self.SOCKS_VERSION, selected_method]))
            await writer.drain()

            if selected_method == self.AUTH_NO_ACCEPTABLE:
                writer.close()
                await writer.wait_closed()
                return False

            # Handle username/password authentication if required
            if selected_method == self.AUTH_PASSWORD:
                if not await self._handle_password_auth(reader, writer):
                    return False

            return True

        except Exception as e:
            self.logger.log_error(f"SOCKS5 auth negotiation error: {e}")
            return False

    async def _handle_password_auth(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> bool:
        """Handle username/password authentication (RFC 1929)"""

        try:
            # Read auth version and username length
            data = await reader.read(2)
            if len(data) < 2:
                return False

            auth_version, ulen = data[0], data[1]
            if auth_version != 1:  # Sub-negotiation version
                return False

            # Read username
            username = await reader.read(ulen)
            if len(username) < ulen:
                return False

            # Read password length and password
            plen_data = await reader.read(1)
            if len(plen_data) < 1:
                return False
            plen = plen_data[0]

            password = await reader.read(plen)
            if len(password) < plen:
                return False

            # Verify credentials
            username_str = username.decode("utf-8", errors="ignore")
            password_str = password.decode("utf-8", errors="ignore")

            success = (
                username_str == self.config.username
                and password_str == self.config.password
            )

            # Send authentication response
            writer.write(bytes([1, 0 if success else 1]))
            await writer.drain()

            if not success:
                writer.close()
                await writer.wait_closed()
                return False

            return True

        except Exception as e:
            self.logger.log_error(f"SOCKS5 password auth error: {e}")
            return False

    async def _handle_request(
        self, reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        conn_key: Tuple
    ) -> None:
        """Handle SOCKS5 request"""

        try:
            # Read request header
            data = await reader.read(4)
            if len(data) < 4:
                await self._send_reply(writer, self.REP_GENERAL_FAILURE)
                return

            socks_version, cmd, rsv, atyp = data

            if socks_version != self.SOCKS_VERSION:
                await self._send_reply(writer, self.REP_GENERAL_FAILURE)
                return

            if cmd != self.CMD_CONNECT:
                await self._send_reply(writer, self.REP_COMMAND_NOT_SUPPORTED)
                return

            # Parse destination address
            host, port = await self._parse_address(reader, atyp)
            if host is None:
                await self._send_reply(writer, self.REP_ADDRESS_TYPE_NOT_SUPPORTED)
                return

            host_str = host.decode() if isinstance(host, bytes) else host

            # Create connection info
            conn_info = ConnectionInfo(
                conn_key[0], host_str, "CONNECT", "socks5"
            )

            # Check domain if using auto-blacklist
            if isinstance(self.blacklist_manager, AutoBlacklistManager):
                await self.blacklist_manager.check_domain(
                    host.encode() if isinstance(host, str) else host
                )

            async with self.connections_lock:
                self.active_connections[conn_key] = conn_info

            # Resolve host using external DNS if needed
            resolved_ip = await resolve_host(host_str)
            if not resolved_ip:
                self.logger.log_error(f"SOCKS5 failed to resolve {host_str}")
                await self._send_reply(writer, self.REP_HOST_UNREACHABLE)
                async with self.connections_lock:
                    self.active_connections.pop(conn_key, None)
                return

            # Connect to remote host
            try:
                remote_reader, remote_writer = await asyncio.open_connection(
                    resolved_ip,
                    port,
                    local_addr=(self.out_host, 0) if self.out_host else None,
                )
            except Exception as e:
                self.logger.log_error(f"SOCKS5 failed to connect to {host_str}:{port}: {e}")
                await self._send_reply(writer, self.REP_CONNECTION_REFUSED)
                async with self.connections_lock:
                    self.active_connections.pop(conn_key, None)
                return

            # Send success reply
            await self._send_reply(writer, self.REP_SUCCESS)

            # Handle TLS fragmentation for HTTPS connections
            if port == 443:
                await self._handle_initial_tls_data(reader, remote_writer, host_str, conn_info)

            # Update statistics
            self.statistics.increment_total_connections("socks5")
            if isinstance(self.blacklist_manager, NoBlacklistManager):
                self.statistics.increment_blocked_connections("socks5")
            elif self.blacklist_manager.is_blocked(host_str):
                self.statistics.increment_blocked_connections("socks5")
            else:
                self.statistics.increment_allowed_connections("socks5")

            # Setup bidirectional data piping
            await self._setup_piping(reader, writer, remote_reader, remote_writer, conn_key)

        except Exception as e:
            self.logger.log_error(f"SOCKS5 request error: {traceback.format_exc()}")
            await self._send_reply(writer, self.REP_GENERAL_FAILURE)

    async def _parse_address(
        self, reader: asyncio.StreamReader, atyp: int
    ) -> Tuple[Optional[bytes], Optional[int]]:
        """Parse destination address based on address type"""

        try:
            if atyp == self.ATYP_IPV4:
                # IPv4 address (4 bytes)
                addr = await reader.read(4)
                if len(addr) < 4:
                    return None, None
                host = ".".join(str(b) for b in addr)

            elif atyp == self.ATYP_DOMAIN:
                # Domain name
                len_data = await reader.read(1)
                if len(len_data) < 1:
                    return None, None
                domain_len = len_data[0]
                host = await reader.read(domain_len)
                if len(host) < domain_len:
                    return None, None
                host = host.decode("utf-8", errors="ignore")

            elif atyp == self.ATYP_IPV6:
                # IPv6 address (16 bytes)
                addr = await reader.read(16)
                if len(addr) < 16:
                    return None, None
                # Format IPv6 address
                parts = []
                for i in range(0, 16, 2):
                    parts.append(f"{addr[i]:02x}{addr[i+1]:02x}")
                host = ":".join(parts)

            else:
                return None, None

            # Read port (2 bytes, big-endian)
            port_data = await reader.read(2)
            if len(port_data) < 2:
                return None, None
            port = struct.unpack(">H", port_data)[0]

            return host, port

        except Exception:
            return None, None

    async def _send_reply(
        self, writer: asyncio.StreamWriter, reply_code: int,
        bind_addr: str = "0.0.0.0", bind_port: int = 0
    ) -> None:
        """Send SOCKS5 reply to client"""

        try:
            # Build reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
            reply = bytes([self.SOCKS_VERSION, reply_code, 0, self.ATYP_IPV4])

            # Add bind address (IPv4)
            for part in bind_addr.split("."):
                reply += bytes([int(part)])

            # Add bind port
            reply += struct.pack(">H", bind_port)

            writer.write(reply)
            await writer.drain()

            self.statistics.update_traffic(len(reply), 0, "socks5")

        except Exception:
            pass

    def _extract_sni_position(self, data):
        """Extract SNI position from TLS ClientHello data"""
        i = 0
        while i < len(data) - 8:
            if all(data[i + j] == 0x00 for j in [0, 1, 2, 4, 6, 7]):
                ext_len = data[i + 3]
                server_name_list_len = data[i + 5]
                server_name_len = data[i + 8]
                if (
                    ext_len - server_name_list_len == 2
                    and server_name_list_len - server_name_len == 3
                ):
                    sni_start = i + 9
                    sni_end = sni_start + server_name_len
                    return sni_start, sni_end
            i += 1
        return None

    async def _handle_initial_tls_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        conn_info: ConnectionInfo,
    ) -> None:
        """Handle initial TLS data and fragmentation for SOCKS5"""

        try:
            head = await reader.read(5)
            data = await reader.read(2048)
        except Exception:
            self.logger.log_error(
                f"SOCKS5 {host} : {traceback.format_exc()}")
            return

        should_fragment = True
        if not isinstance(self.blacklist_manager, NoBlacklistManager):
            should_fragment = self.blacklist_manager.is_blocked(host)

        if not should_fragment:
            combined_data = head + data
            writer.write(combined_data)
            await writer.drain()

            self.statistics.update_traffic(0, len(combined_data), "socks5")
            conn_info.traffic_out += len(combined_data)
            return

        parts = []

        if self.config.fragment_method == "sni":
            sni_pos = self._extract_sni_position(data)

            if sni_pos:
                part_start = data[: sni_pos[0]]
                sni_data = data[sni_pos[0]: sni_pos[1]]
                part_end = data[sni_pos[1]:]
                middle = (len(sni_data) + 1) // 2

                parts.append(
                    bytes.fromhex("160304")
                    + len(part_start).to_bytes(2, "big")
                    + part_start
                )
                parts.append(
                    bytes.fromhex("160304")
                    + len(sni_data[:middle]).to_bytes(2, "big")
                    + sni_data[:middle]
                )
                parts.append(
                    bytes.fromhex("160304")
                    + len(sni_data[middle:]).to_bytes(2, "big")
                    + sni_data[middle:]
                )
                parts.append(
                    bytes.fromhex("160304")
                    + len(part_end).to_bytes(2, "big")
                    + part_end
                )

        elif self.config.fragment_method == "random":
            host_end = data.find(b"\x00")
            if host_end != -1:
                part_data = (
                    bytes.fromhex("160304")
                    + (host_end + 1).to_bytes(2, "big")
                    + data[: host_end + 1]
                )
                parts.append(part_data)
                data = data[host_end + 1:]

            while data:
                chunk_len = random.randint(1, len(data))
                part_data = (
                    bytes.fromhex("160304")
                    + chunk_len.to_bytes(2, "big")
                    + data[:chunk_len]
                )
                parts.append(part_data)
                data = data[chunk_len:]

        combined_parts = b"".join(parts)
        writer.write(combined_parts)
        await writer.drain()

        self.statistics.update_traffic(0, len(combined_parts), "socks5")
        conn_info.traffic_out += len(combined_parts)

    async def _setup_piping(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        conn_key: Tuple,
    ) -> None:
        """Setup bidirectional piping between client and remote"""

        async with self.tasks_lock:
            self.tasks.extend(
                [
                    asyncio.create_task(
                        self._pipe_data(
                            client_reader, remote_writer, "out", conn_key)
                    ),
                    asyncio.create_task(
                        self._pipe_data(
                            remote_reader, client_writer, "in", conn_key)
                    ),
                ]
            )

    async def _pipe_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        direction: str,
        conn_key: Tuple,
    ) -> None:
        """Pipe data between reader and writer"""

        conn_info = None
        try:
            while not reader.at_eof() and not writer.is_closing():
                data = await reader.read(1500)
                if not data:
                    break

                if direction == "out":
                    self.statistics.update_traffic(0, len(data), "socks5")
                else:
                    self.statistics.update_traffic(len(data), 0, "socks5")

                async with self.connections_lock:
                    conn_info = self.active_connections.get(conn_key)
                    if conn_info:
                        if direction == "out":
                            conn_info.traffic_out += len(data)
                        else:
                            conn_info.traffic_in += len(data)

                writer.write(data)
                await writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception:
            if conn_info:
                self.logger.log_error(
                    f"SOCKS5 {conn_info.dst_domain} : {traceback.format_exc()}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

            async with self.connections_lock:
                conn_info = self.active_connections.pop(conn_key, None)
                if conn_info:
                    self.logger.log_access(
                        f"[SOCKS5] {conn_info.start_time} {conn_info.src_ip} {conn_info.method} {conn_info.dst_domain} {conn_info.traffic_in} {conn_info.traffic_out}"
                    )

    async def _handle_connection_error(
        self, writer: asyncio.StreamWriter, conn_key: Tuple
    ) -> None:
        """Handle connection errors"""

        async with self.connections_lock:
            conn_info = self.active_connections.pop(conn_key, None)

        self.statistics.increment_total_connections("socks5")
        self.statistics.increment_error_connections("socks5")
        if conn_info:
            self.logger.log_error(
                f"SOCKS5 {conn_info.dst_domain} : {traceback.format_exc()}")

        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass

    async def cleanup_tasks(self) -> None:
        """Clean up completed tasks"""

        while True:
            await asyncio.sleep(60)
            async with self.tasks_lock:
                self.tasks = [t for t in self.tasks if not t.done()]


class ProxyServer:
    """Main HTTP proxy server class"""

    def __init__(
        self,
        config: ProxyConfig,
        blacklist_manager: IBlacklistManager,
        statistics: IStatistics,
        logger: ILogger,
    ):

        self.config = config
        self.blacklist_manager = blacklist_manager
        self.statistics = statistics
        self.logger = logger
        self.connection_handler = ConnectionHandler(
            config, blacklist_manager, statistics, logger
        )
        self.server = None

        self.update_check_task = None
        self.update_available = None
        self.update_event = asyncio.Event()

        logger.set_error_counter_callback(
            statistics.increment_error_connections)

    async def check_for_updates(self):
        """Check for updates"""

        if self.config.quiet:
            return None

        try:
            loop = asyncio.get_event_loop()

            def sync_check():
                try:
                    req = Request(
                        "https://gvcoder09.github.io/nodpi_site/api/v1/update_info.json",
                    )
                    with urlopen(req, timeout=3) as response:
                        if response.status == 200:
                            data = json.loads(response.read())
                            latest_version = data.get("nodpi", "").get(
                                "latest_version", ""
                            )
                            if latest_version and latest_version != __version__:
                                return latest_version
                except (URLError, json.JSONDecodeError, Exception):
                    pass
                return None

            latest_version = await loop.run_in_executor(None, sync_check)
            if latest_version:
                self.update_available = latest_version
                self.update_event.set()
                return f"\033[93m[UPDATE]: Available new version: v{latest_version} \033[97m"
        except Exception:
            pass
        finally:
            self.update_event.set()
        return None

    async def print_banner(self) -> None:
        """Print startup banner"""

        self.update_check_task = asyncio.create_task(self.check_for_updates())

        try:
            await asyncio.wait_for(self.update_event.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            if self.update_check_task and not self.update_check_task.done():
                self.update_check_task.cancel()
                try:
                    await self.update_check_task
                except asyncio.CancelledError:
                    pass

        self.logger.info("\033]0;NoDPI\007")

        if sys.platform == "win32":
            os.system("mode con: lines=33")

        if sys.stdout.isatty():
            console_width = os.get_terminal_size().columns
        else:
            console_width = 80

        disclaimer = (
            "DISCLAIMER. The developer and/or supplier of this software "
            "shall not be liable for any loss or damage, including but "
            "not limited to direct, indirect, incidental, punitive or "
            "consequential damages arising out of the use of or inability "
            "to use this software, even if the developer or supplier has been "
            "advised of the possibility of such damages. The developer and/or "
            "supplier of this software shall not be liable for any legal "
            "consequences arising out of the use of this software. This includes, "
            "but is not limited to, violation of laws, rules or regulations, "
            "as well as any claims or suits arising out of the use of this software. "
            "The user is solely responsible for compliance with all applicable laws "
            "and regulations when using this software."
        )
        wrapped_text = textwrap.TextWrapper(width=70).wrap(disclaimer)

        left_padding = (console_width - 76) // 2

        self.logger.info("\n\n\n")
        self.logger.info(
            "\033[91m" + " " * left_padding + "╔" + "═" * 72 + "╗" + "\033[0m"
        )

        for line in wrapped_text:
            padded_line = line.ljust(70)
            self.logger.info(
                "\033[91m" + " " * left_padding +
                "║ " + padded_line + " ║" + "\033[0m"
            )

        self.logger.info(
            "\033[91m" + " " * left_padding + "╚" + "═" * 72 + "╝" + "\033[0m"
        )

        time.sleep(1)

        update_message = None
        if self.update_check_task and self.update_check_task.done():
            try:
                update_message = self.update_check_task.result()
            except (asyncio.CancelledError, Exception):
                pass

        self.logger.info("\033[2J\033[H")

        self.logger.info(
            """
\033[92m  ██████   █████          ██████████   ███████████  █████
 ░░██████ ░░███          ░░███░░░░███ ░░███░░░░░███░░███
  ░███░███ ░███   ██████  ░███   ░░███ ░███    ░███ ░███
  ░███░░███░███  ███░░███ ░███    ░███ ░██████████  ░███
  ░███ ░░██████ ░███ ░███ ░███    ░███ ░███░░░░░░   ░███
  ░███  ░░█████ ░███ ░███ ░███    ███  ░███         ░███
  █████  ░░█████░░██████  ██████████   █████        █████
 ░░░░░    ░░░░░  ░░░░░░  ░░░░░░░░░░   ░░░░░        ░░░░░\033[0m
        """
        )
        self.logger.info(f"\033[92mVersion: {__version__} (with SOCKS5)".center(50))
        self.logger.info(
            "\033[97m" +
            "Enjoy watching! / Наслаждайтесь просмотром!".center(50)
        )

        self.logger.info("\n")

        if update_message:
            self.logger.info(update_message)

        # HTTP Proxy info
        self.logger.info(
            f"\033[92m[INFO]:\033[97m HTTP Proxy running on {self.config.host}:{self.config.port}"
        )

        # SOCKS5 Proxy info
        if self.config.socks5_host and self.config.socks5_port:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m SOCKS5 Proxy running on {self.config.socks5_host}:{self.config.socks5_port}"
            )
        else:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m SOCKS5 Proxy disabled (use --socks5-host and --socks5-port to enable)"
            )

        self.logger.info(
            f"\033[92m[INFO]:\033[97m The selected fragmentation method: {self.config.fragment_method}"
        )

        self.logger.info(
            "\033[92m[INFO]:\033[97m DNS resolution via DNS over HTTPS (Google, Cloudflare, Quad9)"
        )

        self.logger.info("")
        if isinstance(self.blacklist_manager, NoBlacklistManager):
            self.logger.info(
                "\033[92m[INFO]:\033[97m Blacklist is disabled. All domains will be subject to unblocking."
            )
        elif isinstance(self.blacklist_manager, AutoBlacklistManager):
            self.logger.info(
                "\033[92m[INFO]:\033[97m Auto-blacklist is enabled")
        else:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Blacklist contains {len(self.blacklist_manager.blocked)} domains"
            )
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Path to blacklist: '{os.path.normpath(self.config.blacklist_file)}'"
            )

        self.logger.info("")
        if self.config.log_error_file:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Error logging is enabled. Path to error log: '{self.config.log_error_file}'"
            )
        else:
            self.logger.info(
                "\033[92m[INFO]:\033[97m Error logging is disabled")

        if self.config.log_access_file:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Access logging is enabled. Path to access log: '{self.config.log_access_file}'"
            )
        else:
            self.logger.info(
                "\033[92m[INFO]:\033[97m Access logging is disabled")

        self.logger.info("")
        self.logger.info(
            "\033[92m[INFO]:\033[97m To stop the proxy, press Ctrl+C twice"
        )
        self.logger.info("")

    async def display_stats(self) -> None:
        """Display live statistics"""

        while True:
            await asyncio.sleep(1)
            self.statistics.update_speeds()
            if not self.config.quiet:
                stats_display = self.statistics.get_stats_display()
                print(stats_display)
                print("\033[6A", end="", flush=True)

    async def run(self) -> None:
        """Run the HTTP proxy server"""

        if not self.config.quiet:
            await self.print_banner()

        try:
            self.server = await asyncio.start_server(
                self.connection_handler.handle_connection,
                self.config.host,
                self.config.port,
            )
        except OSError:
            self.logger.error(
                f"\033[91m[ERROR]: Failed to start HTTP proxy on this address ({self.config.host}:{self.config.port}). It looks like the port is already in use\033[0m"
            )
            return False

        if not self.config.quiet:
            asyncio.create_task(self.display_stats())
        asyncio.create_task(self.connection_handler.cleanup_tasks())

        return True

    async def serve(self) -> None:
        """Serve the HTTP proxy"""
        if self.server:
            await self.server.serve_forever()

    async def shutdown(self) -> None:
        """Shutdown the HTTP proxy server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()

        for task in self.connection_handler.tasks:
            task.cancel()


class SOCKS5Server:
    """SOCKS5 proxy server class"""

    def __init__(
        self,
        config: ProxyConfig,
        blacklist_manager: IBlacklistManager,
        statistics: IStatistics,
        logger: ILogger,
    ):

        self.config = config
        self.blacklist_manager = blacklist_manager
        self.statistics = statistics
        self.logger = logger
        self.connection_handler = SOCKS5ConnectionHandler(
            config, blacklist_manager, statistics, logger
        )
        self.server = None

    async def run(self) -> bool:
        """Run the SOCKS5 proxy server"""

        if not self.config.socks5_host or not self.config.socks5_port:
            return True  # SOCKS5 is disabled, not an error

        try:
            self.server = await asyncio.start_server(
                self.connection_handler.handle_connection,
                self.config.socks5_host,
                self.config.socks5_port,
            )

            asyncio.create_task(self.connection_handler.cleanup_tasks())
            return True

        except OSError:
            self.logger.error(
                f"\033[91m[ERROR]: Failed to start SOCKS5 proxy on this address ({self.config.socks5_host}:{self.config.socks5_port}). It looks like the port is already in use\033[0m"
            )
            return False

    async def serve(self) -> None:
        """Serve the SOCKS5 proxy"""
        if self.server:
            await self.server.serve_forever()

    async def shutdown(self) -> None:
        """Shutdown the SOCKS5 proxy server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()

        for task in self.connection_handler.tasks:
            task.cancel()


class BlacklistManagerFactory:
    """Factory for creating blacklist managers"""

    @staticmethod
    def create(config: ProxyConfig, logger: ILogger) -> IBlacklistManager:
        """Create blacklist manager based on config"""

        if config.no_blacklist:
            return NoBlacklistManager()
        elif config.auto_blacklist:
            return AutoBlacklistManager(config)
        else:
            try:
                return FileBlacklistManager(config)
            except FileNotFoundError:
                logger.error(
                    f"\033[91m[ERROR]: Blacklist file not found: {config.blacklist_file}\033[0m"
                )
                sys.exit(1)


class ConfigLoader:
    """Load configuration from command line arguments"""

    @staticmethod
    def load_from_args(args) -> ProxyConfig:
        """Load configuration from parsed arguments"""

        config = ProxyConfig()

        # HTTP Proxy settings
        config.host = args.host
        config.port = args.port

        # SOCKS5 Proxy settings
        config.socks5_host = args.socks5_host
        config.socks5_port = args.socks5_port

        config.out_host = args.out_host
        config.username = args.auth_username
        config.password = args.auth_password

        config.blacklist_file = args.blacklist
        config.no_blacklist = args.no_blacklist
        config.auto_blacklist = args.autoblacklist

        config.fragment_method = args.fragment_method
        config.domain_matching = args.domain_matching

        config.log_access_file = args.log_access
        config.log_error_file = args.log_error
        config.quiet = args.quiet

        return config


class WindowsAutostartManager(IAutostartManager):
    """Windows autostart manager"""

    @staticmethod
    def manage_autostart(action: str) -> None:

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        app_name = "NoDPIProxy"

        if action == "install":
            try:
                exec_path = sys.executable
                blacklist_path = os.path.join(
                    os.path.dirname(exec_path), "blacklist.txt"
                )

                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE
                )
                winreg.SetValueEx(
                    key, app_name, 0, winreg.REG_SZ,
                    f'"{exec_path}" --blacklist "{blacklist_path}" --quiet'
                )
                winreg.CloseKey(key)
                print(f"\033[92m[INFO]: Added to Windows autostart\033[0m")

            except Exception as e:
                print(f"\033[91m[ERROR]: Failed to add to autostart: {e}\033[0m")

        elif action == "uninstall":
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE
                )
                try:
                    winreg.DeleteValue(key, app_name)
                    print(f"\033[92m[INFO]: Removed from Windows autostart\033[0m")
                except FileNotFoundError:
                    print(f"\033[93m[INFO]: Not found in Windows autostart\033[0m")
                winreg.CloseKey(key)

            except Exception as e:
                print(f"\033[91m[ERROR]: Failed to remove from autostart: {e}\033[0m")


class LinuxAutostartManager(IAutostartManager):
    """Linux autostart manager"""

    @staticmethod
    def manage_autostart(action: str) -> None:

        service_name = "nodpi-proxy.service"
        service_file = Path.home() / ".config" / "systemd" / "user" / service_name

        if action == "install":
            try:
                exec_path = sys.executable
                blacklist_path = os.path.join(
                    os.path.dirname(exec_path), "blacklist.txt"
                )

                service_file.parent.mkdir(parents=True, exist_ok=True)

                service_content = f"""[Unit]
Description=NoDPIProxy Service
After=network.target graphical-session.target
Wants=network.target

[Service]
Type=simple
ExecStart={exec_path} --blacklist "{blacklist_path}" --quiet
Restart=on-failure
RestartSec=5
Environment=DISPLAY=:0
Environment=XAUTHORITY=%h/.Xauthority

[Install]
WantedBy=default.target
"""

                with open(service_file, "w", encoding="utf-8") as f:
                    f.write(service_content)

                subprocess.run(
                    ["systemctl", "--user", "daemon-reload"], check=True)

                subprocess.run(
                    ["systemctl", "--user", "enable", service_name], check=True
                )
                subprocess.run(
                    ["systemctl", "--user", "start", service_name], check=True
                )

                print(
                    f"\033[INFO]:\033 Service installed and started: {service_name}"
                )
                print("\033[NOTE]:\033 Service will auto-start on login")

            except subprocess.CalledProcessError as e:
                print(f"\033[ERROR]: Systemd command failed: {e}\033")
            except Exception as e:
                print(
                    f"\033[ERROR]: Autostart operation failed: {e}\033")

        elif action == "uninstall":
            try:
                subprocess.run(
                    ["systemctl", "--user", "stop", service_name],
                    capture_output=True,
                    check=True,
                )
                subprocess.run(
                    ["systemctl", "--user", "disable", service_name],
                    capture_output=True,
                    check=True,
                )

                if service_file.exists():
                    service_file.unlink()

                subprocess.run(
                    ["systemctl", "--user", "daemon-reload"], check=True)

                print("\033[INFO]:\033 Service removed from autostart")

            except subprocess.CalledProcessError as e:
                print(f"\033[ERROR]: Systemd command failed: {e}\033")
            except Exception as e:
                print(
                    f"\033[ERROR]: Autostart operation failed: {e}\033")


class ProxyApplication:
    """Main application class"""

    @staticmethod
    def parse_args():
        """Parse command line arguments"""

        parser = argparse.ArgumentParser(
            description="NoDPI - DPI bypass proxy with HTTP and SOCKS5 support"
        )

        # HTTP Proxy settings
        parser.add_argument("--host", default="127.0.0.1", help="HTTP proxy host")
        parser.add_argument("--port", type=int, default=8881, help="HTTP proxy port")

        # SOCKS5 Proxy settings
        parser.add_argument("--socks5-host", default=None, help="SOCKS5 proxy host (default: disabled)")
        parser.add_argument("--socks5-port", type=int, default=None, help="SOCKS5 proxy port (default: disabled)")

        parser.add_argument("--out-host", help="Outgoing proxy host")

        blacklist_group = parser.add_mutually_exclusive_group()
        blacklist_group.add_argument(
            "--blacklist", default="blacklist.txt", help="Path to blacklist file"
        )
        blacklist_group.add_argument(
            "--no-blacklist",
            action="store_true",
            help="Use fragmentation for all domains",
        )
        blacklist_group.add_argument(
            "--autoblacklist",
            action="store_true",
            help="Automatic detection of blocked domains",
        )

        parser.add_argument(
            "--fragment-method",
            default="random",
            choices=["random", "sni"],
            help="Fragmentation method (random by default)",
        )
        parser.add_argument(
            "--domain-matching",
            default="strict",
            choices=["loose", "strict"],
            help="Domain matching mode (strict by default)",
        )

        parser.add_argument(
            "--auth-username", required=False, help="Username for proxy authentication"
        )
        parser.add_argument(
            "--auth-password", required=False, help="Password for proxy authentication"
        )

        parser.add_argument(
            "--log-access", required=False, help="Path to the access control log"
        )
        parser.add_argument(
            "--log-error", required=False, help="Path to log file for errors"
        )
        parser.add_argument(
            "-q", "--quiet", action="store_true", help="Remove UI output"
        )

        autostart_group = parser.add_mutually_exclusive_group()
        autostart_group.add_argument(
            "--install",
            action="store_true",
            help="Add proxy to Windows/Linux autostart (only for executable version)",
        )
        autostart_group.add_argument(
            "--uninstall",
            action="store_true",
            help="Remove proxy from Windows/Linux autostart (only for executable version)",
        )

        return parser.parse_args()

    @classmethod
    async def run(cls):
        """Run the proxy application"""

        logging.getLogger("asyncio").setLevel(logging.CRITICAL)

        args = cls.parse_args()

        if args.install or args.uninstall:
            if getattr(sys, "frozen", False):
                if args.install:
                    if sys.platform == "win32":
                        WindowsAutostartManager.manage_autostart("install")
                    elif sys.platform == "linux":
                        LinuxAutostartManager.manage_autostart("install")
                elif args.uninstall:
                    if sys.platform == "win32":
                        WindowsAutostartManager.manage_autostart("uninstall")
                    elif sys.platform == "linux":
                        LinuxAutostartManager.manage_autostart("uninstall")
                sys.exit(0)
            else:
                print(
                    "\033[ERROR]: Autostart works only in executable version\033"
                )
                sys.exit(1)

        config = ConfigLoader.load_from_args(args)

        logger = ProxyLogger(
            config.log_access_file, config.log_error_file, config.quiet
        )
        blacklist_manager = BlacklistManagerFactory.create(config, logger)
        statistics = Statistics()

        logger.set_error_counter_callback(
            lambda: statistics.increment_error_connections("http"))

        # Create HTTP proxy server
        http_proxy = ProxyServer(config, blacklist_manager, statistics, logger)

        # Create SOCKS5 proxy server
        socks5_proxy = SOCKS5Server(config, blacklist_manager, statistics, logger)

        try:
            # Start HTTP proxy
            if not await http_proxy.run():
                sys.exit(1)

            # Start SOCKS5 proxy
            if not await socks5_proxy.run():
                sys.exit(1)

            # Run both servers concurrently
            tasks = []
            if http_proxy.server:
                tasks.append(asyncio.create_task(http_proxy.serve()))
            if socks5_proxy.server:
                tasks.append(asyncio.create_task(socks5_proxy.serve()))

            if tasks:
                await asyncio.gather(*tasks)

        except asyncio.CancelledError:
            await http_proxy.shutdown()
            await socks5_proxy.shutdown()
            logger.info(
                "\n" * 6 + "\033[INFO]:\033 Shutting down proxies...")
            try:
                if sys.platform == "win32":
                    os.system("mode con: lines=3000")
                sys.exit(0)
            except asyncio.CancelledError:
                pass


if __name__ == "__main__":
    try:
        asyncio.run(ProxyApplication.run())
    except KeyboardInterrupt:
        pass
