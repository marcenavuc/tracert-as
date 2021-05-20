import re
import socket
from typing import Dict, Optional

from traceroute.icmp import IcmpPacket
from traceroute.traceresult import TraceResult

WHOIS_SERVER_NAME = "whois.iana.org"
WHOIS_RE = re.compile(r"([A-Za-z\-]+):\s+([^\#\n]+)")


class Tracer:

    def __init__(self, destination: str):
        self.time_to_live = 1
        self.depth = float("inf")
        self.destination = socket.gethostbyname(destination)
        self.trace_results = []
        self.sender = None
        self.receiver = None

    @classmethod
    def get_whois_iana_data(cls, address: str) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as whois_sock:
            whois_sock.settimeout(1)
            whois_sock.connect((socket.gethostbyname(WHOIS_SERVER_NAME), 43))
            whois_sock.send(address.encode() + b'\r\n')
            try:
                data = cls.receive_data(whois_sock)
                return cls.parse_whois_response(data.decode()).get("whois", "")
            except (socket.timeout, ValueError):
                return ""

    def get_whois_data(self, addr: str) -> Optional[Dict]:
        whois_addr = self.get_whois_iana_data(addr)

        if not whois_addr:
            return

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as whois_sock:
            whois_sock.settimeout(2)
            whois_sock.connect((whois_addr, 43))
            whois_sock.send(addr.encode(encoding='utf-8') + b'\r\n')
            data = self.receive_data(whois_sock)
            whois_data = self.parse_whois_response(data.decode())
        whois_data['route'] = addr
        return whois_data

    def __enter__(self) -> "Tracer":
        self.sender = socket.socket(socket.AF_INET,
                                    socket.SOCK_DGRAM,
                                    socket.IPPROTO_ICMP)
        self.receiver = socket.socket(socket.AF_INET,
                                      socket.SOCK_RAW,
                                      socket.IPPROTO_ICMP)
        self.receiver.settimeout(3)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.sender.close()
        self.receiver.close()

    def start(self):
        previous_result = None
        while self.time_to_live <= self.depth:
            self.sender.setsockopt(socket.SOL_IP, socket.IP_TTL,
                                   self.time_to_live)
            self.sender.sendto(IcmpPacket(8, 0).pack(), (self.destination, 80))
            try:
                data, addr = self.receiver.recvfrom(1024)
                whois_data = self.get_whois_data(addr[0])
                icmp_response = IcmpPacket.from_bytes(data[20:])
                trace_result = TraceResult.get_from_data(whois_data)

                if previous_result != trace_result:
                    yield trace_result
                previous_result = trace_result
                if icmp_response.code == icmp_response.type == 0:
                    break

            except socket.timeout:
                continue
            finally:
                self.time_to_live += 1

    @staticmethod
    def receive_data(sock: socket.socket) -> bytes:
        data = b""
        while True:
            temp_data = sock.recv(1024)
            if not temp_data:
                break
            data += temp_data
        return data

    @staticmethod
    def parse_whois_response(data: str) -> Dict:
        result = re.findall(WHOIS_RE, data)
        return {key: value for key, value in result}
