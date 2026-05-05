import logging
import os
import psutil
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from scapy.all import sniff, IP, TCP, UDP


class IntrusionDetectionMonitor:
    def __init__(self, interface=None, quiet=False, no_log=False, log_file='intrusion_detection.log', daemon=False):
        self.interface = interface
        self.quiet = quiet
        self.no_log = no_log
        self.log_file = log_file
        self.daemon = daemon
        self.baseline_window = 120
        self.connection_history = defaultdict(lambda: deque(maxlen=200))
        self.alerts = []
        self.logger = self._configure_logging()

    def _configure_logging(self):
        handlers = []
        if not self.no_log:
            handlers.append(logging.FileHandler(self.log_file))
        if not self.quiet:
            handlers.append(logging.StreamHandler())

        if handlers:
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=handlers)
        else:
            logging.disable(logging.CRITICAL)

        return logging.getLogger(__name__)

    def _record_connection(self, src_ip, dst_port):
        now = datetime.now()
        self.connection_history[src_ip].append((dst_port, now))

    def detect_intrusion(self, packet):
        alerts = []
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            self._record_connection(src_ip, dst_port)

            recent = [entry for entry in self.connection_history[src_ip] if (datetime.now() - entry[1]).total_seconds() < self.baseline_window]
            ports = {entry[0] for entry in recent}
            if len(ports) > 20:
                alerts.append(f"Potential port scan from {src_ip}: {len(ports)} unique ports in {self.baseline_window}s")

            if len(recent) > 100:
                alerts.append(f"High-volume connection activity from {src_ip}: {len(recent)} connections")

            if packet.haslayer(UDP):
                alerts.append(f"Suspicious UDP traffic from {src_ip} to port {dst_port}")

        return alerts

    def packet_handler(self, packet):
        try:
            alerts = self.detect_intrusion(packet)
            for alert in alerts:
                self.logger.warning(f"ALERT: {alert}")
                self.alerts.append({'timestamp': datetime.now().isoformat(), 'alert': alert})
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")

    def start_monitoring(self):
        if self.daemon:
            self._daemonize()

        if not self.interface:
            interfaces = list(psutil.net_if_addrs().keys())
            self.interface = interfaces[0] if interfaces else None

        if not self.quiet:
            print(f"Starting intrusion detection on {self.interface or 'all interfaces'}")

        sniff(iface=self.interface, prn=self.packet_handler, store=0, stop_filter=lambda x: False)

    def _daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                raise SystemExit(0)
        except OSError as exc:
            self.logger.error(f"Failed to daemonize: {exc}")
            raise
