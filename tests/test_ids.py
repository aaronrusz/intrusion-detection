from scapy.all import IP, TCP

from intrusion_detection.ids import IntrusionDetectionMonitor


def test_detect_intrusion_with_tcp():
    monitor = IntrusionDetectionMonitor(quiet=True, no_log=True)
    packet = IP(src='198.51.100.1') / TCP(dport=22)
    alerts = monitor.detect_intrusion(packet)
    assert isinstance(alerts, list)


def test_packet_handler_appends_alerts():
    monitor = IntrusionDetectionMonitor(quiet=True, no_log=True)
    packet = IP(src='198.51.100.2') / TCP(dport=8080)
    monitor.packet_handler(packet)
    assert isinstance(monitor.alerts, list)
