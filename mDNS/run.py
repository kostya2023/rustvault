import socket
import time

from zeroconf import IPVersion, ServiceInfo, Zeroconf

HOST_IP = "192.168.1.200"
HOSTNAME = "rustvault.local."

service = ServiceInfo(
    "_https._tcp.local.",
    "RustVault._https._tcp.local.",
    addresses=[socket.inet_aton(HOST_IP)],
    port=443,
    properties={"path": "/"},
    server=HOSTNAME,
)

zc = Zeroconf(
    interfaces=[HOST_IP],
    ip_version=IPVersion.V4Only,
)

zc.register_service(service)

print(f"mDNS started: {HOSTNAME} -> {HOST_IP}")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    zc.unregister_service(service)
    zc.close()