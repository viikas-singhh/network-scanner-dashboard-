from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
from datetime import datetime

previous_devices = {}
scan_logs = []   # store log history

def scan_network(ip_range):
    global previous_devices, scan_logs

    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=4, retry=2, verbose=0)[0]

    current_devices = {}
    devices_list = []
    lookup = MacLookup()

    timestamp = datetime.now().strftime("%H:%M:%S")

    for sent, received in result:
        mac = received.hwsrc
        ip = received.psrc

        try:
            vendor = lookup.lookup(mac)
        except:
            vendor = "Unknown"

        if mac not in previous_devices:
            status = "New"
            scan_logs.append(f"[{timestamp}] New device detected: {ip}")
        else:
            status = "Active"

        current_devices[mac] = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "status": status
        }

    # offline detection
    for mac in previous_devices:
        if mac not in current_devices:
            ip = previous_devices[mac]["ip"]
            scan_logs.append(f"[{timestamp}] Device offline: {ip}")

            devices_list.append({
                "ip": ip,
                "mac": mac,
                "vendor": previous_devices[mac]["vendor"],
                "status": "Offline"
            })

    for mac in current_devices:
        devices_list.append(current_devices[mac])

    previous_devices = current_devices
    return devices_list


def get_logs():
    return scan_logs[-20:]   # return last 20 logs
