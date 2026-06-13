import subprocess, sys

class NetworkScanner:
    def __init__(self):
        self.authorized_macs = []
        self.os_name = sys.platform
    
    def scan_network(self) -> str:
        commands = []
        if self.os_name == "win32":
            commands = ["arp", "-a"]
        elif self.os_name == "darwin":
            commands = ["arp", "-an"]
        elif self.os_name == "linux":
            commands = ["ip", "neigh", "show"]

        target = subprocess.run(commands, capture_output=True, text=True)

        return target.stdout

    def parse_results(self, raw_stdout: str) -> dict:
        devices = {}
        split_stdout = raw_stdout.splitlines()
        for stdout in split_stdout:
            raw_output = stdout.split()
            if self.os_name == "win32" and len(raw_output) == 3:
                ip_addr = raw_output[0]
                mac_sig = raw_output[1].replace("-", ":").lower()
                devices[ip_addr] = mac_sig
            elif self.os_name == "linux" and "lladdr" in raw_output:
                ip_addr = raw_output[0]
                mac_sig = raw_output[raw_output.index("lladdr")+1].replace("-", ":").lower()
                devices[ip_addr] = mac_sig
        return devices

    def verify_parameters(self, active_devices: dict) -> bool:
        for mac_sig in active_devices.values():
            if mac_sig not in self.authorized_macs:
                return False
        return True