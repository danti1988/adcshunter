import subprocess
import threading
import queue
import ipaddress
import os

def make_curl_request(ip):
    try:
        url = f"http://{ip}/certsrv/certsnsh.asp"
        result = subprocess.Popen(f"curl {url}", 
                                  shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = result.communicate(timeout=10)

        if output:
            return output.decode('utf-8'), None
        else:
            return None, error.decode('utf-8')
    except subprocess.TimeoutExpired:
        return None, "Curl request timed out"
    except Exception as e:
        return None, f"Error in curl request: {e}"

def worker(ip_queue, progress):
    while True:
        ip = ip_queue.get()
        if ip is None:
            break

        try:
            command = f"rpcdump.py {ip}"
            result = subprocess.Popen(command, 
                                      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = result.communicate(timeout=10)

            if output:
                output_decoded = output.decode('utf-8')
                if 'certsrv.exe' in output_decoded.lower():
                    curl_output, curl_error = make_curl_request(ip)
                    if curl_output and "401 - Unauthorized: Access is denied due to invalid credentials" in curl_output:
                        print(f"\033[91mVulnerable Web Enrollment endpoint identified: http://{ip}/certsrv/certsnsh.asp\033[0m")
                    elif curl_error:
                        print(f"Error accessing Web Enrollment endpoint for {ip}: {curl_error}")
            if error:
                print(f"Error for {ip}:\n{error.decode('utf-8')}")
        except subprocess.TimeoutExpired:
            print(f"Timeout expired for {ip}")
            result.kill()
        except Exception as e:
            print(f"Error running {command} on {ip}: {e}")
        
        with progress.get_lock():
            progress.value += 1
            print(f"Scanned {progress.value}/{progress.total}", end='\r')

        ip_queue.task_done()

def run_rpcdump_concurrently(ip_list):
    num_worker_threads = 10
    ip_queue = queue.Queue()

    # Shared progress counter
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
        t.start()
        threads.append(t)

    try:
        for ip in ip_list:
            ip_queue.put(ip.strip())

        ip_queue.join()

        for _ in range(num_worker_threads):
            ip_queue.put(None)
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting gracefully.")
        for _ in range(num_worker_threads):
            ip_queue.put(None)
        for t in threads:
            t.join()
    except Exception as e:
        print(f"\nAn error occurred: {e}")

def parse_input_line(line):
    if '/' in line:  # CIDR range
        return [str(ip) for ip in ipaddress.ip_network(line, strict=False)]
    elif is_valid_ip(line):  # Single IP
        return [line]
    else:
        return []

def is_valid_ip(input_string):
    try:
        ipaddress.ip_address(input_string)
        return True
    except ValueError:
        return False

def main():
    try:
        user_input = input("Enter a file path, CIDR range, or an IP address: ")
        
        if os.path.isfile(user_input):
            ip_list = []
            with open(user_input, 'r') as file:
                for line in file:
                    ip_list.extend(parse_input_line(line.strip()))
            run_rpcdump_concurrently(ip_list)
        elif is_valid_ip(user_input) or '/' in user_input:  # Single IP or CIDR
            ip_list = parse_input_line(user_input)
            run_rpcdump_concurrently(ip_list)
        else:
            print("Invalid input. Please enter a valid file path, CIDR range, or IP address.")
    except KeyboardInterrupt:
        print("\nOperation interrupted by user. Exiting gracefully.")

if __name__ == "__main__":
    main()
