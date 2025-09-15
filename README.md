# CS-331_CN_Assignment-1

## **Task 1**

This task implements a custom DNS Resolver using Python. The client extracts DNS queries from a PCAP file, adds a custom header, and sends them to the server. The server resolves the queries using a predefined IP pool and returns the results back to the client. It uses two programs: 
- **Client** → Reads DNS queries from a PCAP file, adds a custom header, and sends them out.
- **Server** → Waits for queries, resolves them based on rules, and sends the answers back. 

So first to run this, make sure you have the following installed: 
- **Python 3.x**
- **[Scapy](https://scapy.net/)** – for parsing PCAP and DNS packets
    ```bash
    pip install scapy

## **Steps to follow**

1. **PCAP File Selection**  
   Choose the correct PCAP file based on team roll numbers:
    ```bash
    X = (sum of last 3 digits of both team members) % 10 -> (058 + 338) % 10 = 6

So the correct file is **6.pcap** for this task.  

2. **Clone Repository**  
   Clone this repository to directly run on any device:  
   ```bash
    git clone https://github.com/Rushitha-Thipparapu/CS-331_CN_Assignment-1.git
    cd CS-331_CN_Assignment-1

3. **Run the Server**
    Open a terminal and run:
    ```bash
    python server.py

4. **Run the Client**
    In parallel, open another terminal and run:
    ```bash
    python client.py

5. **Output**

After running the above commands, a CSV file will be generated with the following format:

| CustomHeader | Domain        | ResolvedIP     |
|--------------|--------------|----------------|
| 18041600     | linkedin.com | 192.168.1.6    |
| 18041601     | reddit.com   | 192.168.1.7    |
| 18041602     | facebook.com | 192.168.1.8    |
| 18041603     | bing.com     | 192.168.1.9    |
| 18041604     | example.com  | 192.168.1.10   |
| 18041605     | wikipedia.org| 192.168.1.6    |
| 18041606     | github.com   | 192.168.1.7    |

## **Task 2**

Part 1: How to Perform the Experiment (macOS)

Steps to capture traffic for the `traceroute` command on macOS:

1. Open **Wireshark** and the **Terminal** app.  
2. In Wireshark, select your active network interface (usually **en0** for Wi-Fi).  
3. Start capturing by clicking the **blue shark icon**.  
4. In Terminal, run the command:  
   ```bash
   traceroute www.youtube.com
5. Wait until the command finishes.
6. Stop capturing in Wireshark (red square 🟥 icon).
7. Apply the filter in Wireshark:
   ```bash
   (udp.port >= 33434) or icmp
8. Save the capture as tracert_youtube_mac.pcapng (this file is also provided in the repository).

Part 2: 

Steps to capture traffic for the tracert command on Windows:
1. Open Wireshark and Command Prompt (cmd).
2. Start capturing in Wireshark.
3 In Command Prompt, run the command:
      ```bash
      tracert www.youtube.com

4. Wait until the command finishes.
5. Stop capturing in Wireshark.
   
7. Apply the filter in Wireshark:
      ```bash
      icmp
7. Save the capture as tracert_youtube_windows.pcapng (this file is also provided in the repository).
