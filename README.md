# CS-331_CN_Assignment-1
##Task 1
This task implements a custom DNS Resolver using Python. The client extracts DNS queries from a PCAP file, adds a custom header, and sends them to the server. The server resolves the queries using a predefined IP pool and returns the results back to the client.
It uses two programs:  
- **Client** → Reads DNS queries from a PCAP file, adds a custom header, and sends them out.  
- **Server** → Waits for queries, resolves them based on rules, and sends the answers back.  

So first to run this, make sure you have the following installed:
- **Python 3.x**
- 
- **[Scapy](https://scapy.net/)** – for parsing PCAP and DNS packets  
  ```bash
  pip install scapy
  -** ```bash
  pip install pandas
