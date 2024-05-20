# dn_udp_ddos
a python udp ddos tool with different  attack methods /n
to use this tool you must have python3 install in your device 
/n
Here's a breakdown of what it does:
\begin{itemize}
\item Parses command line arguments.
\item Creates a raw socket for sending packets.
\item If the attack type is UDP flood, it generates random packets and sends them to the target hosts.
\item If the attack type is UDP port dst, it generates packets with the specified source port and random destination ports and sends them to the target hosts.
\item If the attack type is UDP port src, it generates packets with random source ports and the specified destination port and sends them to the target hosts.
\item If the attack type is ICMP flood, it generates ICMP echo request packets with a random ICMP identifier and sends them to the target hosts.
\end{itemize}

The attack functions (`attack_udp_flood`, `attack_udp_port_dst`, `attack_udp_port_src`, `attack_icmp_flood`) generate packets according to the attack type and send them using the raw socket. They use `random.randint` to generate random values for some fields of the packets. The ICMP checksum calculation is done using the `icmp_checksum` function.

This code can be run with the command line arguments:

```bash
python attack.py -a udp_flood -t 192.168.1.1
