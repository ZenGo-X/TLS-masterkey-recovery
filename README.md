Recovers the TLS session masterkey 
- Inputs (hard coded):
  - Server parameters in plaintext, as obtained from trafic (e.g. PCAP) 
    - Server random
    - Server DH public key
  - The predetermined Client parameters
    - Client Random (can be also obtained from traffic) 
    - Client DH private key
- outputs: 
  - Save the masterkey output in the standard SSLKEYLOGFILE format 
