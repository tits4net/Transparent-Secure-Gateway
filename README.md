# TSG-Bridge
Connection less VPN project design for industrial protocols. 

# How it works
The Transparent Secure Gateway is a prototype of new way to secure IP communication. 
The software get IP captured packet from nfnetfilter-queue and encrypt/decrypt the IP payload with libsodium and send the packet back. 
It's connect securely to a server via ZeroMQ to get the encryption key.

The project was design to be use on an OpenWRT device with 2 bridged interface (WAN to network and LAN to protected device)
## Global architecture (without the server)
![Global architecture](http://i.imgur.com/DAPfn9P.png)
## Capture schematics
![Capture architecture](http://i.imgur.com/wqkksF1.png)

# Warning 
This software is a Proof-Of-Concept. User feedback and error handling are not good but there is comments in source codes. 

# Features
## Client side
* Read the netfilter-queue and get packets
* encrypt/decrypt IP payload
* Modify IP header to adapt checksum / size / IP protocol number (253)
* Read configuration file with server IP / server public key / Id in /etc/crypt_bridge/cb.conf
* Detect packet replay (with a delay of 4 seconds)



## Installation
* Get client authentication request
* Provide a webgui (port 8888) to trust clients connection by adding there private key
* Send key, anti-replay numbers, iptables rules and commands to all clients
* Can receive SIGUSR1 to change symmetric key

# Install server side

1. Install Server dependencies
	* Python2
	* sqlite3
	* pysqlite3
	* libsodium
	* libzmq
	* pyzmq
	* tornado
2. Generate public/private key with gen_cert.py
3. You can start the server (TSG_SRV_v0.3.py) and connect via http to localhost:8888

# Install client side
1. Install Client dependencies
	* libnetfilter-queue1
	* libnetfilter-queue-dev
	* libsodium-dev
	* libsodium
	* libzmq-dev
	* libzmq


2. Generate configuration file with cb_gen_config_file and copy it to /etc/crypt_bridge/cb.conf
3. Generate client public/private key with "key generator/client/crypt_bridge_gen_key"
4. Configure the two interfaces as bridge with brctl. The bridge name have to be br-br0.
5. Make sure your interfaces don't use Generic Receive Offload or Large Receive Offload or disable them with ethtool
6. Allow iptable to inspect bridge traffic
```
echo "1" > /proc/sys/net/bridge/bridge-nf-call-iptables 
```
7. Add MSS-Clamping to avoid MTU oversize by adding the TSG metadata with TCP
```
iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o br-br0 -j TCPMSS --set-mss 1411
```
8. You can start the crypt_bridge software. After start it gets demonized. 

## Usage
1. The client connect to the secure server and send its private key
2. You can trust it in server's web-gui
3. You have to connect  two TSG-client to secure a communication
3. After trusting both of them, you can send a new iptables rules for a protocole. This one will be encrypted/decrypted by the crypt_bridge.

# FAQ
* UDP/Other IP protocol packets are lost after encryption

The TSG add 39 Bytes of metadatas the be able to reconstruct the original packet and for encryption header. 
TCP handle packet size with MSS-Clamping but other protocol should not send more then 1411 byte of data.
You can still reduce MTU if maximum packet size could be bigger.

* ZeroMQ loose connection after 127 messages

You have to use version bigger then 4.1.3 (4.0.X is retired)


* Is there any log ?

Somes logs are written in /var/log/syslog



