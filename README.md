# TSG-Bridge
Connection less VPN project design for industrial protocols. 

# How it works
The Transparent Secure Gateway is a prototype of new way to secure IP communication. 
The software get IP captured packet from nfnetfilter-queue and encrypt/decrypt the IP payload with libsodium and send the packet back. 
It's connect securly to a server via ZeroMQ to get the encryption key.

The project was design to be use on an OpenWRT device with 2 bridged interface (WAN to network and LAN to protected device)
## Global architecture (without the server)
![Global architecture](http://i.imgur.com/DAPfn9P.png)
## Capture schematics
![Capture architecture](http://i.imgur.com/wqkksF1.png)

# Warning 
This software is a Proof-Of-Concept. User feedback and error handling are not good. If you are looking for more documentation, please read the source code. 

# Features
## Client side
* Read the netfilter-queue and get packets
* encryt/decrypt IP payload
* Modify IP header to adapt checksum / size / IP protocol number (253)
* Read configuration file with server IP / server public key / Id in /etc/crypt_bridge/cb.conf
* Detect packet replay (with a delay of 4 seconds)



## Server side
* Get client authentification request
* Provide a webgui (port 8888) to trust clients connection by adding there private key
* Send key, anti-replay numbers, iptables rules and commands to all clients
* Can receive SIGUSR1 to change symetric key

# Installation server side

1. Install Server dependancies 
	* Python2
	* sqlite3
	* pysqlite3
	* libsodium
	* libzmq
	* pyzmq
	* tornado
2. Generate public/private key with gen_cert.py
3. You can start the server and connect via http to localhost:8888

# Installation client side
1. Install Client dependancies
	* libnetfilter-queue1
	* libnetfilter-queue-dev
	* libsodium-dev
	* libsodium
	* libzmq-dev
	* libzmq


2. Generate configuration file with cb_gen_config_file and copy it to /etc/crypt_bridge/cb.conf
3. Generate client public/private key with "key generator/client/crypt_bridge_gen_key"
4. Configure the two interfaces as bridge with brctl. The bridge name have to be br-br0.
5. Allow iptable to inspect bridge traffic
```
echo "1" > /proc/sys/net/bridge/bridge-nf-call-iptables 
```
6. Add MSS-Clamping to avoid MTU oversize by adding the TSG metadata with TCP
```
iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o br-br0 -j TCPMSS --set-mss 1411
```

7. You can start the crypt_bridge software. After start it gets demonized. 

# FAQ
* UDP/Other IP protocol packets are lost after encryption
The TSG add 39 Bytes of metadatas the be able to reconstruct the original packet and for encryption header. 
TCP handle packet size with MSS-Clamping but other protocol should not send more then 1411 byte of data.
You can still reduce MTU if maximum packet size could be bigger.

* ZeroMQ lost connection after 127 messages
You have to use version bigger then 4.1.3

* Is there any log 
Somes logs are written in /var/log/syslog

