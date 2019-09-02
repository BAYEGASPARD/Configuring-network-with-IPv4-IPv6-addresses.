# INR Lab 2 - IPv4 & IPv6
### Task 1 - Ports and Protocols
#### 1. Check the open ports and listening Unix sockets against ssh and http on Admin and Web respectivly.
- Using the <code>netstat</code> comand, we are able to Print network connections, routing tables, interface statistics, masquerade connections, and multicast memberships.
- Four our case, we will use <code>netstat -atn</code> which will be able to list: a (all ports), t (tcp) and n (show ports in numbers rather than service name) as seen in the picture below.
![](https://i.imgur.com/ZrQuA5K.png)
- Also, we can use the command <code>lsof</code> which lists all the open files of all processes and services for a given port as seen in the picture below.
![](https://i.imgur.com/M2VvJGz.png)
#### 2. Scan your gateway from the outside. What are the known open ports?
- Nmap is an open source network scanner which sends packets and analyze the response. It is used to discover hosts and services.
- We install it by using the command <code>apt-get install nmap</code>
- For our case, we use the parameter -sS to scan and syn respectively.
![](https://i.imgur.com/DYs0ZWR.png)
### 3. A gateway should be transparent, you should not see any port that is not specifically forwarded. Adjust your firewall rules to make this happen. Disable any unnecessary services and scan again.
- First we have to block it in service list, IP->service
![](https://i.imgur.com/Ya7Dp7m.png)

- We use firewall rules to in IP->Firewal ->Filter rule and filer or drop all traffic from the pool of ports as specified on the diagram below or Ip->Firewall ->service ports.
![](https://i.imgur.com/3TNNUwt.png)
- Then we go to : 
![](https://i.imgur.com/5xu7hR8.png)
- And we apply the changes.
![](https://i.imgur.com/MXBFVO3.png)

- The Nmap result will be showing that we filtered all uneccessary ports/services but the scanner will be able to see filtered ports : 
![](https://i.imgur.com/V6m6Cad.png)
### 4. Some scanners start by scanning the known ports and pinging a host to see if it is alive.Scan the Worker VM from Admin . Can you see any ports?
- The nmap 192.168.1.3 on the worker's pc gives the following result.
![](https://i.imgur.com/9vbCESt.png)
- To block the ICMP traffic on the worker PC, we proceed as such.
![](https://i.imgur.com/1PMEknv.png)
![](https://i.imgur.com/t3uPbWE.png)
- After blocking ICMP packets, the admin can't ping the worker pc anymore.
- Changing the port, we need to edit the <code>nano /etc/ssh/sshd_config</code> file.
![](https://i.imgur.com/g54pbC0.png)
- With command netstat -ntl , we realise the ssh port is now 23000 as precised in the screen shot above.
![](https://i.imgur.com/jxF6qMn.png)
- After changing the port, the normal scan without any argument is not detecting the ssh port.
![](https://i.imgur.com/NjBAAvz.png)
- In orther cases, when the worker is scanned with specific parameters, scanning ports in a range which includes the ssh port, this will show the port.Example, using $nmap -p 1-65535.This is for all open ports. 
- This will detect the open port of 23000 for SSH(inovaport1).(see picture below)
![](https://i.imgur.com/OU3ylOX.png)
### 5. Gather some information about your open ports on Web ( ssh and http )
- In order to know deeply the functionalities of nmap, we can write "man nmap" in terminal and this will show us many other options depending on our needs.Some of the useful commands include: 
-p- is used to scan all ports.
-AO is used for OS detection, version detection, script scanning, and tracerouting.
-d RND:10 is used to decoy with random 10 IPs from its range.
-T5 is used to sever the intensity to do things fast.
-Pn is used to do steal scan.
–badsum is to send bogus TCP/UDP/SCTP checksum for not to be detected.
- etc...
- Performing this on the terminal, we have <code>sudo nmap -AO -T5 -p- -Pn -d RND:10 --badsum 192.168.1.3</code> which is used to evade detection by firewalls or IPS/IDS, we have: 
![](https://i.imgur.com/CR8cmFR.png)
- Also, After tweaking it so it can show some results quickly, we have this result.
![](https://i.imgur.com/0I9BNRR.png)



- In summary, we detected that the scanner detected that there are 2 ports open for ssh(22) using openssh 7.6p1 ubuntu0.3 and http(80), the webserver is nginx and the version is 1.14.0 running ubuntu, Mac address:0C:58:6B:F8:98:00
### Task 2 - Traffic Captures & IP
### 1. Access your Web Page from the outside and capture the tra ic between the gateway and the bridged interface. Can you see what is being sent? What kind of information can you get from this?What do the headers mean?
- Running wireshark as root from the host pc and enabling it to capture virbr0 traffic, we collected a lot of data.We will annalyze these data below.
![](https://i.imgur.com/gtccbic.png)
- From the picture above, we see Time, source address, destination address, protocols , length, and infos giving more data about the transfer of data.
  1. MNDP => Mikrotik Neighbour Discovery Protocol, eases configuration and management by enabling each MikroTik router to discover other connected MikroTik routers .
  2.CDP => Cisco Discovery Protocol
  3.DHCP, ARP =Address Resolution Protocol to map ip to MAC, MDNS=>Multicast DNS to locally map names to IP where there is no name server.
  4.TCP, SSDP=> The Simple Service Discovery Protocol is a network protocol based on the Internet protocol suite for advertisement and discovery of network services and presence information.
- Considering the data recieved during curl, sniffing virbr0.Consider the picture below.
![](https://i.imgur.com/nKh2RqH.png)
- From the above , the green part is the region of data transfer between the web server and the terminal or web browser.
- It shows TCP packets, called 3 ways handshake (SYN, SYN-ACK, ACK), the host sent a GET requestion via the HTTP using some random port number like (59614), The web server after the 3 ways handshake response with the web content via an HTTP 200 ok code (serves the text/html content) via port 80.
- Also, below if we click and expand the Line based text data below after selecting the respinse on the HTTP 200 ok code above, we can see the actual content that was transfered to the host machine.(see picture below).
![](https://i.imgur.com/cbx4cae.png)
### 2. SSH to the Admin from the outside and capture the traffic (make sure to start capturing before connecting to the server)
- Having an ssh connection while the wireshark packet sniffer is on, we have the same initial data as from task 2 but here, instead of http transactions we have ssh transactions.First lets see the cifers.
![](https://i.imgur.com/BD5ZQAb.png)
- On the above picture, we see source and destination address, we see the SSHv2 protocol used openssh7_6p1,ubuntu ,  there is the exchange of certificate between the client and server  via the key init, and then Diffie-Hellman key exchange used.
- Once this is done, the server can share data in a secured way, i.e we see the packets are encrypted between clients and servers.We can't access it as the previous packet which was plain text.

### 3. Configure Burp Suite as a proxy on your machine and intercept your HTTP tra ic. Show that you can modify the contents by changing something in the request. Why are you able to do this here and not in an SSH connection ? 
- Let's first install burp suite.Before we install burp suite, we have to install the following as Burp suite works with java run time environement(JRE) and java development kit(JDK) which provide the  libraries and JVM(java virtual environemnt) for a better worklow for Burp suite.
![](https://i.imgur.com/CW9zvMw.png)
- Using the above commands, we install jre and jdk using the terminal.
![](https://i.imgur.com/3PrLkbz.png)
- To install burpe suite, we download the .jar file from this link: (https://portswigger.net/burp/communitydownload)
- Then we copy it to a desired location , we type ./<name_of_jar_file> and run. or we can also download the linux file still in that same link and run <code>sh <linux_file_with.sh>.
- We will have the following : 
- 
![](https://i.imgur.com/evJmG8A.png)
![](https://i.imgur.com/zVi3SV9.png)

(source: https://tutorialsoverflow.com/how-to-install-and-configure-burp-suite-on-ubuntu-18-04/)
- To configure burp suite as a proxy, we need to Open Burp Suite-> Temporary project.
![](https://i.imgur.com/UJpkDLC.png)
- We go to proxy-> options and verify if the config is as shown below.
![](https://i.imgur.com/KVPPMhF.png)
- On the browser, 
  1. In Firefox, Go to Firefox menu and click on “Preferences” / “Options”  Select the General Tab and scroll down to the end of general tab. 
  2. At the end you will see the “Network Proxy” settings. Click on settings button.
  3. Select the “Manual proxy configuration” option.
  4. Enter your Burp Proxy listener address and the Burp Proxy listener port in the “HTTP Proxy” field (by default this is set to 127.0.0.18080).
  5. Make sure the “Use this proxy server for all protocols” box is checked.
  6. Delete anything that appears in the “No proxy for” field.
  7. Now click “OK” to close all of the options dialogs.
![](https://i.imgur.com/lMsyrBA.png)
- In order to modify responses, click on Action-> Do intercept-> Response to this request and then click to the Forward on the top left the corner.Note that intercept must be on before performing this as seen in the picture below.
![](https://i.imgur.com/SCEaZed.jpg)
- From the diagram below, we can see that I have modefied the "welcome to nginx!" to "Welcome to SNE!" at the "h1" tag.So this can be modified.
![](https://i.imgur.com/u9hPTwp.png)
- The result after modification is seen below from the browser : 
![](https://i.imgur.com/i0C9clb.png)

### Why are you able to do this here and not in an SSH connection ?
- Transmission is in plain text since we are using http (hyper text transfer protocol). No encryption is used. In order to encrypt the data, we use SSL certificate to provide a secure socket layer to it.
- Since SSH(Secure SHell) uses Diffie-Hellman algorithm to encrypt the data, we cannot  have access to it talkless of modiying the data.
### 4. Configure IPv6 from the Web Server to the Worker. This includes IPs on the servers and the default gateways.
- First we have to install ipv6 module from winbox.To do that, we go to settings then package and enable ipv6.
![](https://i.imgur.com/Q3Ed9aT.png)
- After that , we reboot the router.This enable ipv6 as seen below.
![](https://i.imgur.com/JkhNGNe.png)
- Then we add the gateways on the different interfaces.
- To navigate to our ipv6 addresses, we will see a new button ipv6 added after enabling it, then we click on it then on addresses.
![](https://i.imgur.com/iFIrqBY.png)
- We will add our gateways ipv6 addresses to the ipv6 addres list and select the respective interfaces of the two different subnets respectively as seen below.
![](https://i.imgur.com/zlDJY1J.png)
- After that, we have to manually assign ipv6 addresses to our different PCs respectively.
- To do that, we open netplan for all the different PCs web, admin and worker and manually add ipv6 address, ipv6 gateway and thats all and disable dhcp6 as seen below.
- For the admin machine, we have: 
![](https://i.imgur.com/s3w8Blk.png)
- For the web machine we have : 
![](https://i.imgur.com/HJgwQM8.png)
- And lastly for the worker, we have : 
![](https://i.imgur.com/PL55Wv6.png)
- Our different PCs with their respective ipv6 addresses.
![](https://i.imgur.com/v9ke69w.png)

- To test if they communicate, we are going to ping the different PCs.
![](https://i.imgur.com/EYwFzyM.png)
- To access the web page from admin, we use the command <code> curl [fd00:2::8] </code>
![](https://i.imgur.com/3OhqLrv.png)
- The captured information can be found below.
![](https://i.imgur.com/jfulfw1.png)
- From the above capture, we realise that IPV6 addresses of the admin is used to send a Get request to IPV6 address of the web server.Same process of 3 ways handsake occur and same data.
- Find the wireshark captures in the capture folder.