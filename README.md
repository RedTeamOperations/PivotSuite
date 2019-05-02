# PivotSuite
#### PivotSuite: Hack The Hidden Network -  A Network Pivoting Toolkit

#### Description 
PivotSuite is a portable, platform independent and powerful network pivoting toolkit, 
Which helps Red Teamers / Penetration Testers to use a compromised system to move around inside a network. 
It is a Standalone Utility, Which can use as a Server or as a Client.

##### PivotSuite as a Server : 
If the Compromised host is directly accessable (Forward Connection) from Our pentest machine,
Then we can run pivotsuite as a server on compromised machine and access the different subnet hosts from our pentest machine, 
Which was only accessable from compromised machine. 

##### PivotSuite as a Client : 
If the Compromised host is behind a Firewall / NAT and isn't directly accessable from our 
pentest machine, Then we can run pivotsuite as a server on pentest machine and pivotsuite as a client on compromised machine
for creating a reverse tunnel (Reverse Connection). Using this we can reach different subnet hosts from our pentest machine,
which was only accessable from compromised machine. 


#### Key Features: 
1. Supported Forward & Reverse TCP Tunneling
2. Supported Forward & Reverse socks5 Proxy Server
3. UDP over TCP and TCP over TCP Protocol Supported
4. Corporate Proxy Authentication (NTLM) Supported
5. Inbuilt Network Enumeration Functionality, Eg. Host Discovery, Port Scanning, OS Command Execution 
6. PivotSuite allows to get access to different Compromised host and their network, simultaneously (Act as C&C Server) 
7. Single Pivoting, Double Pivoting and Multi-level pivoting can  perform with help of PivotSuite. 
8. PivotSuite also works as SSH Dynamic Port Forwarding but in the Reverse Direction.   


#### Advantage Over Other tools:

1. Doesn't required admin/root access on Compromised host
2. PivotSuite also works when Compromised host is behind a Firewall / NAT, When Only Reverse Connection is allowed. 
3. No dependency other than python standard libraries.
4. No Installation Required 
5. UDP Port is accessable over TCP

#### Installation
You can download the latest version of pivotsuite by cloning the Git repository or PyPI Package.

    git clone https://github.com/RedTeamOperations/PivotSuite.git
            
                                  OR
    pip install pivotsuite
     
PivotSuite works out of the box with Python version 2.7.x and 3.6.x on any platform.
    
----------------------------------------------------------------------------------------------------------------------------

 #### Requirements:
 
    a. Only Python Standard Libraries are Required
    b. Compatible for both Python 2.7.x & Python 3.6.x
  
