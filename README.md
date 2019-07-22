#### DISCLAIMER: This software is for educational purposes only. This software should not be used for illegal activity. The author is not responsible for its use.

# PivotSuite
#### PivotSuite: Hack The Hidden Network -  A Network Pivoting Toolkit

#### Description 
PivotSuite is a portable, platform independent and powerful network pivoting toolkit, 
Which helps Red Teamers / Penetration Testers to use a compromised system to move around inside a network. 
It is a Standalone Utility, Which can use as a Server or as a Client.

##### PivotSuite as a Server : 
If the compromised host is directly accessable (Forward Connection) from Our pentest machine,
Then we can run pivotsuite as a server on compromised machine and access the different subnet hosts from our pentest machine, 
Which was only accessable from compromised machine. 

##### PivotSuite as a Client : 
If the compromised host is behind a Firewall / NAT and isn't directly accessable from our 
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
1. You can download the latest version of pivotsuite by cloning the Git repository or PyPI Package.

       git clone https://github.com/RedTeamOperations/PivotSuite.git
            
                  OR
                  
        pip install PivotSuite
     
     PivotSuite works out of the box with Python version 2.7.x and 3.6.x on any platform.
     
2. PivotSuite Standalone Executable Download from Github Release Section 

       https://github.com/RedTeamOperations/PivotSuite/releases
       
      No installation require, No python interpreter require 
----------------------------------------------------------------------------------------------------------------------------

 #### Requirements:
 
    a. Only Python Standard Libraries are Required
    b. Compatible for both Python 2.7.x & Python 3.6.x
    c. Tested on Windows and Linux. 

 #### Usages :
  
  $ pivotsuite.py [options] SERVER-IP SERVER-PORT


Options:

     --version             show program's version number and exit
  
    -h, --help            show this help message and exit
  
    -S, --server          Run PivotSuite as a Server
  
    -C, --client          Run PivotSuite as a Client
  
     - -server-ip=SERVER_IP
  
                        Server Listen/Connect IP address, Default  0.0.0.0
                        
     --server-port=SERVER_PORT
  
                        Server Listen/Connect Port, Default 7777
                        

  PivotSuite Server Options:
  
    -F, --forward-connection
    
                        Forward Network Traffic
                        
    --server-option=SP/PF
    
                        Use Server as Socks_Proxy(SP)/Port_Forward(PF),
                        Default SP
                        
    --network-protocol=T/U
    
                        Select Protocol For Port Forwarding TCP(T)/ UDP(U),
                        Default T
                        
    --forward-ip=Remote-Host-IP
    
                        Remote Host IP for Port Forwarding
                        
    --forward-port=Remote-Host-Port
    
                        Remote Host Port for Port Forwarding
                        
    -W, --reverse-connection
    
                        Reverse Network Traffic


  PivotSuite Client Options:
  
    -O SP/PF/NE, --option=SP/PF/NE
                        Use Client as Socks_Proxy(SP)/ Port_Forwarding(PF)/
                        Network_Enumeration(NE), Default SP
                        
    -L, --local-forward
    
                        Use Local Port Forwarding
                        
    -R, --remote-forward
    
                        Use Remote Port Forwarding
                        
    -P T/U, --protocol=T/U
    
                        Select Protocol For Port Forwarding TCP(T)/ UDP(U),
                        Default T
                        
    --local-ip=LOCAL_IP
    
                        Local IP For Port Forwarding
                        
    --local-port=LOCAL_PORT
    
                        Local Port For Port Forwarding
                        
    --remote-ip=REMOTE_IP
    
                        Remote IP For Port Forwarding
                        
    --remote-port=REMOTE_PORT
    
                        Remote Port For Port Forwarding
                        

  NTLM Proxy Authentication Options:
  
    --ntlm-proxy-ip=NTLM_PROXY_IP
    
                        IP address of NTLM proxy
                        
    --ntlm-proxy-port=NTLM_PROXY_PORT
    
                        Port of NTLM proxy
                        
    --username=USERNAME
    
                        Username to authenticate with NTLM proxy
                        
    --domain=DOMAIN     Domain to authenticate with NTLM proxy
    
    --password=PASSWORD
    
                        Password to authenticate with NTLM proxy
                        
    --hashes=HASHES     Hashes to authenticate with instead of password.
                        Format - LMHASH:NTHASH
  
  
  #### Documentation 
  
##### Case 1 : (Forward TCP Tunneling)

IF the Compromised host is directly accessible from our pentest machine.


    Then run PivotSuite as a server on the compromised machine as per our requirements:

        a. Dynamic Port Forwarding (Socks5 Proxy Server) On Compromised machine:

             $  python pivotsuite.py -S -F --server-option SP --server-ip IP --server-port PORT


        b. Single Port Forwarding (TCP/UDP Relay) On Compromised machine :

            $ python pivotsuite.py -S -F --server-option PF --network-protocol T/U --remote-ip IP --remote-port PORT 
              --server-ip IP (local-ip) --server-port PORT (local-port)


##### Case 2 : (Reverse TCP Tunneling)

IF the Compromised host is behind a Firewall / NAT and directly not accessible from our pentest machine.


    Then run PivotSuite as a Server on pentest machine and PivotSuite as a Client on compromised machine.


      i. Run PivotSuite as a Sever On Pentest Machine :

          $ python pivotsute.py -S -W 


      ii. Run PivotSuite as a Client on Compromise Machine as per our requirements:

          a. Dynamic Port Forwarding (Socks5 Proxy Server) On Pentest Machine:

              $ python pivotsuite.py -C -O SP --server-ip IP --server-port PORT

          b. Local / Remote Port Forwarding On Pentest Machine:

               $ python pivotsuite.py -C -O PF  - L / -R (local or remote port forwarding) -P T/U  --local-ip IP 
                  --local-port PORT --remote-ip IP --remote-port PORT  --server-ip IP --server-port PORT

          c. Network Enumeration of Compromised Machine:

                $ python pivotsuite.py -C -O NE --server-ip IP --server-port PORT


IF Corportate Proxy Authentication (NTLM) required for reverse connection on Compromised Host :

      $ python pivotsuite.py -C -O SP --ntlm-proxy-ip IP --ntlm-proxy-port PORT --username USERNAME --password PASSWORD 
        --server-ip IP --server-port PORT
        
#### Contact Information :
 
I would greatly appreciate it if you kindly give me some feedback or suggestion on PivotSuite Toolkit. 

Email:    admin@myhacker.online 

LinkedIn: https://www.linkedin.com/in/cehmanish/ 
 
