#!/usr/bin/env python
import sys
import optparse
import logging

try:
    from pivot_suite.server import main as server_main
except ImportError:
    from server import main as server_main

try:
    from pivot_suite.client import main as client_main
except ImportError:
    from client import main as client_main

logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s : %(message)s")
handler.setFormatter(formatter)
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

cmd_options= {}


def main():
    # Command Line Arguments Description
    global cmd_options
    parser = optparse.OptionParser(description='Network Pivot Suite',usage="Usage: %prog [options] SERVER-IP SERVER-PORT",version="%prog 1.0")
    parser.add_option('-S', '--server', action="store_true", dest='server', help="Run PivotSuite as a Server")
    parser.add_option('-C', '--client', action="store_true", dest='client',help="Run PivotSuite as a Client")
    parser.add_option('--server-ip', action="store", dest='server_ip', default='0.0.0.0',help="Server Listen/Connect IP address, Default  0.0.0.0")
    parser.add_option('--server-port', action="store", dest='server_port', default='7777',help="Server Listen/Connect Port, Default 7777")


    pivot_suite_server = optparse.OptionGroup(parser, 'PivotSuite Server Options')

    pivot_suite_server.add_option('-F', '--forward-connection', action="store_true", dest='forward', help="Forward Network Traffic")
    pivot_suite_server.add_option('--server-option',metavar="SP/PF", action="store", dest='option', default='SP',
                      help="Use Server as Socks_Proxy(SP)/Port_Forward(PF), Default SP")
    pivot_suite_server.add_option('--network-protocol',metavar="T/U", action="store", dest='protocol', default='T',
                      help="Select Protocol For Port Forwarding TCP(T)/ UDP(U), Default T")
    pivot_suite_server.add_option('--forward-ip', metavar="Remote-Host-IP",action="store", dest='remote_ip',default=None, help="Remote Host IP for Port Forwarding ")
    pivot_suite_server.add_option('--forward-port',metavar="Remote-Host-Port",action="store", dest='remote_port',default=None, help="Remote Host Port for Port Forwarding")
    pivot_suite_server.add_option('-W', '--reverse-connection', action="store_true", dest='reverse',
                                  help="Reverse Network Traffic")
    parser.add_option_group(pivot_suite_server)


    pivot_suite_client = optparse.OptionGroup(parser, 'PivotSuite Client Options')

    pivot_suite_client.add_option('-O','--option',metavar="SP/PF/NE" ,action="store", dest='option', default='SP',
                      help="Use Client as Socks_Proxy(SP)/ Port_Forwarding(PF)/ Network_Enumeration(NE), Default SP")
    pivot_suite_client.add_option('-L', '--local-forward', action="store_true", dest='local_forward',default=None ,help="Use Local Port Forwarding")
    pivot_suite_client.add_option('-R', '--remote-forward', action="store_true", dest='remote_forward',default=None,
                      help="Use Remote Port Forwarding")
    pivot_suite_client.add_option('-P', '--protocol',metavar="T/U",action="store", dest='protocol', default='T',
                      help="Select Protocol For Port Forwarding TCP(T)/ UDP(U), Default T")
    pivot_suite_client.add_option('--local-ip', action="store", dest='local_ip',help="Local IP For Port Forwarding",default=None)
    pivot_suite_client.add_option('--local-port', action="store", dest='local_port',help="Local Port For Port Forwarding",default='0')
    pivot_suite_client.add_option('--remote-ip', action="store", dest='remote_ip',help="Remote IP For Port Forwarding",default=None)
    pivot_suite_client.add_option('--remote-port', action="store", dest='remote_port',help="Remote Port For Port Forwarding",default='0')
    parser.add_option_group(pivot_suite_client)


    ntlm_proxy = optparse.OptionGroup(parser, 'NTLM Proxy Authentication Options')

    ntlm_proxy.add_option('--ntlm-proxy-ip', dest='ntlm_proxy_ip', default=None, action='store',
                           help='IP address of NTLM proxy')
    ntlm_proxy.add_option('--ntlm-proxy-port', dest='ntlm_proxy_port', default=None, action='store',
                           help='Port of NTLM proxy')
    ntlm_proxy.add_option('--username', dest='username', default='', action='store',
                           help='Username to authenticate with NTLM proxy')
    ntlm_proxy.add_option('--domain', dest='domain', default='', action='store',
                           help='Domain to authenticate with NTLM proxy')
    ntlm_proxy.add_option('--password', dest='password', default='', action='store',
                           help='Password to authenticate with NTLM proxy')
    ntlm_proxy.add_option('--hashes', dest='hashes', default=None, action='store',
                           help='Hashes to authenticate with instead of password. Format - LMHASH:NTHASH')

    parser.add_option_group(ntlm_proxy)

    cmd_options = parser.parse_args()[0]

    # PivotSuite Parameter Error Handling
    if cmd_options.server and cmd_options.client:
        parser.error("Choose Option Either -S (Server) OR -C (Client)")


    if ( not cmd_options.server) and ( not cmd_options.client) :
        parser.error("Choose Option Either -S (Server) OR -C (Client)")

    # Handling Server Options

    if cmd_options.server and (not cmd_options.forward) and (not cmd_options.reverse):
        parser.error("Choose Option Either -F (Forward Connection) OR -W (Reverse Connection)")

    if cmd_options.server and cmd_options.forward and  cmd_options.reverse:
        parser.error("Choose Option Either -F (Forward Connection) OR -W (Reverse Connection)")

    if (cmd_options.server and cmd_options.forward)  and (not cmd_options.option == "PF" and not cmd_options.option =="SP"):
        parser.error("Choose Option Either --server-option SP (Socks Proxy Server) OR --server-option PF (Port Forwarding), Default SP")

    if (cmd_options.server and cmd_options.forward and cmd_options.option == "PF") and (not cmd_options.protocol == "T" and not cmd_options.protocol =="U") :
        parser.error("Choose Option Either --network-protoco T (TCP) OR --network-protocol U (UDP), Default T")

    if (cmd_options.server and cmd_options.forward and cmd_options.option == "PF") and (not cmd_options.remote_ip and not cmd_options.remote_port):
        parser.error(
            "Specify the Correct Options: --server-ip(local-ip) IP  --server-port(local-port) PORT  --remote-ip IP  --remote-port PORT ; For Port Forwarding ")

    # Handling Client Options

    if cmd_options.client and (not cmd_options.option == "SP" and not cmd_options.option == "PF" and not cmd_options.option == "NE"):
        parser.error("Choose Option Either -O SP (Socks Proxy Server) OR -O PF (Port Forwarding) OR -O NE (Network Enumeration), Default SP")

    if cmd_options.client and cmd_options.option == "PF" and (not cmd_options.local_forward and not cmd_options.remote_forward):
        parser.error("Choose Option Either -L (Local Port Forwarding) OR -R (Remote Port Forwarding)")

    if cmd_options.client and cmd_options.option == "PF" and (cmd_options.local_forward or cmd_options.remote_forward) and (not cmd_options.protocol == "T" and not cmd_options.protocol == "U"):
        parser.error("Choose Option Either -P T (TCP) OR -P U (UDP), Default T")

    if cmd_options.client and (cmd_options.local_forward or cmd_options.remote_forward) and (not cmd_options.local_ip and  cmd_options.local_port == '0' and not cmd_options.remote_ip and  cmd_options.remote_port == '0'):
        parser.error("Specify the Correct Options --local-ip IP  --local-port PORT  --remote-ip IP  --remote-port PORT ; For Port Forwarding ")

    if cmd_options.client and cmd_options.server_ip == '0.0.0.0':
        parser.error("Specify the Correct Options --server-ip IP  --server-port PORT")

    # Handling NTLM Proxy Authentication Options

    # Appropriate function calling according to the option specify
    if cmd_options.server:
        try:
            logger.removeHandler(handler)
            server_main(forward_socks=cmd_options.forward,reverse_socks=cmd_options.reverse,server_ip=cmd_options.server_ip,
                        server_port=cmd_options.server_port,remote_ip=cmd_options.remote_ip,remote_port=cmd_options.remote_port,
                        option=cmd_options.option,protocol=cmd_options.protocol)
        except ImportError:
            logger.debug("[-] Error - Server Module Import Error")
            logger.removeHandler(handler)
    else:
        try:
            logger.removeHandler(handler)
            client_main(server_host=cmd_options.server_ip,server_port=cmd_options.server_port,option=cmd_options.option,protocol=cmd_options.protocol,
                        local_forward=cmd_options.local_forward,remote_forward=cmd_options.remote_forward,
                        local_ip=cmd_options.local_ip,local_port=cmd_options.local_port,
                        remote_ip=cmd_options.remote_ip,remote_port=cmd_options.remote_port,ntlm_proxy_host=cmd_options.ntlm_proxy_ip,
                        ntlm_proxy_port=cmd_options.ntlm_proxy_port,username=cmd_options.username,
                        password=cmd_options.password,domain=cmd_options.domain,hashes=cmd_options.hashes)
        except ImportError:
            logger.debug("[-] Error - Client Module Import Error")
            logger.removeHandler(handler)


if __name__ == '__main__':
    main()
