try:
    import socketserver
except:
    import SocketServer as socketserver
import socket
import select
import sys
import random
import logging
import logging.handlers
import struct

try:
    from pivot_suite import six
except ImportError:
    import six
from os import _exit

logger = None
handler = None

# setting global values for remote host
remote_ips="127.0.0.1"
remote_ports= 80


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class UdpRelayHandler():
    global remote_ips
    global remote_ports

    def handler(self,HOST,PORT):
        server_ip = HOST
        server_port = PORT
        sock_client = None
        sock_remote = None

        try:
            sock_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_remote = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_addr = (server_ip, int(server_port))
            remote_addr = (remote_ips, int(remote_ports))
            sock_client.bind(client_addr)

            data, addr = sock_client.recvfrom(65565)
            logger.debug("[+] Client Connected Successfully {}:{} ==>> {}:{}".format(addr[0],addr[1],remote_ips, remote_ports))
            sock_remote.sendto(data, remote_addr)

            while True:
                r, w, e = select.select([sock_client, sock_remote], [], [])

                if sock_client in r:
                    data, _ = sock_client.recvfrom(65565)
                    if sock_remote.sendto(data, remote_addr) <= 0:
                        break

                if sock_remote in r:
                    data, _ = sock_remote.recvfrom(65565)
                    if sock_client.sendto(data, addr) <= 0:
                        break
        except KeyboardInterrupt:
            sock_client.close()
            sock_remote.close()


class TcpRelayHandler(socketserver.StreamRequestHandler):

    def handle(self):
        global remote_ips
        global remote_ports
        logger.debug("[+] Client Connected Successfully {}:{} ==>> {}:{}".format(self.client_address[0],self.client_address[1],remote_ips,remote_ports))
        try:
            self.remote_socket = self.ConnectSocket(remote_ips,int(remote_ports))
        except:
            logger.debug("[-] Connection Refused Error ")
        try:
            self.exchange_loop(self.connection,self.remote_socket)
        except:
            pass

    def exchange_loop(self, remote, client):
        try:
            while True:
                # wait until client or remote is available for read
                r, w, e = select.select([client, remote], [], [])
                if remote in r:
                    data = remote.recv(1024)
                    if client.send(data) <= 0:
                        break
                if client in r:
                    data = client.recv(1024)
                    if remote.send(data) <= 0:
                        break
        except:
            logger.debug("[-] Connection Error")

    def ConnectSocket(self, connect_ip, connect_port):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((connect_ip, connect_port))
        return client_socket


# Forward Connection Handler
class ForwardHandler(socketserver.StreamRequestHandler):

    def handle(self):

        try:
            logger.debug("[+] SOCKS Client {}:{} Connected Successfully".format(self.client_address[0],self.client_address[1]))
            header = self.connection.recv(4)
            version, nmethods = struct.unpack("!BB", header[:2])

            self.connection.sendall(struct.pack("!BB", 5, 0))

            version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))

            if address_type == 1:  # ipv4
                self.address = socket.inet_ntoa(self.connection.recv(4))
            elif address_type == 3:  # domain
                domain_length = ord(self.connection.recv(1)[0])
                self.address = self.connection.recv(domain_length)

            port = struct.unpack('!H', self.connection.recv(2))[0]

            try:
                if cmd == 1:
                    self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.remote.connect((self.address, port))
                elif cmd == 3:
                    self.remote = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    bind_address = self.remote.getsockname()
            except:
                logger.removeHandler(handler)
                logger.debug("[-] Remote Connection Refused")

            bind_address = self.remote.getsockname()
            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", 5, 0, 0, address_type, addr, port)

            self.connection.sendall(reply)

            self.exchange_loop(self.connection, self.remote)

        except KeyboardInterrupt:
            self.remote.close()
            self.connection.close()
            sys.exit(0)

    def exchange_loop(self, remote, client):

        try:
            while True:

                # wait until client or remote is available for read
                r, w, e = select.select([client, remote], [], [])

                if remote in r:
                    data = remote.recv(1024)
                    if client.send(data) <= 0:
                        break

                if client in r:
                    data = client.recv(1024)
                    if remote.send(data) <= 0:
                        break
        except:
            logger.debug("[-] Connection Error")


# Reverse Connection Handler
class ReverseHandler(socketserver.StreamRequestHandler):

    def handle(self):
        try:
            logger.debug('[+] Client {}:{} Connected'.format(self.client_address[0],self.client_address[1]))
            if six.PY3:
                command = six.u(self.connection.recv(1024))
            else:
                command = self.connection.recv(1024)

            if command == six.b("SP"):
                if six.PY3:
                    self.connection.sendall(six.b("SP"))
                else:
                    self.connection.sendall("SP")
                self.sock_handler()
            elif command == six.b("PF"):
                if six.PY3:
                    self.connection.sendall(six.b("PF"))
                else:
                    self.connection.sendall("PF")
                self.port_forward_handler()
            elif command == six.b("NE"):
                if six.PY3:
                    self.connection.sendall(six.b("NE"))
                else:
                    self.connection.sendall("NE")
                self.network_enum_handler()
            else:
                if six.PY3:
                    self.connection.sendall(six.b("ERROR"))
                else:
                    self.connection.sendall("ERROR")

        except:
            logger.debug('[-] Server Error')
            sys.exit(1)

    def sock_handler(self):

        global remote_socket
        listen_socks_host = "0.0.0.0"
        listen_socks_port = random.randint(1001, 9999)
        logger.debug("[+] Configure ProxyChains {}:{} ==>> HOST {}".format(listen_socks_host, listen_socks_port,
                                                                           self.client_address[0]))
        try:
            remote_socket = self.SocketCreate(listen_socks_host, listen_socks_port)
        except:
            logger.debug("[-] PORT LISTENING ERROR")
            sys.exit(1)

        while 1:
            client_socket, client_address = remote_socket.accept()
            if six.PY3:
                data = client_socket.recv(1024)
                self.connection.sendall(data)
            else:
                data = client_socket.recv(1024)
                self.connection.sendall(data)

            self.exchange_loop(self.connection, client_socket)

    def port_forward_handler(self):
        if six.PY3:
            server_string = six.u(self.connection.recv(1024))
        else:
            server_string = self.connection.recv(1024)

        if six.PY3:
            server_string = server_string.decode('utf-8')

        server_string = server_string.split(":")
        forward_option = server_string[0]
        ip = server_string[1]
        port = int(server_string[2])
        protocol=server_string[3]
        if protocol == "T":
            if forward_option == "L":
                logger.debug("[+] TCP Local PORT Forwarding for Client {}:{}".format(self.client_address[0],self.client_address[1]))
                try:
                    remote_socket = self.ConnectSocket(ip, port)
                except:
                    logger.debug("[-] Connection Refused by Remote Host")
                    sys.exit(1)
                self.exchange_loop(self.connection, remote_socket)

            elif forward_option == "R":
                logger.debug("[+] TCP Remote PORT Forwarding for Client {}:{} ".format(self.client_address[0],self.client_address[1]))
                local_socket = self.SocketCreate(ip, port)
                remote_client_socket, remote_client_addr = local_socket.accept()
                self.exchange_loop(self.connection, remote_client_socket)

            else:
                logger.debug("[-] Incorrect Port Forward Option Specified")

        elif protocol == "U" :
            if forward_option == "L":
                udp_host = ip
                udp_port = port
                udp_addr = (udp_host, udp_port)
                logger.debug("[+] UDP Local PORT Forwarding for Client {}:{}".format(self.client_address[0],self.client_address[1]))
                try:
                    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    if six.PY3:
                        data = six.u(self.connection.recv(1024))
                        udp_socket.sendto(data, udp_addr)
                        data, addr = udp_socket.recvfrom(1024)
                        self.connection.sendall(data)
                    else:
                        data = self.connection.recv(1024)
                        udp_socket.sendto(data, udp_addr)
                        data, addr = udp_socket.recvfrom(1024)
                        self.connection.sendall(data)
                    while True:
                        # wait until client or remote is available for read
                        r, w, e = select.select([self.connection, udp_socket], [], [])

                        if self.connection in r:
                            data = self.connection.recv(1024)
                            if udp_socket.sendto(data, udp_addr) is None:
                                pass

                        if udp_socket in r:
                            data, _ = udp_socket.recvfrom(1024)
                            if self.connection.sendall(data) is None:
                                pass
                except KeyboardInterrupt:
                    self.connection.close()

            elif forward_option == "R":
                udp_host = ip
                udp_port = port
                udp_addr = (udp_host, udp_port)
                logger.debug("[+] UDP Remote PORT Forwarding for Client {}:{}".format(self.client_address[0],self.client_address[1]))
                try:
                    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udp_socket.bind(udp_addr)
                    data, addr = udp_socket.recvfrom(1024)
                    self.connection.sendall(data)
                    while True:
                        # wait until client or remote is available for read
                        r, w, e = select.select([self.connection, udp_socket], [], [])

                        if self.connection in r:
                            data = self.connection.recv(1024)
                            if udp_socket.sendto(data, addr) is None:
                                pass

                        if udp_socket in r:
                            data, _ = udp_socket.recvfrom(1024)
                            if self.connection.sendall(data) is None:
                                pass
                except KeyboardInterrupt:
                    self.connection.close()

            else:
                logger.debug("Please Choose Port Forward options Correctly")

        else:
            logger.debug("Choose Correct Protocol")

    def network_enum_handler(self):
        try:
            while 1:
                try:
                    option = str(
                        input("--------------------------------------------------------------------------------\n"
                              "Interactive Network Enumeration:\n"
                              "1. All Available Interface (NIC) Information\n"
                              "2. Host Discovery (ICMP)\n"
                              "3. Port Scanning (TCP)\n"
                              "4. Port Scanning (UDP)\n"
                              "5. OS Command Execution\n"
                              "6. Exit\n"
                              "Option > "))

                    if six.PY3:
                        self.connection.sendall(six.b(option))
                    else:
                        self.connection.sendall(option)
                    if option == "1":
                        result = self.connection.recv(65565)
                        if six.PY3:
                            result = six.u(result).decode('utf-8')
                        print('\n' + result)

                    elif option == "2":
                        output = self.connection.recv(65565)
                        if six.PY3:
                            ranges = str(input("Enter IP Ranges (Eg. 172.16.1.1-255) > "))
                        else:
                            ranges = str(raw_input("Enter IP Ranges (Eg. 172.16.1.1-255) > "))

                        ip, ntBits = ranges.split('-')
                        ip_addresses = []
                        st_bit = ip.split('.')[3:4][0]  # Since it's an IPv4
                        for n in range(1, int(ntBits) + 1):
                            eval_ip = ".".join(ip.split('.')[:-1]) + '.' + str(n)
                            ip_addresses.append(eval_ip)
                        for ip in ip_addresses:
                            if six.PY3:
                                self.connection.sendall(six.b(ip))
                            else:
                                self.connection.sendall(ip)
                            output = self.connection.recv(65565)
                            if six.PY3:
                                output = six.u(output).decode('utf-8')

                            s = output.find("1 received")
                            r = output.find("Received = 1")
                            if (s > 0) and (r < 0):
                                logger.debug(" [+] Host {} UP".format(ip))
                            elif (s < 0) and (r > 0):
                                logger.debug(" [+] Host {} UP".format(ip))
                            else:
                                logger.debug(" [+] Host {} Down".format(ip))

                    elif option == "3":
                        output = self.connection.recv(65565)
                        if six.PY3:
                            IP = str(input("Enter Target IP Address > "))
                        else:
                            IP = str(raw_input("Enter Target IP Address > "))

                        if six.PY3:
                            self.connection.sendall(six.b(IP))
                        else:
                            self.connection.sendall(IP)

                        if six.PY3:
                            PORT_Range = str(input("Enter TCP PORT Range, (Eg. 1-100) > "))
                        else:
                            PORT_Range = str(raw_input("Enter TCP PORT Range, (Eg. 1-100) > "))

                        p_range = PORT_Range.split('-')
                        output = self.connection.recv(65565)

                        for port in range(int(p_range[0]), int(p_range[1]) + 1):
                            if six.PY3:
                                self.connection.sendall(six.int2byte(port))
                            else:
                                self.connection.sendall(str(port))

                            output = self.connection.recv(65565)

                            if six.PY3:
                                output = six.u(output).decode('utf-8')
                            logger.debug("[+] TCP  {} => {}".format(port,output))

                    elif option == "4":
                        output = self.connection.recv(65565)
                        if six.PY3:
                            IP = str(input("Enter Target IP Address > "))
                        else:
                            IP = str(raw_input("Enter Target IP Address > "))

                        if six.PY3:
                            self.connection.sendall(six.b(IP))
                        else:
                            self.connection.sendall(IP)

                        if six.PY3:
                            PORT_Range = str(input("Enter UDP PORT Range, (Eg. 1-100) > "))
                        else:
                            PORT_Range = str(raw_input("Enter UDP PORT Range, (Eg. 1-100) > "))

                        p_range = PORT_Range.split('-')
                        output = self.connection.recv(65565)

                        for port in range(int(p_range[0]), int(p_range[1]) + 1):
                            if six.PY3:
                                self.connection.sendall(six.int2byte(port))
                            else:
                                self.connection.sendall(str(port))

                            output = self.connection.recv(65565)

                            if six.PY3:
                                output = six.u(output).decode('utf-8')
                            logger.debug("[+] TCP  {} => {}".format(port, output))

                    elif option == "5":
                        output = self.connection.recv(65565)
                        if six.PY3:
                            COMMAND = str(input("OS Command > "))
                        else:
                            COMMAND = str(raw_input("OS Command > "))

                        if six.PY3:
                            self.connection.sendall(six.b(COMMAND))
                        else:
                            self.connection.sendall(COMMAND)

                        if six.PY3:
                            output = six.u(self.connection.recv(65565)).decode('utf-8')
                        else:
                            output = self.connection.recv(65565)

                        logger.debug("[+] OS Command Result\n\n{}".format(output))

                    elif option == "6":
                        logger.debug("[-] Successfully Exited from Network Enumeration")
                        break
                    else:
                        logger.debug("[-] Choose Correct Option")

                except Exception as e:
                    print(e)
                    pass

        except KeyboardInterrupt:
            self.connection.close()
            sys.exit(1)

    def exchange_loop(self, remote, client):
        try:
            while True:

                # wait until client or remote is available for read
                r, w, e = select.select([client, remote], [], [])

                if remote in r:
                    data = remote.recv(1024)
                    if client.send(data) <= 0:
                        break

                if client in r:
                    data = client.recv(1024)
                    if remote.send(data) <= 0:
                        break
        except:
            logger.debug("[-] Socket Connection Error")
            remote.close()
            client.close()
            sys.exit(1)

    def SocketCreate(self, listen_socks_host, listen_socks_port):
        try:
            self.host = listen_socks_host
            self.port = int(listen_socks_port)
            self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.remote.bind((self.host, self.port))
            self.remote.listen(1)
            return self.remote
        except:
            logger.debug("[-] PORT LISTEN ERROR")

    def ConnectSocket(self, connect_ip, connect_port):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((connect_ip, connect_port))
            return client_socket
        except:
            logger.debug("[-] Connection Refused")

# Main Function definition


def main(forward_socks=None, reverse_socks=None, server_ip='0.0.0.0', server_port=7777,remote_ip='127.0.0.1',remote_port=80,option="SP",protocol="T"):
    HOST, PORT = server_ip, int(server_port)

    # Setting Up Log Handler
    global logger
    global handler
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s : %(message)s")
    handler.setFormatter(formatter)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    # Setting the value of remote hosts
    global  remote_ips
    global remote_ports
    remote_ips = remote_ip
    remote_ports= remote_port

    # Server options Handling and appropriate function calling
    if (forward_socks is not None) and (reverse_socks is not None):
        logger.debug("[-] Sever Option Error")

    elif reverse_socks is not None:
        try:
            server = ThreadingTCPServer((HOST, PORT), ReverseHandler)
            logger.removeHandler(handler)
            logger.debug('[*] PivotSuite TCP Server LISTEN On {}:{} For Reverse TCP Connection'.format(server.server_address[0],server.server_address[1]))
            logger.removeHandler(handler)
            server.serve_forever()
        except KeyboardInterrupt:
            logger.debug('[-] SIGINT Received. Closing Server and Exiting')
            server.server_close()
            server.shutdown()
            _exit(1)
        except:
            logger.removeHandler(handler)
            logger.debug("[-] Wait 15s OR Change Listen Port")

    elif forward_socks is not None:
        if option == "SP":
            try:
                server = ThreadingTCPServer((HOST, PORT), ForwardHandler)
                logger.removeHandler(handler)
                logger.debug('[*] PivotSuite SOCKS Proxy Server LISTEN On {}:{} ; Waiting for SOCKS Client to Connect'.format(server.server_address[0],
                                                                                              server.server_address[1]))
                server.serve_forever()
            except KeyboardInterrupt:
                logger.debug('[-] SIGINT Received. Closing Server and Exiting')
                server.shutdown()
                server.server_close()
                sys.exit(0)
            except:
                logger.removeHandler(handler)
                logger.debug('[-] Wait 15 Sec.')
                sys.exit(0)

        elif option == "PF":
            if protocol == "T":
                try:
                    server = ThreadingTCPServer((HOST, PORT), TcpRelayHandler)
                    logger.removeHandler(handler)
                    logger.debug('[*] TCP Port Forward: Local-Host {} : Local-Port {} ==>> Remote-Host {} : Remote-Port {}'.format(server.server_address[0],
                                                                                          server.server_address[1],remote_ip,remote_port))
                    server.serve_forever()
                except KeyboardInterrupt:
                    logger.debug('[*] SIGINT Received. Closing Server and Exiting')
                    server.shutdown()
                    server.server_close()
                    sys.exit(0)
                except:
                    logger.removeHandler(handler)
                    logger.debug('[-] Wait 15 Sec.')
                    sys.exit(0)

            elif protocol == "U":

                try:
                    server=UdpRelayHandler()
                    logger.removeHandler(handler)
                    logger.debug('[*] UDP Port Forward: Local-Host {} : Local-Port {} ==>> Remote-Host {} : Remote-Port {}'.format(server_ip,server_port, remote_ip, remote_port))
                    server.handler(HOST,PORT)

                except KeyboardInterrupt:
                    logger.debug('[*] SIGINT Received. Closing Server and Exiting')
                    server.close()
                    sys.exit(1)
                except:
                    logger.removeHandler(handler)
                    logger.debug('[-] Wait 15 Sec.')
                    sys.exit(0)

            else:
                logger.debug("[-] Server Option Error")
                sys.exit(1)

        else:
            logger.debug("[-] Server Option Error")
            sys.exit(1)

    else:
        logger.debug("[-] Server Option Error")
        sys.exit(1)
