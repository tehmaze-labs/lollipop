import ctypes
import io
import ipaddress
import logging
import os
import platform
import random
import socket
import struct

from . import netlink


logger = logging.getLogger(__name__)


class OperatingSystem:
    def get_peer(self, remote):
        raise NotImplementedError()


class Linux(OperatingSystem):
    proc_net_tcp_header = ('sl', 'local_address', 'remote_address', 'st',
                           'tx_rx_queue', 'tr_tm_when', 'retransmit', 'uid',
                           'timeout', 'inode')

    def get_peer(self, remote):
        peercred = remote.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize('3i'),
        )
        pid, uid, gid = struct.unpack('3i', peercred)
        return dict(
            pid=pid,
            uid=uid,
            gid=gid,
        )

    def get_process_addresses(self, pid):
        inodes = []
        path = '/proc/{}/fd'.format(pid)
        try:
            for fd in os.listdir(path):
                try:
                    target = os.readlink(os.path.join(path, fd))
                except FileNotFoundError:
                    continue
                if target.startswith('socket:['):
                    inodes.append(target[8:-1])
        except FileNotFoundError:
            return

        logger.debug('possible inodes for pid {}: {}'.format(
            pid,
            ','.join(inodes) if inodes else 'none',
        ))
        for inode in inodes:
            for ip in self.get_tcp_sessions_by_inode(inode, pid):
                yield ip

    def get_tcp_sessions_by_inode(self, inode, pid=0):
        inode = int(inode)
        for family in (netlink.AF_INET, netlink.AF_INET6):
            payload = netlink.build_inet_diag_request(
                family,                                 # familiy
                netlink.IPPROTO_TCP,                    # protocol
                0,                                      # ext
                0,                                      # pad
                netlink.TCPF_ESTABLISHED,               # states
            )
            headers = netlink.build_sock_diag(
                payload,
            )
            request = socket.socket(
                socket.AF_NETLINK,
                socket.SOCK_RAW,
                netlink.NETLINK_SOCK_DIAG,
            )
            request.bind((0, 0))
            request.send(headers + payload)

            finished = False
            while not finished:
                data = request.recv(0xfffd)
                blob = io.BytesIO(data)
                while True:
                    if blob.tell() >= len(data):
                        break

                    message = netlink.parse_message(blob)
                    if message['type'] == netlink.DONE:
                        finished = True
                        break
                    elif message['type'] == netlink.ERROR:
                        raise ValueError(message)
                    elif message['seq'] != 201527:
                        break

                    payload_length = blob.tell() - 16 + message['length']
                    payload = netlink.parse_inet_diag_message(blob)
                    attribs = netlink.parse_attributes(blob, payload_length)
                    if payload['inode'] == inode:
                        if family == netlink.AF_INET:
                            yield ipaddress.IPv4Address(payload['dst'][0])
                        else:
                            yield ipaddress.IPv6Address(payload['dst'])

    @property
    def libc(self):
        if not hasattr(self, '_libc'):
            for lib in ('libc.so.7', 'libc.so.6', 'libc.so.5'):
                try:
                    self._libc = ctypes.CDLL(lib)
                except OSError:
                    pass
        return self._libc

    @property
    def memset(self):
        return self.libc.memset


def get_operatingsystem():
    system = platform.system()
    if system == 'Linux':
        return Linux()


operatingsystem = get_operatingsystem()
