import os
import socket
import struct

from .operatingsystem import operatingsystem

DEFAULT_READ_SIZE = 1024


class Remote(object):
    def __init__(self, remote, server=True):
        self.remote = remote
        self.server = server
        self.read_buffer = bytearray()
        self.send_buffer = bytearray()
        self.peer = None
        self.peer_addresses = set()

    # Socket method wrappers

    def close(self):
        try:
            self.remote.shutdown(socket.SHUT_RDWR)
            self.remote.close()
        except socket.error:
            pass

    def fileno(self):
        return self.remote.fileno()

    def recv(self, size):
        return self.remote.recv(size)

    def send(self, data):
        return self.remote.send(data)

    def setblocking(self, mode):
        self.remote.setblocking(mode)

    # Multiplexer loop handlers

    def handle_accept(self):
        remote, address = self.remote.accept()
        return Remote(remote, server=False)

    def handle_close(self):
        '''
        This remote has close the connection.
        '''
        pass

    def handle_error(self):
        '''
        There was an error communicating with this remote.
        '''
        pass

    def handle_read(self, read_size=DEFAULT_READ_SIZE):
        chunk = self.remote.recv(read_size)
        if len(chunk):
            self.read_buffer.extend(chunk)
        else:
            raise socket.error('Zero read size')

    def handle_send(self):
        if len(self.send_buffer):
            sent = self.send(self.send_buffer)
            self.send_buffer = self.send_buffer[sent:]
            return sent
        else:
            return 0

    def handle_poll_pre(self):
        pass

    def handle_poll_post(self):
        pass

    # Get remote end process

    def get_peer(self):
        if self.peer is None:
            self.peer = operatingsystem.get_peer(self.remote)
        return self.peer

    def get_peer_addresses(self):
        if self.peer is None:
            self.get_peer()

        if 'pid' in self.peer:
            pid = self.peer['pid']
            for address in operatingsystem.get_process_addresses(pid):
                self.peer_addresses.add(address)

        return self.peer_addresses
