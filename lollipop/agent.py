import logging
import os
import socket
import struct
import tempfile

from . import security
from .buffer import Buffer
from .remote import Remote
from .key import Key, DSA, ECDSA, RSA
from .identity import Identity


logger = logging.getLogger(__name__)


DEFAULT_BACKLOG = 128
SSH_AGENTC = dict(
    SSH1_REQUEST_RSA_IDENTITIES    = 0x01,
    SSH1_RSA_CHALLENGE             = 0x03,
    SSH1_ADD_RSA_IDENTITY          = 0x07,
    SSH1_REMOVE_RSA_IDENTITY       = 0x08,
    SSH1_REMOVE_ALL_RSA_IDENTITIES = 0x09,
    SSH1_ADD_RSA_ID_CONSTRAINED    = 0x18,

    SSH2_REQUEST_IDENTITIES        = 0x0b,
    SSH2_SIGN_REQUEST              = 0x0d,
    SSH2_ADD_IDENTITY              = 0x11,
    SSH2_REMOVE_IDENTITY           = 0x12,
    SSH2_REMOVE_ALL_IDENTITIES     = 0x13,
    SSH2_ADD_ID_CONSTRAINED        = 0x19,

    ADD_SMARTCARD_KEY              = 0x14,
    REMOVE_SMARTCARD_KEY           = 0x15,
    LOCK                           = 0x16,
    UNLOCK                         = 0x17,
    ADD_SMARTCARD_KEY_CONSTRAINED  = 0x1a,
)
SSH_AGENTC_MAP = dict((v, k) for k, v in SSH_AGENTC.items())
SSH_AGENT = dict(
    FAILURE                    = 0x05,
    SUCCESS                    = 0x06,

    SSH1_RSA_IDENTITIES_ANSWER = 0x02,
    SSH1_RSA_RESPONSE          = 0x04,

    SSH2_IDENTITIES_ANSWER     = 0x0c,
    SSH2_SIGN_RESPONSE         = 0x0e,

    CONSTRAIN_LIFETIME         = 0x01,
    CONSTRAIN_CONFIRM          = 0x02,
)
SSH_AGENT_MAP = dict((v, k) for k, v in SSH_AGENT.items())


class Packet(object):
    def __init__(self, request_type, request, remote):
        self.type = request_type
        self.request = request
        self.remote = remote
        self.buffer = Buffer()

    def __repr__(self):
        return '<Packet type={} request={!r}>'.format(
            SSH_AGENTC_MAP.get(self.type, 'unknown'),
            self.request,
        )

    @classmethod
    def new(cls, remote):
        data = remote.recv(4)
        if len(data) != 4:
            return None

        size = struct.unpack('>i', data)[0]
        if size > 256 * 1024:
            logger.warn('message size overflow')
            return None

        request = Buffer(remote.recv(size))
        request_type = request.pop(0)
        return Packet(request_type, request, remote)


class AgentClient(Remote):
    def __init__(self, agent, remote):
        self.agent = agent
        super(AgentClient, self).__init__(remote, server=False)
        self.send_buffer = Buffer()

    def __repr__(self):
        return '<AgentClient fileno={} peer={}>'.format(
            self.fileno(),
            self.get_peer(),
        )

    def recv(self, size):
        print('{}.recv({})'.format(self.__class__.__name__, size))
        data = self.remote.recv(size)
        print(' `-> {!r}'.format(data))
        return data

    def send(self, data):
        print('{}.send({})'.format(self.__class__.__name__, data))
        sent = self.remote.send(data)
        return sent

    # Convenience

    def get_str(self):
        data = self.recv(4)
        if len(data) != 4:
            return None
        else:
            size = struct.unpack('>i', data)[0]
            return self.recv(size)

    def put(self, blob):
        self.send_buffer.extend(blob)

    def put_chr(self, value):
        if not isinstance(self.send_buffer, Buffer):
            self.send_buffer = Buffer(self.send_buffer)
        self.send_buffer.put_chr(value)

    def put_int(self, value):
        if not isinstance(self.send_buffer, Buffer):
            self.send_buffer = Buffer(self.send_buffer)
        self.send_buffer.put_int(value)

    def put_str(self, value):
        if not isinstance(self.send_buffer, Buffer):
            self.send_buffer = Buffer(self.send_buffer)
        self.send_buffer.put_str(value)

    def handle_read(self, read_size=None):
        packet = Packet.new(self)
        try:
            self.handle_packet(packet)
        finally:
            del packet
            security.gc()

    def handle_packet(self, packet):
        if packet is None:
            raise socket.error('Invalid read')

        packet_type = SSH_AGENTC_MAP.get(packet.type, 'INVALID')
        if self.agent.locked and packet_type != 'UNLOCK':
            self.put_int(1)
            self.put_chr(SSH_AGENT['FAILURE'])
            return

        if packet_type in {'LOCK', 'UNLOCK'}:
            self.agent.process_lock(self, packet, packet_type == 'LOCK')

        elif packet.type == SSH_AGENTC['SSH2_ADD_IDENTITY']:
            self.agent.process_add_identity(self, packet)
            del packet

        elif packet.type == SSH_AGENTC['SSH2_REQUEST_IDENTITIES']:
            self.agent.process_request_identities(self)

        elif packet.type == SSH_AGENTC['SSH2_REMOVE_IDENTITY']:
            self.agent.process_remove_identity(self, packet)

        elif packet.type == SSH_AGENTC['SSH2_REMOVE_ALL_IDENTITIES']:
            self.agent.process_remove_all_identities(self)

        elif packet.type == SSH_AGENTC['SSH2_SIGN_REQUEST']:
            self.agent.process_sign_request(self, packet)
            del packet

        else:
            logger.error('Invalid request {} ({:02x})'.format(
                packet_type,
                packet.type,
            ))
            self.put_int(1)
            self.put_chr(SSH_AGENT['FAILURE'])


class AgentSocket(Remote):
    def __init__(self, agent, sockname):
        self.agent = agent
        self.sockname = sockname

        # Setup listening UNIX socket
        logger.info('starting agent on {}'.format(self.sockname))
        remote = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        remote.setblocking(0)
        remote.bind(self.sockname)
        remote.listen(DEFAULT_BACKLOG)

        # Set secure file mode
        os.chmod(self.sockname, 0o600)

        # Finally, construct a Remote object
        super(AgentSocket, self).__init__(remote, server=True)

        # Our buffer types
        self.send_buffer = Buffer()

    def handle_accept(self):
        client, _ = self.remote.accept()
        remote = AgentClient(self.agent, client)
        remote.send_buffer = Buffer()
        return remote


class Agent(object):
    def __init__(self, path, config):
        self.path = path
        self.config = config
        self.acls = self.config.acls
        self.identities = self.config.identities

        self.sockname = os.path.join(self.path, 'agent.sock')
        self.remote = AgentSocket(self, self.sockname)
        self.locked = False

    def process_lock(self, client, packet, lock):
        ok = False
        password = packet.request.get_str()

        if self.locked and not lock and password == self.locked_password:
            self.locked = False
            del self.locked_password
            logger.info('agent unlocked')
            ok = True

        elif not self.locked and lock:
            self.locked = True
            self.locked_password = password
            logger.info('agent locked')
            ok = True

        del password
        client.put_int(1)
        client.put_chr(SSH_AGENT['SUCCESS'] if ok else SSH_AGENT['FAILURE'])

    def process_add_identity(self, client, packet):
        ok = False
        identity = Identity.from_blob(packet.request)
        if identity is not None and identity.key.is_private:
            self.identities.add(identity)
            ok = True

        client.put_int(1)
        client.put_chr(SSH_AGENT['SUCCESS'] if ok else SSH_AGENT['FAILURE'])

    def process_request_identities(self, client):
        #client.put_int(1)
        message = Buffer()
        identities = []
        addresses = client.get_peer_addresses()
        for identity in self.identities:
            if identity.acl.policy_for_addresses(addresses) is not False:
                identities.append(identity)
        message.put_chr(SSH_AGENT['SSH2_IDENTITIES_ANSWER'])
        message.put_int(len(identities))
        for identity in identities:
            message.put_str(identity.key.public_key)
            message.put_str(identity.comment or '')
        client.put_str(message)

    def process_remove_identity(self, client, packet):
        ok = False
        blob = Buffer(packet.request.pop_str())
        key = Key.from_blob(blob)

        if key is not None:
            if key in self.identities:
                self.identities.remove_key(key)
                ok = True

        client.put_int(1)
        client.put_chr(SSH_AGENT['SUCCESS'] if ok else SSH_AGENT['FAILURE'])

    def process_remove_all_identities(self, client):
        for identity in self.identities:
            self.identities.remove(identity)

        client.put_int(1)
        client.put_chr(SSH_AGENT['SUCCESS'])

    def process_sign_request(self, client, packet):
        logger.info('signing request for {}'.format(client))
        blob = Buffer(packet.request.pop_str())
        data = Buffer(packet.request.pop_str())
        flag = packet.request.pop_int()

        key = Key.from_blob(blob)
        identity = self.identities[key]
        if identity.acl.policy_for_client(client) is False:
            client.put_int(1)
            client.put_chr(SSH_AGENT['FAILURE'])

        if identity is not None:
            signature = identity.sign(data)
            print('signature', signature)
            client.put_int(len(signature))
            client.put_chr(SSH_AGENT['SSH2_SIGN_RESPONSE'])
            client.put(signature)
        else:
            client.put_int(1)
            client.put_chr(SSH_AGENT['FAILURE'])
