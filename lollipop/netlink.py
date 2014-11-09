import io
import struct
import socket


NETLINK_ROUTE              = 0x00
NETLINK_UNUSED             = 0x01
NETLINK_USERSOCK           = 0x02
NETLINK_FIREWALL           = 0x03
NETLINK_SOCK_DIAG          = 0x04
NETLINK_NFLOG              = 0x05
NETLINK_XFRM               = 0x06
NETLINK_SELINUX            = 0x07
NETLINK_ISCSI              = 0x08
NETLINK_AUDIT              = 0x09
NETLINK_FIB_LOOKUP         = 0x0a
NETLINK_CONNECOTR          = 0x0b
NETLINK_NETFILTER          = 0x0c
NETLINK_IP6_FW             = 0x0d
NETLINK_DNRTMSG            = 0x0e
NETLINK_KOBJECT_UEVENT     = 0x0f
NETLINK_GENERIC            = 0x10
NETLINK_SCSITRANSPORT      = 0x12
NETLINK_ECRYPTFS           = 0x13
NETLINK_RDMA               = 0x14
NETLINK_CRYPTO             = 0x15
# Address families
AF_UNPSEC                  = 0x00
AF_UNIX                    = 0x01
AF_LOCAL                   = 0x01
AF_INET                    = 0x02
AF_BRIDGE                  = 0x07
AF_INET6                   = 0x0a
AF_NETLINK                 = 0x10
AF_PACKET                  = 0x11
# IP protocols
IPPROTO_IP                 = 0x00
IPPROTO_ICMP               = 0x01
IPPROTO_IGMP               = 0x02
IPPROTO_IPIP               = 0x04
IPPROTO_TCP                = 0x06
IPPROTO_EGP                = 0x08
IPPROTO_PUP                = 0x0c
IPPROTO_UDP                = 0x11
IPPROTO_TP                 = 0x1d
IPPROTO_DCCP               = 0x21
IPPROTO_IPV6               = 0x29
IPPROTO_RSVP               = 0x2e
IPPROTO_GRE                = 0x2f
IPPROTO_ESP                = 0x32
IPPROTO_AH                 = 0x33
IPPROTO_MTP                = 0x5c
IPPROTO_BEETPH             = 0x5e
IPPROTO_ENCAP              = 0x62
IPPROTO_PIM                = 0x67
IPPROTO_COMP               = 0x6c
IPPROTO_SCTP               = 0x84
IPPROTO_UDPLITE            = 0x88
IPPROTO_RAW                = 0xff
# TCP flags
TCPF_ESTABLISHED           = 1 << 1
TCPF_SYN_SENT              = 1 << 2
TCPF_SYN_RECV              = 1 << 3
TCPF_FIN_WAIT1             = 1 << 4
TCPF_FIN_WAIT2             = 1 << 5
TCPF_TIME_WAIT             = 1 << 6
TCPF_CLOSE                 = 1 << 7
TCPF_CLOSE_WAIT            = 1 << 8
TCPF_LAST_ACK              = 1 << 9
TCPF_LISTEN                = 1 << 10
TCPF_CLOSING               = 1 << 11
TCPF_ALL                   = 0xfff
SOCK_DIAG_BY_FAMILY        = 0x14
# Flags
F_REQUEST                  = 0x001
F_MULTI                    = 0x002
F_ACK                      = 0x004
F_ECHO                     = 0x008
F_DUMP_INTR                = 0x010
# Modifiers to GET request
F_ROOT                     = 0x100
F_MATCH                    = 0x200
F_AOTMIC                   = 0x400
F_DUMP                     = F_ROOT | F_MATCH
# Modifiers to NEW request
F_REPLACE                  = 0x100
F_EXCL                     = 0x200
F_CREATE                   = 0x400
F_APPEND                   = 0x800

NOOP                       = 0x01
ERROR                      = 0x02
DONE                       = 0x03
OVERRUN                    = 0x04
MIN_TYPE                   = 0x10

IP_ANY                     = (0, 0, 0, 0)

MESSAGE                    = 'IHHII'
MESSAGE_FIELDS             = ('length', 'type', 'flags', 'seq', 'pid')


def build_message(kind, payload, seq, flags=F_REQUEST, pid=0):
    return struct.pack(
        'IHHII',
        16 + len(payload),
        kind,
        flags,
        seq,
        pid
    )


def build_inet_diag_request(family, protocol, ext, pad, states):
    return struct.pack(
        'BBBBI',
        family,
        protocol,
        ext,
        pad,
        states
    ) + build_socket_id()


def build_sock_diag(payload, seq=201527, pid=0):
    return build_message(
        SOCK_DIAG_BY_FAMILY,
        payload,
        seq,
        F_REQUEST | F_DUMP,
        pid,
    )


def build_socket_id(sport=0, dport=0, src=IP_ANY, dst=IP_ANY,
                    interface=0, cookie=(0, 0)):
    return b''.join([
        struct.pack('>H', sport),
        struct.pack('>H', dport),
        struct.pack('>IIII', *src),
        struct.pack('>IIII', *dst),
        struct.pack('I', interface),
        struct.pack('II', *cookie),
    ])


def parse(buf, spec):
    message_format = ''.join([field[0] for field in spec])
    message_fields = [field[1] for field in spec]
    raw = buf.read(struct.calcsize(message_format))
    return dict(zip(message_fields, struct.unpack(message_format, raw)))


def parse_attribute(buf):
    attribute = parse(buf, (
        ('H', 'length'),
        ('H', 'type'),
    ))
    attribute['payload'] = buf.read(attribute['length'] - 4)
    mark = buf.tell()
    if mark % 4:
        buf.seek(4 - (mark % 4), io.SEEK_CUR)
    return attribute


def parse_attributes(buf, length):
    attributes = []
    while buf.tell() < length:
        attributes.append(parse_attribute(buf))
    return attributes


def parse_message(buf):
    message = buf.read(struct.calcsize(MESSAGE))
    return dict(zip(
        MESSAGE_FIELDS,
        struct.unpack(MESSAGE, message)
    ))


def parse_inet_diag_message(buf):
    message = {}
    message.update(parse(buf, (
        ('B', 'family'),
        ('B', 'state'),
        ('B', 'timer'),
        ('B', 'retransmit'),
    )))
    message.update(parse_socket_id(buf))
    message.update(parse(buf, (
        ('I', 'expires'),
        ('I', 'rqueue'),
        ('I', 'tqueue'),
        ('I', 'uid'),
        ('I', 'inode'),
    )))
    return message


def parse_socket_id(buf):
    return dict((
        ('sport',  struct.unpack('>H',    buf.read(0x02))[0]),
        ('dport',  struct.unpack('>H',    buf.read(0x02))[0]),
        ('src',    struct.unpack('>IIII', buf.read(0x10))),
        ('dst',    struct.unpack('>IIII', buf.read(0x10))),
        ('if',     struct.unpack('I',     buf.read(0x04))[0]),
        ('cookie', struct.unpack('II',    buf.read(0x08))),
    ))
