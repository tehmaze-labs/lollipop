import codecs
import struct


ZERO_BYTE = bytearray(b'\x00')
MAXI_BYTE = bytearray(b'\xff')

def deflate_long(value):
    '''
    Turns a long into a normalized byte string.
    '''
    s = bytearray()
    n = int(value)

    while n != 0 and n != -1:
        s = bytearray(struct.pack('>I', n & 0xffffffff)) + s
        n >>= 32

    for i in enumerate(s):
        if n == 0 and i[1] != 0x00:
            break
        if n == -1 and i[1] != 0xff:
            break

    else:
        i = (0,)
        if n == 0:
            s = bytearray(chr(0x00))
        else:
            s = bytearray(chr(0xff))

    s = s[i[0]:]
    if n == 0 and s[0] >= 0x80:
        s = ZERO_BYTE + s
    if n == -1 and s[0] < 0x80:
        s = MAXI_BYTE + s

    return s


def inflate_long(s, always_positive=False):
    out = 0
    neg = 0

    if not always_positive and len(s) > 0 and s[0] > 0x80:
        neg = 1

    if len(s) % 4:
        fill = MAXI_BYTE if neg else ZERO_BYTE
        s = fill * (4 - len(s) % 4) + s

    for i in range(0, len(s), 4):
        out = (out << 32) + struct.unpack('>I', s[i:i + 4])[0]

    if neg:
        out -= (1 << (8 * len(s)))

    return out


class Buffer(bytearray):
    INT_MAX = 0xff000000

    def __repr__(self):
        return '<Buffer {!r}>'.format(super(Buffer, self).__repr__())

    def __str__(self):
        return super(Buffer, self).__str__()

    def clear(self):
        for _ in range(len(self)):
            self.pop()

    def encode(self, encoding):
        return codecs.encode(self, encoding)

    def get_str(self):
        data = self[:4]
        print('get_str', repr(data), len(data))
        if len(data) == 0:
            return None
        else:
            size = struct.unpack('>i', data)[0]
            return str(self[4:4 + size])

    def pop_int(self):
        data = bytearray()
        for _ in range(4):
            data.append(self.pop(0))
        return struct.unpack('>i', data)[0]

    def pop_mpint(self):
        blob = self.pop_str()
        return inflate_long(blob)

    def pop_size(self):
        data = bytearray()
        for _ in range(4):
            data.append(self.pop(0))
        return struct.unpack('>i', data)[0]

    def pop_str(self):
        size = self.pop_size()
        print('pop_str size', size)
        data = bytearray()
        for _ in range(size):
            data.append(self.pop(0))
        return data

    def put_chr(self, value):
        if isinstance(value, (bytes, str)):
            self.extend(value)
        else:
            self.append(value)

    def put_size(self, value):
        self.extend(struct.pack('>I', value))
        return self

    def put_int(self, value):
        if value >= self.INT_MAX:
            self.extend(self.INT_MAX)
            self.extend(deflate_long(value))
        else:
            self.extend(struct.pack('>I', value))
        return self

    def put_int64(self, value):
        self.extend(struct.pack('>Q', value))
        return self

    def put_mpint(self, value):
        self.put_str(deflate_long(value))
        return self

    def put_str(self, value, encoding='ascii'):
        self.put_size(len(value))
        if isinstance(value, bytearray):
            self.extend(value)
        else:
            self.extend(bytearray(value, encoding))
        return self
