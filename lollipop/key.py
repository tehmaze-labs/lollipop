import codecs
import hashlib
import logging
import os

from Crypto.Cipher import AES, DES3
from Crypto.PublicKey import DSA as DSAKey
from Crypto.PublicKey import RSA as RSAKey
from ecdsa import der, curves, SigningKey
from pyasn1.codec.ber import decoder as ber_decoder
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder

from . import security
from .asn1 import (
    DSAPrivateKey,
    ECPrivateKey,
    OID,
    OID_HASH,
)
from .buffer import Buffer


logger = logging.getLogger(__name__)


CIPHERS = {
    'AES-128-CBC': {
        'cipher': AES,
        'keysize': 16,
        'blocksize': 16,
        'mode': AES.MODE_CBC,
    },
    'DES-EDE3-CBC': {
        'cipher': DES3,
        'keysize': 24,
        'blocksize': 8,
        'mode': DES3.MODE_CBC,
    },
}


def bit_size(n):
    '''
    Number of bits needed to represent a integer excluding any prefix.
    '''
    if n == 0:
        n = 0
    if n < 0:
        n = -n

    # Make sure this is an integer
    n & 1

    hex_n = '{:x}'.format(n)
    return ((len(hex_n) - 1) * 4) + {
        '0':0, '1':1, '2':2, '3':2, '4':3, '5':3, '6':3, '7':3,
        '8':4, '9':4, 'a':4, 'b':4, 'c':4, 'd':4, 'e':4, 'f':4,
     }[hex_n[0]]

def byte_size(n):
    quanta, mod = divmod(bit_size(n), 8)
    if mod or n == 0:
        quanta += 1
    return quanta

def fingerprint_hex(data):
    fingerprint = hashlib.md5(data).hexdigest()
    return ':'.join(
        a + b for a, b in zip(fingerprint[::2], fingerprint[1::2])
    )

def generate_key(hashfunc, salt, key, length):
    keydata = bytes()
    digest = bytes()
    if len(salt) > 8:
        salt = salt[:8]
    while length > 0:
        hashing = hashfunc()
        if len(digest) > 0:
            hashing.update(digest)
        hashing.update(key)
        hashing.update(salt)
        digest = hashing.digest()
        size = min(length, len(digest))
        keydata += digest[:size]
        length -= size
    return keydata

def load_der(pem, pem_marker=b'PUBLIC KEY', password=None):
    pem_start = b'-----BEGIN ' + pem_marker + b'-----'
    pem_end = b'-----END ' + pem_marker + b'-----'
    pem_lines = []
    pem_keep = False
    pem_header = {}

    for line in pem.splitlines():
        line = line.strip()
        if not line:
            continue

        if line == pem_start:
            if pem_keep or pem_lines:
                raise ValueError('More than one start marker found "{}"'.format(
                    pem_marker,
                ))
            else:
                pem_keep = True

        elif line == pem_end:
            if not pem_lines:
                raise ValueError('End marker "{}" found without start'.format(
                    pem_marker,
                ))

        elif pem_keep:
            if b': ' in line:
                key, value = line.split(b': ', 1)
                pem_header[key.lower()] = str(value, 'ascii')
            else:
                pem_lines.append(line)

    data = codecs.decode(b''.join(pem_lines), 'base64')

    if not b'proc-type' in pem_header:
        return data

    else:
        encryption_type, salt = pem_header[b'dek-info'].split(',')
        if encryption_type not in CIPHERS:
            raise ValueError('Unsupported private key cipher "{}"'.format(
                encryption_type,
            ))
        if password is None:
            raise ValueError('Private key file is encrypted')

        cipher = CIPHERS[encryption_type]['cipher']
        keysize = CIPHERS[encryption_type]['keysize']
        mode = CIPHERS[encryption_type]['mode']
        salt = codecs.decode(salt, 'hex')
        key = generate_key(hashlib.md5, salt, password.encode('ascii'), keysize)
        return cipher.new(key, mode, salt).decrypt(data)


class Key:
    def __init__(self):
        security.ensure_gc()

    def __repr__(self):
        return '<{} {} ({})>'.format(
            self.__class__.__name__,
            self.fingerprint,
            'private' if self.is_private_key else 'public',
        )

    @classmethod
    def from_blob(cls, blob):
        key_type = blob.pop_str()
        if key_type == b'ssh-dss':
            return DSA.from_blob(blob)
        elif key_type == b'ssh-rsa':
            return RSA.from_blob(blob)
        elif key_type.startswith(b'ecdsa-sha2-'):
            return ECDSA.from_blob(blob)
        else:
            return None

    @property
    def fingerprint(self):
        if not hasattr(self, '_fingerprint'):
            return fingerprint_hex(self.public_key)

        return self._fingerprint

    @property
    def is_private_key(self):
        return False

    @property
    def public_key(self):
        raise NotImplementedError()


class DSA(Key):
    def __init__(self, p, q, g, public, private=None):
        super(DSA, self).__init__()
        self.p = p
        self.q = q
        self.g = g
        self.public = public
        self.private = private

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        else:
            return (
                self.p == other.p and
                self.q == other.q and
                self.g == other.g and
                self.public == other.public
            )

    @classmethod
    def from_blob(cls, blob):
        keydata = dict()
        for attr in ('p', 'q', 'g', 'public'):
            keydata[attr] = blob.pop_mpint()
        for attr in ('private',):
            try:
                keydata[attr] = blob.pop_mpint()
            except IndexError:
                break
        return cls(**keydata)

    @classmethod
    def from_pem(cls, data, password=None):
        encoded = load_der(data, b'DSA PRIVATE KEY', password=password)
        keyinfo = der_decoder.decode(encoded, asn1Spec=DSAPrivateKey())[0]
        keydata = dict(
            p=int(keyinfo.getComponentByName('p')),
            q=int(keyinfo.getComponentByName('q')),
            g=int(keyinfo.getComponentByName('g')),
            public=int(keyinfo.getComponentByName('public')),
            private=int(keyinfo.getComponentByName('private')),
        )
        return cls(**keydata)

    @property
    def is_private_key(self):
        return self.private is not None

    @property
    def public_key(self):
        '''
        RFC4263#6.6 encoded public key.
        '''
        output = Buffer()
        output.put_str('ssh-dss')
        output.put_mpint(self.p)
        output.put_mpint(self.q)
        output.put_mpint(self.g)
        output.put_mpint(self.public)
        return output


class ECDSA(Key):
    named_curves = {
        '1.2.840.10045.3.1.1.1': 'prime192v1',
        '1.2.840.10045.3.1.1.2': 'prime192v2',
        '1.2.840.10045.3.1.1.3': 'prime192v3',
        '1.2.840.10045.3.1.1.4': 'prime239v1',
        '1.2.840.10045.3.1.1.5': 'prime239v2',
        '1.2.840.10045.3.1.1.6': 'prime239v3',
        '1.2.840.10045.3.1.7':   'nistp256',
    }
    curves = {
        'nistp192':  curves.NIST192p,
        'nistp224':  curves.NIST224p,
        'nistp256':  curves.NIST256p,
        'nistp384':  curves.NIST384p,
        'nistp521':  curves.NIST521p,
        'secp256k1': curves.SECP256k1,
    }

    def __init__(self, private_key, named_curve):
        super(ECDSA, self).__init__()
        self.private_key = private_key
        self.named_curve = named_curve
        self.verifyingKey = self.private_key.verifying_key

    @classmethod
    def from_blob(cls, blob):
        named_curve = str(blob.pop_str(), 'ascii')
        if named_curve not in cls.curves:
            logger.warn('unsupported named curve "{}"'.format(named_curve))
            return None

        curve = cls.curves[named_curve]
        group = blob.pop_mpint()
        eckey = blob.pop_mpint()
        keydata = dict(
            named_curve=named_curve,
            private_key=SigningKey.from_secret_exponent(eckey, curve),
        )
        return cls(**keydata)

    @classmethod
    def from_pem(cls, data, password=None):
        encoded = load_der(data, b'EC PRIVATE KEY', password=password)
        keyinfo, padding = der_decoder.decode(encoded, asn1Spec=ECPrivateKey())
        signkey = SigningKey.from_der(der_encoder.encode(keyinfo))
        keydata = dict(
            private_key=signkey,
            named_curve=cls.named_curves[
                str(keyinfo.getComponentByName('named_curve'))
            ],
        )
        del keyinfo
        del padding
        security.gc()
        return cls(**keydata)

    @property
    def is_private_key(self):
        return self.private_key is not None

    @property
    def public_key(self):
        '''
        RFC4263#6.6 encoded public key.
        '''
        output = Buffer()
        output.put_str('ecdsa-sha2-{}'.format(self.named_curve))
        output.put_str(self.named_curve)
        output.put_str('{}'.format(self.verifyingKey.to_string()))
        return output


class RSA(Key):
    def __init__(self, n, e, d=None, iqmp=None, p=None, q=None):
        super(RSA, self).__init__()
        self.n = n
        self.e = e
        self.d = d
        self.iqmp = iqmp
        self.p = p
        self.q = q
        self.exp1 = None
        self.exp2 = None

        # exp1 and exp2 can be calculated from {d, p, q}
        if self.p is not None:
            self.exp1 = self.d % (self.p - 1)
        if self.q is not None:
            self.exp2 = self.d % (self.q - 1)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        else:
            return (
                self.n == other.n and
                self.e == other.e
            )

    def __del__(self):
        security.bzero(self.d)
        security.bzero(self.iqmp)
        security.bzero(self.p)
        security.bzero(self.q)
        security.gc()

    @classmethod
    def from_blob(cls, blob):
        keydata = dict()
        for attr in ('e', 'n'):
            keydata[attr] = blob.pop_mpint()
        for attr in ('d', 'iqmp', 'p', 'q'):
            try:
                keydata[attr] = blob.pop_mpint()
            except IndexError:
                break
        security.gc()
        return cls(**keydata)

    @classmethod
    def from_pem(cls, data, password=None):
        encoded = load_der(data, b'RSA PRIVATE KEY', password=password)
        keylist = ber_decoder.decode(encoded)[0]
        keydata = dict(
            n=int(keylist[1]),
            e=int(keylist[2]),
            d=int(keylist[3]),
            p=int(keylist[4]),
            q=int(keylist[5]),
        )
        del keylist
        security.gc()
        return cls(**keydata)

    @property
    def is_private_key(self):
        return self.q is not None

    @property
    def public_key(self):
        '''
        RFC4263#6.6 encoded public key.
        '''
        output = Buffer()
        output.put_str('ssh-rsa')
        output.put_mpint(self.e)
        output.put_mpint(self.n)
        return output

    def sign(self, data, hash_algorithm):
        hashed = hash_algorithm(data).digest()
        clear_text = OID_HASH[hash_algorithm] + hashed
        key_length = byte_size(self.n)
        padded = self._pad_for_signing(clear_text, key_length)
        payload = int.from_bytes(padded, byteorder='big')
        encrypted = RSA.encrypt_int(payload, self.d, self.n)
        return encrypted.to_bytes(
            (encrypted.bit_length() // 8) + 1,
            byteorder='big'
        )

    @classmethod
    def decrypt_int(cls, message, dkey, n):
        return pow(message, dkey, n)

    @classmethod
    def encrypt_int(cls, message, ekey, n):
        if message > n:
            raise OverflowError("The message {} is too long for n={}".format(
                message,
                n,
            ))
        return pow(message, ekey, n)

    def _pad_for_signing(self, message, length):
        max_length = length - 11
        msg_length = len(message)

        if msg_length > max_length:
            raise OverflowError('Message is {} bytes, but only {} allowed'.format(
                msg_length, max_length,
            ))

        padding = b''
        padding_length = length - msg_length - 3

        while len(padding) < padding_length:
            needed = padding_length - len(padding)
            new_padding = os.urandom(needed + 5)
            new_padding = new_padding.replace(b'\x00', b'')
            padding = padding + new_padding[:needed]

        assert len(padding) == padding_length
        return b''.join([
            b'\x00\x02',
            padding,
            b'\x00',
            message,
        ])
