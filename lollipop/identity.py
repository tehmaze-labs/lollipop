import codecs
import hashlib
import logging
import os

from . import security
from .key import Key, DSA, ECDSA, RSA, load_der
from .buffer import Buffer

logger = logging.getLogger(__name__)


class Identity(object):
    type = None
    marker = (
        b'-----BEGIN ',
        b' PRIVATE KEY-----',
    )

    def __init__(self, key, comment=None, provider=None, death=None):
        self.key = key
        self.comment = comment
        self.provider = provider
        self.death = death
        logger.info('loaded identity {!r}'.format(self))

    def __repr__(self):
        return '<{} fingerprint={} comment={}>'.format(
            self.__class__.__name__,
            self.key.fingerprint,
            self.comment,
        )

    @classmethod
    def from_blob(cls, blob):
        data = dict(
            key = Key.from_blob(blob),
        )
        print('remain', blob)
        try:
            data['comment'] = str(blob.pop_str(), 'ascii')
        except IndexError:
            pass
        print('new key', data)
        return cls.from_key(**data)

    @classmethod
    def from_key(cls, key, **kwargs):
        if isinstance(key, DSA):
            return DSAIdentity(key, **kwargs)
        elif isinstance(key, ECDSA):
            return ECDSAIdentity(key, **kwargs)
        elif isinstance(key, RSA):
            return RSAIdentity(key, **kwargs)
        else:
            return None

    @classmethod
    def from_keyfile(cls, filename, password=None):
        filename = os.path.abspath(filename)
        if cls is Identity:
            with open(filename, 'rb') as file:
                kind = None
                for line in file:
                    line = line.strip()
                    if line.startswith(cls.marker[0]) and \
                        line.endswith(cls.marker[1]):
                        kind = line[len(cls.marker[0]):-len(cls.marker[1])]
                        kind = str(kind, 'ascii').strip()
                        break

                if kind is None:
                    raise TypeError("Can't determine key type for {}".format(
                        filename,
                    ))

                file.seek(0)
                for subclass in Identity.__subclasses__():
                    if subclass.type.__name__ == kind:
                        return subclass.from_str(
                            file.read(),
                            password=password,
                            comment=filename,
                        )

                raise TypeError('Unsupported key type "{}"'.format(kind))
        else:
            logger.info('loading {} identity from keyfile {}'.format(
                self.__class__.__name__,
                filename,
            ))
            with open(filename, 'rb') as file:
                return cls.from_str(file.read())

    @classmethod
    def from_str(cls, data, password=None, comment=None):
        return cls(
            key=cls.type.from_pem(data, password=password),
            comment=comment,
        )


class DSAIdentity(Identity):
    type = DSA


class ECDSAIdentity(Identity):
    type = ECDSA


class RSAIdentity(Identity):
    type = RSA

    def sign(self, data):
        output = Buffer()
        output.put_str('ssh-rsa')
        output.extend(self.key.sign(data, hashlib.sha1))
        return output


class Identities(object):
    def __init__(self):
        self.identities = []

    def __contains__(self, item):
        if isinstance(item, Key):
            for identity in self.identities:
                if identity.key == item:
                    return True
            return False
        elif isinstance(item, Identity):
            return item in self.identities
        else:
            raise ValueError(item)

    def __getitem__(self, key):
        for identity in self.identities:
            if identity.key == key:
                return identity

    def __iter__(self):
        self.__cursor__ = -1
        return self

    def __next__(self):
        self.__cursor__ += 1
        if self.__cursor__ >= len(self.identities):
            raise StopIteration()
        else:
            return self.identities[self.__cursor__]

    def __len__(self):
        return len(self.identities)

    def add(self, identity):
        self.identities.append(identity)

    def add_dsa_keyfile(self, filename, password=None):
        self.add(DSAIdentity.from_keyfile(filename, password=password))

    def add_ecdsa_keyfile(self, filename, password=None):
        self.add(ECDSAIdentity.from_keyfile(filename, password=password))

    def add_rsa_keyfile(self, filename, password=None):
        self.add(RSAIdentity.from_keyfile(filename, password=password))

    def remove(self, identity):
        logger.info('removing identity {}'.format(identity))
        if identity in self.identities:
            self.identities.remove(identity)
            del identity.key
            del identity
            security.gc()

    def remove_key(self, key):
        for identity in self.identities:
            if identity.key == key:
                self.remove(identity)
