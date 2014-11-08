from collections import defaultdict, OrderedDict
from ipaddress import ip_network, IPv4Address, IPv6Address
from fnmatch import fnmatch
import logging
import os

import yaml

from .identity import Identity, Identities


logger = logging.getLogger(__name__)


POLICY = dict(
    accept=True,
    reject=False,
    permit=True,
)


class OrderedDefaultDict(OrderedDict):
    def __init__(self, *args, **kwargs):
        if not args:
            self.default_factory = None
        else:
            if not (args[0] is None or callable(args[0])):
                raise TypeError('first argument must be callable or None')
            self.default_factory = args[0]
            args = args[1:]
        super(OrderedDefaultDict, self).__init__(*args, **kwargs)

    def __missing__(self, key):
        if self.default_factory is None:
            raise KeyError(key)
        self[key] = default = self.default_factory()
        return default

    def __reduce__(self):  # optional, for pickle support
        args = (self.default_factory,) if self.default_factory else ()
        return self.__class__, args, None, None, self.iteritems()


class ACL:
    def __init__(self, network, policy):
        self.network = ip_network(
            '0.0.0.0/0' if network == 'default' else network,
            strict=False,
        )
        self.policy = POLICY[policy]

    def __contains__(self, address):
        if not isinstance(address, (IPv4Address, IPv6Address)):
            address = ip_network(address)
        return address in self.network

    def __getitem__(self, address):
        if not isinstance(address, (IPv4Address, IPv6Address)):
            address = ip_network(address)

        if address in self:
            return self.policy
        else:
            return None

    def __repr__(self):
        return '<ACL network={} policy={}>'.format(
            self.network,
            'accept' if self.policy else 'reject'
        )


class ACLS(list):
    def policy(self, address):
        '''
        Evaluate policy for the supplied address, will return:

            - ``True`` if address is permitted
            - ``False`` if address is rejected
            - ``None`` if undecided
        '''
        if not isinstance(address, (IPv4Address, IPv6Address)):
            address = ip_network(address)

        for acl in self:
            policy = acl[address]
            if policy is not None:
                return policy

    def policy_for_addresses(self, addresses):
        logger.info('policy for addresses {}'.format(addresses))
        for address in addresses:
            policy = self.policy(address)
            if policy is True:
                logger.info('client request allowed (policy)')
                return True
            elif policy is False:
                logger.warn('client request denied (policy)')
                return False

    def policy_for_client(self, client):
        '''
        Evaluate policy for the supplied client, will return:

            - ``True`` if address is permitted
            - ``False`` if address is rejected
            - ``None`` if undecided
        '''
        addresses = client.get_peer_addresses()
        return self.policy_for_addresses(addresses)


class Config:
    DEFAULT_PATH = (
        '.lollipop.yaml',
        '~/.ssh/lollipop.yaml',
        '/etc/ssh/lollipop.yaml',
        '/etc/lollipop/lillipop.yaml',
        '/etc/lollipop.yaml',
    )

    def __init__(self, filename):
        self.filename = os.path.abspath(filename)
        while os.path.islink(self.filename):
            self.filename = os.readlink(self.filename)

        with open(self.filename, 'rb') as file:
            self.config = yaml.load(file)

        self.acls = OrderedDefaultDict(ACLS)
        for identity, acls in self.config['acls'].items():
            if identity != 'default':
                identity = self.expand_path(identity)
            for acl in acls:
                for network, policy in acl.items():
                    self.acls[identity].append(ACL(network, policy))

        print(self.acls)
        if not 'default' in self.acls:
            logger.warn('no default ACL, defaulting to permit')
            self.acls['default'].append(ACL('default', 'permit'))

        self.identities = Identities()
        for key in self.config['keys']:
            for filename, password in key.items():
                filename = self.expand_path(filename)
                identity = Identity.from_keyfile(filename, password)
                identity.acl = self.acls_for(filename)
                self.identities.add(identity)

        print(self.acls)

    def acls_for(self, filename):
        for pattern, acls in self.acls.items():
            if fnmatch(filename, pattern):
                return acls
        return self.acls['default']

    def expand_path(self, filename):
        if filename.startswith(os.sep):
            return os.path.abspath(filename)
        else:
            return os.path.join(
                os.path.dirname(self.filename),
                filename,
            )

    def get(self, key, default=None):
        tree = self.config
        while '.' in key:
            node, key = key.split('.', 1)
            if node in tree:
                tree = tree[node]
            else:
                return default
        return tree.get(tree, default)


if __name__ == '__main__':
    import sys
    config = Config(sys.argv[1])
