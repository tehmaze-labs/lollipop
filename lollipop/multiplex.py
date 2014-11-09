import logging
import select
import socket


logger = logging.getLogger(__name__)


class BaseMultiplexer:
    def __init__(self):
        self.remotes = {}

    def loop(self, timeout=0.1):
        raise NotImplementedError()

    def register(self, remote):
        logger.info('registering remote {!r}'.format(remote))
        fileno = remote.fileno()
        self.remotes[fileno] = remote
        return fileno

    def unregister(self, remote, close=False):
        logger.info('unregistering remote {!r}'.format(remote))
        fileno = remote.fileno()
        del self.remotes[fileno]


class EpollMultiplexer(BaseMultiplexer):
    def __init__(self):
        super(EpollMultiplexer, self).__init__()
        self.poll = None

        # We initialise these here, because on platforms that don't implement
        # `select.epoll()`, these flags may not be available.
        self.RO = (
            select.EPOLLIN  |
            select.EPOLLPRI |
            select.EPOLLHUP |
            select.EPOLLERR
        )
        self.RW = self.RO | select.EPOLLOUT

    def loop(self, timeout=0.1):
        logger.info('starting epoll multiplexer loop')

        # Register polling object
        self.poll = select.epoll()

        # Register file descriptors
        for fileno in self.remotes:
            self.poll.register(fileno, self.RO)

        while self.remotes:
            # Push poll pre events
            for remote in self.remotes.values():
                remote.handle_poll_pre()

            events = self.poll.poll(timeout)
            for fileno, event in events:
                remote = self.remotes[fileno]

                if event & (select.EPOLLIN | select.EPOLLPRI):
                    logger.info('{!r} became readable'.format(remote))

                    if remote.server:
                        client = remote.handle_accept()
                        self.register(client)

                    else:
                        try:
                            remote.handle_read()
                            self.poll.modify(fileno, self.RW)
                        except socket.error as error:
                            self.unregister(remote, close=True)

                elif event & select.EPOLLOUT:
                    logger.debug('{!r} became writable'.format(remote))
                    self.remotes[fileno].handle_send()
                    self.poll.modify(fileno, self.RO)

                elif event & select.EPOLLHUP:
                    logger.info('{!r} hang up'.format(remote))
                    self.remotes[fileno].handle_close()
                    self.unregister(remote, close=True)

                elif event & select.EPOLLERR:
                    logger.info('{!r} raised error'.format(remote))
                    self.remotes[fileno].handle_error()
                    self.unregister(remote, close=True)

            # Push poll post events
            for remote in self.remotes.values():
                remote.handle_poll_post()

        # Unregister polling object
        self.poll.close()
        self.poll = None

    def register(self, remote):
        fileno = super(EpollMultiplexer, self).register(remote)
        remote.setblocking(0)
        if self.poll:
            self.poll.register(fileno, select.EPOLLIN)

    def unregister(self, remote, close=False):
        fileno = super(EpollMultiplexer, self).unregister(remote)
        if self.poll:
            self.poll.unregister(fileno)

        if close:
            try:
                remote.close()
            except socket.error:
                pass


class SelectMultiplexer(BaseMultiplexer):
    def loop(self, timeout=0.1):
        logger.info('starting select multiplexer loop')

        while self.remotes:
            filenos = self.remotes.keys()
            filenos_w = [
                fileno
                for fileno, remote in self.remotes.items()
                if remote.send_buffer
            ]
            r, w, x = select.select(filenos, filenos_w, filenos, timeout)

            for fileno in x:
                remote = self.remotes[fileno]
                logger.info('{!r} raised error'.format(remote))
                self.remotes[fileno].handle_error()
                self.unregister(remote, close=True)

                if fileno in r:
                    r.remove(fileno)
                if fileno in w:
                    w.remove(fileno)

            for fileno in r:
                remote = self.remotes[fileno]
                logger.info('{!r} became readable'.format(remote))

                if remote.server:
                    client = remote.handle_accept()
                    self.register(client)

                else:
                    try:
                        remote.handle_read()
                    except socket.error as error:
                        self.unregister(remote, close=True)
                        if fileno in w:
                            w.remove(fileno)

            for fileno in w:
                remote = self.remotes[fileno]
                logger.debug('{!r} became writable'.format(remote))
                self.remotes[fileno].handle_send()

    def register(self, remote):
        super(SelectMultiplexer, self).register(remote)
        remote.setblocking(1)


def multiplexer():
    if hasattr(select, 'epollx'):
        return EpollMultiplexer()

    elif hasattr(select, 'select'):
        return SelectMultiplexer()

    else:
        raise SystemError('No suitable poller found for your operating system')
