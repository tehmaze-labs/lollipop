lollipop
========

Python 3 ssh agent that allows ACL-based key access.


WARNING
-------

*Do not use this for production purposes, storing private encryption keys in
Python is NOT secure.*


Features
--------

- Supports multiple key types:
  - DSA fully supported
  - RSA fully supported
  - ECDSA partially supported

- ACL based agent access:
  - IPv4 and IPv6 supported

- Platform support:
  - Linux fully supported (depends on `AF_NETLINK` sockets and `/proc`)

- ssh-agent compatibility:
  - `SSH2_ADD_IDENTITY`
  - `SSH2_REQUEST_IDENTITIES`
  - `SSH2_REMOVE_IDENTITY`
  - `SSH2_REMOVE_ALL_IDENTITIES`
  - `SSH2_SIGN_REQUEST`


TODO
----

- Proxy request to other `ssh-agent` based on ACL
