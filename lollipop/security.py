from ctypes import (
    Structure,
    c_int,
    c_long,
    c_longlong,
    c_ssize_t,
    py_object,
    sizeof,
)
import ctypes
import gc as core_gc
import logging
import sys
from .operatingsystem import operatingsystem


logger = logging.getLogger(__name__)
gc_checked = False

def gc(generations=2):
    core_gc.collect(generations)

def ensure_gc():
    global gc_checked
    if not core_gc.isenabled():
        logger.info('enabling garbage collector')
        core_gc.enable()
    elif not gc_checked:
        logger.info('garbage collecting was enabled')
        core_gc_checked = True

    core_gc.set_debug(
        core_gc.DEBUG_STATS |
        core_gc.DEBUG_UNCOLLECTABLE |
        core_gc.DEBUG_SAVEALL
    )

if hasattr(ctypes.pythonapi, 'Py_InitModule4'):
    Py_ssize_t = ctypes.c_int
elif hasattr(ctypes.pythonapi, 'Py_InitModule4_64'):
    Py_ssize_t = ctypes.c_int64
else:
    #raise TypeError("Cannot determine type of Py_ssize_t")
    Py_ssize_t = ctypes.c_int64


class PyIntObject(Structure):
    _fields_ = [
        ('ob_refcnt', c_ssize_t),
        ('ob_type',   py_object),
        ('ob_digit',  Py_ssize_t),
    ]


class PyStringObject(Structure):
    _fields_ = [
        ('ob_refcnt', c_ssize_t),
        ('ob_type',   py_object),
        ('ob_size',   c_ssize_t),
        ('ob_shash',  c_long),
        ('ob_sstate', c_int),
    ]


def bzero_int(obj):
    if not isinstance(obj, int):
        raise TypeError('Expected "int" got "{}"'.format(type(obj).__name__))

    int_obj = PyIntObject.from_address(id(obj))
    offset = sizeof(PyIntObject)
    bufsiz = sizeof(Py_ssize_t)
    logger.info('memset(0x{:x}, 0, {})'.format(id(obj) + offset, bufsiz))
    operatingsystem.memset(id(obj) + offset, 0, bufsiz)
    return True

def bzero_str(obj):
    if not isinstance(obj, str):
        raise TypeError('Expected "str" got "{}"'.format(type(obj).__name__))

    str_obj = PyStringObject.from_address(id(obj))
    if s_obj.ob_sstate > 0:
        logger.warn('Can\'t zero internal string')
        return False

    s_obj.ob_shash = -1  # not hashed yet
    offset = sizeof(PyStringObject)
    logger.info('memset(0x{:x}, 0, {})'.format(id(obj) + offset, len(obj)))
    operatingsystem.memset(id(obj) + offset, 0, len(obj))
    return True


def bzero(obj):
    logger.info('bzero(0x{:x}) ({})'.format(
        id(obj),
        type(obj).__name__,
    ))

    if obj is None:
        return False
    else:
        return True

    if isinstance(obj, int):
        return bzero_int(obj)

    elif isinstance(obj, str):
        return bzero_str(obj)

    else:
        logger.warn('bzero on "{}" not supported'.format(type(obj)))
