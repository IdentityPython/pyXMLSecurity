import base64
import threading

__author__ = 'leifj'

from xmlsec.exceptions import XMLSigException
from urlparse import urlparse
import os
import logging
from xmlsec.utils import b642pem

_modules = {}

try:
    import PyKCS11
    from PyKCS11.LowLevel import CKA_ID, CKA_LABEL, CKA_CLASS, CKO_PRIVATE_KEY, CKO_CERTIFICATE, CKK_RSA, CKA_KEY_TYPE, CKA_VALUE
except ImportError:
    raise XMLSigException("pykcs11 is required for PKCS#11 keys - cf README.rst")

all_attributes = PyKCS11.CKA.keys()

# remove the CKR_ATTRIBUTE_SENSITIVE attributes since we can't get
all_attributes.remove(PyKCS11.LowLevel.CKA_PRIVATE_EXPONENT)
all_attributes.remove(PyKCS11.LowLevel.CKA_PRIME_1)
all_attributes.remove(PyKCS11.LowLevel.CKA_PRIME_2)
all_attributes.remove(PyKCS11.LowLevel.CKA_EXPONENT_1)
all_attributes.remove(PyKCS11.LowLevel.CKA_EXPONENT_2)
all_attributes.remove(PyKCS11.LowLevel.CKA_COEFFICIENT)
all_attributes = [e for e in all_attributes if isinstance(e, int)]


def parse_uri(pk11_uri):
    o = urlparse(pk11_uri)
    if o.scheme != 'pkcs11':
        raise XMLSigException("Bad URI scheme in pkcs11 URI %s" % pk11_uri)

    logging.debug("parsed pkcs11 uri: %s" % repr(o))

    slot = 0
    library = None
    keyname = None
    query = {}

    if not '/' in o.path:
        raise XMLSigException("Missing keyname part in pkcs11 URI (pkcs11://[library[:slot]/]keyname[?pin=<pin>])")

    (module_path, sep, keyqs) = o.path.rpartition('/')

    qs = o.query
    if qs:
        keyname = keyqs
    elif '?' in keyqs:
        (keyname, sep, qss) = keyqs.rpartition('?')
        qs = qss
    else:
        keyname = keyqs

    if qs:
        for av in qs.split('&'):
            if not '=' in av:
                raise XMLSigException("Bad query string in pkcs11 URI %s" % pk11_uri)
            (a, sep, v) = av.partition('=')
            assert a
            assert v
            query[a] = v

    if ':' in module_path:
        (library, sep, slot_str) = module_path.rpartition(":")
        slot = int(slot_str)
    else:
        library = module_path

    if library is None or len(library) == 0:
        library = os.environ.get('PYKCS11LIB', None)

    if library is None or len(library) == 0:
        raise XMLSigException("No PKCS11 module in pkcs11 URI %s" % pk11_uri)

    logging.debug("returning %s %s %s %s" % (library, slot, keyname, query))
    return library, slot, keyname, query


def _intarray2bytes(x):
    return ''.join(chr(i) for i in x)


def _close_session(session):
    _session_lock.acquire()
    session.logout()
    session.closeSession()
    _session_lock.release()


def _sign_and_close(session, key, data, mech):
    logging.debug("signing %d bytes using %s" % (len(data), mech))
    #import pdb; pdb.set_trace()
    sig = session.sign(key, data, mech)
    _close_session(session)

    return _intarray2bytes(sig)


def _find_object(session, template):
    for o in session.findObjects(template):
        try:
            logging.debug("Found pkcs11 object: %s" % o)
        except PyKCS11.PyKCS11Error as exc:
            # Fetching attributes might be restricted (CKR_ATTRIBUTE_SENSITIVE)
            logging.debug("Found pkcs11 object, but can't print it (%s)" % exc)
            pass
        return o
    return None


def _get_object_attributes(session, o):
    attributes = session.getAttributeValue(o, all_attributes)
    return dict(zip(all_attributes, attributes))


def _find_key(session, keyname):
    key = _find_object(session, [(CKA_LABEL, keyname), (CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_RSA)])
    if key is None:
        return None, None
    key_a = _get_object_attributes(session, key)
    cert = _find_object(session, [(CKA_ID, key_a[CKA_ID]), (CKA_CLASS, CKO_CERTIFICATE)])
    cert_pem = None
    if cert is not None:
        cert_a = _get_object_attributes(session, cert)
        cert_pem = b642pem(base64.standard_b64encode(_intarray2bytes(cert_a[CKA_VALUE])))
        logging.debug(cert)
    return key, cert_pem


_session_lock = threading.RLock()


def _session(library, slot, pin=None):
    _session_lock.acquire()
    if not library in _modules:
        logging.debug("loading library %s" % library)
        lib = PyKCS11.PyKCS11Lib()
        assert type(library) == str  # lib.load does not like unicode
        lib.load(library)
        # XXX should check result of C_Initialize()
        lib.lib.C_Initialize()
        _modules[library] = lib
    else:
        logging.debug("already loaded: %s: %s" % (library, _modules[library]))

    lib = _modules[library]
    session = lib.openSession(slot)
    if pin is not None:
        assert type(pin) == str  # session.login does not like unicode
        session.login(pin)
    else:
        logging.warning("No pin provided - not logging in")

    _session_lock.release()
    return session


def signer(pk11_uri, mech=PyKCS11.MechanismRSAPKCS1):
    library, slot, keyname, query = parse_uri(pk11_uri)

    pin = None
    pin_spec = query.get('pin', "env:PYKCS11PIN")
    if pin_spec.startswith("env:"):
        pin = os.environ.get(pin_spec[4:], None)
    else:
        pin = pin_spec

    session = _session(str(library), slot, str(pin))

    key, cert = _find_key(session, keyname)
    if key is None:
        raise XMLSigException("No such key: %s" % pk11_uri)

    if cert is not None:
        logging.info("Found matching cert in token")

    return lambda data: _sign_and_close(session, key, data, mech), cert
