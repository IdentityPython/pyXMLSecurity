
__author__ = 'leifj'

from exceptions import XMLSigException
from urlparse import urlparse
import os

_modules = {}

try:
    import PyKCS11
    from PyKCS11.LowLevel import CKA_ID, CKA_LABEL
except ImportError:
    raise XMLSigException("pykcs11 is required for PKCS#11 keys - cf README.rst")

def parse_uri(pk11_uri):
    o = urlparse(pk11_uri)
    if o.scheme != 'pkcs11':
        raise XMLSigException("Bad URI scheme in pkcs11 URI %s" % pk11_uri)

    slot = 0
    library = None
    keyname = None
    query = {}

    if not '/' in o.path:
        raise XMLSigException("Missing keyname part in pkcs11 URI (pkcs11://[library[:slot]/]keyname[?pin=<pin>])")

    (module_path,sep,keyqs) = o.path.rpartition('/')

    if '?' in keyqs:
        (keyname,sep,qs) = keyqs.rpartition('?')
        for av in qs.split('&'):
            if not '=' in av:
                raise XMLSigException("Bad query string in pkcs11 URI %s" % pk11_uri)
            (a,sep,v) = av.partition('=')
            assert(a)
            assert(v)
            query[a] = v
    else:
        keyname = keyqs

    if ':' in module_path:
        (library,sep,slot_str) = o.netloc.rpartition()
        slot = int(slot_str)
    else:
        library = module_path

    if library is None or len(library) == 0:
        library = os.environ.get('PYKCS11LIB',None)

    if library is None or len(library) == 0:
        raise XMLSigException("No PKCS11 module in pkcs11 URI %s" % pk11_uri)

    return library,slot,keyname,query

def _sign_and_close(session,key,data,mech):
    sig = session.sign(key,data,mech)
    session.logout()
    session.closeSession()

    return sig

def _find_key(session,keyname):
    for o in session.findObjects((CKA_ID,keyname)):
        return o
    for o in session.findObjects((CKA_LABEL,keyname)):
        return o

    return None

def signer(pk11_uri,mech=PyKCS11.MechanismRSAPKCS1):
    library,slot,keyname,query = parse_uri(pk11_uri)

    if not _modules.has_key(library):
        lib = PyKCS11.PyKCS11Lib()
        lib.load(library)
        _modules[library] = lib

    lib = _modules[library]
    session = lib.openSession(slot)

    pin = None
    pin_spec = query.get('pin',"env:PYKCS11PIN")
    if pin_spec.startswith("env:"):
        pin = os.environ.get(pin_spec[4:],None)
    else:
        pin = pin_spec

    if pin is not None:
        session.login(pin)

    key = _find_key(session,keyname)
    if key is None:
        raise XMLSigException("No such key: %s" % pk11_uri)

    return lambda data: _sign_and_close(session,key,data,mech)
