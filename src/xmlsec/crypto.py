import io
import os
import base64
import hashlib
import logging
import threading
from UserDict import DictMixin
from . import rsa_x509_pem
from xmlsec.exceptions import XMLSigException


def from_keyspec(keyspec, private=False, signature_element=None):
    """
    Load a key referenced by a keyspec (see below).

    To 'load' a key means different things based on what can be loaded through a
    given specification. For example, if keyspec is a a PKCS#11 reference to a
    private key then naturally the key itself is not available.

    Possible keyspecs, in evaluation order :

      - XMLSECCrypto   If keyspec is already a loaded key, just return it.
      - a callable.    Return a partial dict with 'f_private' set to the keyspec.
      - a filename.    Load a PEM X.509 certificate from the file.
      - a PKCS#11-URI  (see xmlsec.pk11.parse_uri()). Return a dict with 'f_private'
                       set to a function calling the 'sign' function for the key,
                       and the rest based on the (public) key returned by
                       xmlsec.pk11.signer().
      - a fingerprint. If signature_element is provided, the key is located using
                       the fingerprint (provided as string).
      - X.509 string.  An X.509 certificate as string.

    :param keyspec: Keyspec as string or callable. See above.
    :param private: True of False, is keyspec a private key or not?
    :param signature_element:
    :returns: Loaded keyspec

    :rtype: XMlSecCrypto
    """
    thread_local = threading.local()
    cache = getattr(thread_local, 'keycache', {})
    if keyspec in cache:
        return cache[keyspec]
    key = _load_keyspec(keyspec, private, signature_element)

    if key is None:
        raise XMLSigException('Unable to load private key from {!s}'.format(keyspec))

    cache[keyspec] = key
    thread_local.cache = cache
    return key


class XMlSecCrypto(object):

    def __init__(self, source, do_padding, private):
        # Public attributes
        self.source = source
        self.keysize = None
        self.cert_pem = None
        self.key = None
        self.is_private = private
        self.do_padding = do_padding

    def sign(self, data):
        # This used to be f_private()
        return rsa_x509_pem.f_sign(self.key)(data)

    def verify(self, data, actual):
        # This used to be f_public()
        expected = rsa_x509_pem.f_public(self.key)(data)
        # XXX does constant time comparision of RSA signatures matter?
        return actual == expected


class XMLSecCryptoCallable(XMlSecCrypto):

    def __init__(self, private):
        super(XMLSecCryptoCallable, self).__init__(source = 'callable', do_padding = True, private = private)
        self._private_callable = private

    def sign(self, data):
        return self._private_callable(data)

    def verify(self, data, actual):
        raise XMLSigException('Trying to verify with a private key (from a callable)')


class XMLSecCryptoFile(XMlSecCrypto):

    def __init__(self, filename, private):
        super(XMLSecCryptoFile, self).__init__(source = 'file', do_padding = True, private = private)
        with io.open(filename) as c:
            data = c.read()

        cert = rsa_x509_pem.parse(data)
        self.cert_pem = cert.get('pem')
        self.key = rsa_x509_pem.get_key(cert)
        self.keysize = int(self.key.size()) + 1

        self._from_file = filename  # for debugging


class XMLSecCryptoP11(XMlSecCrypto):

    def __init__(self, keyspec):
        super(XMLSecCryptoP11, self).__init__(source = 'pkcs11', do_padding = False, private = True)

        from xmlsec import pk11

        self._private_callable, data = pk11.signer(keyspec)
        logging.debug("Using pkcs11 signing key: {!s}".format(self._private_callable))
        cert = rsa_x509_pem.parse(data)
        self.cert_pem = cert.get('pem')

        self._from_keyspec = keyspec  # for debugging

    def sign(self, data):
        return self._private_callable(data)


class XMLSecCryptoFromXML(XMlSecCrypto):

    def __init__(self, signature_element, keyspec):
        cd = _find_matching_cert(signature_element, keyspec)
        if cd is not None:
            data = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % cd
            source = 'signature_element'
        elif '-----BEGIN' in keyspec:
            data = keyspec
            source = 'keyspec'

        super(XMLSecCryptoFromXML, self).__init__(source = source, do_padding = False, private = True)

        cert = rsa_x509_pem.parse(data)
        self.cert_pem = cert.get('pem')

        self._from_keyspec = keyspec  # for debugging


def _load_keyspec(keyspec, private=False, signature_element=None):
    if isinstance(keyspec, XMlSecCrypto):
        return keyspec
    if private and hasattr(keyspec, '__call__'):
        return XMLSecCryptoCallable(keyspec)
    if isinstance(keyspec, basestring):
        if os.path.isfile(keyspec):
            return XMLSecCryptoFile(keyspec, private)
        elif private and keyspec.startswith("pkcs11://"):
            return XMLSecCryptoP11(keyspec)
        elif signature_element is not None:
            return XMLSecCryptoFromXML(signature_element, keyspec)

    #raise XMLSigException("Unable to find a useful key from keyspec '%s'" % (keyspec))
    return None



class CertDict(DictMixin):
    """
    Extract all X509Certificate XML elements and create a dict-like object
    to access the certificates.
    """

    def __init__(self, t):
        """
        :param t: XML as lxml.etree
        """
        self.certs = {}
        for cd in t.findall(".//{%s}X509Certificate" % NS['ds']):
            cert_pem = cd.text
            cert_der = base64.b64decode(cert_pem)
            m = hashlib.sha1()
            m.update(cert_der)
            fingerprint = m.hexdigest().lower()
            fingerprint = ":".join([fingerprint[x:x + 2] for x in xrange(0, len(fingerprint), 2)])
            self.certs[fingerprint] = cert_pem

    def __getitem__(self, item):
        return self.certs[item]

    def keys(self):
        return self.certs.keys()

    def __setitem__(self, key, value):
        self.certs[key] = value

    def __delitem__(self, key):
        del self.certs[key]


def _find_matching_cert(t, fp):
    """
    Find certificate using fingerprint.

    :param t: XML as lxml.etree or None
    :param fp: fingerprint as string
    :returns: PEM formatted certificate as string or None
    """
    if t is None:
        return None
    for cfp, pem in CertDict(t).iteritems():
        if fp.lower() == cfp:
            return pem
    return None
