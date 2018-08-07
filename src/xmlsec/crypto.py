import pdb
import io
import os
import base64
import hashlib
import logging
import threading
from UserDict import DictMixin
from xmlsec.exceptions import XMLSigException
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import rsa,padding,utils
from cryptography.x509 import load_pem_x509_certificate


NS = {'ds': 'http://www.w3.org/2000/09/xmldsig#'}


def from_keyspec(keyspec, private=False, signature_element=None):
    """
    Load a key referenced by a keyspec (see below).

    To 'load' a key means different things based on what can be loaded through a
    given specification. For example, if keyspec is a a PKCS#11 reference to a
    private key then naturally the key itself is not available.

    Possible keyspecs, in evaluation order :

      - a callable.    Return a partial dict with 'f_private' set to the keyspec.
      - a filename.    Load a PEM X.509 certificate from the file.
      - a PKCS#11-URI  (see xmlsec.pk11.parse_uri()). Return a dict with 'f_private'
                       set to a function calling the 'sign' function for the key,
                       and the rest based on the (public) key returned by
                       xmlsec.pk11.signer().
      - an http:// URL REST URL used for signing (see pyeleven).
      - a fingerprint. If signature_element is provided, the key is located using
                       the fingerprint (provided as string).
      - X.509 string.  An X.509 certificate as string.

    If the keyspec is prefixed by 'xmlsec+', that prefix will be removed.
    This is a workaround for pysaml2 that handles keyspecs starting with
    'http' differently.

    Resulting dictionary (used except for 'callable') :

      {'keyspec': keyspec,
       'source': 'pkcs11' or 'file' or 'fingerprint' or 'keyspec',
       'cert_pem': key as string if source != 'pkcs11',
       'key': pyca.cryptography key instance if source != 'pkcs11',
       'keysize': Keysize in bits if source != 'pkcs11',
       'private': True if private key, False if public key/certificate,
      }

    :param keyspec: Keyspec as string or callable. See above.
    :param private: True of False, is keyspec a private key or not?
    :param signature_element:
    :returns: dict, see above.
    """
    if keyspec.startswith('xmlsec+'):
        # workaround for pysaml2 which handles http keyspecs differently
        keyspec = keyspec[7:]
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
    def __init__(self, source, do_padding, private, do_digest=True):
        # Public attributes
        self.source = source
        self.keysize = None
        self.cert_pem = None
        self.key = None
        self.is_private = private
        self.do_padding = do_padding
        self.do_digest = do_digest

    def sign(self, data, hash_alg=None):
        if hash_alg is None:
            hash_alg = "sha1"
        if self.is_private:
            chosen_hash = getattr(hashes, hash_alg.upper())()
            return self.key.sign(data,
                                padding.PKCS1v15(),
                                chosen_hash
                                )
        else:
            raise XMLSigException('Signing is only possible with a private key.')

    def verify(self, signature, msg, hash_alg=None):
        if hash_alg is None:
            hash_alg = "sha1"
        if not self.is_private:
            try:
                chosen_hash = getattr(hashes, hash_alg.upper())()
                self.key.public_key().verify(
                    signature,
                    msg,
                    padding.PKCS1v15(),
                    chosen_hash
                )
            except InvalidSignature:
                return False
            return True
        else:
            raise XMLSigException('Verifying is only possible with a certificate.')


class XMLSecCryptoCallable(XMlSecCrypto):
    def __init__(self, private):
        super(XMLSecCryptoCallable, self).__init__(source='callable', do_padding=True, private=private)
        self._private_callable = private

    def sign(self, data, hash_alg=None):
        return self._private_callable(data)

    def verify(self, data, actual, hash_alg=None):
        raise XMLSigException('Trying to verify with a private key (from a callable)')


class XMLSecCryptoFile(XMlSecCrypto):
    def __init__(self, filename, private):
        super(XMLSecCryptoFile, self).__init__(source='file', do_padding=False, private=private, do_digest=False)
        with io.open(filename,"rb") as file:
            if private:
                self.key = serialization.load_pem_private_key(file.read(),password=None, backend=default_backend())
                if not isinstance(self.key, rsa.RSAPrivateKey):
                    raise XMLSigException("We don't support non-RSA keys at the moment.")

                # XXX now we could implement encrypted-PEM-support
                self.cert_pem = self.key.private_bytes(
                                                   encoding=serialization.Encoding.PEM,
                                                   format=serialization.PrivateFormat.PKCS8,
                                                   encryption_algorithm=serialization.NoEncryption())

                self.keysize = self.key.key_size
            else:
                self.key = load_pem_x509_certificate(file.read(), backend=default_backend())
                if not isinstance(self.key.public_key(), rsa.RSAPublicKey):
                    raise XMLSigException("We don't support non-RSA keys at the moment.")

                self.cert_pem = self.key.public_bytes(encoding=serialization.Encoding.PEM)
                self.keysize = self.key.public_key().key_size
        
        self._from_file = filename  # for debugging


class XMLSecCryptoP11(XMlSecCrypto):
    def __init__(self, keyspec):
        super(XMLSecCryptoP11, self).__init__(source='pkcs11', do_padding=False, private=True)

        from xmlsec import pk11

        self._private_callable, data = pk11.signer(keyspec)
        logging.debug("Using pkcs11 signing key: {!s}".format(self._private_callable))
        if data is not None:
            self.key = load_pem_x509_certificate(data, backend=default_backend())
            if not isinstance(self.key.public_key(), rsa.RSAPublicKey):
                raise XMLSigException("We don't support non-RSA keys at the moment.")

            self.cert_pem = self.key.public_bytes(encoding=serialization.Encoding.PEM)
            self.keysize = self.key.public_key().key_size

        self._from_keyspec = keyspec  # for debugging

    def sign(self, data, hash_alg=None):
        return self._private_callable(data)


class XMLSecCryptoFromXML(XMlSecCrypto):
    def __init__(self, signature_element, keyspec):
        source = None
        data = None
        #print "XMLSecCryptoFromXML using %s and keyspec=%s" % (signature_element, keyspec)
        fp = keyspec
        if ':' not in keyspec:
            fp,_ = _cert_fingerprint(keyspec)
        cd = _find_cert_by_fingerprint(signature_element, fp)
        if cd is not None:
            data = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % cd
            source = 'signature_element'
        elif '-----BEGIN' in keyspec:
            data = keyspec
            source = 'keyspec'

        if data is None:
            raise ValueError("Unable to find cert matching fingerprint: %s" % fp)

        super(XMLSecCryptoFromXML, self).__init__(source=source, do_padding=False, private=False, do_digest=False)

        self.key = load_pem_x509_certificate(data, backend=default_backend())
        if not isinstance(self.key.public_key(), rsa.RSAPublicKey):
            raise XMLSigException("We don't support non-RSA keys at the moment.")

        # XXX now we could implement encrypted-PEM-support
        self.cert_pem = self.key.public_bytes(encoding=serialization.Encoding.PEM)

        self.keysize = self.key.public_key().key_size
        self._from_keyspec = keyspec  # for debugging


class XMLSecCryptoREST(XMlSecCrypto):
    def __init__(self, keyspec):
        super(XMLSecCryptoREST, self).__init__(source="rest", do_padding=False, private=True)
        self._keyspec = keyspec

    def sign(self, data, hash_alg=None):
        try:
            import requests
            import json
            url = '{!s}/rawsign'.format(self._keyspec)
            r = requests.post(url, json=dict(mech='RSAPKCS1', data=data.encode("base64")))
            if r.status_code != requests.codes.ok:
                r.raise_for_status()
            msg = r.json()
            if not 'signed' in msg:
                raise ValueError("Missing signed data in response message")
            return msg['signed'].decode('base64')
        except Exception, ex:
            from traceback import print_exc
            print_exc(ex)
            raise XMLSigException(ex)


def _load_keyspec(keyspec, private=False, signature_element=None):
    if private and hasattr(keyspec, '__call__'):
        return XMLSecCryptoCallable(keyspec)
    if isinstance(keyspec, basestring):
        if os.path.isfile(keyspec):
            return XMLSecCryptoFile(keyspec, private)
        elif private and keyspec.startswith("pkcs11://"):
            return XMLSecCryptoP11(keyspec)
        elif private and keyspec.startswith("http://"):
            return XMLSecCryptoREST(keyspec)
        elif signature_element is not None:
            return XMLSecCryptoFromXML(signature_element, keyspec)

    # raise XMLSigException("Unable to find a useful key from keyspec '%s'" % (keyspec))
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
            fingerprint, cert_pem = _cert_fingerprint(cd.text)
            self.certs[fingerprint] = cert_pem

    def __getitem__(self, item):
        return self.certs[item]

    def keys(self):
        return self.certs.keys()

    def __setitem__(self, key, value):
        self.certs[key] = value

    def __delitem__(self, key):
        del self.certs[key]

def _cert_fingerprint(cert_pem):
    # XXX might use cryptography internals instead of parsing it on our own
    if "-----BEGIN CERTIFICATE" in cert_pem:
        cert_pem = pem2b64(cert_pem)
    cert_der = base64.b64decode(cert_pem)
    m = hashlib.sha1()
    m.update(cert_der)
    fingerprint = m.hexdigest().lower()
    fingerprint = ":".join([fingerprint[x:x + 2] for x in xrange(0, len(fingerprint), 2)])
    return fingerprint, cert_pem


def _find_cert_by_fingerprint(t, fp):
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
