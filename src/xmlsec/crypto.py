import io
import os
import base64
import logging
import threading
import six
from six.moves import xrange
from xmlsec import constants
from binascii import hexlify
from xmlsec.exceptions import XMLSigException
from xmlsec.utils import unicode_to_bytes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate, Certificate
from xmlsec.utils import sigvalue2dsssig, noop
import base64

log = logging.getLogger('xmlsec.crypto')

if six.PY2:
    from UserDict import DictMixin
else:
    from collections.abc import MutableMapping as DictMixin

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

    def mk_hasher(self, hash_alg):
        if 'sha3-' in hash_alg:
            raise XMLSigException("sha3 hashes not yet supported")

        hasher = getattr(hashes, hash_alg.upper())
        return hasher()

    _salts = {'sha224': 28, 'sha256': 32, 'sha384': 48, 'sha512': 64}

    def salt_length(self, hash_alg):
        if hash_alg not in self._salts:
            raise XMLSigException("sha3 hashes not yet supported")

        return self._salts[hash_alg]

    def parse_sig_scheme(self, sig_alg, parameters=None):
        if sig_alg == 'mgf1' or sig_alg == 'rsa-pss':
            if not parameters:
                hasher = hashes.SHA256()
                padder = padding.PSS(mgf=padding.MGF1(hasher), salt_length=self.salt_length('sha256'))
                return [padder, hasher], noop, noop
            else:
                raise XMLSigException("Parametrized RSA-PSS or RSA-PSS-MGF1 not yet supported")

        if sig_alg.endswith('rsa-mgf1'):
            sig_alg_lst = sig_alg.split('-')
            if len(sig_alg_lst) != 3:
                raise XMLSigException("Unable to determine MGF1 digest method f '{}'".format(sig_alg))

            hasher = self.mk_hasher(sig_alg_lst[0])
            padder = padding.PSS(mgf=padding.MGF1(hasher), salt_length=self.salt_length(sig_alg_lst[0]))
            return [padder, hasher], noop, noop

        if sig_alg.startswith('rsa-'):
            sig_alg_lst = sig_alg.split('-')
            if len(sig_alg_lst) != 2:
                raise XMLSigException("Unable to determine digest method from '{}'".format(sig_alg))
            hasher = self.mk_hasher(sig_alg_lst[1])
            padder = padding.PKCS1v15()
            return [padder, hasher], noop, noop

        if sig_alg.startswith('ecdsa-'):
            sig_alg_lst = sig_alg.split('-')
            if len(sig_alg_lst) != 2:
                raise XMLSigException("Unable to determine digest method from '{}'".format(sig_alg))
            hasher = self.mk_hasher(sig_alg_lst[1])
            return [ec.ECDSA(hasher)], lambda x: dsssig2sigvalue(x, 32), sigvalue2dsssig # 32 is right for P-256...

        raise XMLSigException("Unable to determine padder for '{}'".format(sig_alg))

    def sign(self, data, sig_uri, parameters=None):
        if self.is_private:
            if not isinstance(data, six.binary_type):
                data = unicode_to_bytes(data)
            sig_alg = constants.sign_alg_xmldsig_sig_to_sigalg(sig_uri)
            scheme, encoder, decoder = self.parse_sig_scheme(sig_alg,parameters=parameters)
            return self.key.sign(data, *scheme)
        else:
            raise XMLSigException('Signing is only possible with a private key.')

    def verify(self, signature, msg, sig_uri, parameters=None):
        if not self.is_private:
            if not isinstance(msg, six.binary_type):
                msg = unicode_to_bytes(msg)
            try:
                sig_alg = constants.sign_alg_xmldsig_sig_to_sigalg(sig_uri)
                scheme, encoder, decoder = self.parse_sig_scheme(sig_alg, parameters=parameters)
                self.key.public_key().verify(decoder(signature), msg, *scheme)
            except InvalidSignature:
                return False
            return True
        else:
            raise XMLSigException('Verifying is only possible with a certificate.')


class XMLSecCryptoCallable(XMlSecCrypto):
    def __init__(self, private):
        super(XMLSecCryptoCallable, self).__init__(source='callable', do_padding=True, private=private)
        self._private_callable = private

    def sign(self, data, sig_uri=None, parameters=None):
        return self._private_callable(data)

    def verify(self, data, actual, sig_uri=None, parameters=None):
        raise XMLSigException('Trying to verify with a private key (from a callable)')


class XMLSecCryptoFile(XMlSecCrypto):
    def __init__(self, filename, private):
        super(XMLSecCryptoFile, self).__init__(source='file', do_padding=False, private=private, do_digest=False)
        with io.open(filename, "rb") as file:
            if private:
                self.key = serialization.load_pem_private_key(file.read(), password=None, backend=default_backend())

                # XXX Do not leak private key -- is there any situation
                # where we might need this pem?
                self.cert_pem = None
                # self.cert_pem = self.key.private_bytes(
                #     encoding=serialization.Encoding.PEM,
                #     format=serialization.PrivateFormat.PKCS8,
                #     encryption_algorithm=serialization.NoEncryption())

                self.keysize = self.key.key_size
            else:
                self.key = load_pem_x509_certificate(file.read(), backend=default_backend())
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
            self.cert_pem = self.key.public_bytes(encoding=serialization.Encoding.PEM)
            self.keysize = self.key.public_key().key_size

        self._from_keyspec = keyspec  # for debugging

    def sign(self, data, sig_uri=None, parameters=None):
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
            data = cd
            source = 'signature_element'
        elif '-----BEGIN' in keyspec:
            data = keyspec
            source = 'keyspec'

        if data is None:
            raise ValueError("Unable to find cert matching fingerprint: %s" % fp)

        super(XMLSecCryptoFromXML, self).__init__(source=source, do_padding=False, private=False, do_digest=False)

        self.key = load_pem_x509_certificate(data, backend=default_backend())

        # XXX now we could implement encrypted-PEM-support
        self.cert_pem = self.key.public_bytes(encoding=serialization.Encoding.PEM)

        self.keysize = self.key.public_key().key_size
        self._from_keyspec = keyspec  # for debugging


class XMLSecCryptoREST(XMlSecCrypto):
    def __init__(self, keyspec):
        super(XMLSecCryptoREST, self).__init__(source="rest", do_padding=False, private=True)
        self._keyspec = keyspec

    def sign(self, data, sig_uri=None, parameters=None):
        try:
            import requests
            import json
            url = '{!s}/rawsign'.format(self._keyspec)
            if not isinstance(data, six.binary_type):
                data = data.encode("utf-8")
            data = base64.b64encode(data)
            r = requests.post(url, json=dict(mech='RSAPKCS1', data=data))
            if r.status_code != requests.codes.ok:
                r.raise_for_status()
            msg = r.json()
            if 'signed' not in msg:
                raise ValueError("Missing signed data in response message")
            signed_msg = msg['signed']
            if not isinstance(signed_msg, six.binary_type):
                signed_msg = signed_msg.encode("utf-8")
            return base64.b64decode(signed_msg)
        except Exception as ex:
            from traceback import format_exc
            log.debug(format_exc())
            raise XMLSigException(ex)


def _load_keyspec(keyspec, private=False, signature_element=None):
    if private and hasattr(keyspec, '__call__'):
        return XMLSecCryptoCallable(keyspec)
    if isinstance(keyspec, six.string_types):
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
    to access the certificates as pem strings.
    """

    def __init__(self, t):
        """
        :param t: XML as lxml.etree
        """
        self.certs = {}
        for cd in t.findall(".//{%s}X509Certificate" % NS['ds']):
            fingerprint, cert = _cert_fingerprint(cd.text)
            self.certs[fingerprint] = cert

    def __getitem__(self, item):
        return self.certs[item].public_bytes(encoding=serialization.Encoding.PEM)

    def keys(self):
        return self.certs.keys()

    def __setitem__(self, key, value):
        if isinstance(value, Certificate):
            self.certs[key] = value
        else:
            self.certs[key] = load_pem_x509_certificate(value, backend=default_backend())

    def __delitem__(self, key):
        del self.certs[key]

    def __len__(self):
        return len(self.certs)

    def __iter__(self):
        for item in self.certs:
            yield item

    def _get_cert_by_fp(self, fp):
        """
        Get the cryptography.x509.Certificate representation.

        :param fp: A fingerprint in the format "aa:bb:cc:..."
        :returns: a cryptography.x509.Certificate or None
        """
        try:
            c = self.certs[fp]
        except KeyError:
            return None
        
        return c


def _cert_fingerprint(cert_pem):
    if "-----BEGIN CERTIFICATE" in cert_pem:
        cert = load_pem_x509_certificate(cert_pem, backend=default_backend())
    else:
        cert = load_der_x509_certificate(base64.standard_b64decode(cert_pem), backend=default_backend())

    fingerprint = hexlify(cert.fingerprint(hashes.SHA1())).lower().decode('ascii')
    fingerprint = ":".join([fingerprint[x:x + 2] for x in xrange(0, len(fingerprint), 2)])
    
    return fingerprint, cert


def _find_cert_by_fingerprint(t, fp):
    """
    Find certificate using fingerprint.

    :param t: XML as lxml.etree or None
    :param fp: fingerprint as string
    :returns: PEM formatted certificate as string or None
    """
    if t is None:
        return None

    d = CertDict(t)
    cert = d._get_cert_by_fp(fp.strip().lower())
    
    if cert is None:
        return None

    return cert.public_bytes(encoding=serialization.Encoding.PEM)


def _digest(data, hash_alg):
    """
    Calculate a hash digest of algorithm hash_alg and return the result base64 encoded.

    :param hash_alg: String with algorithm, such as 'SHA256' (as named by pyca/cryptography)
    :param data: The data to digest
    :returns: Base64 string
    """
    h = getattr(hashes, hash_alg)
    d = hashes.Hash(h(), backend=default_backend())
    if not isinstance(data, six.binary_type):
        data = unicode_to_bytes(data)
    d.update(data)
    return base64.b64encode(d.finalize())
