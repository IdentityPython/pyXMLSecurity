import io
import os
import threading
from threading import current_thread
from . import rsa_x509_pem


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
      - a fingerprint. If signature_element is provided, the key is located using
                       the fingerprint (provided as string).
      - X.509 string.  An X.509 certificate as string.

    Resulting dictionary (used except for 'callable') :

      {'keyspec': keyspec,
       'source': 'pkcs11' or 'file' or 'fingerprint' or 'keyspec',
       'data': X.509 certificate as string if source != 'pkcs11',
       'key': Parsed key from certificate if source != 'pkcs11',
       'keysize': Keysize in bits if source != 'pkcs11',
       'f_public': rsa_x509_pem.f_public(key) if private == False,
       'f_private': rsa_x509_pem.f_private(key) if private == True,
      }

    :param keyspec: Keyspec as string or callable. See above.
    :param private: True of False, is keyspec a private key or not?
    :param signature_element:
    :returns: dict, see above.
    """
    threadLocal = threading.local()
    cache = getattr(threadLocal, 'keycache', {})
    if keyspec in cache:
        return cache[keyspec]
    key = _load_keyspec(keyspec, private, signature_element)
    cache[keyspec] = key
    threadLocal.cache = cache
    return key


def _load_keyspec(keyspec, private=False, signature_element=None):
    data = None
    source = None
    key_f_private = None
    if private and hasattr(keyspec, '__call__'):
        return {'keyspec': keyspec,
                'source': 'callable',
                'f_private': keyspec}
    if isinstance(keyspec, basestring):
        if os.path.isfile(keyspec):
            with io.open(keyspec) as c:
                data = c.read()
            source = 'file'
        elif private and keyspec.startswith("pkcs11://"):
            from xmlsec import pk11

            key_f_private, data = pk11.signer(keyspec)
            logging.debug("Using pkcs11 signing key: %s" % key_f_private)
            cert_pem = rsa_x509_pem.parse(data)
            return {'keyspec': keyspec,
                    'source': 'pkcs11',
                    'data': cert_pem['pem'],
                    'f_private': key_f_private}
        elif signature_element is not None:
            cd = _find_matching_cert(signature_element, keyspec)
            if cd is not None:
                data = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % cd
                source = 'signature_element'
        elif '-----BEGIN' in keyspec:
            data = keyspec
            source = 'keyspec'

    #print "Certificate data (source '%s') :\n%s" % (source, data)

    if data is None:
        return None
        #raise XMLSigException("Unable to find a useful key from keyspec '%s'" % (keyspec))

    cert_pem = rsa_x509_pem.parse(data)
    key = rsa_x509_pem.get_key(cert_pem)

    res = {'keyspec': keyspec,
           'source': source,
           'key': key,
           'keysize': int(key.size()) + 1}

    if private:
        res['f_private'] = key_f_private or rsa_x509_pem.f_sign(key)
        res['data'] = data  # TODO - normalize private keyspec too!
    else:
        res['data'] = cert_pem['pem']  # normalized PEM
        res['f_public'] = rsa_x509_pem.f_public(key)

    return res
