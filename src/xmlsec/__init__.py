from UserDict import DictMixin

__author__ = 'leifj'

import os
import xmlsec.rsa_x509_pem as rsa_x509_pem
import lxml.etree as etree
import logging
import base64
import hashlib
import copy
import xmlsec.int_to_bytes as itb
from lxml.builder import ElementMaker
from xmlsec.exceptions import XMLSigException
import re
import htmlentitydefs

NS = {'ds': 'http://www.w3.org/2000/09/xmldsig#'}
DS = ElementMaker(namespace=NS['ds'], nsmap=NS)

# Enable this to get various parts written to files in /tmp. Not for production!
_DEBUG_WRITE_TO_FILES = False

# ASN.1 BER SHA1 algorithm designator prefixes (RFC3447)
ASN1_BER_ALG_DESIGNATOR_PREFIX = {
    # disabled 'md2': '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02\x05\x00\x04\x10',
    # disabled 'md5': '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
    'sha1': '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
    'sha256': '\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
    'sha384': '\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
    'sha512': '\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}

TRANSFORM_ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
TRANSFORM_C14N_EXCLUSIVE_WITH_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'
TRANSFORM_C14N_EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n'
TRANSFORM_C14N_INCLUSIVE = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'

ALGORITHM_DIGEST_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
ALGORITHM_SIGNATURE_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"

# This code was inspired by https://github.com/andrewdyates/xmldsig
# and includes https://github.com/andrewdyates/rsa_x509_pem with
# permission from the author.


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


def _load_keyspec(keyspec, private=False, signature_element=None):
    """
    Load a key referenced by a keyspec (see below).

    To 'load' a key means different things based on what can be loaded through a
    given specification. For example, if keyspec is a a PKCS#11 reference to a
    private key then naturally the key itself is not available.

    :param private:
    :param signature_element:
    Possible keyspecs, in evaluation order :

      - a callable.    Return a partial dict with 'f_private' set to the keyspec.
      - a filename.    Load an X.509 certificate from the file.
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
       'data': X.509 certificate as string,
       'key': Parsed key from certificate,
       'keysize': Keysize in bits,
       'f_public': rsa_x509_pem.f_public(key) if private == False,
       'f_private': rsa_x509_pem.f_private(key) if private == True,
      }

    :param sig: Signature element as lxml.Element or None
    :param keyspec: Keyspec as string or callable. See above.
    :returns: dict, see above.
    """
    data = None
    source = None
    key_f_private = None
    if private and hasattr(keyspec, '__call__'):
        return {'keyspec': keyspec,
                'source': 'callable',
                'f_private': keyspec}
    if isinstance(keyspec, basestring):
        if os.path.isfile(keyspec):
            with open(keyspec) as c:
                data = c.read()
            source = 'file'
        elif private and keyspec.startswith("pkcs11://"):
            import xmlsec.pk11

            key_f_private, data = pk11.signer(keyspec)
            logging.debug("Using pkcs11 signing key: %s" % key_f_private)
            source = 'pkcs11'
        elif signature_element is not None:
            cd = _find_matching_cert(signature_element, keyspec)
            if cd is not None:
                data = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % cd
                source = 'signature_element'
        elif '-----BEGIN' in keyspec:
            data = keyspec
            source = 'keyspec'

    if data is None:
        return None
        #raise XMLSigException("Unable to find a useful key from keyspec '%s'" % (keyspec))

    #logging.debug("Certificate data (source '%s') :\n%s" % (source, data))

    cert_pem = rsa_x509_pem.parse(data)
    key = rsa_x509_pem.get_key(cert_pem)

    res = {'keyspec': keyspec,
           'source': source,
           'data': data,
           'key': key,
           'keysize': int(key.size()) + 1}

    if private:
        res['f_private'] = key_f_private or rsa_x509_pem.f_private(key)
    else:
        res['f_public'] = rsa_x509_pem.f_public(key)

    return res


def _root(t):
    if hasattr(t, 'getroot') and hasattr(t.getroot, '__call__'):
        return t.getroot()
    else:
        return t


def number_of_bits(num):
    """
    Return the number of bits required to represent num.

    In python >= 2.7, there is num.bit_length().

    NOTE: This function appears unused, so it might go away.
    """
    assert num >= 0
    # this is much faster than you would think, AND it is easy to read ;)
    return len(bin(num)) - 2


b64d = lambda s: s.decode('base64')


def b64e(s):
    if type(s) in (int, long):
        s = itb.int_to_bytes(s)
    return s.encode('base64').replace('\n', '')


def _signed_value(data, key_size, do_pad, hash_alg):  # TODO Do proper asn1 CMS
    """Return unencrypted rsa-sha1 signature value `padded_digest` from `data`.

    The resulting signed value will be in the form:
    (01 | FF* | 00 | prefix | digest) [RSA-SHA1]
    where "digest" is of the generated c14n xml for <SignedInfo>.

    Args:
      data: str of bytes to sign
      key_size: int of key length in bits; => len(`data`) + 3
    Returns:
      str: rsa-sha1 signature value of `data`
    """

    prefix = ASN1_BER_ALG_DESIGNATOR_PREFIX.get(hash_alg)
    if not prefix:
        raise XMLSigException("Unknown hash algorithm %s" % hash_alg)
    asn_digest = prefix + data
    if do_pad:
        # Pad to "one octet shorter than the RSA modulus" [RSA-SHA1]
        # WARNING: key size is in bits, not bytes!
        padded_size = key_size / 8 - 1
        pad_size = padded_size - len(asn_digest) - 2
        pad = '\x01' + '\xFF' * pad_size + '\x00'
        return pad + asn_digest
    else:
        return asn_digest


def _digest(data, hash_alg):
    """
    Calculate a hash digest of algorithm hash_alg and return the result base64 encoded.

    :param hash_alg: String with algorithm, such as 'sha1'
    :param data: The data to digest
    :returns: Base64 string
    """
    h = getattr(hashlib, hash_alg)()
    h.update(data)
    digest = b64e(h.digest())
    return digest


def _get_by_id(t, id_v):
    for id_a in _id_attributes:
        logging.debug("Looking for #%s using id attribute '%s'" % (id_v, id_a))
        elts = t.xpath("//*[@%s='%s']" % (id_a, id_v))
        if elts is not None and len(elts) > 0:
            return elts[0]
    return None


def _alg(elt):
    """
    Return the hashlib name of an Algorithm. Hopefully.
    :returns: None or string
    """
    uri = elt.get('Algorithm', None)
    if uri is None:
        return None
    else:
        return uri.rstrip('#')


def _remove_child_comments(t):
    #root = _root(t)
    for c in t.iter():
        if c.tag is etree.Comment or c.tag is etree.PI:
            _delete_elt(c)
    return t


def _process_references(t, sig=None, return_verified=True):
    """
    :returns: hash algorithm as string
    """
    if sig is None:
        sig = t.find(".//{%s}Signature" % NS['ds'])
    hash_alg = None
    for ref in sig.findall(".//{%s}Reference" % NS['ds']):
        obj = None
        verified = None
        uri = ref.get('URI', None)
        if uri is None or uri == '#' or uri == '':
            ct = _remove_child_comments(_root(copy.deepcopy(t)))
            obj = _root(ct)
        elif uri.startswith('#'):
            ct = copy.deepcopy(t)
            obj = _remove_child_comments(_get_by_id(ct, uri[1:]))
        else:
            raise XMLSigException("Unknown reference %s" % uri)

        if obj is None:
            raise XMLSigException("Unable to dereference Reference URI='%s'" % uri)

        if return_verified:
            verified = copy.deepcopy(obj)

        for tr in ref.findall(".//{%s}Transform" % NS['ds']):
            logging.debug("transform: %s" % _alg(tr))
            obj = _transform(_alg(tr), obj, tr)

        if _DEBUG_WRITE_TO_FILES:
            with open("/tmp/foo-obj.xml", "w") as fd:
                fd.write(obj)

        dm = ref.find(".//{%s}DigestMethod" % NS['ds'])
        if dm is None:
            raise XMLSigException("Unable to find DigestMethod")
        this_hash_alg = (_alg(dm).split("#"))[1]
        logging.debug("using hash algorithm %s" % this_hash_alg)
        hash_alg = hash_alg or this_hash_alg
        if this_hash_alg != hash_alg:
            raise XMLSigException("Unable to handle more than one hash algorithm (%s != %s)"
                                  % (this_hash_alg, hash_alg))
        digest = _digest(obj, this_hash_alg)
        logging.debug("digest for %s: %s" % (uri, digest))
        dv = ref.find(".//{%s}DigestValue" % NS['ds'])
        logging.debug(etree.tostring(dv))
        dv.text = digest

    if return_verified:
        return hash_alg, verified
    else:
        return hash_alg

##
# Removes HTML or XML character references and entities from a text string.
#
# @param text The HTML (or XML) source text.
# @return The plain text, as a Unicode string, if necessary.


def _unescape(text):
    def fixup(m):
        text = m.group(0)
        if text[:2] == "&#":
            # character reference
            try:
                if text[:3] == "&#x":
                    return unichr(int(text[3:-1], 16))
                else:
                    return unichr(int(text[2:-1]))
            except ValueError:
                pass
        else:
            # named entity
            try:
                if not text in ('&amp;', '&lt;', '&gt;'):
                    text = unichr(htmlentitydefs.name2codepoint[text[1:-1]])
            except KeyError:
                pass
        return text  # leave as is

    return re.sub("&#?\w+;", fixup, text)


def _delete_elt(elt):
    if elt.getparent() is None:
        raise XMLSigException("Cannot delete root")
    if elt.tail is not None:
        logging.debug("tail: '%s'" % elt.tail)
        p = elt.getprevious()
        if p is not None:
            logging.debug("adding tail to previous")
            if p.tail is None:
                p.tail = ''
            p.tail += elt.tail
        else:
            logging.debug("adding tail to parent")
            up = elt.getparent()
            if up is None:
                raise XMLSigException("Signature has no parent")
            if up.text is None:
                up.text = ''
            up.text += elt.tail
    elt.getparent().remove(elt)


def _enveloped_signature(t):
    sig = t.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
    _delete_elt(sig)
    if _DEBUG_WRITE_TO_FILES:
        with open("/tmp/foo-env.xml", "w") as fd:
            fd.write(etree.tostring(t))
    return t


def _c14n(t, exclusive, with_comments, inclusive_prefix_list=None):
    """
    Perform XML canonicalization (c14n) on an lxml.etree.

    NOTE: The c14n done here is missing whitespace removal. The whitespace has to
    be removed at parse time. One way to do that is to use xmlsec.parse_xml().

    :param t: XML as lxml.etree
    :param exclusive: boolean
    :param with_comments: boolean, keep comments or not
    :param inclusive_prefix_list: List of namespaces to include (?)
    :returns: XML as string (utf8)
    """
    cxml = etree.tostring(t, method="c14n", exclusive=exclusive, with_comments=with_comments,
                          inclusive_ns_prefixes=inclusive_prefix_list)
    u = _unescape(cxml.decode("utf8", 'replace')).encode("utf8").strip()
    if u[0] != '<':
        raise XMLSigException("C14N buffer doesn't start with '<'")
    if u[-1] != '>':
        raise XMLSigException("C14N buffer doesn't end with '>'")
    return u


def _transform(uri, t, tr=None):
    if uri == TRANSFORM_ENVELOPED_SIGNATURE:
        return _enveloped_signature(t)

    if uri == TRANSFORM_C14N_EXCLUSIVE_WITH_COMMENTS:
        nslist = None
        if tr is not None:
            elt = tr.find(".//{%s}InclusiveNamespaces" % 'http://www.w3.org/2001/10/xml-exc-c14n#')
            if elt is not None:
                nslist = elt.get('PrefixList', '').split()
        return _c14n(t, exclusive=True, with_comments=True, inclusive_prefix_list=nslist)

    if uri == TRANSFORM_C14N_EXCLUSIVE:
        nslist = None
        if tr is not None:
            elt = tr.find(".//{%s}InclusiveNamespaces" % 'http://www.w3.org/2001/10/xml-exc-c14n#')
            if elt is not None:
                nslist = elt.get('PrefixList', '').split()
        return _c14n(t, exclusive=True, with_comments=False, inclusive_prefix_list=nslist)

    if uri == TRANSFORM_C14N_INCLUSIVE:
        return _c14n(t, exclusive=False, with_comments=False)

    raise XMLSigException("unknown or unimplemented transform %s" % uri)


_id_attributes = ['ID', 'id']


def setID(ids):
    _id_attributes = ids


def pem2b64(pem):
    return '\n'.join(pem.strip().split('\n')[1:-1])


def b642pem(data):
    x = data
    r = "-----BEGIN CERTIFICATE-----\n"
    while len(x) > 64:
        r += x[0:64]
        r += "\n"
        x = x[64:]
    r += x
    r += "\n"
    r += "-----END CERTIFICATE-----"
    return r


def pem2cert(pem):
    return rsa_x509_pem.parse(pem)


def b642cert(data):
    return rsa_x509_pem.parse(b642pem(data))


def _verify(t, keyspec):
    """
    Verify the signature(s) in an XML document.

    Throws an XMLSigException on any non-matching signatures.

    :param t: XML as lxml.etree
    :param keyspec: X.509 cert filename, string with fingerprint or X.509 cert as string
    :returns: True if signature(s) validated, False if there were no signatures
    """
    if _DEBUG_WRITE_TO_FILES:
        with open("/tmp/foo-sig.xml", "w") as fd:
            fd.write(etree.tostring(_root(t)))

    # Load and parse certificate, unless keyspec is a fingerprint.
    cert = _load_keyspec(keyspec)

    validated = []
    for sig in t.findall(".//{%s}Signature" % NS['ds']):
        sv = sig.findtext(".//{%s}SignatureValue" % NS['ds'])
        if sv is None:
            raise XMLSigException("No SignatureValue")

        this_f_public = None
        this_keysize = None
        if cert is None:
            # keyspec is fingerprint - look for matching certificate in XML
            this_cert = _load_keyspec(keyspec, signature_element=sig)
            if this_cert is None:
                raise XMLSigException("Could not find certificate to validate signature")
            this_f_public = this_cert['f_public']
            this_keysize = this_cert['keysize']
        else:
            # Non-fingerprint keyspec, use pre-parsed values
            this_cert = cert
            this_f_public = cert['f_public']
            this_keysize = cert['keysize']

        logging.debug("key size: %d bits" % this_cert['keysize'])

        if this_cert is None:
            raise XMLSigException("Could not find certificate to validate signature")

        hash_alg, ref = _process_references(t, sig)
        si = sig.find(".//{%s}SignedInfo" % NS['ds'])
        b_digest = _create_signature_digest(si, hash_alg)

        actual = _signed_value(b_digest, this_keysize, True, hash_alg)
        expected = this_f_public(b64d(sv))

        if expected != actual:
            raise XMLSigException("Signature validation failed")
        validated.append(ref)

    return validated


def verify(t, keyspec):
    return len(_verify(t, keyspec)) > 0


def verified(t, keyspec):
    return _verify(t, keyspec)


## TODO - support transforms with arguments
def _signed_info_transforms(transforms):
    ts = [DS.Transform(Algorithm=t) for t in transforms]
    return DS.Transforms(*ts)


# standard enveloped rsa-sha1 signature
def _enveloped_signature_template(c14n_method, digest_alg, transforms, reference_uri):
    return DS.Signature(
        DS.SignedInfo(
            DS.CanonicalizationMethod(Algorithm=c14n_method),
            DS.SignatureMethod(Algorithm=ALGORITHM_SIGNATURE_RSA_SHA1),
            DS.Reference(
                _signed_info_transforms(transforms),
                DS.DigestMethod(Algorithm=digest_alg),
                DS.DigestValue(),
                URI=reference_uri
            )
        )
    )


def add_enveloped_signature(t, c14n_method=TRANSFORM_C14N_INCLUSIVE, digest_alg=ALGORITHM_DIGEST_SHA1, transforms=None,
                            reference_uri=""):
    if transforms is None:
        transforms = (TRANSFORM_ENVELOPED_SIGNATURE, TRANSFORM_C14N_EXCLUSIVE_WITH_COMMENTS)
    _root(t).insert(0, _enveloped_signature_template(c14n_method, digest_alg, transforms, reference_uri))


def sign(t, key_spec, cert_spec=None, reference_uri=''):
    """
    Sign an XML document. This means to 'complete' all Signature elements in the XML.

    :param t: XML as lxml.etree
    :param key_spec: private key reference, see _load_keyspec() for syntax.
    :param cert_spec: None or public key reference (to add cert to document), see _load_keyspec() for syntax.
    :param reference_uri: Envelope signature reference URI
    :returns: XML as lxml.etree (for convenience, 't' is modified in-place)
    """
    do_padding = False  # only in the case of our fallback keytype do we need to do pkcs1 padding here

    private = _load_keyspec(key_spec, private=True)
    if private is None:
        raise XMLSigException("Unable to load private key from '%s'" % key_spec)

    if private['source'] == 'file':
        do_padding = True  # need to do p1 padding in this case

    if cert_spec is None and private['source'] == 'pkcs11':
        cert_spec = private['data']
        logging.debug("Using P11 cert_spec :\n%s" % cert_spec)

    public = _load_keyspec(cert_spec)
    if public is None:
        raise XMLSigException("Unable to load public key from '%s'" \
                              % (cert_spec))
    if public['keysize'] != private['keysize']:
        raise XMLSigException("Public and private key sizes do not match (%s, %s)" \
                                  % (public['keysize'], private['keysize']))
    logging.debug("Using %s bit key" % (private['keysize']))

    if t.find(".//{%s}Signature" % NS['ds']) is None:
        add_enveloped_signature(t, reference_uri=reference_uri)

    if _DEBUG_WRITE_TO_FILES:
        with open("/tmp/sig-ref.xml", "w") as fd:
            fd.write(etree.tostring(_root(t)))

    for sig in t.findall(".//{%s}Signature" % NS['ds']):
        hash_alg = _process_references(t, sig, return_verified=False)
        si = sig.find(".//{%s}SignedInfo" % NS['ds'])
        b_digest = _create_signature_digest(si, hash_alg)

        # RSA sign hash digest and insert it into the XML
        tbs = _signed_value(b_digest, private['keysize'], do_padding, hash_alg)
        signed = private['f_private'](tbs)
        signature = b64e(signed)
        logging.debug("SignatureValue: %s" % signature)
        si.addnext(DS.SignatureValue(signature))

        if public is not None:
            # Insert cert_data as b64-encoded X.509 certificate into XML document
            sv_elt = si.getnext()
            sv_elt.addnext(DS.KeyInfo(DS.X509Data(DS.X509Certificate(pem2b64(public['data'])))))

    return t


def _create_signature_digest(si, hash_alg):
    """
    :param hash_alg: string such as 'sha1'
    """
    cm = si.find(".//{%s}CanonicalizationMethod" % NS['ds'])
    cm_alg = _alg(cm)
    if cm is None or cm_alg is None:
        raise XMLSigException("No CanonicalizationMethod")
    sic = _transform(cm_alg, si)
    logging.debug("SignedInfo C14N: %s" % sic)
    digest = _digest(sic, hash_alg)
    logging.debug("SignedInfo digest: %s" % digest)
    return b64d(digest)


def parse_xml(data, remove_whitespace=True, remove_comments=True):
    """
    Parse XML data into an lxml.etree and remove whitespace in the process.

    :param data: XML as string
    :param remove_whitespace: boolean
    :returns: XML as lxml.etree
    """
    parser = etree.XMLParser(remove_blank_text=remove_whitespace, remove_comments=remove_comments)
    return etree.XML(data, parser)
