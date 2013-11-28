
__author__ = 'leifj'

import os
from . import rsa_x509_pem
from lxml import etree as etree
import logging
import base64
import hashlib
import copy
from . import int_to_bytes as itb
from lxml.builder import ElementMaker
from xmlsec.exceptions import XMLSigException
from UserDict import DictMixin
from xmlsec import constants
from xmlsec.utils import parse_xml, pem2b64, unescape_xml_entities, delete_elt, root_elt, b64d, b64e


NS = {'ds': 'http://www.w3.org/2000/09/xmldsig#'}
NSDefault = {None: 'http://www.w3.org/2000/09/xmldsig#'}
DS = ElementMaker(namespace=NS['ds'], nsmap=NSDefault)


def _implicit_same_document(t, sig):  # this is actually incorrect according to the xml-dsig core spec
    return copy.deepcopy(sig.getparent())


def _implicit_same_document_correct(t, sig):
    if constants.SAME_DOCUMENT_IS_ROOT:
        return root_elt(copy.deepcopy(t))
    else:
        return copy.deepcopy(sig.getparent())


def set_default_signature_alg(alg):
    constants.default_signature_alg = alg


def set_default_digest_alg(alg):
    constants.default_digest_alg = alg


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
            from xmlsec import pk11

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
           'key': key,
           'keysize': int(key.size()) + 1}

    if private:
        res['f_private'] = key_f_private or rsa_x509_pem.f_private(key)
        res['data'] = data  # TODO - normalize private keyspec too!
    else:
        res['data'] = cert_pem['pem']  # normalized PEM
        res['f_public'] = rsa_x509_pem.f_public(key)

    return res


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

    prefix = constants.ASN1_BER_ALG_DESIGNATOR_PREFIX.get(hash_alg)
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
    logging.debug(h)
    h.update(data)
    digest = h.digest().encode("base64").rstrip("\n") #b64e(h.digest())
    return digest


def _get_by_id(t, id_v):
    for id_a in constants.id_attributes:
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
        return uri


def _remove_child_comments(t):
    #root = root_elt(t)
    for c in t.iter():
        if c.tag is etree.Comment or c.tag is etree.PI:
            delete_elt(c)
    return t


def _process_references(t, sig, return_verified=True, sig_path=".//{%s}Signature" % NS['ds']):
    """
    :returns: hash algorithm as string
    """

    verified_objects = []
    for ref in sig.findall(".//{%s}Reference" % NS['ds']):
        obj = None
        hash_alg = None
        uri = ref.get('URI', None)
        if uri is None or uri == '#' or uri == '':
            ct = _remove_child_comments(_implicit_same_document(t, sig))
            obj = root_elt(ct)
        elif uri.startswith('#'):
            ct = copy.deepcopy(t)
            obj = _remove_child_comments(_get_by_id(ct, uri[1:]))
        else:
            raise XMLSigException("Unknown reference %s" % uri)

        if obj is None:
            raise XMLSigException("Unable to dereference Reference URI='%s'" % uri)

        if return_verified:
            verified_objects.append(copy.deepcopy(obj))

        if constants.DEBUG_WRITE_TO_FILES:
            with open("/tmp/foo-pre-transform.xml", "w") as fd:
                fd.write(etree.tostring(obj))

        for tr in ref.findall(".//{%s}Transform" % NS['ds']):
            logging.debug("transform: %s" % _alg(tr))
            obj = _transform(_alg(tr), obj, tr=tr, sig_path=sig_path)

        if not isinstance(obj, basestring):
            if constants.DEBUG_WRITE_TO_FILES:
                with open("/tmp/foo-pre-serialize.xml", "w") as fd:
                    fd.write(etree.tostring(obj))
            obj = _transform(constants.TRANSFORM_C14N_INCLUSIVE, obj)

        if constants.DEBUG_WRITE_TO_FILES:
            with open("/tmp/foo-obj.xml", "w") as fd:
                fd.write(obj)

        dm = ref.find(".//{%s}DigestMethod" % NS['ds'])
        if dm is None:
            raise XMLSigException("Unable to find DigestMethod")
        hash_alg = (_alg(dm).split("#"))[1]
        logging.debug("using hash algorithm %s" % hash_alg)
        digest = _digest(obj, hash_alg)
        logging.debug("using digest %s (%s) for ref %s" % (digest, hash_alg, uri))
        dv = ref.find(".//{%s}DigestValue" % NS['ds'])
        logging.debug(etree.tostring(dv))
        dv.text = digest

    if return_verified:
        return verified_objects
    else:
        return None


def _enveloped_signature(t, sig_path=".//{%s}Signature" % NS['ds']):
    sig = t.find(sig_path)
    if sig is not None:
        delete_elt(sig)
    if constants.DEBUG_WRITE_TO_FILES:
        with open("/tmp/foo-env.xml", "w") as fd:
            fd.write(etree.tostring(t))
    return t


def _c14n(t, exclusive, with_comments, inclusive_prefix_list=None, schema=None):
    """
    Perform XML canonicalization (c14n) on an lxml.etree.

    :param t: XML as lxml.etree
    :param exclusive: boolean
    :param with_comments: boolean, keep comments or not
    :param inclusive_prefix_list: List of namespaces to include (?)
    :returns: XML as string (utf8)
    """
    xml_str = etree.tostring(t)
    doc = parse_xml(xml_str, remove_whitespace=False, remove_comments=not with_comments, schema=schema)
    buf = etree.tostring(doc, method='c14n', exclusive=exclusive, with_comments=with_comments, inclusive_ns_prefixes=inclusive_prefix_list)
    u = unescape_xml_entities(buf.decode("utf8", 'replace')).encode("utf8").strip()
    if u[0] != '<':
        raise XMLSigException("C14N buffer doesn't start with '<'")
    if u[-1] != '>':
        raise XMLSigException("C14N buffer doesn't end with '>'")
    return u


def _transform(uri, t, tr=None, schema=None, sig_path=".//{%s}Signature" % NS['ds']):
    if uri == constants.TRANSFORM_ENVELOPED_SIGNATURE:
        return _enveloped_signature(t, sig_path)

    if uri == constants.TRANSFORM_C14N_EXCLUSIVE_WITH_COMMENTS:
        nslist = None
        if tr is not None:
            elt = tr.find(".//{%s}InclusiveNamespaces" % 'http://www.w3.org/2001/10/xml-exc-c14n#')
            if elt is not None:
                nslist = elt.get('PrefixList', '').split()
        return _c14n(t, exclusive=True, with_comments=True, inclusive_prefix_list=nslist, schema=schema)

    if uri == constants.TRANSFORM_C14N_EXCLUSIVE:
        nslist = None
        if tr is not None:
            elt = tr.find(".//{%s}InclusiveNamespaces" % 'http://www.w3.org/2001/10/xml-exc-c14n#')
            if elt is not None:
                nslist = elt.get('PrefixList', '').split()
        return _c14n(t, exclusive=True, with_comments=False, inclusive_prefix_list=nslist, schema=schema)

    if uri == constants.TRANSFORM_C14N_INCLUSIVE:
        return _c14n(t, exclusive=False, with_comments=False, schema=schema)

    raise XMLSigException("unknown or unimplemented transform %s" % uri)


def setID(ids):
    constants.id_attributes = ids


def _verify(t, keyspec, sig_path=".//{%s}Signature" % NS['ds']):
    """
    Verify the signature(s) in an XML document.

    Throws an XMLSigException on any non-matching signatures.

    :param t: XML as lxml.etree
    :param keyspec: X.509 cert filename, string with fingerprint or X.509 cert as string
    :returns: True if signature(s) validated, False if there were no signatures
    """
    if constants.DEBUG_WRITE_TO_FILES:
        with open("/tmp/foo-sig.xml", "w") as fd:
            fd.write(etree.tostring(root_elt(t)))

    # Load and parse certificate, unless keyspec is a fingerprint.
    cert = _load_keyspec(keyspec)

    validated = []
    for sig in t.findall(sig_path):
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

        si = sig.find(".//{%s}SignedInfo" % NS['ds'])
        cm_alg = _cm_alg(si)
        digest_alg = _sig_digest(si)

        validated_objects = _process_references(t, sig, sig_path)
        b_digest = _create_signature_digest(si, cm_alg, digest_alg)
        actual = _signed_value(b_digest, this_keysize, True, digest_alg)
        expected = this_f_public(b64d(sv))

        if expected != actual:
            raise XMLSigException("Signature validation failed")
        validated.extend(validated_objects)

    return validated


def verify(t, keyspec, sig_path=".//{%s}Signature" % NS['ds']):
    return len(_verify(t, keyspec, sig_path)) > 0


def verified(t, keyspec, sig_path=".//{%s}Signature" % NS['ds']):
    return _verify(t, keyspec, sig_path)


## TODO - support transforms with arguments
def _signed_info_transforms(transforms):
    ts = [DS.Transform(Algorithm=t) for t in transforms]
    return DS.Transforms(*ts)


# standard enveloped signature
def _enveloped_signature_template(c14n_method,
                                  digest_alg,
                                  transforms,
                                  reference_uri,
                                  signature_alg):
    return DS.Signature(
        DS.SignedInfo(
            DS.CanonicalizationMethod(Algorithm=c14n_method),
            DS.SignatureMethod(Algorithm=signature_alg),
            DS.Reference(
                _signed_info_transforms(transforms),
                DS.DigestMethod(Algorithm=digest_alg),
                DS.DigestValue(),
                URI=reference_uri
            )
        )
    )


def add_enveloped_signature(t,
                            c14n_method=constants.default_c14n_alg,
                            digest_alg=constants.default_digest_alg,
                            signature_alg=constants.default_signature_alg,
                            transforms=None,
                            reference_uri='',
                            pos=0):
    if transforms is None:
        transforms = (constants.TRANSFORM_ENVELOPED_SIGNATURE,
                      constants.TRANSFORM_C14N_EXCLUSIVE_WITH_COMMENTS)

    tmpl = _enveloped_signature_template(c14n_method, digest_alg, transforms, reference_uri, signature_alg)
    if pos == -1:
        root_elt(t).append(tmpl)
    else:
        root_elt(t).insert(pos, tmpl)


def sign(t, key_spec, cert_spec=None, reference_uri='', sig_path=".//{%s}Signature" % NS['ds']):
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
        raise XMLSigException("Unable to load public key from '%s'" % cert_spec)
    if public['keysize'] != private['keysize']:
        raise XMLSigException("Public and private key sizes do not match (%s, %s)"
                              % (public['keysize'], private['keysize']))
    logging.debug("Using %s bit key" % (private['keysize']))

    if t.find(sig_path) is None:
        add_enveloped_signature(t, reference_uri=reference_uri)

    if constants.DEBUG_WRITE_TO_FILES:
        with open("/tmp/sig-ref.xml", "w") as fd:
            fd.write(etree.tostring(root_elt(t)))

    for sig in t.findall(sig_path):
        logging.debug("processing sig template: %s" % etree.tostring(sig))
        si = sig.find(".//{%s}SignedInfo" % NS['ds'])
        cm_alg = _cm_alg(si)
        digest_alg = _sig_digest(si)

        _process_references(t, sig, return_verified=False, sig_path=sig_path)
        # XXX create signature reference duplicates/overlaps process references unless a c14 is part of transforms
        b_digest = _create_signature_digest(si, cm_alg, digest_alg)

        # sign hash digest and insert it into the XML
        tbs = _signed_value(b_digest, private['keysize'], do_padding, digest_alg)
        signed = private['f_private'](tbs)
        signature = b64e(signed)
        logging.debug("SignatureValue: %s" % signature)
        si.addnext(DS.SignatureValue(signature))

        if public is not None:
            # Insert cert_data as b64-encoded X.509 certificate into XML document
            sv_elt = si.getnext()
            sv_elt.addnext(DS.KeyInfo(DS.X509Data(DS.X509Certificate(pem2b64(public['data'])))))

    return t


def _cm_alg(si):
    cm = si.find(".//{%s}CanonicalizationMethod" % NS['ds'])
    cm_alg = _alg(cm)
    if cm is None or cm_alg is None:
        raise XMLSigException("No CanonicalizationMethod")
    return cm_alg


def _sig_alg(si):
    sm = si.find(".//{%s}SignatureMethod" % NS['ds'])
    sig_alg = _alg(sm)
    if sm is None or sig_alg is None:
        raise XMLSigException("No SignatureMethod")
    return (sig_alg.split("#"))[1]


def _sig_digest(si):
    return (_sig_alg(si).split("-"))[1]


def _create_signature_digest(si, cm_alg, hash_alg):
    """
    :param hash_alg: string such as 'sha1'
    """
    logging.debug("transform %s on %s" % (cm_alg, etree.tostring(si)))
    sic = _transform(cm_alg, si)
    logging.debug("SignedInfo C14N: %s" % sic)
    digest = _digest(sic, hash_alg)
    logging.debug("SignedInfo digest: %s" % digest)
    return b64d(digest)


