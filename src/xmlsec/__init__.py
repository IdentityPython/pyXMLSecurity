
# This code was inspired by https://github.com/andrewdyates/xmldsig
# and includes https://github.com/andrewdyates/rsa_x509_pem with
# permission from the author.

__author__ = 'leifj'

from defusedxml import lxml
from lxml import etree as etree
import logging
import hashlib
import copy
from . import int_to_bytes as itb
from lxml.builder import ElementMaker
from xmlsec.exceptions import XMLSigException
from xmlsec import constants
from xmlsec.utils import parse_xml, pem2b64, unescape_xml_entities, delete_elt, root_elt, b64d, b64e, b642cert
import xmlsec.crypto
import pyconfig

NS = {'ds': 'http://www.w3.org/2000/09/xmldsig#'}
NSDefault = {None: 'http://www.w3.org/2000/09/xmldsig#'}
DS = ElementMaker(namespace=NS['ds'], nsmap=NSDefault)


class Config(object):
    """
    This class holds a set of configuration parameters (using pyconfig) for pyXMLSecurity:

    :param default_signature_alg: The URI of the default signature algorithm (RSA_SHA1 by default)
    :param default_digest_alg: The URI of the default digest algorithm (SHA1 by default)
    :param default_c14n_alg: The URI of the default c14n algorithm (c14n exclusive by default)
    :param debug_write_to_files: Set to True to dump certain XML traces to /tmp. Danger! Not for production!
    :param same_document_is_root: Set to True to treat implicit null same-document-references as reference to the whole document.
    :param id_attributes: A list of attributes to be used as 'id's. By default set to ['ID','id']
    :param c14n_strip_ws: Set to True to strip whitespaces in c14n. Only use if you have very special needs.

    Refer to the pyconfig documentation for information on how to override these in your own project.
    """
    default_signature_alg = pyconfig.setting("xmlsec.default_signature_alg", constants.ALGORITHM_SIGNATURE_RSA_SHA256)
    default_digest_alg = pyconfig.setting("xmlsec.default_digest_alg", constants.ALGORITHM_DIGEST_SHA256)
    default_c14n_alg = pyconfig.setting("xmlsec.default_c14n_alg", constants.TRANSFORM_C14N_INCLUSIVE)
    debug_write_to_files = pyconfig.setting("xmlsec.config.debug_write_to_files", False)
    same_document_is_root = pyconfig.setting("xmlsec.same_document_is_root", False)
    id_attributes = pyconfig.setting("xmlsec.id_attributes", ['ID', 'id'])
    c14n_strip_ws = pyconfig.setting("xmlsec.c14n_strip_ws", False)


config = Config()


def _implicit_same_document(t, sig):
    if config.same_document_is_root:
        return root_elt(copy.deepcopy(t))
    else:
        return copy.deepcopy(sig.getparent())


def _signed_value(data, key_size, do_pad, hash_alg):  # TODO Do proper asn1 CMS
    """Return unencrypted rsa-sha1 signature value `padded_digest` from `data`.

    The resulting signed value will be in the form:
    (01 | FF* | 00 | prefix | digest) [RSA-SHA1]
    where "digest" is of the generated c14n xml for <SignedInfo>.

    :param data: str of bytes to sign
    :param key_size: key length (if known) in bits; => len(`data`) + 3
    :param do_pad: Do PKCS1 (?) padding of the data - requires integer key_size
    :param hash_alg: Hash algorithm as string (e.g. 'sha1')
    :returns: rsa-sha signature value of `data`

    :type data: string
    :type key_size: None | int
    :type do_pad: bool
    :type hash_alg: string
    :rtype: string
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
    h.update(data)
    digest = b64e(h.digest())
    return digest


def _get_by_id(t, id_v):
    for id_a in config.id_attributes:
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


def _process_references(t, sig, verify_mode=True, sig_path=".//{%s}Signature" % NS['ds'], drop_signature=False):
    """
    :returns: hash algorithm as string
    """

    verified_objects = {}
    for ref in sig.findall(".//{%s}Reference" % NS['ds']):
        obj = None
        hash_alg = None
        uri = ref.get('URI', None)
        if uri is None or uri == '#' or uri == '':
            ref_obj = _implicit_same_document(t, sig)
            if ref_obj is None:
                raise XMLSigException("Unable to find reference while processing implicit same document reference")
            ct = _remove_child_comments(ref_obj)
            obj = root_elt(ct)
        elif uri.startswith('#'):
            ct = copy.deepcopy(t)
            ref_obj = _get_by_id(ct, uri[1:])
            if ref_obj is None:
                raise XMLSigException("Unable to find reference while processing '%s'" % uri)
            obj = _remove_child_comments(ref_obj)
        else:
            raise XMLSigException("Unknown reference %s" % uri)

        if obj is None:
            raise XMLSigException("Unable to dereference Reference URI='%s'" % uri)

        obj_copy = obj
        if verify_mode:
            obj_copy = copy.deepcopy(obj)
            if drop_signature:
                for sig in obj_copy.findall(sig_path):
                    sig.getparent().remove(sig)

        if config.debug_write_to_files:
            with open("/tmp/foo-pre-transform.xml", "w") as fd:
                fd.write(etree.tostring(obj))

        for tr in ref.findall(".//{%s}Transform" % NS['ds']):
            obj = _transform(_alg(tr), obj, tr=tr, sig_path=sig_path)
            nslist = _find_nslist(tr)
            if nslist is not None:
                r = root_elt(t)
                for nsprefix in nslist:
                    if nsprefix in r.nsmap:
                        obj_copy.nsmap[nsprefix] = r.nsmap[nsprefix]

        if not isinstance(obj, basestring):
            if config.debug_write_to_files:
                with open("/tmp/foo-pre-serialize.xml", "w") as fd:
                    fd.write(etree.tostring(obj))
            obj = _transform(constants.TRANSFORM_C14N_INCLUSIVE, obj)

        if config.debug_write_to_files:
            with open("/tmp/foo-obj.xml", "w") as fd:
                fd.write(obj)

        hash_alg = _ref_digest(ref)
        logging.debug("using hash algorithm %s" % hash_alg)
        digest = _digest(obj, hash_alg)
        logging.debug("computed %s digest %s for ref %s" % (hash_alg, digest, uri))
        dv = ref.find(".//{%s}DigestValue" % NS['ds'])

        if verify_mode:
            logging.debug("found %s digest %s for ref %s" % (hash_alg, dv.text, uri))
            computed_digest_binary = b64d(digest)
            digest_binary = b64d(dv.text)
            if digest_binary == computed_digest_binary: # no point in verifying signature if the digest doesn't match
                verified_objects[ref] = obj_copy
            else:
                logging.error("not returning ref %s - digest mismatch" % uri)
        else: # signing - lets store the digest
            logging.debug("replacing digest in %s" % etree.tostring(dv))
            dv.text = digest


    if verify_mode:
        return verified_objects
    else:
        return None


def _ref_digest(ref):
    dm = ref.find(".//{%s}DigestMethod" % NS['ds'])
    if dm is None:
        raise XMLSigException("Unable to find DigestMethod for Reference@URI {!s}".format(ref.get('URI')))
    alg_uri = _alg(dm)
    hash_alg = (alg_uri.split("#"))[1]
    if not hash_alg:
        raise XMLSigException("Unable to determine digest algorithm from {!s}".format(alg_uri))
    return hash_alg


def _enveloped_signature(t, sig_path=".//{%s}Signature" % NS['ds']):
    sig = t.find(sig_path)
    if sig is not None:
        delete_elt(sig)
    if config.debug_write_to_files:
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
    doc = t
    if root_elt(doc).getparent() is not None:
        xml_str = etree.tostring(doc, encoding=unicode)
        doc = parse_xml(xml_str, remove_whitespace=config.c14n_strip_ws, remove_comments=not with_comments, schema=schema)
        del xml_str

    buf = etree.tostring(doc,
                         method='c14n',
                         exclusive=exclusive,
                         with_comments=with_comments,
                         inclusive_ns_prefixes=inclusive_prefix_list)
    #u = unescape_xml_entities(buf.decode("utf8", 'strict')).encode("utf8").strip()
    assert buf[0] == '<'
    assert buf[-1] == '>'
    #if u[0] != '<':
    #    raise XMLSigException("C14N buffer doesn't start with '<'")
    #if u[-1] != '>':
    #    raise XMLSigException("C14N buffer doesn't end with '>'")
    #return u
    return buf


def _find_nslist(tr):
    nslist = None
    if tr is not None:
        elt = tr.find(".//{%s}InclusiveNamespaces" % 'http://www.w3.org/2001/10/xml-exc-c14n#')
        if elt is not None:
            nslist = elt.get('PrefixList', '').split()
    return nslist


def _transform(uri, t, tr=None, schema=None, sig_path=".//{%s}Signature" % NS['ds']):
    if uri == constants.TRANSFORM_ENVELOPED_SIGNATURE:
        return _enveloped_signature(t, sig_path)

    if uri == constants.TRANSFORM_C14N_EXCLUSIVE_WITH_COMMENTS:
        return _c14n(t, exclusive=True, with_comments=True, inclusive_prefix_list=_find_nslist(tr), schema=schema)

    if uri == constants.TRANSFORM_C14N_EXCLUSIVE:
        return _c14n(t, exclusive=True, with_comments=False, inclusive_prefix_list=_find_nslist(tr), schema=schema)

    if uri == constants.TRANSFORM_C14N_INCLUSIVE:
        return _c14n(t, exclusive=False, with_comments=False, schema=schema)

    raise XMLSigException("unknown or unimplemented transform %s" % uri)


def setID(ids):
    constants.id_attributes = ids


def _verify(t, keyspec, sig_path=".//{%s}Signature" % NS['ds'], drop_signature=False):
    """
    Verify the signature(s) in an XML document.

    Throws an XMLSigException on any non-matching signatures.

    :param t: XML as lxml.etree
    :param keyspec: X.509 cert filename, string with fingerprint or X.509 cert as string
    :returns: True if signature(s) validated, False if there were no signatures
    """
    if config.debug_write_to_files:
        with open("/tmp/foo-sig.xml", "w") as fd:
            fd.write(etree.tostring(root_elt(t)))

    validated = []
    for sig in t.findall(sig_path):
        try:
            sv = sig.findtext(".//{%s}SignatureValue" % NS['ds'])
            if not sv:
                raise XMLSigException("No SignatureValue")

            logging.debug("SignatureValue: {!s}".format(sv))
            this_cert = xmlsec.crypto.from_keyspec(keyspec, signature_element=sig)
            logging.debug("key size: {!s} bits".format(this_cert.keysize))

            si = sig.find(".//{%s}SignedInfo" % NS['ds'])
            logging.debug("Found signedinfo {!s}".format(etree.tostring(si)))
            cm_alg = _cm_alg(si)
            sig_digest_alg = _sig_digest(si)

            refmap = _process_references(t, sig, verify_mode=True, sig_path=sig_path, drop_signature=drop_signature)
            for ref,obj in refmap.items():
                b_digest = _create_signature_digest(si, cm_alg, sig_digest_alg)
                actual = _signed_value(b_digest, this_cert.keysize, True, sig_digest_alg)
                if not this_cert.verify(b64d(sv), actual):
                    raise XMLSigException("Failed to validate {!s} using sig digest {!s} and cm {!s}".format(etree.tostring(sig),sig_digest_alg,cm_alg))
                validated.append(obj)
        except XMLSigException, ex:
            logging.error(ex)

    if not validated:
        raise XMLSigException("No valid ds:Signature elements found")

    return validated


def verify(t, keyspec, sig_path=".//{%s}Signature" % NS['ds']):
    return len(_verify(t, keyspec, sig_path)) > 0


def verified(t, keyspec, sig_path=".//{%s}Signature" % NS['ds'], drop_signature=False):
    return _verify(t, keyspec, sig_path, drop_signature)


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
                            c14n_method=config.default_c14n_alg,
                            digest_alg=config.default_digest_alg,
                            signature_alg=config.default_signature_alg,
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

    return tmpl


def _is_template(sig):
    si = sig.find(".//{%s}SignedInfo" % NS['ds'])
    if si is None:
        return False
    dv = si.find(".//{%s}DigestValue" % NS['ds'])
    if dv is not None and dv.text is not None and len(dv.text) > 0:
        return False
    sv = sig.find(".//{%s}SignatureValue" % NS['ds'])
    if sv is not None and sv.text is not None and len(sv.text) > 0:
        return False
    return True


def sign(t, key_spec, cert_spec=None, reference_uri='', insert_index=0, sig_path=".//{%s}Signature" % NS['ds']):
    """
    Sign an XML document. This means to 'complete' all Signature elements in the XML.

    :param t: XML as lxml.etree
    :param key_spec: private key reference, see xmlsec.crypto.from_keyspec() for syntax.
    :param cert_spec: None or public key reference (to add cert to document),
                      see xmlsec.crypto.from_keyspec() for syntax.
    :param sig_path: An xpath expression identifying the Signature template element
    :param reference_uri: Envelope signature reference URI
    :param insert_index: Insertion point for the Signature element,
                         Signature is inserted at beginning by default
    :returns: XML as lxml.etree (for convenience, 't' is modified in-place)
    """
    private = xmlsec.crypto.from_keyspec(key_spec, private=True)

    public = None
    if cert_spec is not None:
        public = xmlsec.crypto.from_keyspec(cert_spec)
        if public is None:
            raise XMLSigException("Unable to load public key from '%s'" % cert_spec)
        if public.keysize and private.keysize:  # XXX maybe one set and one not set should also raise exception?
            if public.keysize != private.keysize:
                raise XMLSigException("Public and private key sizes do not match ({!s}, {!s})".format(
                                      public.keysize, private.keysize))
            # This might be incorrect for PKCS#11 tokens if we have no public key
            logging.debug("Using {!s} bit key".format(private.keysize))

    templates = filter(_is_template, t.findall(sig_path))
    if not templates:
        tmpl = add_enveloped_signature(t, reference_uri=reference_uri, pos=insert_index)
        templates = [tmpl]

    assert templates, XMLSigException("Failed to both find and add a signing template")

    if config.debug_write_to_files:
        with open("/tmp/sig-ref.xml", "w") as fd:
            fd.write(etree.tostring(root_elt(t)))

    for sig in templates:
        logging.debug("processing sig template: %s" % etree.tostring(sig))
        si = sig.find(".//{%s}SignedInfo" % NS['ds'])
        assert si is not None
        cm_alg = _cm_alg(si)
        digest_alg = _sig_digest(si)

        _process_references(t, sig, verify_mode=False, sig_path=sig_path)
        # XXX create signature reference duplicates/overlaps process references unless a c14 is part of transforms
        b_digest = _create_signature_digest(si, cm_alg, digest_alg)

        # sign hash digest and insert it into the XML
        tbs = _signed_value(b_digest, private.keysize, private.do_padding, digest_alg)
        signed = private.sign(tbs)
        signature = b64e(signed)
        logging.debug("SignatureValue: %s" % signature)
        sv = sig.find(".//{%s}SignatureValue" % NS['ds'])
        if sv is None:
            si.addnext(DS.SignatureValue(signature))
        else:
            sv.text = signature

        for cert_src in (public, private):
            if cert_src is not None and cert_src.cert_pem:
                # Insert cert_data as b64-encoded X.509 certificate into XML document
                sv_elt = si.getnext()
                sv_elt.addnext(DS.KeyInfo(DS.X509Data(DS.X509Certificate(pem2b64(cert_src.cert_pem)))))
                break  # add the first we find, no more

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


