import logging
import six
import xmlsec
import xmlsec.exceptions
import xmlsec.crypto
from lxml.builder import ElementMaker
from lxml import etree as etree
from xmlsec.utils import  pem2b64, b64e

NS = {'ds': 'http://www.w3.org/2000/09/xmldsig#'}
NSDefault = {None: 'http://www.w3.org/2000/09/xmldsig#'}
DS = ElementMaker(namespace=NS['ds'], nsmap=NSDefault)

class Signer(object):
    def __init__(self, key_spec, cert_spec=None, debug=False):
        """
        :param key_spec: private key reference, see xmlsec.crypto.from_keyspec() for syntax.
        :param cert_spec: None or public key reference (to add cert to document),
                          see xmlsec.crypto.from_keyspec() for syntax.
        """
        self.log = logging.getLogger('xmlsec')
        self.debug = debug
        self.private = xmlsec.crypto.from_keyspec(key_spec, private=True)
        self.public = None
        if cert_spec is not None:
            self.public = xmlsec.crypto.from_keyspec(cert_spec)
            if self.public is None:
                raise xmlsec.exceptions.XMLSigException("Unable to load public key from '%s'" % cert_spec)
            if self.public.keysize and self.private.keysize:  # XXX maybe one set and one not set should also raise exception?
                if self.public.keysize != self.private.keysize:
                    raise xmlsec.exceptions.XMLSigException("Public and private key sizes do not match ({!s}, {!s})".format(
                                          self.public.keysize, self.private.keysize))
                # This might be incorrect for PKCS#11 tokens if we have no public key
                self.log.debug("Using {!s} bit key".format(self.private.keysize))


    def sign(self, t, reference_uri='', insert_index=0, sig_path=".//{%s}Signature" % NS['ds']):
        """
        Sign an XML document. This means to 'complete' all Signature elements in the XML.

        :param t: XML as lxml.etree
        :param sig_path: An xpath expression identifying the Signature template element
        :param reference_uri: Envelope signature reference URI
        :param insert_index: Insertion point for the Signature element,
                             Signature is inserted at beginning by default
        :returns: XML as lxml.etree (for convenience, 't' is modified in-place)
        """
        sig_paths = t.findall(sig_path)
        templates = list(filter(xmlsec._is_template, sig_paths))
        if not templates:
            tmpl = xmlsec.add_enveloped_signature(t, reference_uri=reference_uri, pos=insert_index)
            templates = [tmpl]

        assert templates, xmlsec.exceptions.XMLSigException("Failed to both find and add a signing template")

        if self.debug:
            with open("/tmp/sig-ref.xml", "w") as fd:
                fd.write(etree_to_string(root_elt(t)))

        for sig in templates:
            self.log.debug("processing sig template: %s" % etree.tostring(sig))
            si = sig.find(".//{%s}SignedInfo" % NS['ds'])
            assert si is not None
            cm_alg = xmlsec._cm_alg(si)
            sig_alg = xmlsec._sig_alg(si)

            xmlsec._process_references(t, sig, verify_mode=False, sig_path=sig_path)
            # XXX create signature reference duplicates/overlaps process references unless a c14 is part of transforms
            self.log.debug("transform %s on %s" % (cm_alg, etree.tostring(si)))
            sic = xmlsec._transform(cm_alg, si)
            self.log.debug("SignedInfo C14N: %s" % sic)

            # sign hash digest and insert it into the XML
            if self.private.do_digest:
                digest = xmlsec.crypto._digest(sic, sig_alg)
                self.log.debug("SignedInfo digest: %s" % digest)
                b_digest = b64d(digest)
                tbs = xmlsec._signed_value(b_digest, private.keysize, private.do_padding, sig_alg)
            else:
                tbs = sic

            signed = self.private.sign(tbs, sig_alg)
            signature = b64e(signed)
            if isinstance(signature, six.binary_type):
                signature = six.text_type(signature, 'utf-8')
            self.log.debug("SignatureValue: %s" % signature)
            sv = sig.find(".//{%s}SignatureValue" % NS['ds'])
            if sv is None:
                si.addnext(DS.SignatureValue(signature))
            else:
                sv.text = signature

            for cert_src in (self.public, self.private):
                if cert_src is not None and cert_src.cert_pem:
                    # Insert cert_data as b64-encoded X.509 certificate into XML document
                    sv_elt = si.getnext()
                    sv_elt.addnext(DS.KeyInfo(DS.X509Data(DS.X509Certificate(pem2b64(cert_src.cert_pem)))))
                    break  # add the first we find, no more

        return t
