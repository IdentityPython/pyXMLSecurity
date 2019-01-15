import logging

__author__ = 'leifj'

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
from defusedxml import lxml
from lxml import etree as etree
from xmlsec.PyCryptoShim import RSAobjShim
from xmlsec.int_to_bytes import int_to_bytes
from xmlsec.exceptions import XMLSigException
from six.moves import html_entities as htmlentitydefs
import six
import re
from io import BytesIO
from base64 import b64encode, standard_b64decode

def parse_xml(data, remove_whitespace=True, remove_comments=True, schema=None):
    """
    Parse XML data into an lxml.etree and remove whitespace in the process.

    :param data: XML as string
    :param remove_whitespace: boolean
    :returns: XML as lxml.etree
    """
    parser = etree.XMLParser(remove_blank_text=remove_whitespace, remove_comments=remove_comments, schema=schema)
    return etree.XML(data, parser)


def pem2b64(pem):
    """
    Strip the header and footer of a .pem. BEWARE: Won't work with explanatory
    strings above the header.
    @params pem A string representing the pem
    """
    # XXX try to use cryptography parser to support things like
    # https://tools.ietf.org/html/rfc7468#section-5.2
    pem = pem.decode('ascii')
    return '\n'.join(pem.strip().split('\n')[1:-1])


def b642pem(data):
    x = data
    r = b"-----BEGIN CERTIFICATE-----\n"
    while len(x) > 64:
        r += x[0:64]
        r += b"\n"
        x = x[64:]
    r += x
    r += b"\n"
    r += b"-----END CERTIFICATE-----"
    return r

def _cert2dict(cert):
    """
    Build cert_dict similar to old rsa_x509_pem backend. Shouldn't
    be used by new code.
    @param cert A cryptography.x509.Certificate object
    """
    key = cert.public_key()
    if not isinstance(key, rsa.RSAPublicKey):
        raise XMLSigException("We don't support non-RSA public keys at the moment.")
    cdict = dict()
    cdict['type'] = "X509 CERTIFICATE"
    cdict['pem'] = cert.public_bytes(encoding=serialization.Encoding.PEM)
    cdict['body'] = b64encode(cert.public_bytes(encoding=serialization.Encoding.DER))
    n = key.public_numbers()
    cdict['modulus'] = n.n
    cdict['publicExponent'] = n.e
    cdict['subject'] = cert.subject
    cdict['cert'] = RSAobjShim(cert)

    return cdict

def pem2cert(pem):
    """
    Return cert_dict similar to old rsa_x509_pem backend. Shouldn't
    be used by new code.
    @param pem The certificate as pem string
    """
    cert = load_pem_x509_certificate(pem, backend=default_backend())
    return _cert2dict(cert)

def b642cert(data):
    """
    Return cert_dict similar to old rsa_x509_pem backend. Shouldn't
    be used by new code.
    @param data The certificate as base64 string (i.e. pem without header/footer)
    """
    cert = load_der_x509_certificate(standard_b64decode(data), backend=default_backend())    
    return _cert2dict(cert)

def unescape_xml_entities(text):
    """
    Removes HTML or XML character references and entities from a text string.
    @param text The HTML (or XML) source text.
    @return The plain text, as a Unicode string, if necessary.
    """
    def fixup(m):
        txt = m.group(0)
        if txt[:2] == "&#":
            # character reference
            try:
                if txt[:3] == "&#x":
                    return txt
                    #return unichr(int(txt[3:-1], 16))
                else:
                    return unichr(int(txt[2:-1]))
            except ValueError:
                pass
        else:
            # named entity
            try:
                if not txt in ('&amp;', '&lt;', '&gt;', '&quot;', '&pos;'):
                    txt = unichr(htmlentitydefs.name2codepoint[txt[1:-1]])
            except KeyError:
                pass
        return txt  # leave as is
    return re.compile("&#?\w+;").sub(fixup, text)
    #return re.sub("&#?\w+;", fixup, text)


def delete_elt(elt):
    if elt.getparent() is None:
        raise XMLSigException("Cannot delete root")
    if elt.tail is not None:
        #logging.debug("tail: '%s'" % elt.tail)
        p = elt.getprevious()
        if p is not None:
            #logging.debug("adding tail to previous")
            if p.tail is None:
                p.tail = ''
            p.tail += elt.tail
        else:
            #logging.debug("adding tail to parent")
            up = elt.getparent()
            if up is None:
                raise XMLSigException("Signature has no parent")
            if up.text is None:
                up.text = ''
            up.text += elt.tail
    elt.getparent().remove(elt)


def root_elt(t):
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


def b64d(s):
    return standard_b64decode(s)

def b64e(s):
    if isinstance(s, six.integer_types):
        s = int_to_bytes(s)

    return b64encode(s)


def serialize(t, stream=None):
    xml = etree.tostring(t, xml_declaration=True)
    if stream is not None:
        with open(stream, 'w') as xml_out:
            xml_out.write(xml)
    else:
        print(xml)


def unicode_to_bytes(u):
    if six.PY2:
        return u.encode('utf-8')
    else:
        return bytes(u, encoding='utf-8')


def etree_to_string(obj):
    """
    :param obj: etree element
    :type obj: lxml.etree.Element
    :return: serialized element
    :rtype: six.string_types
    """
    if six.PY2:
        return etree.tostring(obj, encoding='UTF-8')
    else:
        return etree.tostring(obj, encoding='unicode')
