import logging

__author__ = 'leifj'

from defusedxml import lxml
from lxml import etree as etree
from rsa_x509_pem import parse as pem_parse
from int_to_bytes import int_to_bytes
from xmlsec.exceptions import XMLSigException
import htmlentitydefs
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
    return pem_parse(pem)


def b642cert(data):
    return pem_parse(b642pem(data))


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
    if type(s) in (int, long):
        s = int_to_bytes(s)

    return b64encode(s)


def serialize(t, stream=None):
    xml = etree.tostring(t, xml_declaration=True)
    if stream is not None:
        with open(stream, 'w') as xml_out:
            xml_out.write(xml)
    else:
        print(xml)