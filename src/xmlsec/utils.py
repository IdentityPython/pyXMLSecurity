import base64
import logging

__author__ = 'leifj'

from lxml import etree as etree
from . import rsa_x509_pem
from . import int_to_bytes as itb
from xmlsec.exceptions import XMLSigException
import html.entities
import re


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
    return b'\n'.join(pem.strip().split(b'\n')[1:-1])


def b642pem(data):
    group_by = 64
    lines = [b'-----BEGIN CERTIFICATE-----']
    i = 0
    while i < len(data):
        lines.append(data[i:i + group_by])
        i += group_by
    lines.append(b'-----END CERTIFICATE-----')
    return b'\n'.join(lines)


def pem2cert(pem):
    return rsa_x509_pem.parse(pem)


def b642cert(data):
    return rsa_x509_pem.parse(b642pem(data))


def unescape_xml_entities(text):
    """
    Removes HTML or XML character references and entities from a text string.
    @param text The HTML (or XML) source text.
    @return The plain text, as a Unicode string, if necessary.
    """
    def fixup(m):
        text = m.group(0)
        if text[:2] == "&#":
            # character reference
            try:
                if text[:3] == "&#x":
                    return chr(int(text[3:-1], 16))
                else:
                    return chr(int(text[2:-1]))
            except ValueError:
                pass
        else:
            # named entity
            try:
                if not text in ('&amp;', '&lt;', '&gt;'):
                    text = chr(html.entities.name2codepoint[text[1:-1]])
            except KeyError:
                pass
        return text  # leave as is

    return re.sub("&#?\w+;", fixup, text)


def delete_elt(elt):
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


b64d = lambda s: base64.b64decode(s)


def b64e(s):
    if isinstance(s, int):
        s = itb.int_to_bytes(s)
    return base64.b64encode(s).replace(b'\n', b'')
