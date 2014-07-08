#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright ©2011 Andrew D. Yates
# andrewyates.name@gmail.com
#
# Modified and redistributed as part of pyXMLSecurity by leifj@mnt.se
# with permission from the original author
#
"""Parse x509 PEM Certificates.

The objective of this script is to parse elements from x509
certificates in PEM binary format which use RSA cryptographic keys for
use in XML digital signature (xmldsig) signatures and
verification. Much of this module has been adapted from the pyasn1
source code example "pyasn1/examples/x509.py" [pyasn1].

USE:

>>> data = open("cert.pem").read()
... dict = x509_pem.parse(data)
... n, e = dict['modulus'], dict['publicExponent']
... subject = dict['subject']

REFERENCES:

pyasn1
"ASN.1 tools for Python"
http://pyasn1.sourceforge.net/

RFC5480
"Elliptic Curve Cryptography Subject Public Key Information"
http://www.ietf.org/rfc/rfc5480.txt

X500attr
"2.5.4 - X.500 attribute types"
http://www.alvestrand.no/objectid/2.5.4.html

X500email
"1.2.840.113549.1.9.1 - e-mailAddress"
http://www.alvestrand.no/objectid/1.2.840.113549.1.9.1.html
"""
import base64
import binascii
import re

from .pyasn1.type import tag, namedtype, namedval, univ, constraint, char, useful
from .pyasn1.codec.der import decoder

from .sequence_parser import SequenceParser


MAX = 64
CERT_FILE = "keys/cacert_pass_helloworld.pem"

RSA_ID = "1.2.840.113549.1.1.1"
RSA_SHA1_ID = "1.2.840.113549.1.1.5"

RX_PUBLIC_KEY = re.compile("subjectPublicKey=(?:\")?'([01]+)'(?:\")?B")
RX_SUBJECT = re.compile(" +subject=Name:.*?\n\n\n", re.M | re.S)
RX_SUBJECT_ATTR = re.compile("""
RelativeDistinguishedName:.*?
type=(\S+).*?
AttributeValue:\n\s+?
[^=]+=([^\n]*)\n
""", re.M | re.S | re.X)

# abbreviated code map
X500_CODE_MAP = {
    '2.5.4.3': 'CN',  # commonName
    '2.5.4.6': 'C',  # countryName
    '2.5.4.7': 'L',  # localityName (City)
    '2.5.4.8': 'ST',  # stateOrProvinceName (State)
    '2.5.4.9': 'STREET',  # streetAddress
    '2.5.4.10': 'O',  # organizationName
    '2.5.4.11': 'OU',  # organizationalUnitName
    '2.5.4.12': 'T',  # title
    '1.2.840.113549.1.9.1': 'E',  # e-mailAddress
    '2.5.4.17': 'postalAddress'
}


class DirectoryString(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('teletexString',
                            char.TeletexString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('printableString',
                            char.PrintableString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('universalString',
                            char.UniversalString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('utf8String',
                            char.UTF8String().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('bmpString', char.BMPString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('ia5String', char.IA5String().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX)))
    )


class AttributeValue(DirectoryString):
    def __str__(self):
        return self[1].__str__()


class AttributeType(univ.ObjectIdentifier):
    def __str__(self):
        oid = '.'.join("%d" % x for x in self)
        if oid in X500_CODE_MAP:
            return X500_CODE_MAP[oid]
        else:
            return oid


class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeType()),
        namedtype.NamedType('value', AttributeValue())
    )

    def __str__(self):
        return "%s=%s" % (self['type'], self['value'])


class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()

    def __str__(self):
        return "+".join(avp.__str__() for avp in self)


class RDNSequence(univ.SequenceOf):
    componentType = RelativeDistinguishedName()

    def __str__(self):
        return "/".join([rdn.__str__() for rdn in self])


class Name(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('', RDNSequence())
    )

    def __str__(self):
        return self[0].__str__()


class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Null())
    )


class Extension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extnID', univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType('critical', univ.Boolean('False')),
        namedtype.NamedType('extnValue', univ.OctetString())
    )


class Extensions(univ.SequenceOf):
    componentType = Extension()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)


class SubjectPublicKeyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', AlgorithmIdentifier()),
        namedtype.NamedType('subjectPublicKey', univ.BitString())
    )


class UniqueIdentifier(univ.BitString):
    pass


class Time(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('utcTime', useful.UTCTime()),
        namedtype.NamedType('generalTime', useful.GeneralizedTime())
    )


class Validity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('notBefore', Time()),
        namedtype.NamedType('notAfter', Time())
    )


class CertificateSerialNumber(univ.Integer):
    pass


class Version(univ.Integer):
    namedValues = namedval.NamedValues(
        ('v1', 0), ('v2', 1), ('v3', 2)
    )


class TBSCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version', Version('v1', tagSet=Version.tagSet.tagExplicitly(
            tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))),
        namedtype.NamedType('serialNumber', CertificateSerialNumber()),
        namedtype.NamedType('signature', AlgorithmIdentifier()),
        namedtype.NamedType('issuer', Name()),
        namedtype.NamedType('validity', Validity()),
        namedtype.NamedType('subject', Name()),
        namedtype.NamedType('subjectPublicKeyInfo', SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType('issuerUniqueID', UniqueIdentifier().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('subjectUniqueID', UniqueIdentifier().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('extensions', Extensions().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)))
    )


class Certificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsCertificate', TBSCertificate()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signatureValue', univ.BitString())
    )

    def getSubject(self):
        return self['tbsCertificate']['subject'][0]

    def get_subject(self):
        return self.getSubject()

    def getIssuer(self):
        return self['tbsCertificate']['issuer'][0]

    def get_issuer(self):
        return self.get_issuer()

    def getValidity(self):
        return self['tbsCertificate']['validity']

    def getNotAfter(self):
        return self.getValidity()['notAfter'][0]

    def get_notAfter(self):
        return self.getNotAfter()

    def getNotBefore(self):
        return self.getValidity()['notBefore'][0]

    def get_notBefore(self):
        return self.getNotBefore()

    def dict(self):
        """Return simple dictionary of key elements as simple types.

    Note: this only returns the RSA Public key information for this certificate.

    Returns:
      {str, value} where `value` is simple type like `long`
    """
        cdict = {}

        # hack directly from prettyPrint
        # we just want to verify that this is RSA-SHA1 and get the public key
        text = self.prettyPrint()
        if not (RSA_ID in text or RSA_SHA1_ID in text):
            raise NotImplementedError("Only RSA-SHA1 X509 certificates are supported.")
        # rip out public key binary
        bits = RX_PUBLIC_KEY.search(text).group(1)

        # 'hex' produces a string with a 0x prefix and, on Python 2, a 'L' suffix.
        # Strip these.
        binhex = hex(int(bits, 2)).lstrip('0x').rstrip('L')
        bindata = base64.b16decode(binhex.upper())

        # Get X509SubjectName string
        # fake this for now; generate later using RX
        cdict['subject'] = 'SubjectName'

        # re-parse RSA Public Key PEM binary
        pubkey = RSAPublicKey()
        key = decoder.decode(bindata, asn1Spec=pubkey)[0]
        cdict.update(key.dict())

        return cdict


class RSAPublicKey(SequenceParser):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer())
    )


def rfc2253_name(map):
    """Return subjectName formatted string from list of pairs.

  Args:
    map: [(str, str)] pairs such that:
      (str, str) = ([x.500 attribute type], value)
  Returns:
    str of rfc2253 formmated name

  Example:
   map = [('2.5.4.3', 'Kille, Steve'), ('2.5.4.10', 'Isode')
   returs: "CN=Kille\, Steve,O=Isode"
  """
    pairs = []
    for code, value in map:
        s = "%s=%s" % (X500_CODE_MAP.get(code, code), value.replace(',', '\,'))
        pairs.append(s)
    name = ','.join(pairs)
    return name


def parse(data):
    """Return elements from parsed X509 certificate data.

  Args:
    data: str of X509 certificate file contents
  Returns:
    {str: value} of notable certificate elements s.t.:
      ['modulus'] = int of included RSA public key
      ['publicExponent'] = int of included RSA public key
      ['subject'] = str of compiled subject in rfc2253 format
      ['body'] = str of X509 DER binary in base64
      ['type'] = str of "X509 PRIVATE"
      ['pem'] = PEM format
  """
    # initialize empty return dictionary
    cdict = {}

    lines = []
    grab = False
    for s in data.splitlines():
        if b'-----' == s[:5] and b"BEGIN" in s:
            if b"CERTIFICATE" not in s:
                raise NotImplementedError("Only PEM Certificates are supported. Header: %s", s)
            grab = True
        elif b'-----' == s[:5] and b"END" in s:
            if b"CERTIFICATE" not in s:
                raise NotImplementedError("Only PEM Certificates are supported. Footer: %s", s)
            grab = False
        else:
            # include this b64 data for decoding
            if grab:
                lines.append(s.strip())

    body = b''.join(lines)
    pem_lines = [b"-----BEGIN CERTIFICATE-----"]
    pem_lines.extend(lines)
    pem_lines.append(b"-----END CERTIFICATE-----")
    pem = b'\n'.join(pem_lines) + b'\n'
    raw_data = base64.b64decode(body)

    cert = decoder.decode(raw_data, asn1Spec=Certificate())[0]

    # dump parsed PEM data to text
    text = cert.prettyPrint()

    # GET RSA KEY
    # ===========
    if not (RSA_ID in text):
        raise NotImplementedError("Only RSA X509 certificates are supported.")
        # rip out RSA public key binary
    key_bits = RX_PUBLIC_KEY.search(text).group(1)
    # 'hex' produces a string with a 0x prefix and, on Python 2, a 'L' suffix.
    # Strip these.
    key_binhex = hex(int(key_bits, 2)).lstrip('0x').rstrip('L')
    key_bin = base64.b16decode(key_binhex.upper())
    # reparse RSA Public Key PEM binary
    key = decoder.decode(key_bin, asn1Spec=RSAPublicKey())[0]
    # add RSA key elements to return dictionary
    cdict.update(key.dict())

    # GET CERTIFICATE SUBJECT
    # =======================
    subject_text = RX_SUBJECT.search(text).group(0)
    attrs = RX_SUBJECT_ATTR.findall(subject_text)
    cdict['subject'] = rfc2253_name(attrs)

    # add base64 encoding and type to return dictionary

    cdict['body'] = body
    cdict['pem'] = pem
    cdict['type'] = "X509 CERTIFICATE"
    cdict['cert'] = cert
    return cdict


def dict_to_tuple(dict):
    """Return RSA PyCrypto tuple from parsed X509 dict with public RSA key.

  Args:
    dict: dict of {str: value} returned from `parse`
  Returns:
    tuple of (int) of RSA public key integers for PyCrypto key construction
  """
    tuple = (
        dict['modulus'],
        dict['publicExponent'],
    )
    return tuple
