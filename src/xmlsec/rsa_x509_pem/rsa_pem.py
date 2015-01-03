#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright ©2011 Andrew D. Yates
# andrewyates.name@gmail.com
#
# Modified and redistributed as part of pyXMLSecurity by leifj@mnt.se
# with permission from the original author
#
"""Generate RSA Key from PEM data.

See examples/sshkey.py from pyasn1 for reference.

Much of this module has been adapted from the pyasn1
source code example "pyasn1/examples/sshkey.py" [pyasn1].

USE:

.. code-block:: python

data = open("cert.pem").read()
dict = rsa_pem.parse(data)
n = dict['modulus']
e = dict['publicExponent']
d = dict['privateExponent']


REFERENCES:

pyasn1
"ASN.1 tools for Python"
http://pyasn1.sourceforge.net/
"""
from .pyasn1.type import univ, namedtype, namedval
from .pyasn1.codec.der import decoder
from .utils import SingleAccessCallable

der_decode = SingleAccessCallable(decoder.decode)

from . import sequence_parser

MAX = 16


class RSAPrivateParser(sequence_parser.SequenceParser):
    """PKCS#1 compliant RSA private key structure.
  """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer(namedValues=namedval.NamedValues(('two-prime', 0), ('multi', 1)))),
        # n
        namedtype.NamedType('modulus', univ.Integer()),
        # e
        namedtype.NamedType('publicExponent', univ.Integer()),
        # d
        namedtype.NamedType('privateExponent', univ.Integer()),
        # p
        namedtype.NamedType('prime1', univ.Integer()),
        # q
        namedtype.NamedType('prime2', univ.Integer()),
        # dp
        namedtype.NamedType('exponent1', univ.Integer()),
        # dq
        namedtype.NamedType('exponent2', univ.Integer()),
        # u or inverseQ
        namedtype.NamedType('coefficient', univ.Integer()),
    )


def parse(data, password=None):
    """Return a simple dictionary of labeled numeric key elements from key data.

  TO DO:
    support DSA signatures
    include support for encrypted private keys e.g. DES3

  Args:
    data: str of bytes read from PEM encoded key file
    password: str of password to decrypt key [not supported]
  Returns:
    {str: value} of labeled RSA key elements s.t.:
      ['version'] = int of 0 or 1 meaning "two-key" or "multi" respectively
      ['modulus'] = int of RSA key value `n`
      ['publicExponent'] = int of RSA key value `e`
      ['privateExponent'] = int of RSA key value `d` [optional]
      ['prime1'] = int of RSA key value `p` [optional]
      ['prime2'] = int of RSA key value `q` [optional]
      ['exponent1'] = int of RSA key value `dp` [optional]
      ['exponent2'] = int of RSA key value `dq` [optional]
      ['coefficient'] = int of RSA key value `u` or `inverseQ` [optional]
      ['body'] = str of key DER binary in base64
      ['type'] = str of "RSA PRIVATE"
  """
    lines = []
    ktype = None
    encryption = False
    # read in key lines from keydata string
    for s in data.splitlines():
        # skip file headers
        if '-----' == s[:5] and "BEGIN" in s:
            # Detect RSA or DSA keys
            if "RSA" in s:
                ktype = "RSA"
            elif "DSA" in s:
                ktype = "DSA"
            else:
                ktype = s.replace("-----", "")

        # skip cryptographic headers
        elif ":" in s or " " in s:
            # detect encryption, if any
            if "DEK-Info: " == s[0:10]:
                encryption = s[10:]
        else:
            # include this b64 data for decoding
            lines.append(s.strip())

    body = ''.join(lines)
    raw_data = body.decode("base64")

    # Private Key cipher (Not Handled)
    if encryption:
        raise NotImplementedError("Symmetric encryption is not supported. DEK-Info: %s" % encryption)

    # decode data string using RSA
    if ktype == 'RSA':
        asn1Spec = RSAPrivateParser()
    else:
        raise NotImplementedError("Only RSA is supported. Type was %s." % ktype)

    key = der_decode(raw_data, asn1Spec=asn1Spec)[0]

    # generate return dict base from key dict
    kdict = key.dict()
    # add base64 encoding and type to return dictionary
    kdict['body'] = body
    kdict['type'] = "RSA PRIVATE"

    return kdict


def dict_to_tuple(dict):
    """Return RSA PyCrypto tuple from parsed rsa private dict.

  Args:
    dict: dict of {str: value} returned from `parse`
  Returns:
    tuple of (int) of RSA private key integers for PyCrypto key construction
  """
    tuple = (
        dict['modulus'],
        dict['publicExponent'],
        dict['privateExponent'],
        dict['prime1'],
        dict['prime2'],
        dict['coefficient'],
    )
    return tuple
