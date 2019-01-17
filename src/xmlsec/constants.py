from xmlsec.exceptions import XMLSigException


_SHA1_INTERNAL = 'SHA1'
_SHA256_INTERNAL = 'SHA256'
_SHA384_INTERNAL = 'SHA384'
_SHA512_INTERNAL = 'SHA512'

TRANSFORM_ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
TRANSFORM_C14N_EXCLUSIVE_WITH_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'
TRANSFORM_C14N_EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n#'
TRANSFORM_C14N_INCLUSIVE = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'

ALGORITHM_DIGEST_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
ALGORITHM_DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
ALGORITHM_DIGEST_SHA384 = "http://www.w3.org/2001/04/xmlenc#sha384"
ALGORITHM_DIGEST_SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"

ALGORITHM_SIGNATURE_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
ALGORITHM_SIGNATURE_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
ALGORITHM_SIGNATURE_RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
ALGORITHM_SIGNATURE_RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

# ASN.1 BER SHA1 algorithm designator prefixes (RFC3447)
ASN1_BER_ALG_DESIGNATOR_PREFIX = {
    # disabled 'md2': '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02\x05\x00\x04\x10',
    # disabled 'md5': '\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
    _SHA1_INTERNAL: b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
    _SHA256_INTERNAL: b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
    _SHA384_INTERNAL: b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
    _SHA512_INTERNAL: b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}

sign_alg_xmldsig_digest_to_internal_d = {
    ALGORITHM_DIGEST_SHA1:   _SHA1_INTERNAL,
    ALGORITHM_DIGEST_SHA256: _SHA256_INTERNAL,
    ALGORITHM_DIGEST_SHA384: _SHA384_INTERNAL,
    ALGORITHM_DIGEST_SHA512: _SHA512_INTERNAL,
}

sign_alg_xmldsig_sig_to_internal_d = {
    ALGORITHM_SIGNATURE_RSA_SHA1:   _SHA1_INTERNAL,
    ALGORITHM_SIGNATURE_RSA_SHA256: _SHA256_INTERNAL,
    ALGORITHM_SIGNATURE_RSA_SHA384: _SHA384_INTERNAL,
    ALGORITHM_SIGNATURE_RSA_SHA512: _SHA512_INTERNAL,
}


def _try_a_to_b(dic, item):
    try:
        return dic[item]
    except KeyError:
        raise XMLSigException("Algorithm '%s' not supported." % item)


def sign_alg_xmldsig_sig_to_internal(xmldsig_sign_alg):
    return _try_a_to_b(sign_alg_xmldsig_sig_to_internal_d, xmldsig_sign_alg)


def sign_alg_xmldsig_digest_to_internal(xmldsig_digest_alg):
    return _try_a_to_b(sign_alg_xmldsig_digest_to_internal_d, xmldsig_digest_alg)
