from xmlsec.exceptions import XMLSigException

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
ALGORITHM_SIGNATURE_RSA_RIPEMD = "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160"
ALGORITHM_SIGNATURE_RSA_WHIRLPOOL = "http://www.w3.org/2007/05/xmldsig-more#rsa-whirlpool"

ALGORITHM_SIGNATURE_ECDSA_SHA1 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
ALGORITHM_SIGNATURE_ECDSA_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224"
ALGORITHM_SIGNATURE_ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
ALGORITHM_SIGNATURE_ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
ALGORITHM_SIGNATURE_ECDSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
ALGORITHM_SIGNATURE_ECDSA_RIPEMD160 = "http://www.w3.org/2007/05/xmldsig-more#ecdsa-ripemd160"
ALGORITHM_SIGNATURE_ECDSA_WHIRLPOOL = "http://www.w3.org/2007/05/xmldsig-more#ecdsa-whirlpool"

ALGORITHM_SIGNATURE_RSA_PSS_SHA1_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha1-rsa-MGF1"
ALGORITHM_SIGNATURE_RSA_PSS_SHA224_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha224-rsa-MGF1"
ALGORITHM_SIGNATURE_RSA_PSS_SHA256_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
ALGORITHM_SIGNATURE_RSA_PSS_SHA384_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1"
ALGORITHM_SIGNATURE_RSA_PSS_SHA512_MGF1 = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1"

ALGORITHM_BASE_URIS = ['http://www.w3.org/2000/09/xmldsig',
                       'http://www.w3.org/2001/04/xmldsig-more',
                       'http://www.w3.org/2007/05/xmldsig-more']

# ASN.1 BER SHA1 algorithm designator prefixes (RFC3447)
ASN1_BER_ALG_DESIGNATOR_PREFIX = {
    'SHA1': b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
    'SHA256': b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
    'SHA384': b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
    'SHA512': b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}

sign_alg_xmldsig_digest_to_hashalg_d = {
    ALGORITHM_DIGEST_SHA1:   'SHA1',
    ALGORITHM_DIGEST_SHA256: 'SHA256',
    ALGORITHM_DIGEST_SHA384: 'SHA384',
    ALGORITHM_DIGEST_SHA512: 'SHA512',
}

sign_alg_xmldsig_sig_to_hashalg_d = {
    ALGORITHM_SIGNATURE_RSA_SHA1:   'SHA1',
    ALGORITHM_SIGNATURE_RSA_SHA256: 'SHA256',
    ALGORITHM_SIGNATURE_RSA_SHA384: 'SHA384',
    ALGORITHM_SIGNATURE_RSA_SHA512: 'SHA512',
    ALGORITHM_SIGNATURE_ECDSA_SHA1: 'SHA1',
    ALGORITHM_SIGNATURE_ECDSA_SHA224: 'SHA224',
    ALGORITHM_SIGNATURE_ECDSA_SHA256: 'SHA256',
    ALGORITHM_SIGNATURE_ECDSA_SHA384: 'SHA384',
    ALGORITHM_SIGNATURE_ECDSA_SHA512: 'SHA512',
    ALGORITHM_SIGNATURE_RSA_PSS_SHA1_MGF1: 'SHA1',
    ALGORITHM_SIGNATURE_RSA_PSS_SHA224_MGF1: 'SHA224',
    ALGORITHM_SIGNATURE_RSA_PSS_SHA256_MGF1: 'SHA256',
    ALGORITHM_SIGNATURE_RSA_PSS_SHA384_MGF1: 'SHA384',
    ALGORITHM_SIGNATURE_RSA_PSS_SHA512_MGF1: 'SHA512'
}

def _try_a_to_b(dic, item):
    try:
        return dic[item]
    except KeyError:
        raise XMLSigException("Algorithm '{}' not supported.".format(item))


def sign_alg_xmldsig_sig_to_hashalg(xmldsig_sign_alg):
    return _try_a_to_b(sign_alg_xmldsig_sig_to_hashalg_d, xmldsig_sign_alg)


def sign_alg_xmldsig_digest_to_internal(xmldsig_digest_alg):
    return _try_a_to_b(sign_alg_xmldsig_digest_to_hashalg_d, xmldsig_digest_alg)


def sign_alg_xmldsig_sig_to_sigalg(xmldsig_sign_alg):
    (base, _, method) = xmldsig_sign_alg.rpartition('#')
    if base not in ALGORITHM_BASE_URIS:
        raise XMLSigException("Algorithm '{}' not supported.".format(xmldsig_sign_alg))

    return method.lower()
