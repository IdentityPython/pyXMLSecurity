from defusedxml import lxml
from lxml import etree
import os
import copy
import unittest
import xmlsec
import pkg_resources
from xmlsec.test.case import load_test_data
from xmlsec import constants
from . import find_alts, run_cmd
import tempfile

__author__ = 'ft'

XMLSEC1 = find_alts(['/usr/local/bin/xmlsec1', '/usr/bin/xmlsec1'])


def root(t):
    if hasattr(t, 'getroot') and hasattr(t.getroot, '__call__'):
        return t.getroot()
    else:
        return t


def _get_all_signatures(t):
    res = []
    for sig in t.findall(".//{%s}Signature" % xmlsec.NS['ds']):
        sv = sig.findtext(".//{%s}SignatureValue" % xmlsec.NS['ds'])
        assert sv is not None
        # base64-dance to normalize newlines
        res.append(sv.decode('base64').encode('base64'))
    return res


class TestSignVerifyXmlSec1(unittest.TestCase):
    def setUp(self):
        self.datadir = pkg_resources.resource_filename(__name__, 'data')
        self.private_keyspec = os.path.join(self.datadir, 'test.key')
        self.public_keyspec = os.path.join(self.datadir, 'test.pem')
        self.cases = load_test_data('data/verifyxmlsec1')
        self.tmpf = tempfile.NamedTemporaryFile(delete=False)

    @unittest.skipIf(XMLSEC1 is None, "xmlsec1 binary not installed")
    def test_sign_verify_all(self):
        """
        Run through all testcases, sign and verify using xmlsec1
        """
        for case in self.cases.values():
            if case.has_data('in.xml'):
                signed = xmlsec.sign(case.as_etree('in.xml'),
                                     key_spec=self.private_keyspec,
                                     cert_spec=self.public_keyspec)
                res = xmlsec.verify(signed, self.public_keyspec)
                self.assertTrue(res)
                with open(self.tmpf.name, "w") as fd:
                    fd.write(etree.tostring(signed))

                run_cmd([XMLSEC1,
                         '--verify',
                         '--store-references',
                         '--id-attr:ID', 'urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor',
                         '--id-attr:ID', 'urn:oasis:names:tc:SAML:2.0:metadata:EntitiesDescriptor',
                         '--id-attr:ID', 'urn:oasis:names:tc:SAML:2.0:assertion:Assertion',
                         '--verification-time', '2009-11-01 12:00:00',
                         '--trusted-pem', self.public_keyspec,
                         self.tmpf.name])

    def tearDown(self):
        if os.path.exists(self.tmpf.name):
            pass
            # os.unlink(self.tmpf.name)


class TestVerify(unittest.TestCase):

    def setUp(self):
        self.datadir = pkg_resources.resource_filename(__name__, 'data')
        self.resource_dir = pkg_resources.resource_filename(__name__, '')
        self.cases = load_test_data('data/verify')

    def test_verify_all(self):
        for case in self.cases.values():
            print str(case)
            public_keyspec = os.path.join(self.resource_dir, case.name, "signer.crt")
            res = xmlsec.verify(case.as_etree("in.xml"), public_keyspec)
            self.assertTrue(res)


class TestSignVerify(unittest.TestCase):
    
    def setUp(self):
        self.datadir = pkg_resources.resource_filename(__name__, 'data')
        self.private_keyspec = os.path.join(self.datadir, 'test.key')
        self.public_keyspec = os.path.join(self.datadir, 'test.pem')
        self.cases = load_test_data('data/signverify')

    def test_sign_verify_SAML_assertion1(self):
        """
        Test signing a SAML assertion, and making sure we can verify it.
        """
        case = self.cases['SAML_assertion1']
        print("XML input :\n{}\n\n".format(case.as_buf('in.xml')))

        signed = xmlsec.sign(case.as_etree('in.xml'),
                             key_spec=self.private_keyspec,
                             cert_spec=self.public_keyspec)
        res = xmlsec.verify(signed, self.public_keyspec)
        self.assertTrue(res)

    def test_sign_verify_SAML_assertion_sha256(self):
        """
        Test signing a SAML assertion using sha256, and making sure we can verify it.
        """
        case = self.cases['SAML_assertion_sha256']
        print("XML input :\n{}\n\n".format(case.as_buf('in.xml')))

        signed = xmlsec.sign(case.as_etree('in.xml'),
                             key_spec=self.private_keyspec,
                             cert_spec=self.public_keyspec)
        res = xmlsec.verify(signed, self.public_keyspec)
        self.assertTrue(res)

    def test_sign_verify_SAML_assertion_unwrap2(self):
        """
        Test signing a SAML assertion, and return verified data.
        """
        case = self.cases['SAML_assertion1']
        print("XML input :\n{}\n\n".format(case.as_buf('in.xml')))

        tbs = case.as_etree('in.xml')
        signed = xmlsec.sign(tbs,
                             key_spec=self.private_keyspec,
                             cert_spec=self.public_keyspec)
        refs = xmlsec.verified(signed, self.public_keyspec)
        self.assertTrue(len(refs) == 1)
        print("verified XML: %s" % etree.tostring(refs[0]))
        self.assertTrue(tbs.tag == refs[0].tag)
        set1 = set(etree.tostring(i, method='c14n') for i in root(tbs))
        set2 = set(etree.tostring(i, method='c14n') for i in root(refs[0]))
        self.assertTrue(set1 == set2)

    def test_wrapping_attack(self):
        """
        Test resistance to attempted wrapping attack
        """
        case = self.cases['SAML_assertion1']
        print("XML input :\n{}\n\n".format(case.as_buf('in.xml')))
        tbs = case.as_etree('in.xml')
        signed = xmlsec.sign(tbs,
                             key_spec=self.private_keyspec,
                             cert_spec=self.public_keyspec)
        attack = case.as_etree('evil.xml')
        attack.append(signed)
        refs = xmlsec.verified(attack, self.public_keyspec)
        self.assertTrue(len(refs) == 1)
        print("verified XML: %s" % etree.tostring(refs[0]))
        seen_foo = False
        seen_bar = False
        for av in refs[0].findall(".//{%s}AttributeValue" % 'urn:oasis:names:tc:SAML:2.0:assertion'):
            print(etree.tostring(av))
            print(av.text)
            if av.text == 'Foo':
                seen_foo = True
            elif av.text == 'Bar':
                seen_bar = True
            self.assertTrue(av.text != 'admin')
        self.assertTrue(seen_foo and seen_bar)

    def test_sign_SAML_assertion1(self):
        """
        Test signing a SAML assertion, and compare resulting signature with that of another implementation (xmlsec1).
        """
        case = self.cases['SAML_assertion1']
        print("XML input :\n{}\n\n".format(case.as_buf('in.xml')))

        signed = xmlsec.sign(case.as_etree('in.xml'),
                             key_spec=self.private_keyspec,
                             cert_spec=self.public_keyspec)
        expected = case.as_etree('out.xml')

        # extract 'SignatureValue's
        expected_sv = _get_all_signatures(expected)
        signed_sv = _get_all_signatures(signed)

        print "Signed   SignatureValue: %s" % (repr(signed_sv))
        print "Expected SignatureValue: %s" % (repr(expected_sv))

        self.assertEqual(signed_sv, expected_sv)

    def test_sign_SAML_assertion_sha256(self):
        """
        Test signing a SAML assertion using sha256, and compare resulting signature with that of another implementation (xmlsec1).
        """
        case = self.cases['SAML_assertion_sha256']
        print("XML input :\n{}\n\n".format(case.as_buf('in.xml')))

        signed = xmlsec.sign(case.as_etree('in.xml'),
                             key_spec=self.private_keyspec,
                             cert_spec=self.public_keyspec)
        expected = case.as_etree('out.xml')

        # extract 'SignatureValue's
        expected_sv = _get_all_signatures(expected)
        signed_sv = _get_all_signatures(signed)

        print "Signed   SignatureValue: %s" % (repr(signed_sv))
        print "Expected SignatureValue: %s" % (repr(expected_sv))

        self.assertEqual(signed_sv, expected_sv)

    def test_duo_vuln_attack(self):
        """
        Test https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations
        """
        case = self.cases['SAML_assertion_sha256']
        print("XML input :\n{}\n\n".format(case.as_buf('in.xml')))

        signed = xmlsec.sign(case.as_etree('in.xml'),
                             key_spec=self.private_keyspec,
                             cert_spec=self.public_keyspec)
        refs = xmlsec.verified(signed, self.public_keyspec)
        self.assertTrue(len(refs) == 1)
        print("verified XML: %s" % etree.tostring(refs[0]))
        assert('evil' not in [x.text for x in refs[0].findall(".//{%s}AttributeValue" % 'urn:oasis:names:tc:SAML:2.0:assertion')])

    def test_verify_SAML_assertion1(self):
        """
        Test that we can verify signatures created by another implementation (xmlsec1).
        """
        case = self.cases['SAML_assertion1']
        print("XML input :\n{}\n\n".format(case.as_buf('out.xml')))

        res = xmlsec.verify(case.as_etree('out.xml'),
                            self.public_keyspec)
        self.assertTrue(res)

    def test_verify_SAML_assertion2(self):
        """
        Test that we reject a modified XML document.
        """
        case = copy.deepcopy(self.cases['SAML_assertion1'])

        # modify the givenName in the XML and make sure the signature
        # does NOT validate anymore
        case.data['out.xml'] = case.data['out.xml'].replace('>Bar<', '>Malory<')

        print("XML input :\n{}\n\n".format(case.as_buf('out.xml')))
        with self.assertRaises(xmlsec.XMLSigException):
            res = xmlsec.verify(case.as_etree('out.xml'), self.public_keyspec)
            print(res)

    def test_sign_xades(self):
        """
        Test that we can sign an already signed document without breaking the first signature
        """

        case = self.cases['dont_break_xades']
        t = case.as_etree('in.xml')

        signed = xmlsec.sign(t, self.private_keyspec)
        self.assertIsNotNone(signed)
        digests = [dv.text for dv in signed.findall('.//{%s}DigestValue' % xmlsec.NS['ds'])]
        assert 'JvmW5vKjaTEVHzOdiC/H3HSGNocGamY9sDeU86ld6TA=' in digests
        res = xmlsec.verify(signed, self.public_keyspec)
        self.assertTrue(res)

    def test_mm1(self):
        case = self.cases['mm1']
        signed = xmlsec.sign(case.as_etree('in.xml'),
                             key_spec=self.private_keyspec,
                             cert_spec=self.public_keyspec)
        print etree.tostring(signed)

    def test_mm2(self):
        case = self.cases['mm2']
        t = case.as_etree('in.xml')
        xmlsec.add_enveloped_signature(t,
                                       pos=-1,
                                       c14n_method=constants.TRANSFORM_C14N_EXCLUSIVE,
                                       digest_alg=constants.ALGORITHM_DIGEST_SHA1,
                                       signature_alg=constants.ALGORITHM_SIGNATURE_RSA_SHA1,
                                       transforms=[constants.TRANSFORM_ENVELOPED_SIGNATURE])
        signed = xmlsec.sign(t,
                             key_spec=self.private_keyspec,
                             cert_spec=self.public_keyspec)

        expected = case.as_etree('out.xml')

        print " --- Expected"
        print etree.tostring(expected)
        print " --- Actual"
        print etree.tostring(signed)

        # extract 'SignatureValue's
        expected_sv = _get_all_signatures(expected)
        signed_sv = _get_all_signatures(signed)

        print "Signed   SignatureValue: %s" % (repr(signed_sv))
        print "Expected SignatureValue: %s" % (repr(expected_sv))

        self.assertEqual(signed_sv, expected_sv)

    def test_mm_with_xmlsec1(self):
        case = self.cases['mm3']
        t = case.as_etree('in.xml')
        signed = xmlsec.sign(t,
                             key_spec=self.private_keyspec,
                             cert_spec=self.public_keyspec)

        expected = case.as_etree('out.xml')

        print " --- Expected"
        print etree.tostring(expected)
        print " --- Actual"
        print etree.tostring(signed)

        # extract 'SignatureValue's
        expected_sv = _get_all_signatures(expected)
        signed_sv = _get_all_signatures(signed)

        print "Signed   SignatureValue: %s" % (repr(signed_sv))
        print "Expected SignatureValue: %s" % (repr(expected_sv))

        self.assertEqual(signed_sv, expected_sv)

    def test_mm_with_java(self):
        case = self.cases['mm4']
        t = case.as_etree('in.xml')
        signed = xmlsec.sign(t,
                             key_spec=self.private_keyspec,
                             cert_spec=self.public_keyspec)

        expected = case.as_etree('out.xml')

        print " --- Expected"
        print etree.tostring(expected)
        print " --- Actual"
        print etree.tostring(signed)

        # extract 'SignatureValue's
        expected_sv = _get_all_signatures(expected)
        signed_sv = _get_all_signatures(signed)

        print "Signed   SignatureValue: %s" % (repr(signed_sv))
        print "Expected SignatureValue: %s" % (repr(expected_sv))

        self.assertEqual(signed_sv, expected_sv)

    def test_mm_with_java_alt(self):
        case = self.cases['mm5']
        t = case.as_etree('in.xml')
        xmlsec.add_enveloped_signature(t,
                                       pos=-1,
                                       c14n_method=constants.TRANSFORM_C14N_EXCLUSIVE,
                                       digest_alg=constants.ALGORITHM_DIGEST_SHA1,
                                       signature_alg=constants.ALGORITHM_SIGNATURE_RSA_SHA1,
                                       transforms=[constants.TRANSFORM_ENVELOPED_SIGNATURE])
        signed = xmlsec.sign(t,
                             key_spec=self.private_keyspec,
                             cert_spec=self.public_keyspec)

        expected = case.as_etree('out.xml')

        print " --- Expected"
        print etree.tostring(expected)
        print " --- Actual"
        print etree.tostring(signed)

        # extract 'SignatureValue's
        expected_sv = _get_all_signatures(expected)
        signed_sv = _get_all_signatures(signed)

        print "Signed   SignatureValue: %s" % (repr(signed_sv))
        print "Expected SignatureValue: %s" % (repr(expected_sv))

        self.assertEqual(signed_sv, expected_sv)

    def test_mm_with_inner_signature(self):
        expected_digest = 'd62qF9gk1F1/JcdUrtJUqPtoMHc='
        case = self.cases['mm6']
        t = case.as_etree('in.xml')

        xmlsec.add_enveloped_signature(t,
                                       pos=-1,
                                       c14n_method=constants.TRANSFORM_C14N_EXCLUSIVE,
                                       digest_alg=constants.ALGORITHM_DIGEST_SHA1,
                                       signature_alg=constants.ALGORITHM_SIGNATURE_RSA_SHA1,
                                       transforms=[constants.TRANSFORM_ENVELOPED_SIGNATURE])
        signed = xmlsec.sign(t,
                             key_spec=self.private_keyspec,
                             cert_spec=self.public_keyspec,
                             sig_path="./{http://www.w3.org/2000/09/xmldsig#}Signature")

        expected = case.as_etree('out.xml')

        sig = t.find("./{%s}Signature" % xmlsec.NS['ds'])
        digest = sig.findtext('.//{%s}DigestValue' % xmlsec.NS['ds'])

        print " --- Expected digest value"
        print expected_digest
        print " --- Actual digest value"
        print digest

        print " --- Expected"
        print etree.tostring(expected)
        print " --- Actual"
        print etree.tostring(signed)

        # extract 'SignatureValue's
        expected_sv = _get_all_signatures(expected)
        signed_sv = _get_all_signatures(signed)

        print "Signed   SignatureValue: %s" % (repr(signed_sv))
        print "Expected SignatureValue: %s" % (repr(expected_sv))

        self.assertEquals(digest, expected_digest)
        self.assertEqual(signed_sv, expected_sv)

    def test_verify_href(self):
        case = self.cases['href']
        t = case.as_etree('href.xml', remove_comments=False, remove_whitespace=False)
        href_signer = os.path.join(self.datadir, "signverify/href/href-metadata-signer-2011.crt")
        res = xmlsec.verify(t, href_signer)
        self.assertTrue(res)

    def test_edugain_with_xmlsec1(self):
        case = self.cases['edugain']
        t = case.as_etree('xmlsec1_in.xml')
        signed = xmlsec.sign(t,
                             key_spec=self.private_keyspec,
                             cert_spec=self.public_keyspec)

        expected = case.as_etree('xmlsec1_out.xml')

        print " --- Expected"
        print etree.tostring(expected)
        print " --- Actual"
        print etree.tostring(signed)

        # extract 'SignatureValue's
        expected_sv = _get_all_signatures(expected)
        signed_sv = _get_all_signatures(signed)

        print "Signed   SignatureValue: %s" % (repr(signed_sv))
        print "Expected SignatureValue: %s" % (repr(expected_sv))


def main():
    unittest.main()


if __name__ == '__main__':
    main()
