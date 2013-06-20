from lxml import etree
from pyff.utils import root

__author__ = 'ft'

import os
import copy
import unittest
import xmlsec
import pkg_resources
from xmlsec.test.case import load_test_data


def _get_all_signatures(t):
    res = []
    for sig in t.findall(".//{%s}Signature" % xmlsec.NS['ds']):
        sv = sig.findtext(".//{%s}SignatureValue" % xmlsec.NS['ds'])
        assert sv is not None
        # base64-dance to normalize newlines
        res.append(sv.decode('base64').encode('base64'))
    return res


class TestTransforms(unittest.TestCase):
    def setUp(self):
        datadir = pkg_resources.resource_filename(__name__, 'data')
        self.private_keyspec = os.path.join(datadir, 'test.key')
        self.public_keyspec = os.path.join(datadir, 'test.pem')

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
            xmlsec.verify(case.as_etree('out.xml'), self.public_keyspec)


def main():
    unittest.main()


if __name__ == '__main__':
    main()
