import os
import unittest
import xmlsec
from xmlsec.Signer import Signer
import pkg_resources
from xmlsec.test.case import load_test_data
from xmlsec import constants, utils
from . import find_alts, run_cmd
import tempfile

XMLSEC1 = find_alts(['/usr/local/bin/xmlsec1', '/usr/bin/xmlsec1'])

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
        signer = Signer(key_spec=self.private_keyspec, cert_spec=self.public_keyspec)
        for case in self.cases.values():
            if case.has_data('in.xml'):
                signed = signer.sign(case.as_etree('in.xml'))
                res = xmlsec.verify(signed, self.public_keyspec)
                self.assertTrue(res)
                with open(self.tmpf.name, "w") as fd:
                    xml_str = utils.etree_to_string(signed)
                    fd.write(xml_str)

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

def main():
    unittest.main()


if __name__ == '__main__':
    main()
