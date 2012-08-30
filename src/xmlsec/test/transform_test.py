import pkg_resources

__author__ = 'leifj'

import unittest
import lxml.etree as etree
import xmlsec
from xmlsec.test.case import XMLTestData

class TestTransforms(unittest.TestCase):

    def setUp(self):
        self.cases = {}
        for case_n in pkg_resources.resource_listdir(__name__,"data/transform"):
            case = XMLTestData(__name__,"data/transform/%s" % case_n)
            self.cases[case_n] = case

    def test_enveloped1(self):
        case = self.cases['enveloped1']
        out = xmlsec._transform('http://www.w3.org/2000/09/xmldsig#enveloped-signature',case.as_etree('in.xml'))
        self.assertEqual(case.as_buf('out.xml'),etree.tostring(out))

def main():
    unittest.main()

if __name__ == '__main__':
    main()