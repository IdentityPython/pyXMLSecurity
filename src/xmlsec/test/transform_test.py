import pkg_resources

__author__ = 'leifj'

import unittest
from defusedxml import lxml
import lxml.etree as etree
import xmlsec
from xmlsec.test.case import XMLTestData


class TestTransforms(unittest.TestCase):
    def setUp(self):
        self.cases = {}
        for case_n in pkg_resources.resource_listdir(__name__, "data/transform"):
            case = XMLTestData(__name__, "data/transform/%s" % case_n)
            self.cases[case_n] = case

    def test_enveloped1(self):
        case = self.cases['enveloped1']
        out = xmlsec._transform('http://www.w3.org/2000/09/xmldsig#enveloped-signature',
                                case.as_etree('in.xml', remove_whitespace=False, remove_comments=False))
        self.assertEqual(case.as_buf('out.xml'),etree.tostring(out))

    def test_c14n_1(self):
        """
        Test that whitespaces and newlines are removed properly.
        """
        data = '<foo>\n   <bar>1 </bar   >       \n</foo> \n  \n    '
        expect = '<foo><bar>1 </bar></foo>'
        self.assertEqual(_c14n_parse_test(data), expect)

    def test_c14n_2(self):
        """
        Test that whitespaces and newlines are removed properly.
        """
        data = '<a> <b> 1 </b> </a>'
        expect = '<a><b> 1 </b></a>'
        self.assertEqual(_c14n_parse_test(data), expect)

    def test_c14n_with_comments(self):
        """
        Test that whitespaces and newlines are removed properly with comments retained.
        """
        data = '<a    foo="x ">bar <!-- d a dd a- --> </a >'
        expect = '<a foo="x ">bar <!-- d a dd a- --> </a>'
        self.assertEqual(_c14n_parse_test(data, remove_comments=False), expect)


def _c14n_parse_test(data, remove_whitespace=True, remove_comments=True):
    xml = xmlsec.parse_xml(data, remove_whitespace=remove_whitespace, remove_comments=remove_comments)
    out = xmlsec._c14n(xml, False, with_comments=(not remove_comments))
    print "C14N output (remove_whitespace={}, remove_comments={}) :\n{}".format(remove_whitespace, remove_comments, out)
    return out


def main():
    unittest.main()


if __name__ == '__main__':
    main()
