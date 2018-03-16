"""
A simple package to keep track of XML test cases
"""

__author__ = 'leifj'

import os
import pkg_resources
from defusedxml import lxml
import lxml.etree as etree
from StringIO import StringIO
import xmlsec


class XMLTestDataException(Exception):
    pass


class XMLTestData():
    def __init__(self, base, name):
        self.base = base
        self.name = name
        self.data = {}
        for fn in pkg_resources.resource_listdir(self.base, self.name):
            if fn.endswith(".xml"):
                self.data[fn] = pkg_resources.resource_stream(self.base, "%s/%s" % (self.name, fn)).read()

    def has_data(self, n):
        return n in self.data

    def __str__(self):
        return "Testcase {}/{}".format(self.base, self.name)

    def as_buf(self, n):
        assert n in self.data, XMLTestDataException("No data named %s in test case %s" % (n, self.name))
        return self.data[n]

    def as_etree(self, n, remove_whitespace=False, remove_comments=False):
        return xmlsec.parse_xml(self.as_buf(n), remove_whitespace=remove_whitespace, remove_comments=remove_comments)


def load_test_data(path=None):
    """
    Load files from the resource path and store them in dict.
    """
    if not path:
        return  # fool unittest that executes this function
    cases = {}
    for case_n in pkg_resources.resource_listdir(__name__, path):
        if case_n[0] != '.': # ignore hidden files/directories
            case = XMLTestData(__name__, os.path.join(path, case_n))
            cases[case_n] = case
    return cases
