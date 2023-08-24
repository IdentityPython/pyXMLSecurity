"""
A simple package to keep track of XML test cases
"""

__author__ = 'leifj'

import os
from defusedxml import lxml
from lxml import etree
from six.moves import StringIO
import xmlsec
from importlib_resources import files


class XMLTestDataException(Exception):
    pass


class XMLTestData():
    def __init__(self, path):
        self.path = path 
        self.data = {}
        for fn in self.path.iterdir():
            if fn.name.endswith(".xml"):
                self.data[fn.name] = fn.read_bytes()

    def has_data(self, n):
        return n in self.data

    def __str__(self):
        return "Testcase {}".format(self.path)

    @property
    def name(self):
        return self.path.name

    def as_buf(self, n):
        assert n in self.data, XMLTestDataException("No data named %s in test case %s" % (n, self))
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
    for case_n in files(__name__).joinpath(path).iterdir():
        if case_n.name[0] != '.': # ignore hidden files/directories
            cases[case_n.name] = XMLTestData(case_n)
    return cases
