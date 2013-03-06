"""
A simple package to keep track of XML test cases
"""

__author__ = 'leifj'

import pkg_resources
import lxml.etree as etree
from StringIO import StringIO
import xmlsec

class XMLTestDataException(Exception):
    pass

class XMLTestData():

    def __init__(self,base,name):
        self.base = base
        self.name = name
        self.data = {}
        for fn in pkg_resources.resource_listdir(self.base,self.name):
            self.data[fn] = pkg_resources.resource_stream(self.base,"%s/%s" % (self.name,fn)).read()

    def as_buf(self,n):
        assert self.data.has_key(n),XMLTestDataException("No data named %s in test case %s" % (n,self.name))
        return self.data[n]

    def as_etree(self,n,remove_whitespace=True):
        return xmlsec.parse_xml(self.as_buf(n), remove_whitespace)
