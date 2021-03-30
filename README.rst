python XML Security
===================

.. image:: https://img.shields.io/travis/IdentityPython/pyXMLSecurity.svg
   :target: https://travis-ci.org/IdentityPython/pyXMLSecurity
   :alt: Travis Build
.. image:: https://img.shields.io/coveralls/IdentityPython/pyXMLSecurity.svg
   :target: https://coveralls.io/r/IdentityPython/pyXMLSecurity?branch=master
   :alt: Coverage
.. image:: https://api.codeclimate.com/v1/badges/a99a88d28ad37a79dbf6/test_coverage
   :target: https://codeclimate.com/github/codeclimate/codeclimate/test_coverage
   :alt: Test Coverage
.. image:: https://api.codeclimate.com/v1/badges/a99a88d28ad37a79dbf6/maintainability
   :target: https://codeclimate.com/github/codeclimate/codeclimate/maintainability
   :alt: Maintainability
.. image:: https://img.shields.io/pypi/l/pyXMLSecurity.svg
   :target: https://github.com/IdentityPython/pyXMLSecurity/blob/master/LICENSE.txt
   :alt: License
.. image:: https://img.shields.io/pypi/format/pyXMLSecurity.svg
   :target: https://pypi.python.org/pypi/pyXMLSecurity
   :alt: Format
.. image:: https://img.shields.io/pypi/v/pyXMLSecurity.svg
   :target: https://pypi.python.org/pypi/pyXMLSecurity
   :alt: PyPI Version

This is a python implementation of XML-Security - XML-DSIG only right now. There are no
dependencies except lxml and pyca/cryptography currently.

This code was inspired by https://github.com/andrewdyates/xmldsig (this implementation is
a refactor and extension of that implementation) and in former versions used to include a
pure-python RSA implementation https://github.com/andrewdyates/rsa_x509_pem by and with
permission from Andrew Yates. Cryptographic primitives are now provided by
pyca/cryptography (https://cryptography.io).

In order to sign with a PKCS#11-module you need to install pykcs11 (http://www.bit4id.org/pykcs11/)

This package is available under the NORDUnet BSD license (cf LICENSE.txt)

Limitations:

- only support for RSA-SHA1/256/512 signatures with PKCS1.5 padding
- no encryption support

Some of those limitations might be addressed. Patches and pull-requests are most welcome!
