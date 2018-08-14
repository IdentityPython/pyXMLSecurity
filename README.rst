python XML Security
===================

.. image:: https://img.shields.io/travis/leifj/pyXMLSecurity.svg
   :target: https://travis-ci.org/leifj/pyXMLSecurity
   :alt: Travis Build
.. image:: https://img.shields.io/coveralls/leifj/pyXMLSecurity.svg
   :target: https://coveralls.io/r/leifj/pyXMLSecurity?branch=master
   :alt: Coverage
.. image:: https://img.shields.io/requires/github/leifj/pyXMLSecurity.svg
   :target: https://requires.io/github/leifj/pyXMLSecurity/requirements/?branch=master
   :alt: Requirements Status
.. image:: https://img.shields.io/codeclimate/github/leifj/pyXMLSecurity.svg
   :target: https://codeclimate.com/github/leifj/pyXMLSecurity
   :alt: Code Climate
.. image:: https://img.shields.io/pypi/l/pyXMLSecurity.svg
   :target: https://github.com/leifj/pyXMLSecurity/blob/master/LICENSE.txt
   :alt: License
.. image:: https://img.shields.io/pypi/format/pyXMLSecurity.svg
   :target: https://pypi.python.org/pypi/pyXMLSecurity
   :alt: Format
.. image:: https://img.shields.io/pypi/v/pyXMLSecurity.svg
   :target: https://pypi.python.org/pypi/pyXMLSecurity
   :alt: PyPI Version

This is a python implementation of XML-Security - XML-DSIG only right now. There are no
dependencies except lxml currently.

This code was inspired by https://github.com/andrewdyates/xmldsig (this implementation is
a refactor and extension of that implementation) and includes a pure-python RSA implementation
https://github.com/andrewdyates/rsa_x509_pem by and with permission from Andrew Yates.

In order to sign with a PKCS#11-module you need to install pykcs11 (http://www.bit4id.org/pykcs11/)

This package is available under the NORDUnet BSD license (cf LICENSE.txt)

Limitations:

- only support for enveloped signatures
- only support for RSA signatures
- no encryption support

Some of those limitations might be addressed. Patches and pull-requests are most welcome!
