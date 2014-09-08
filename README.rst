python XML Security
===================

.. image:: https://travis-ci.org/leifj/pyXMLSecurity.svg?branch=master
    :target: https://travis-ci.org/leifj/pyXMLSecurity
    :alt: Build Status
.. image:: https://landscape.io/github/leifj/pyXMLSecurity/master/landscape.png
   :target: https://landscape.io/github/leifj/pyXMLSecurity/master
   :alt: Code Health
.. image:: https://coveralls.io/repos/leifj/pyXMLSecurity/badge.png?branch=master
   :target: https://coveralls.io/r/leifj/pyXMLSecurity?branch=master
   :alt: Coverage
.. image:: https://pypip.in/license/pyXMLSecurity/badge.svg
    :target: https://pypi.python.org/pypi/pyXMLSecurity/
    :alt: License


This is a python implementation of XML-Security - XML-DSIG only right now. There are no
dependencies except lxml currently.

This code was inspired by https://github.com/andrewdyates/xmldsig (this implementation is
a refactor and extension of that implementation) and includes a pure-python RSA implementation
https://github.com/andrewdyates/rsa_x509_pem by and with permission from Andrew Yates.

In order to sign with a PKCS#11-module you need to install pykcs11 (http://www.bit4id.org/pykcs11/)

This package is available under the NORDUnet BSD license (cf LICENSE.txt)

Limitations:

- only support for enveloped signatures
- only support for RSA-SHA1 signatures
- no encryption support

Some of those limitations might be addressed. Patches and pull-requests are most welcome!
