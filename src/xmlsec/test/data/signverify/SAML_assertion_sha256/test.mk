all: out.xml

out.xml:
	xmlsec1 --sign --privkey-pem ../../test.key --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion in.xml > out.xml
