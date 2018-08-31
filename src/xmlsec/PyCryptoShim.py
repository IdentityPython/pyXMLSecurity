"""
Emulate pycrypto RSAobj object as used by former crypto backend 
rsa_x509_pem.
"""

datefmt = "%y%m%d%H%M%SZ"

class RSAobjShim(object):

    def __init__(self, cert):
        self.cert = cert

        self.validity = dict()
        self.validity['notAfter'] = [self.cert.not_valid_after.strftime(datefmt)]
        self.validity['notBefore'] = [self.cert.not_valid_before.strftime(datefmt)]
        self.subject = self.cert.subject
        self.issuer = self.cert.issuer

    def getSubject(self):
        return self.subject

    def get_subject(self):
        return self.getSubject()

    def getIssuer(self):
        return self.issuer

    def get_issuer(self):
        return self.getIssuer()

    def getValidity(self):
        return self.validity

    def getNotAfter(self):
        return self.getValidity()['notAfter'][0]

    def get_notAfter(self):
        return self.getNotAfter()

    def getNotBefore(self):
        return self.getValidity()['notBefore'][0]

    def get_notBefore(self):
        return self.getNotBefore()

    def dict(self):
        raise NotImplementedError("Legacy interface not supported anymore.")
