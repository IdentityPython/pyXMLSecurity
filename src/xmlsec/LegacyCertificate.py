
class LegacyCertificate(object):

    def __init__(self, cert):
        self.cert = cert

    def getSubject(self):
        return self.cert.subject

    def get_subject(self):
        return self.getSubject()

    def getIssuer(self):
        return self.cert.issuer

    def get_issuer(self):
        return self.get_issuer()

    def getValidity(self):
        d = dict()
        d['notAfter'] = [self.cert.not_valid_after.strftime("%y%m%d%H%M%SZ")]
        d['notBefore'] = [self.cert.not_valid_before.strftime("%y%m%d%H%M%SZ")]
        return d

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
