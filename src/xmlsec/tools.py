"""
xmlsign|xmlverify - pyXMLSecurity cmdline tools
Usage: xmlsign
       [-h]
       -k|--key <keyspec>
       [-c|--cert <certspec>]
       [-o|--output <output>]
       [<xml-file to be signed>]
"""

__author__ = 'leifj'



from . import sign, verify, root_elt

import sys
import getopt
import traceback
import logging
from lxml import etree


def sign_cmd():
    """
    xmlsign command entrypoint
    """

    opts = None
    args = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hk:c:o:r:',
                                   ['help', 'key=', 'cert=', 'version', 'output=', 'loglevel=', 'logfile=', 'reference='])
    except getopt.error, msg:
        print msg
        print __doc__
        sys.exit(2)

    output = None
    keyspec = None
    certspec = None
    reference = ""
    loglevel = logging.WARN
    logfile = None
    for o, a in opts:
        if o in ('-h', '--help'):
            print __doc__
            sys.exit(0)
        elif o in '--version':
            print "pyff version %s" % __version__
            sys.exit(0)
        elif o in ('-k','--key'):
            keyspec = a
        elif o in ('-c','--cert'):
            certspec = a
        elif o in ('-r','--reference'):
            reference = a
        elif o in '--loglevel':
            loglevel = getattr(logging, a.upper(), None)
            if not isinstance(loglevel, int):
                raise ValueError('Invalid log level: %s' % a)
        elif o in '--logfile':
            logfile = a

    log_args = {'level': loglevel}
    if logfile is not None:
        log_args['filename'] = logfile
    logging.basicConfig(**log_args)

    if keyspec is None:
        print "Missing -k|--key argument"
        print __doc__
        sys.exit(0)

    def _output(t):
        if output is not None:
            with open(output, 'w') as xml_out:
                xml_out.write(etree.tostring(t))
        else:
            print etree.tostring(t)

    def _resolve_reference_uri(ref, t): # can probably be improved a bit
        if ref.startswith('@'):
            r = root_elt(t)
            return "#%s" % r.get(ref[1:])
        else:
            return ref

    if len(args) > 0:
        for f in args:
            with open(f) as xml:
                t = etree.parse(xml)
                reference_uri = _resolve_reference_uri(reference, t)
                signed = sign(t, keyspec, certspec, reference_uri=reference_uri)
                if signed:
                    _output(signed)
    else:
        t = etree.parse(sys.stdin)
        reference_uri = _resolve_reference_uri(reference, t)
        signed = sign(t, keyspec, certspec, reference_uri=reference_uri)
        if signed:
            _output(signed)