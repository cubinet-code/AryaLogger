#!/usr/bin/env python
"""AryaLogger.

A small server based on SimpleAciUiLogServer that can convert APIC GUI logging
messages to ACI Python SDK (cobra) code.

Depends on SimpleAciUiLogServer, arya and acicobra/acimodel python modules.
"""

import logging
import os
import signal
import socket
import sys
import tempfile
from collections import OrderedDict, namedtuple
from urllib.parse import urlparse, ResultBase, parse_qs
from argparse import ArgumentParser
from SimpleAciUiLogServer import SimpleAciUiLogServer, ThreadingSimpleAciUiLogServer, serve_forever
from cobra.mit.naming import Dn
from arya import arya

SERVER_CERT = b"""
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCc306NrF69glHq
P7mpEA2AgqUbzdUjP7cwACZM5CRxtqDEkwgdX9iUMyhi208CkfJ0GlBQ2l+rEbPX
/mFqaQ+KwRF76uxWQAJh2ja6cc7Y1odcE87uwmdAuvczk8bVawD8roUbHH409LgU
O74rqiObA10UBRy8QitifXiWDdDOafp8BNwt6ShrqUu4utIWimzKTPMHadO+zLTC
y8RI2BG1g8dnPa2TK0u/XbJmdIOawbF85z1GWC4VifwB2LDtRAgbOSy0fybuMG8L
zrqs6isGnNJCbmxkbtRw2m5gJnSLQDB0gsegE0zuZ8IjSaBycS73DhnpeGAJepeU
8DVYDiTLAgMBAAECggEACrxJfu6N6UAy5OoJhaVglyvZqsZyUKA6pCFOfbKbP+D0
rZ82TfRSOQorOGCzzoQ4aHOojW/0XhuvCBgTiJm6A4/k52sTU2+7+gBaAHZrZnF/
//AnGDXbpRVmd3QkhlR1U9WJrGpNxMf+lPvlrs1M9H3Nb+JNriCFIY9eoj49zPJe
Sz81MULMI3pCtMqBiQ3vHP7AIm6NYQqZ+sW7yGquhFUEi8YPxF/3t96KtQFyVFm+
1LDQTG4MR2f5kcUAqncrj8UxTJzpMrTVUqoru0TO6ckkAqZyZp1OuBmcsd9SgekC
aKexj/vGElvASLyO5uvtihtV/0516KnG63mbHDRI8QKBgQDQ2zMwVC6LtGpK+NrD
LPkMdHC4Z1rAfdsfR7yjMsWfyK9TURYNTHe7/7h2BxJLHppcnTmikfSxvLxnds9F
gNCzp6mwTbuk6V1027DmAPRX90affK7NHI2sFIH7nYSZqWq59mqtVmEothLpIFOm
m+FqwZWq+rLbYomoMoF/tZLCgwKBgQDASDQblbDxZ9ODLCRrok5ps05+e1/3l+71
AoY4w/c42F1zTKF1jlnT6RHwT9lwmvjb107L5JnI3TZSZyiPW1YL9ttIeHI86vcp
702ykgP4PdpnwPwfiLzzT5kS1vOSF80ccNiPqToob7VU9aufVx0Rb1sWtXAdj2Kp
Gw2y2UFiGQKBgClKvSMX8Z/jSoSKEM43rQF+X+7FWFboSxMzHqNxXUsK5UbmqCJ2
9NExbKnBGifJ5CDdYNC4ZJVjSCh4f+Aw6JIsWsslgyzGipiY+q9ujuB5XfgYMYMR
2xyjbVNuwBGVQimEA3FDu6/N141Ju+Abv4RYw5trN0NShv6/BYVXQ627AoGAfJxO
aLISAeCviorI75g4CPhTHlUGVIb6LX59TbxyMzzFEzvOR0kBnfulzH9zAy7rqE1Y
m3qCz1HNKooAFyeyE/7fDZBBOIlttJeJWviV6gLrz+GZgzYyfdxP742uPDeAjbX0
IuYg8qOyeGTd3F2wUORBu+3Jwt5xqfYGYqm5XcECgYAnWdE8LD3uLpn8iOObMIi1
E6r5cBKwsJU0ropaMGEQGs6Fo7DTax19QRVXpEgQXS6OedV2eIlgFGJ0b8akXbdM
YSLTFvx0Xl4q+5le2EnPJurf9IW+PYlPczlSnLbZQyDAWxHU/ZJUhM5V2Ed/Ymv6
doytojKYSi9XBL3B5yAHyA==
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIICpjCCAY4CCQCcTR73pIOU9zANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDDAox
MC4xLjEuMjAwMB4XDTIyMDQxOTIxMzc1MFoXDTIzMDQxOTIxMzc1MFowFTETMBEG
A1UEAwwKMTAuMS4xLjIwMDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJzfTo2sXr2CUeo/uakQDYCCpRvN1SM/tzAAJkzkJHG2oMSTCB1f2JQzKGLbTwKR
8nQaUFDaX6sRs9f+YWppD4rBEXvq7FZAAmHaNrpxztjWh1wTzu7CZ0C69zOTxtVr
APyuhRscfjT0uBQ7viuqI5sDXRQFHLxCK2J9eJYN0M5p+nwE3C3pKGupS7i60haK
bMpM8wdp077MtMLLxEjYEbWDx2c9rZMrS79dsmZ0g5rBsXznPUZYLhWJ/AHYsO1E
CBs5LLR/Ju4wbwvOuqzqKwac0kJubGRu1HDabmAmdItAMHSCx6ATTO5nwiNJoHJx
LvcOGel4YAl6l5TwNVgOJMsCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAY7ImvdXl
NPoqb91eW2CF9zi0z+YJSghnMTCnvF25vMky90p43KqaILsvYaMAZWMxw1kbmLc9
AHdrNKqrIj73SMpSocroNG9SQyDiPguEY+FgORa+4SRmeer73c9mboM0FPAJd63E
jk6Ef0Bmlh0vd40vkFcp6z5IKbbFxZq1iVcK05THa9OfO4x57cGzcXGP8BIF79Iq
jmZaSabR2Qg9u+aazMBy4FCnZDZvQtkd60Mf+Jq5HBKruwyRhrwoULx+QdAMnuDF
D7Q2i301zlng06OxKn+fAlRB9tA3grQECLR17lEEE+5zEWeQ2cKMc0kB/iYQpsDO
DeoR995oqt/VWQ==
-----END CERTIFICATE-----
"""


class ApicParseResult(namedtuple('ApicParseResult',
                                 'scheme netloc path params query fragment'),
                      ResultBase):

    """ApicParseResult class.

    Mixin type of class that adds some apic specific properties to the urlparse
    named tuple
    """

    @property
    def dn_or_class(self):
        """Check if a path is for a dn or class."""
        pathparts = self._get_path_parts()
        if pathparts[1] != 'node':
            return self._get_dn_or_class(pathparts, 1)
        else:
            return self._get_dn_or_class(pathparts, 2)

    @property
    def api_format(self):
        """return the api format portion of the URL."""
        return self._get_api_format(self.path)

    @property
    def api_method(self):
        """Return the api method."""
        pathparts = self._get_path_parts()
        if pathparts[1] == 'node':
            return pathparts[2]
        else:
            return pathparts[1]

    @property
    def classnode(self):
        """Return the class or an empty string for mo queries."""
        if self.api_method != 'class':
            return ""
        pathparts = self._get_path_parts()
        if pathparts[1] != 'node':
            return self._get_classnode(pathparts, 3)
        else:
            return self._get_classnode(pathparts, 4)

    @staticmethod
    def _get_classnode(parts, index):
        """Get the class portion of a path."""
        if len(parts) <= index:
            return ""
        else:
            return "/".join(parts[index - 1:-1])

    def _get_path_parts(self):
        """Return a list of path parts."""
        dn_str = self._remove_format_from_path(self.path, self.api_format)
        dn_str = self._sanitize_path(dn_str)
        return dn_str[1:].split("/")

    @staticmethod
    def _remove_format_from_path(path, fmt):
        """Remove the api format from the path, including the ."""
        return path[:-len("." + fmt)]

    @staticmethod
    def _get_api_format(path):
        """Return either xml or json for the api format."""
        if path.endswith(".xml"):
            return 'xml'
        elif path.endswith(".json"):
            return 'json'

    @staticmethod
    def _get_dn_or_class(parts, index):
        """Return just the dn or the class."""
        if parts[index] == 'class':
            return parts[-1]
        elif parts[index] == 'mo':
            return "/".join(parts[index + 1:])
        else:
            return ""

    @staticmethod
    def _sanitize_path(path):
        """Left strip any / from the path."""
        return path.lstrip("/")


def apic_rest_urlparse(url):
    """Parse the APIC REST API URL."""
    atuple = urlparse(url)
    scheme, netloc, path, params, query, fragment = atuple
    return ApicParseResult(scheme, netloc, path, params, query, fragment)


def convert_dn_to_cobra(dn_str):
    """Convert an ACI distinguished name to ACI Python SDK (cobra) code."""
    cobra_dn = Dn.fromString(dn_str)
    parent_mo_or_dn = "''"
    dn_dict = OrderedDict()
    for rname in cobra_dn.rns:
        rn_str = str(rname)
        dn_dict[rn_str] = {}
        dn_dict[rn_str]['namingVals'] = tuple(rname.namingVals)
        dn_dict[rn_str]['moClassName'] = rname.meta.moClassName
        dn_dict[rn_str]['className'] = rname.meta.className
        dn_dict[rn_str]['parentMoOrDn'] = parent_mo_or_dn
        parent_mo_or_dn = rname.meta.moClassName
    cobra_str = ""
    for arn in dn_dict.items():
        if len(arn[1]['namingVals']) > 0:
            nvals = [str(val) for val in arn[1]['namingVals']]
            nvals_str = ", '" + ", ".join(nvals) + "'"
        else:
            nvals_str = ""
        cobra_str += "    # {0} = {1}({2}{3})\n".format(arn[1]['moClassName'],
                                                        arn[1]['className'],
                                                        arn[1]['parentMoOrDn'],
                                                        nvals_str)
    return cobra_str


def parse_apic_options_string(options):
    """Parse the REST API options string."""
    dictmap = {
        'rsp-prop-include':     'propInclude',
        'rsp-subtree-filter':   'subtreePropFilter',
        'rsp-subtree-class':    'subtreeClassFilter',
        'rsp-subtree-include':  'subtreeInclude',
        'query-target':         'queryTarget',
        'target-subtree-class': 'classFilter',
        'query-target-filter':  'propFilter',
        'rsp-subtree':          'subtree',
        'replica':              'replica',
        'target-class':         'targetClass',
        'page':                 'page',
        'page-size':            'pageSize',
        'order-by':             'orderBy',
    }
    qstring = ''
    if options is None or options == '':
        return qstring
    for opt, value in parse_qs(options).items():
        if opt in dictmap.keys():
            val_str = value[0].replace('"', '\"')
            qstring += '    query.{0} = "{1}"\n'.format(dictmap[opt], val_str)
        else:
            qstring += ('    # Query option "{0}" is not'.format(opt) +
                        ' supported by Cobra SDK\n')
    return qstring


def get_dn_query(dn_str):
    """Get the dn query string."""
    cobra_str = "    query = cobra.mit.request.DnQuery('"
    cobra_str += str(dn_str)
    cobra_str += "')"
    return cobra_str


def get_class_query(kls):
    """Get the class query string."""
    cobra_str = "    query = cobra.mit.request.ClassQuery('"
    cobra_str += str(kls)
    cobra_str += "')"
    return cobra_str


def handle_mo(purl, qstring):
    cobra_str2 = convert_dn_to_cobra(purl.dn_or_class)
    cobra_str2 += "    # Direct dn query:\n"
    cobra_str2 += get_dn_query(purl.dn_or_class)
    cobra_str2 += "\n"
    cobra_str = "SDK:\n\n    # Object instantiation:\n"
    cobra_str += "{0}".format(cobra_str2)
    cobra_str += "{0}\n".format(qstring)
    return cobra_str


def handle_class(purl, qstring):
    if purl.classnode != "":
        cobra_str = ""
        cobra_str += "    # Cobra does not support APIC based node " + \
                     "queries at this time\n"
    else:
        cobra_str2 = ""
        cobra_str2 += "    # Direct class query:\n"
        cobra_str2 += get_class_query(purl.dn_or_class)
        cobra_str2 += "\n"
        cobra_str = "SDK:\n\n{0}".format(cobra_str2)
        cobra_str += "{0}\n".format(qstring)
    return cobra_str

def handle_aaa_login(purl, qstring):
    # Special case the login, not sure when this would ever be seen though
    cobra_str = "SDK:\n\n    md.login()"
    return cobra_str


def handle_aaa_logout(purl, qstring):
    # Special case the logout.
    cobra_str = "SDK:\n\n    md.logout()"
    return cobra_str


def process_get(url):
    """Process a get request log message."""
    if 'subscriptionRefresh.json' in url or 'aaaRefresh.json' in url:
        return
    purl = apic_rest_urlparse(url)
    qstring = parse_apic_options_string(purl.query)
    supported_api_methods = {
        'mo': handle_mo,
        'class': handle_class,
        'aaaLogin': handle_aaa_login,
        'aaaLogout': handle_aaa_logout,
    }

    try:
        cobra_str = supported_api_methods[purl.api_method](purl, qstring)
    except KeyError:
        cobra_str = "\n# api method {0} is not supported yet".format(
            purl.api_method)

    logging_str = "GET URL: {0}\n{1}".format(url, cobra_str)
    logging.debug(logging_str)


def process_post(url, payload):
    """Process a post request log message."""
    purl = apic_rest_urlparse(url)
    qstring = parse_apic_options_string(purl.query)
    arya_inst = arya()
    cobra_str = arya_inst.getpython(jsonstr=payload, brief=True)
    cobra_str2 = ""
    for line in cobra_str.split("\n"):
        cobra_str2 += "    {0}\n".format(line)
    return cobra_str2

def undefined(**kwargs):
    """Process an undefined logging message."""
    process_get(kwargs['data']['url'])


def GET(**kwargs):   # pylint:disable=invalid-name
    """Process a GET logging message."""
    process_get(kwargs['data']['url'])


def POST(**kwargs):  # pylint:disable=invalid-name
    """Process a POST logging message."""
    cobra_str = process_post(kwargs['data']['url'], kwargs['data']['payload'])
    logging_str = "POST URL: %s\nPOST Payload:\n%s\nSDK:\n\n%s"

    logging.info(logging_str, kwargs['data']['url'], 
                  kwargs['data']['payload'], cobra_str)

def EventChannelMessage(**kwargs):  # pylint:disable=C0103,W0613
    """Process an event channel logging message."""
    pass


def start_server(args):
    """Start the server threads."""
    # This is used to store the certificate filename
    cert = ""

    # Setup a signal handler to catch control-c and clean up the cert temp file
    # No way to catch sigkill so try not to do that.
    # noinspection PyUnusedLocal
    def sigint_handler(sig, frame):  # pylint:disable=unused-argument
        """A signal handler for interrupt."""
        if not args.cert:
            try:
                os.unlink(cert)
            except OSError:  # pylint:disable=pointless-except
                pass
        print("Exiting...")
        sys.exit(0)

    http_server = None
    https_server = None

    if args.single_server is not None:
        SimpleAciUiLogServer.prettyprint = args.nice_output
        SimpleAciUiLogServer.indent = args.indent
    else:
        ThreadingSimpleAciUiLogServer.prettyprint = args.nice_output
        ThreadingSimpleAciUiLogServer.indent = args.indent

    if args.single_server is None:
        http_server = ThreadingSimpleAciUiLogServer(("", args.port),
                                                log_requests=args.logrequests,
                                                location=args.location,
                                                excludes=args.exclude)
    elif args.single_server == 'http':
        http_server = SimpleAciUiLogServer(("", args.port),
                                           log_requests=args.logrequests,
                                           location=args.location,
                                           excludes=args.exclude)
    if http_server:
        # register our callback functions
        http_server.register_function(POST)
        http_server.register_function(GET)
        http_server.register_function(undefined)
        http_server.register_function(EventChannelMessage)

    if not args.cert and (args.single_server is None or
                          args.single_server == 'https'):
        # Workaround ssl wrap socket not taking a file like object
        cert_file = tempfile.NamedTemporaryFile(delete=False)
        cert_file.write(SERVER_CERT)
        cert_file.close()
        cert = cert_file.name
        print("\n+++WARNING+++ Using an embedded self-signed certificate " +
              "for HTTPS, this is not secure.\n")
    else:
        cert = args.cert

    if args.single_server is None:
        https_server = ThreadingSimpleAciUiLogServer(("", args.sslport),
                                                 cert=cert,
                                                 location=args.location,
                                                 log_requests=args.logrequests,
                                                 excludes=args.exclude,
                                                 request_types=args.request_type)
    elif args.single_server == 'https':
        https_server = SimpleAciUiLogServer(("", args.sslport),
                                            cert=cert,
                                            location=args.location,
                                            log_requests=args.logrequests,
                                            excludes=args.exclude,
                                            request_types=args.request_type)

    if https_server:
        # register our callback functions
        https_server.register_function(POST)
        https_server.register_function(GET)
        https_server.register_function(undefined)
        https_server.register_function(EventChannelMessage)

    signal.signal(signal.SIGINT, sigint_handler)  # Or whatever signal

    # This simply sets up a socket for UDP which has a small trick to it.
    # It won't send any packets out that socket, but this will allow us to
    # easily and quickly interogate the socket to get the source IP address
    # used to connect to this subnet which we can then print out to make for
    # and easy copy/paste in the APIC UI.
    ip_addr = [(s.connect((args.apicip, 80)), s.getsockname()[0], s.close())
               for s in [socket.socket(socket.AF_INET,
                                       socket.SOCK_DGRAM)]][0][1]
    print("serving at:")  # pylint:disable=C0325
    if http_server:
        print("http://{0}:{1}{2}".format(str(ip_addr), str(args.port),
                                         str(args.location)))
    if https_server:
        print("https://{0}:{1}{2}".format(str(ip_addr), str(args.sslport),
                                          str(args.location)))

    print("")  # pylint:disable=C0325
    print("Make sure your APIC(s) are configured to send log messages: " +
          "welcome username -> Start Remote Logging")
    if args.single_server == 'http':
        print("Note: If you connect to the APIC GUI via HTTPS, you need to " +
              "start and use the HTTPS server.")
    elif args.single_server is None:
        print("Note: If you connect to your APIC via HTTPS, configure the " +
              "remote logging to use the https server.")
    print("")

    if http_server and https_server:
        serve_forever([http_server, https_server])
    elif http_server:
        serve_forever([http_server])
    elif https_server:
        serve_forever([https_server])


def main():
    """The main function run when AryaLogger is run in standalone mode."""
    parser = ArgumentParser('Archive APIC Rest API calls in the PythonSDK ' +
                            'syntax')
    parser.add_argument('-a', '--apicip', required=False, default='8.8.8.8',
                        help=('If you have a multihomed system, where the ' +
                              'apic is on a private network, the server ' +
                              'will print the ip address your local system ' +
                              'has a route to 8.8.8.8.  If you want the ' +
                              'server to print a more accurate ip address ' +
                              'for theserver you can tell it the apicip ' +
                              'address.'))

    parser.add_argument('-c', '--cert', type=str, required=False,
                        help=('The server certificate file for ssl ' +
                              'connections, default="server.pem"'))

    parser.add_argument('-e', '--exclude', action='append', nargs='*',
                        default=[], choices=['subscriptionRefresh',
                                             'aaaRefresh', 'aaaLogout',
                                             'HDfabricOverallHealth5min-0',
                                             'topInfo', 'all'],
                        help=('Exclude certain types of common "noise" ' +
                              'queries.'))

    parser.add_argument('-i', '--indent', type=int, default=2, required=False,
                        help=('The number of spaces to indent when pretty ' +
                              'printing'))

    parser.add_argument('-l', '--location', default="/apiinspector",
                        required=False,
                        help=('Location that transaction logs are being ' +
                              'sent to, default=/apiinspector'))

    parser.add_argument('-n', '--nice-output', action='store_true',
                        default=False, required=False,
                        help='Pretty print the response and payload')

    parser.add_argument('-po', '--port', type=int, required=False,
                        default=8987,
                        help='Local port to listen on, default=8987')

    parser.add_argument('-r', '--logrequests', action='store_true',
                        default=False, required=False,
                        help=('Log server requests and response codes to ' +
                              'standard error'))
 
    parser.add_argument('-s', '--sslport', type=int, required=False,
                        default=8443,
                        help=('Local port to listen on for ssl connections, ' +
                              ' default=8443'))

    parser.add_argument('-si', '--single-server', type=str, required=False,
                        default=None, choices=['http', 'https'],
                        help=('Only start either the http server or the ' +
                              'https server, the default is to start both'))

    parser.add_argument('-ty', '--request-type', action='append', nargs='*',
                        default=[], choices=['POST', 'GET', 'undefined',
                                             'EventChannelMessage', 'all'],
                        help=('Only log specific request-types, default is ' +
                              'log all that are supported.'))

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - \n%(message)s')

    if args.exclude:
        # Flatten the list
        args.exclude = [val for sublist in args.exclude for val in sublist]
        if 'all' in args.exclude:
            args.exclude = ['subscriptionRefresh', 'aaaRefresh', 'aaaLogout',
                            'HDfabricOverallHealth5min-0', 'topInfo']

    if args.request_type:
        # Flatten the list
        args.request_type = [val for sublist in args.request_type for val in 
                                 sublist]
        if 'all' in args.request_type:
            args.request_type = ['POST', 'GET', 'undefined',
                                 'EventChannelMessage']
    else:
        args.request_type = ['POST', 'GET', 'undefined', 'EventChannelMessage']

    start_server(args)


if __name__ == '__main__':
    main()
