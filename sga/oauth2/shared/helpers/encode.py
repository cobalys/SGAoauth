import urllib


def x_www_form_urlencoded_encode():
    '''
    Appendix B. Use of application/x-www-form-urlencoded Media Type

    At the time of publication of this specification, the
    "application/x-www-form-urlencoded" media type was defined in
    Section 17.13.4 of [W3C.REC-html401-19991224] but not registered in
    the IANA MIME Media Types registry
    (<http://www.iana.org/assignments/media-types>).  Furthermore, that
    definition is incomplete, as it does not consider non-US-ASCII
    characters.

    To address this shortcoming when generating payloads using this media
    type, names and values MUST be encoded using the UTF-8 character
    encoding scheme [RFC3629] first; the resulting octet sequence then
    needs to be further encoded using the escaping rules defined in
    [W3C.REC-html401-19991224].

    When parsing data from a payload using this media type, the names and
    values resulting from reversing the name/value encoding consequently
    need to be treated as octet sequences, to be decoded using the UTF-8
    character encoding scheme.

    For example, the value consisting of the six Unicode code points
    (1) U+0020 (SPACE), (2) U+0025 (PERCENT SIGN),
    (3) U+0026 (AMPERSAND), (4) U+002B (PLUS SIGN),
    (5) U+00A3 (POUND SIGN), and (6) U+20AC (EURO SIGN) would be encoded
    into the octet sequence below (using hexadecimal notation):

      20 25 26 2B C2 A3 E2 82 AC

    and then represented in the payload as:

      +%25%26%2B%C2%A3%E2%82%AC
    '''
    #MUST be encoded using the UTF-8 character
    #encoding scheme
    #the resulting octet sequence then
    #needs to be further encoded using the escaping rules defined in
    #[W3C.REC-html401-19991224].



def x_www_form_urlencoded_decode():
    urllib.urlencode()
