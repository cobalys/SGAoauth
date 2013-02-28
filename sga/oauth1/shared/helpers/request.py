from sga_oauth.shared.helpers.encode import encode_parameters
import base64
import httplib


def fetch_oauth(url, port, path, method, params):
    params = encode_parameters(params)
    headers = {"Authorization": "OAuth %s" % params, }
    conn = httplib.HTTPConnection(url, port)
    conn.request(method, path, headers=headers)
    response = conn.getresponse()
    status = response.status
    data = response.read()
    conn.close()
    return data, status
