from sga_oauth.shared.helpers.encode import encode_parameters
import base64
import httplib


import urllib2



def fetch_oauth(url, headers, data):
    params = encode_parameters(params)
    headers = {"Authorization": "OAuth %s" % params, }
    request = urllib2.Request(url, headers)

    response = urllib2.urlopen(req)
    the_page = response.read()




def fetch_oauth(url, port, path, method, params):

    conn = httplib.HTTPConnection(url, port)
    conn.request(method, path, headers=headers)
    response = conn.getresponse()
    status = response.status
    data = response.read()
    conn.close()
    return data, status


