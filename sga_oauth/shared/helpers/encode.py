import urllib


def encode_parameters(parameters):
    d = {encode_oauth(k): encode_oauth(v) for k, v in parameters.iteritems()}
    d = iter(sorted(d.iteritems()))
    return ', '.join('%s=%s' % (item[0], item[1]) for item in d)




def encode_oauth(s):
    if isinstance(s, basestring):
        return urllib.quote(s.encode('utf8'), safe='~')
    else:
        return s


def encode_secrets(oauth_consumer_secret, oauth_token_secret=''):
    encoded_secret = '%s&%s' % (encode_oauth(oauth_consumer_secret), 
                                encode_oauth(oauth_token_secret))
    return encode_oauth(encoded_secret)


def encode_for_signature(parameters):
    try:
        del parameters['oauth_signature']
    except:
        pass
    return encode_parameters(parameters)


def url_with_querystring(path, **kwargs):
    return path + '?' + urllib.urlencode(kwargs)

