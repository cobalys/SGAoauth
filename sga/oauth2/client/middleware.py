

class OauthMiddleware(object):

    def process_exception(self, request, exception):
        print str(exception)
        #OauthAccessTokenNoValid