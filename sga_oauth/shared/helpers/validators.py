from sga_oauth.shared.helpers.signature import sign_request
import time


def check_timestamp(timestamp):
    timestamp_threshold = 300
    timestamp = int(timestamp)
    now = int(time.time())
    lapsed = now - timestamp
    if lapsed > timestamp_threshold:
        return False
    else:
        return True


def check_signature(signature, method, request, parameters, oauth_consumer_secret, oauth_token_secret=''):
    signature_confirmation = sign_request(method, parameters, oauth_consumer_secret, oauth_token_secret)
    if signature == signature_confirmation:
        return True
    else:
        return False

