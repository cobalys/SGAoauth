from datetime import datetime
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt
from sga.oauth1.shared.helpers.generators import generate_verifier, \
    generate_timestamp
from sga.oauth1.shared.persistence.models import ClientCredentials, \
    TemporaryCredentials, TokenCredentials
from sga.oauth1.shared.reponses import HttpMissingRequiredParameter, \
    HttpInvalidConsumerKey, HttpInvalidSignature, HttpInvalidExpiredToken, \
    HttpInvalidUsedNonce
from urllib import urlencode, unquote


@csrf_exempt
def temporary_credential_request_endpoint(request):
    '''
    2.1. Temporary Credentials

      The client obtains a set of temporary credentials from the server by
      making an authenticated (Section 3) HTTP "POST" request to the
      Temporary Credential Request endpoint (unless the server advertises
      another HTTP request method for the client to use).  The client
      constructs a request URI by adding the following REQUIRED parameter
      to the request (in addition to the other protocol parameters, using
      the same parameter transmission method):

      oauth_callback:  An absolute URI back to which the server will
                       redirect the resource owner when the Resource Owner
                       Authorization step (Section 2.2) is completed.  If
                       the client is unable to receive callbacks or a
                       callback URI has been established via other means,
                       the parameter value MUST be set to "oob" (case
                       sensitive), to indicate an out-of-band
                       configuration.

      Servers MAY specify additional parameters.

      When making the request, the client authenticates using only the
      client credentials.  The client MAY omit the empty "oauth_token"
      protocol parameter from the request and MUST use the empty string as
      the token secret value.

      Since the request results in the transmission of plain text
      credentials in the HTTP response, the server MUST require the use of
      a transport-layer mechanisms such as TLS or Secure Socket Layer (SSL)
      (or a secure channel with equivalent protections).

      For example, the client makes the following HTTPS request:

        POST /request_temp_credentials HTTP/1.1
        Host: server.example.com
        Authorization: OAuth realm="Example",
           oauth_consumer_key="jd83jd92dhsh93js",
           oauth_signature_method="PLAINTEXT",
           oauth_callback="http%3A%2F%2Fclient.example.net%2Fcb%3Fx%3D1",
           oauth_signature="ja893SD9%26"

      The server MUST verify (Section 3.2) the request and if valid,
      respond back to the client with a set of temporary credentials (in
      the form of an identifier and shared-secret).  The temporary
      credentials are included in the HTTP response body using the
      "application/x-www-form-urlencoded" content type as defined by
      [W3C.REC-html40-19980424] with a 200 status code (OK).

      The response contains the following REQUIRED parameters:

      oauth_token
            The temporary credentials identifier.

      oauth_token_secret
            The temporary credentials shared-secret.

      oauth_callback_confirmed
            MUST be present and set to "true".  The parameter is used to
            differentiate from previous versions of the protocol.

      Note that even though the parameter names include the term 'token',
      these credentials are not token credentials, but are used in the next
      two steps in a similar manner to token credentials.

      For example (line breaks are for display purposes only):

        HTTP/1.1 200 OK
        Content-Type: application/x-www-form-urlencoded

        oauth_token=hdk48Djdsa&oauth_token_secret=xyz4992k83j47x0b&
        oauth_callback_confirmed=true
    '''
    authenticated_request = AuthenticatedRequest(request)
    authenticated_request.verify()

    client_credentials = authenticated_request.client_credentials

    try:
        client_credentials = ClientCredentials.objects.get(oauth_key=client_credentials)
    except Exception, e:
        return HttpInvalidConsumerKey()

    #Create Temporary Credentials
    request_token = TemporaryCredentials()
    request_token.consumer = client_credentials
    request_token.timastamp_created = generate_timestamp(length=8)
    request_token.generate_tokens()
    request_token.callback = authenticated_request.oauth_callback
    request_token.save()

    result = urlencode({
        'oauth_token': request_token.oauth_key,
        'oauth_token_secret': request_token.oauth_secret,
        'oauth_callback_confirmed': 'true'
    })
    return HttpResponse(result, content_type='application/x-www-form-urlencoded')


@csrf_exempt
@login_required
#TODO: ask a cliente authorization to use oath decorator
def resource_owner_authorization_endpoint(request):
    '''
    2.2. Resource Owner Authorization

    Before the client requests a set of token credentials from the
    server, it MUST send the user to the server to authorize the request.
    The client constructs a request URI by adding the following REQUIRED
    query parameter to the Resource Owner Authorization endpoint URI:

    oauth_token
          The temporary credentials identifier obtained in Section 2.1 in
          the "oauth_token" parameter.  Servers MAY declare this
          parameter as OPTIONAL, in which case they MUST provide a way
          for the resource owner to indicate the identifier through other
          means.

    Servers MAY specify additional parameters.

    The client directs the resource owner to the constructed URI using an
    HTTP redirection response, or by other means available to it via the
    resource owner's user-agent.  The request MUST use the HTTP "GET"
    method.

    For example, the client redirects the resource owner's user-agent to
    make the following HTTPS request:

      GET /authorize_access?oauth_token=hdk48Djdsa HTTP/1.1
      Host: server.example.com

    The way in which the server handles the authorization request,
    including whether it uses a secure channel such as TLS/SSL is beyond
    the scope of this specification.  However, the server MUST first
    verify the identity of the resource owner.

    When asking the resource owner to authorize the requested access, the
    server SHOULD present to the resource owner information about the
    client requesting access based on the association of the temporary
    credentials with the client identity.  When displaying any such
    information, the server SHOULD indicate if the information has been
    verified.

    After receiving an authorization decision from the resource owner,
    the server redirects the resource owner to the callback URI if one
    was provided in the "oauth_callback" parameter or by other means.

    To make sure that the resource owner granting access is the same
    resource owner returning back to the client to complete the process,
    the server MUST generate a verification code: an unguessable value
    passed to the client via the resource owner and REQUIRED to complete
    the process.  The server constructs the request URI by adding the
    following REQUIRED parameters to the callback URI query component:

    oauth_token
          The temporary credentials identifier received from the client.

    oauth_verifier
          The verification code.

    If the callback URI already includes a query component, the server
    MUST append the OAuth parameters to the end of the existing query.

    For example, the server redirects the resource owner's user-agent to
    make the following HTTP request:

      GET /cb?x=1&oauth_token=hdk48Djdsa&oauth_verifier=473f82d3 HTTP/1.1
      Host: client.example.net

    If the client did not provide a callback URI, the server SHOULD
    display the value of the verification code, and instruct the resource
    owner to manually inform the client that authorization is completed.
    If the server knows a client to be running on a limited device, it
    SHOULD ensure that the verifier value is suitable for manual entry.
    '''  
    oauth_token = request.GET.get('oauth_token', None)
    try:
        temporary_credentials = TemporaryCredentials.objects.get(oauth_key=oauth_token)
    except:
        return HttpInvalidExpiredToken()
    callback = temporary_credentials.callback
    temporary_credentials.is_approved = True
    temporary_credentials.user = request.user
    temporary_credentials.verifier = generate_verifier()
    temporary_credentials.save()
    callback = callback % (temporary_credentials.oauth_key, temporary_credentials.verifier)
    return HttpResponseRedirect(callback)


@csrf_exempt
def grant_access_token(request):
    '''
    2.3. Token Credentials

    The client obtains a set of token credentials from the server by
    making an authenticated (Section 3) HTTP "POST" request to the Token
    Request endpoint (unless the server advertises another HTTP request
    method for the client to use).  The client constructs a request URI
    by adding the following REQUIRED parameter to the request (in
    addition to the other protocol parameters, using the same parameter
    transmission method):

    oauth_verifier
         The verification code received from the server in the previous
         step.

    When making the request, the client authenticates using the client
    credentials as well as the temporary credentials.  The temporary
    credentials are used as a substitute for token credentials in the
    authenticated request and transmitted using the "oauth_token"
    parameter.

    Since the request results in the transmission of plain text
    credentials in the HTTP response, the server MUST require the use of
    a transport-layer mechanism such as TLS or SSL (or a secure channel
    with equivalent protections).

    For example, the client makes the following HTTPS request:

     POST /request_token HTTP/1.1
     Host: server.example.com
     Authorization: OAuth realm="Example",
        oauth_consumer_key="jd83jd92dhsh93js",
        oauth_token="hdk48Djdsa",
        oauth_signature_method="PLAINTEXT",
        oauth_verifier="473f82d3",
        oauth_signature="ja893SD9%26xyz4992k83j47x0b"

    The server MUST verify (Section 3.2) the validity of the request,
    ensure that the resource owner has authorized the provisioning of
    token credentials to the client, and ensure that the temporary
    credentials have not expired or been used before.  The server MUST
    also verify the verification code received from the client.  If the
    request is valid and authorized, the token credentials are included
    in the HTTP response body using the
    "application/x-www-form-urlencoded" content type as defined by
    [W3C.REC-html40-19980424] with a 200 status code (OK).

    The response contains the following REQUIRED parameters:

    oauth_token
         The token identifier.

    oauth_token_secret
         The token shared-secret.

    For example:

     HTTP/1.1 200 OK
     Content-Type: application/x-www-form-urlencoded

     oauth_token=j49ddk933skd9dks&oauth_token_secret=ll399dj47dskfjdk

    The server must retain the scope, duration, and other attributes
    approved by the resource owner, and enforce these restrictions when
    receiving a client request made with the token credentials issued.

    Once the client receives and stores the token credentials, it can
    proceed to access protected resources on behalf of the resource owner
    by making authenticated requests (Section 3) using the client
    credentials together with the token credentials received.
    '''
    authenticated_request = AuthenticatedRequest(request)
    authenticated_request.verify()

    try:
        request_token = TemporaryCredentials.objects.get(
                                            authenticated_request.oauth_token,
                                            is_approved=True)
        consumer = request_token.consumer
    except Exception, e:
        return HttpInvalidExpiredToken()

    if authenticated_request != request_token.verifier:
        raise Exception("Bad Verifier")

    token_credentials = TokenCredentials()
    token_credentials.consumer = request_token.consumer
    token_credentials.generate_tokens()
    token_credentials.save()
    request_token.delete()

    result = urlencode({
        'oauth_token': token_credentials.oauth_key,
        'oauth_token_secret': token_credentials.oauth_secret
    })
    return HttpResponse(result, content_type='application/x-www-form-urlencoded')
