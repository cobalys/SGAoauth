class NoResultFound(Exception):
    """A database result was required but none was found."""


class MultipleResultsFound(Exception):
    """A single database result was required but more than one were found."""


class NoSessionKey(Exception):
    """A single database result was required but more than one were found."""


class NonceExists(Exception):
    """A single database result was required but more than one were found."""


class OauthAccessTokenNoValid(Exception):
    ''''''


class OauthError(Exception):
    ''''''
