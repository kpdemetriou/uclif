import requests, binascii, os, re, jwt, validators, urllib.parse
from enum import Enum

UCLIF_HOST = "uclif.philonas.net"
UCLIF_BASE_URI = "https://" + UCLIF_HOST
UCLIF_AUTH_ENDPOINT = UCLIF_BASE_URI + "/oauth2/authorize"
UCLIF_TOKEN_ENDPOINT = UCLIF_BASE_URI + "/oauth2/token"
UCLIF_JWT_ALGORITHM = "ES256"
UCLIF_JWT_KEY = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpu+SHlObpG0B98efRA94sAsTcLc1
usiRZlk80e3mTajFPJy+cIt2/ZxP6AiUOtsT8HLO7JX0OB79ff4oUF7m0g==
-----END PUBLIC KEY-----
"""


class UCLIFAuthScopes(Enum):
    UUID = "uuid"
    TARGETED_ID = "targeted_id"
    USERNAME = "username"
    SCOPED_USERNAME = "scoped_username"
    EMAIL = "email"
    TITLE = "title"
    FIRST_NAME = "first_name"
    LAST_NAME = "last_name"
    FULL_NAME = "full_name"
    DEPARTMENT = "department"
    AFFILIATIONS = "affiliations"
    SCOPED_AFFILIATIONS = "scoped_affiliations"
    GROUPS = "groups"


class UCLIFHelpers:
    @staticmethod
    def create_state():
        return binascii.hexlify(os.urandom(32)).decode("utf8")

    @staticmethod
    def create_uri(uri, qs_params=None, fragment_params=None, clean_fragment=True):
        parts = list(urllib.parse.urlsplit(uri))

        if qs_params:
            qs_dict = dict(urllib.parse.parse_qsl(parts[4]))
            qs_dict.update(qs_params)
            parts[3] = urllib.parse.urlencode(qs_dict)

        if clean_fragment:
            parts[4] = ""

        if fragment_params:
            fragment_dict = dict(urllib.parse.parse_qsl(parts[5]))
            fragment_dict.update(fragment_params)
            parts[4] = urllib.parse.urlencode(fragment_dict)

        return urllib.parse.urlunsplit(parts).replace("+", " ")

    @staticmethod
    def validate_client_id(client_id):
        return re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", client_id)

    @staticmethod
    def validate_client_secret(client_secret):
        return re.match(r"^[0-9a-f]{64}$", client_secret)

    @staticmethod
    def validate_redirect_uri(redirect_uri):
        return validators.url(redirect_uri)

    @staticmethod
    def validate_state(state):
        return re.match(r"^[0-9a-f]{64}$", state)

    @staticmethod
    def validate_code(code):
        return re.match(r"^[0-9a-f]{64}$", code)

    @staticmethod
    def validate_access_token(access_token):
        return re.match(r"^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$", access_token)

    @staticmethod
    def decode_jwt(token, client_id):
        try:
            return jwt.decode(
                token,
                algorithm=UCLIF_JWT_ALGORITHM,
                key=UCLIF_JWT_KEY,
                issuer=UCLIF_HOST,
                audience="{}@{}".format(client_id, UCLIF_HOST),
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "require_exp": True,
                    "require_iat": True,
                    "require_nbf": True,
                },
            )
        except:
            raise ValueError("Invalid token.")


class UCLIFAuthConfidential:
    client_id = None
    client_secret = None
    redirect_uri = None

    def __init__(self, client_id, client_secret, redirect_uri):
        if not UCLIFHelpers.validate_client_id(client_id):
            raise ValueError("Invalid client_id.")
        self.client_id = client_id

        if not UCLIFHelpers.validate_client_secret(client_secret):
            raise ValueError("Invalid client_secret.")
        self.client_secret = client_secret

        if not UCLIFHelpers.validate_redirect_uri(redirect_uri):
            raise ValueError("Invalid redirect_uri.")
        self.redirect_uri = redirect_uri

    def url(self, *scopes):
        scope_tokens = []

        for scope in scopes:
            if not isinstance(scope, UCLIFAuthScopes):
                raise ValueError("Invalid scope: {}".format(repr(scope)))
            scope_tokens.append(scope.value)

        state = UCLIFHelpers.create_state()
        auth_url = UCLIFHelpers.create_uri(
            UCLIF_AUTH_ENDPOINT,
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": " ".join(scope_tokens),
                "state": state,
            },
        )

        return auth_url, state

    def code(self, code, state, saved_state):
        if not UCLIFHelpers.validate_code(code):
            raise ValueError("Invalid code.")
        if not UCLIFHelpers.validate_state(state):
            raise ValueError("Invalid state.")
        if not UCLIFHelpers.validate_state(saved_state):
            raise ValueError("Invalid saved_state.")
        if state != saved_state:
            raise ValueError("State mismatch.")

        try:
            token_response = requests.post(
                UCLIF_TOKEN_ENDPOINT,
                data={
                    "grant_type": "authorization_code",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "redirect_uri": self.redirect_uri,
                    "code": code,
                },
                allow_redirects=False,
            ).json()
        except ValueError:
            raise

        if "token_type" not in token_response:
            raise ValueError("Missing token_type in JSON response.")
        if token_response["token_type"] != "Bearer":
            raise ValueError("Invalid token_type in JSON response.")
        json_token_type = token_response["token_type"]

        if "expires_in" not in token_response:
            raise ValueError("Missing expires_in in JSON response.")
        if not isinstance(token_response["expires_in"], int):
            raise ValueError("Invalid expires_in in JSON response.")
        json_expires_in = token_response["expires_in"]

        if "access_token" not in token_response:
            raise ValueError("Missing access_token in JSON response.")
        if not UCLIFHelpers.validate_access_token(token_response["access_token"]):
            raise ValueError("Invalid access_token in JSON response.")
        json_access_token = token_response["access_token"]

        try:
            token = UCLIFHelpers.decode_jwt(json_access_token, self.client_id)
        except:
            raise ValueError("Invalid access_token in JSON response.")

        return json_token_type, json_expires_in, token

    def token(self, token):
        try:
            return UCLIFHelpers.decode_jwt(token, self.client_id)
        except:
            raise


class UCLIFAuthPublic:
    client_id = None
    redirect_uri = None

    def __init__(self, client_id, redirect_uri):
        if not UCLIFHelpers.validate_client_id(client_id):
            raise ValueError("Invalid client_id.")
        self.client_id = client_id

        if not UCLIFHelpers.validate_redirect_uri(redirect_uri):
            raise ValueError("Invalid redirect_uri.")
        self.redirect_uri = redirect_uri

    def url(self, *scopes):
        scope_tokens = []

        for scope in scopes:
            if not isinstance(scope, UCLIFAuthScopes):
                raise ValueError("Invalid scope: {}".format(repr(scope)))
            scope_tokens.append(scope.value)

        state = UCLIFHelpers.create_state()
        auth_url = UCLIFHelpers.create_uri(
            UCLIF_AUTH_ENDPOINT,
            {
                "response_type": "token",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": " ".join(scope_tokens),
                "state": state,
            },
        )

        return auth_url, state

    def token(self, token):
        try:
            return UCLIFHelpers.decode_jwt(token, self.client_id)
        except:
            raise
