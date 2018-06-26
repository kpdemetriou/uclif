from bottle import get, run, request, response, redirect, template
from bottle import HTTPError
from datetime import datetime
from UCLIFAuth import UCLIFAuthConfidential, UCLIF_JWT_KEY, UCLIF_AUTH_ENDPOINT, UCLIF_TOKEN_ENDPOINT
from config import *
import json


@get("/")
def route_root():
    return template("sso")


@get("/sso")
def route_sso():
    try:
        ucl_auth = UCLIFAuthConfidential(OAUTH2_CLIENT_ID, OAUTH2_CLIENT_SECRET, OAUTH2_REDIRECT_URI)
        auth_url, state = ucl_auth.url(*OAUTH2_SCOPE_TOKENS)
    except ValueError:
        return HTTPError(500, "Internal server error.")

    response.set_cookie("state", state)
    return redirect(auth_url, 302)


@get("/info")
def route_info():
    param_code = request.params.get("code", None)
    param_state = request.params.get("state", None)
    cookie_state = request.get_cookie("state", None)

    response.set_cookie("state", "", expires=0)

    if not param_code:
        return HTTPError(400, "Missing code parameter.")
    if not param_state:
        return HTTPError(400, "Missing state parameter.")
    if not cookie_state:
        return HTTPError(400, "Missing state cookie.")

    try:
        ucl_auth = UCLIFAuthConfidential(OAUTH2_CLIENT_ID, OAUTH2_CLIENT_SECRET, OAUTH2_REDIRECT_URI)
    except ValueError:
        return HTTPError(500, "Internal server error.")

    try:
        token_type, expires_in, token = ucl_auth.code(param_code, param_state, cookie_state)
    except ValueError:
        return HTTPError(400, "Token acquisition or validation failed.")

    info_oauth2_state = param_state
    info_oauth2_code = param_code
    info_oauth2_token_type = token_type
    info_oauth2_expires_in = expires_in
    info_oauth2_client_id = OAUTH2_CLIENT_ID
    info_oauth2_client_secret = "*" * len(OAUTH2_CLIENT_SECRET)
    info_oauth2_redirect_uri = OAUTH2_REDIRECT_URI
    info_oauth2_auth_endpoint = UCLIF_AUTH_ENDPOINT
    info_oauth2_token_endpoint = UCLIF_TOKEN_ENDPOINT

    info_jwt_iss = token.get("iss", "")
    info_jwt_aud = token.get("aud", "")
    info_jwt_exp = datetime.fromtimestamp(token.get("exp", 0)).strftime("%Y-%m-%d %H:%M:%S")
    info_jwt_nbf = datetime.fromtimestamp(token.get("nbf", 0)).strftime("%Y-%m-%d %H:%M:%S")
    info_jwt_iat = datetime.fromtimestamp(token.get("iat", 0)).strftime("%Y-%m-%d %H:%M:%S")
    info_jwt_jti = token.get("jti", "")

    info_pre_key = UCLIF_JWT_KEY.strip()
    info_pre_jwt = json.dumps(token, indent=4)

    return template(
        "info",
        info_oauth2_state=info_oauth2_state,
        info_oauth2_code=info_oauth2_code,
        info_oauth2_token_type=info_oauth2_token_type,
        info_oauth2_expires_in=info_oauth2_expires_in,
        info_oauth2_client_id=info_oauth2_client_id,
        info_oauth2_client_secret=info_oauth2_client_secret,
        info_oauth2_redirect_uri=info_oauth2_redirect_uri,
        info_oauth2_auth_endpoint=info_oauth2_auth_endpoint,
        info_oauth2_token_endpoint=info_oauth2_token_endpoint,
        info_jwt_iss=info_jwt_iss,
        info_jwt_aud=info_jwt_aud,
        info_jwt_exp=info_jwt_exp,
        info_jwt_nbf=info_jwt_nbf,
        info_jwt_iat=info_jwt_iat,
        info_jwt_jti=info_jwt_jti,
        info_pre_key=info_pre_key,
        info_pre_jwt=info_pre_jwt,
    )


run(server=HTTP_SERVER, host=HTTP_HOST, port=HTTP_PORT, debug=APP_DEBUG, reloader=APP_DEBUG)
