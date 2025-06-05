"""Constants definition."""

DOMAIN = "aigues_barcelona"

CONF_CONTRACT = "contract"
CONF_VALUE = "value"
CONF_TWOCAPTCHA_API_KEY = "twocaptcha_api_key"

ATTR_LAST_MEASURE = "Last measure"

DEFAULT_SCAN_PERIOD = 14400

API_HOST = "api.aiguesdebarcelona.cat"
API_COOKIE_TOKEN = "ofexTokenJwt"

API_ERROR_TOKEN_REVOKED = "JWT Token Revoked"

# 2Captcha constants
RECAPTCHA_V2_PAGEURL = "https://www.aiguesdebarcelona.cat/ca/area-clientes#/login"
RECAPTCHA_V2_SITEKEY = "6LfPoasUAAAAAL5M1txzF5PJ91udHgE5PMm0JWWS"
RECAPTCHA_TIMEOUT = 300  # 5 minutes timeout
RECAPTCHA_MAX_RETRIES = 3