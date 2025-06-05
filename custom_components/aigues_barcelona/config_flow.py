"""Config flow for integration."""

from __future__ import annotations

import logging
from typing import Any

import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD
from homeassistant.const import CONF_TOKEN
from homeassistant.const import CONF_USERNAME
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError

from .api import AiguesApiClient
from .const import API_ERROR_TOKEN_REVOKED
from .const import CONF_CONTRACT
from .const import CONF_TWOCAPTCHA_API_KEY
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

ACCOUNT_CONFIG_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
        vol.Optional(CONF_TWOCAPTCHA_API_KEY): cv.string,
        vol.Optional(CONF_TOKEN, description="Manual token (optional if using 2Captcha)"): cv.string,
    }
)
TOKEN_SCHEMA = vol.Schema({vol.Required(CONF_TOKEN): cv.string})


def check_valid_nif(username: str) -> bool:
    """Quick check for NIF/DNI/NIE and return if valid."""

    if len(username) != 9:
        return False

    # DNI 12341234D
    if username[0:8].isnumeric() and not username[-1].isnumeric():
        return True

    # NIF X2341234H
    if (
        username[0].upper() in ["X", "Y", "Z"]
        and username[1:8].isnumeric()
        and not username[-1].isnumeric()
    ):
        return True

    return False


async def validate_credentials(
    hass: HomeAssistant, data: dict[str, Any]
) -> dict[str, Any]:
    username = data[CONF_USERNAME]
    password = data[CONF_PASSWORD]
    token = data.get(CONF_TOKEN)
    twocaptcha_key = data.get(CONF_TWOCAPTCHA_API_KEY)

    if not check_valid_nif(username):
        raise InvalidUsername

    try:
        api = AiguesApiClient(username, password, twocaptcha_api_key=twocaptcha_key)
        
        if token:
            # Manual token provided
            api.set_token(token)
        else:
            # Use automatic login with 2Captcha
            if not twocaptcha_key:
                raise MissingTwoCaptchaKey
            
            _LOGGER.info("Attempting automatic login with 2Captcha")
            login = await hass.async_add_executor_job(api.login_with_recaptcha)
            if not login:
                raise InvalidAuth
            _LOGGER.info("Automatic login succeeded!")
            
        contracts = await hass.async_add_executor_job(api.contracts, username)
        available_contracts = [x["contractDetail"]["contractNumber"] for x in contracts]
        return {CONF_CONTRACT: available_contracts}

    except Exception as exp:
        _LOGGER.debug(f"Last data: {api.last_response}")
        
        if "insufficient funds" in str(exp).lower():
            raise InsufficientFunds
        elif "timeout" in str(exp).lower():
            raise RecaptchaTimeout
        elif not api.last_response:
            raise InvalidAuth
        elif (
            isinstance(api.last_response, dict)
            and api.last_response.get("path") == "recaptchaClientResponse"
        ):
            raise RecaptchaAppeared
        elif (
            isinstance(api.last_response, str)
            and api.last_response == API_ERROR_TOKEN_REVOKED
        ):
            raise TokenExpired

        raise InvalidAuth from exp


class AiguesBarcelonaConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 2
    stored_input = dict()

    async def async_step_token(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Return to user step with stored input (previous user creds) and the
        current provided token."""
        return await self.async_step_user({**self.stored_input, **user_input})

    async def async_step_reauth(self, entry) -> FlowResult:
        """Request OAuth Token again when expired."""
        # get previous entity content back to flow
        self.entry = entry
        if hasattr(entry, "data"):
            self.stored_input = entry.data
        else:
            self.stored_input = entry

            # WHAT: for DataUpdateCoordinator, entry is not valid,
            # as it contains only sensor data. Missing entry_id.
            # This recovers the entry_id data.
            if entry := self.hass.config_entries.async_get_entry(
                self.context["entry_id"]
            ):
                self.entry = entry
        return await self.async_step_reauth_confirm(None)

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle reauth with automatic token refresh if 2Captcha is configured."""

        if not user_input:
            # Check if we have 2Captcha configured for automatic reauth
            if self.stored_input.get(CONF_TWOCAPTCHA_API_KEY):
                # Try automatic reauth
                try:
                    user_input = self.stored_input.copy()
                    user_input.pop(CONF_TOKEN, None)  # Remove old token
                    info = await validate_credentials(self.hass, user_input)
                    
                    if info:
                        contracts = info[CONF_CONTRACT]
                        if contracts == self.stored_input.get(CONF_CONTRACT):
                            self.hass.config_entries.async_update_entry(self.entry, data=user_input)
                            self.hass.async_create_task(
                                self.hass.config_entries.async_reload(self.entry.entry_id)
                            )
                            return self.async_abort(reason="reauth_successful")
                
                except Exception as exp:
                    _LOGGER.warning(f"Automatic reauth failed: {exp}")
                    # Fall back to manual token entry
            
            return self.async_show_form(
                step_id="reauth_confirm", data_schema=TOKEN_SCHEMA
            )

        errors = {}
        _LOGGER.debug(
            f"Current values on reauth_confirm: {self.entry} --> {user_input}"
        )
        user_input = {**self.stored_input, **user_input}
        try:
            info = await validate_credentials(self.hass, user_input)
            _LOGGER.debug(f"Result is {info}")
            if not info:  # invalid oauth token
                raise InvalidAuth

            contracts = info[CONF_CONTRACT]
            if contracts != self.stored_input.get(CONF_CONTRACT):
                _LOGGER.error("Reauth failed, contract does not match stored one")
                raise InvalidAuth

            self.hass.config_entries.async_update_entry(self.entry, data=user_input)
            self.hass.async_create_task(
                self.hass.config_entries.async_reload(self.entry.entry_id)
            )

            return self.async_abort(reason="reauth_successful")

        except InvalidUsername:
            errors["base"] = "invalid_auth"
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except InsufficientFunds:
            errors["base"] = "insufficient_funds"
        except RecaptchaTimeout:
            errors["base"] = "recaptcha_timeout"

        return self.async_show_form(
            step_id="reauth_confirm", data_schema=TOKEN_SCHEMA, errors=errors
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle configuration step from UI."""
        if user_input is None:
            return self.async_show_form(
                step_id="user", 
                data_schema=ACCOUNT_CONFIG_SCHEMA,
                description_placeholders={
                    "twocaptcha_info": "Get your API key from https://2captcha.com"
                }
            )

        errors = {}

        try:
            self.stored_input = user_input
            info = await validate_credentials(self.hass, user_input)
            _LOGGER.debug(f"Result is {info}")
            if not info:
                raise InvalidAuth
            contracts = info[CONF_CONTRACT]

            await self.async_set_unique_id(user_input["username"])
            self._abort_if_unique_id_configured()
        except NotImplementedError:
            errors["base"] = "not_implemented"
        except MissingTwoCaptchaKey:
            errors["base"] = "missing_twocaptcha_key"
        except InsufficientFunds:
            errors["base"] = "insufficient_funds"
        except RecaptchaTimeout:
            errors["base"] = "recaptcha_timeout"
        except TokenExpired:
            errors["base"] = "token_expired"
            return self.async_show_form(
                step_id="token", data_schema=TOKEN_SCHEMA, errors=errors
            )
        except RecaptchaAppeared:
            # Ask for OAuth Token to login.
            return self.async_show_form(step_id="token", data_schema=TOKEN_SCHEMA)
        except InvalidUsername:
            errors["base"] = "invalid_auth"
        except InvalidAuth:
            errors["base"] = "invalid_auth"
        except AlreadyConfigured:
            errors["base"] = "already_configured"
        else:
            _LOGGER.debug(f"Creating entity with {user_input} and {contracts=}")
            nif_oculto = user_input[CONF_USERNAME][-3:][0:2]

            return self.async_create_entry(
                title=f"Aigua ****{nif_oculto}", data={**user_input, **info}
            )

        return self.async_show_form(
            step_id="user", data_schema=ACCOUNT_CONFIG_SCHEMA, errors=errors
        )


class AlreadyConfigured(HomeAssistantError):
    """Error to indicate integration is already configured."""


class RecaptchaAppeared(HomeAssistantError):
    """Error to indicate a Recaptcha appeared and requires an OAuth token
    issued."""


class TokenExpired(HomeAssistantError):
    """Error to indicate the OAuth token has expired."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate credentials are invalid."""


class InvalidUsername(HomeAssistantError):
    """Error to indicate invalid username."""


class MissingTwoCaptchaKey(HomeAssistantError):
    """Error to indicate 2Captcha API key is missing."""


class InsufficientFunds(HomeAssistantError):
    """Error to indicate insufficient funds in 2Captcha account."""


class RecaptchaTimeout(HomeAssistantError):
    """Error to indicate reCAPTCHA solving timeout."""