"""Integration for Aigues de Barcelona."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.config_entries import SOURCE_REAUTH
from homeassistant.const import CONF_PASSWORD
from homeassistant.const import CONF_TOKEN
from homeassistant.const import CONF_USERNAME
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import issue_registry as ir

from .api import AiguesApiClient
from .const import CONF_TWOCAPTCHA_API_KEY
from .const import DOMAIN
from .service import async_setup as setup_service

# from homeassistant.exceptions import ConfigEntryNotReady

PLATFORMS = [Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:

    api = AiguesApiClient(
        entry.data[CONF_USERNAME], 
        entry.data[CONF_PASSWORD],
        twocaptcha_api_key=entry.data.get(CONF_TWOCAPTCHA_API_KEY)
    )
    
    # Check if we have a manual token or should use 2Captcha
    manual_token = entry.data.get(CONF_TOKEN)
    twocaptcha_key = entry.data.get(CONF_TWOCAPTCHA_API_KEY)
    
    if manual_token:
        api.set_token(manual_token)
        if api.is_token_expired():
            if twocaptcha_key:
                # Try automatic refresh with 2Captcha
                try:
                    await hass.async_add_executor_job(api.login_with_recaptcha)
                except Exception as e:
                    if "insufficient funds" in str(e).lower():
                        # Create repair issue for insufficient funds
                        ir.async_create_issue(
                            hass,
                            DOMAIN,
                            "twocaptcha_insufficient_funds",
                            is_fixable=False,
                            severity=ir.IssueSeverity.WARNING,
                            translation_key="twocaptcha_insufficient_funds",
                            translation_placeholders={"account_url": "https://2captcha.com"},
                        )
                    await hass.config_entries.flow.async_init(
                        DOMAIN,
                        context={"source": SOURCE_REAUTH},
                        data=entry,
                    )
                    return False
            else:
                await hass.config_entries.flow.async_init(
                    DOMAIN,
                    context={"source": SOURCE_REAUTH},
                    data=entry,
                )
                return False
    elif twocaptcha_key:
        # Use 2Captcha for automatic login
        try:
            await hass.async_add_executor_job(api.login_with_recaptcha)
        except Exception as e:
            if "insufficient funds" in str(e).lower():
                # Create repair issue for insufficient funds
                ir.async_create_issue(
                    hass,
                    DOMAIN,
                    "twocaptcha_insufficient_funds",
                    is_fixable=False,
                    severity=ir.IssueSeverity.WARNING,
                    translation_key="twocaptcha_insufficient_funds",
                    translation_placeholders={"account_url": "https://2captcha.com"},
                )
            raise ConfigEntryAuthFailed from e
    else:
        # No token and no 2Captcha key - need one of them
        await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_REAUTH},
            data=entry,
        )
        return False

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    await setup_service(hass, entry)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        if entry.entry_id in hass.data[DOMAIN].keys():
            hass.data[DOMAIN].pop(entry.entry_id)
    if not hass.data[DOMAIN]:
        del hass.data[DOMAIN]

    return unload_ok
