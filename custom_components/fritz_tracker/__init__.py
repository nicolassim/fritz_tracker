"""Support for AVM Fritz!Box functions."""
import logging

from fritzconnection.core.exceptions import FritzConnectionException
from homeassistant import core
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PORT, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady, ConfigEntryAuthFailed

from .const import FRITZ_EXCEPTIONS, DOMAIN, DATA_FRITZ, PLATFORMS
from .device_tracker import FritzRouter, FritzData

_LOGGER = logging.getLogger(__name__)

# fixme AttributeError: module 'custom_components.fritz_tracker.device_tracker' has no attribute 'async_setup_entry'


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up fritz_router from config entry."""
    _LOGGER.debug("Setting up FRITZ!Box Tools component")
    fritz_router = FritzRouter(
        hass=hass,
        host=entry.data[CONF_HOST],
        port=entry.data[CONF_PORT],
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
    )

    try:
        await fritz_router.async_setup(entry.options)
    except FRITZ_EXCEPTIONS as ex:
        raise ConfigEntryNotReady from ex
    except FritzConnectionException as ex:
        raise ConfigEntryAuthFailed from ex

    # not working with unprivileged user
    # if (
    #         "X_AVM-DE_UPnP1" in fritz_router.connection.services
    #         and not (await fritz_router.async_get_upnp_configuration())["NewEnable"]
    # ):
    #     raise ConfigEntryAuthFailed("Missing UPnP configuration")

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = fritz_router

    if DATA_FRITZ not in hass.data:
        hass.data[DATA_FRITZ] = FritzData()

    entry.async_on_unload(entry.add_update_listener(update_listener))

    await fritz_router.async_config_entry_first_refresh()

    # Load the other platforms like switch
    hass.config_entries.async_setup_platforms(entry, PLATFORMS)
    return True


# async def async_setup(hass: core.HomeAssistant, config: dict) -> bool:
#     """Set up the Fritz Box Device Tracker component."""
#     # @TODO: Add setup code.
#     return True


async def update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Update when config_entry options update."""
    if entry.options:
        await hass.config_entries.async_reload(entry.entry_id)
