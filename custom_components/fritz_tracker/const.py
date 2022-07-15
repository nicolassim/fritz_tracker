
from fritzconnection.core.exceptions import (
    FritzActionError,
    FritzActionFailedError,
    FritzInternalError,
    FritzLookUpError,
    FritzServiceError,
)
from homeassistant.const import Platform

DOMAIN = "fritz_tracker"

DEFAULT_DEVICE_NAME = "Unknown device"
DEFAULT_HOST = "192.168.2.1"
DEFAULT_PORT = 49000
DEFAULT_USERNAME = "home_assistant"

FRITZ_EXCEPTIONS = (
    FritzActionError,
    FritzActionFailedError,
    FritzInternalError,
    FritzServiceError,
    FritzLookUpError,
)

PLATFORMS = [Platform.DEVICE_TRACKER]

DATA_FRITZ = "fritz_tracker_data"

ERROR_AUTH_INVALID = "invalid_auth"
ERROR_CANNOT_CONNECT = "cannot_connect"
ERROR_UPNP_NOT_CONFIGURED = "upnp_not_configured"
ERROR_UNKNOWN = "unknown_error"
