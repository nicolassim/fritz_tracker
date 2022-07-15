"""HACS Sensor Test Suite."""
# pylint: disable=missing-docstring
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntryType
import pytest

import custom_components.fritz_tracker
from custom_components.fritz_tracker import FritzRouter, DOMAIN

from unittest.mock import patch

import pytest

from homeassistant import config_entries, data_entry_flow
from homeassistant.components.device_tracker.const import (
    CONF_CONSIDER_HOME,
    CONF_SCAN_INTERVAL,
)
from homeassistant.const import CONF_EXCLUDE, CONF_HOSTS, CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import CoreState, HomeAssistant


async def test_form(hass: HomeAssistant) -> None:
    """Test we get the form."""

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] == "form"
    assert result["errors"] == {}

    schema_defaults = result["data_schema"]({})
    assert CONF_SCAN_INTERVAL not in schema_defaults

    with patch(
            "custom_components.fritz_tracker.async_setup_entry",
            return_value=True,
    ) as mock_setup_entry:
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_HOST: "192.168.2.1",
                CONF_PASSWORD: "password",
                CONF_PORT: 49000,
                CONF_USERNAME: "home_assistant",
            },
        )
        await hass.async_block_till_done()

    assert result2["type"] == "create_entry"
    assert result2["title"] == f"Nmap Tracker {4}"
    assert result2["data"] == {}
    assert result2["options"] == {

    }
    assert len(mock_setup_entry.mock_calls) == 1