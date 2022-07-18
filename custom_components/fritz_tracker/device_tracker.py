"""Support for scanning a network with nmap."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import random
from types import MappingProxyType
from typing import Any, TypedDict, ValuesView

from fritzconnection import FritzConnection
from fritzconnection.lib.fritzhosts import FritzHosts
from homeassistant.components.device_tracker.config_entry import ScannerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.dispatcher import dispatcher_send, async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import dt as dt_util

from fritzconnection.core.exceptions import FritzConnectionException, FritzSecurityError

from .const import DOMAIN, DEFAULT_USERNAME, DEFAULT_HOST, DEFAULT_PORT, FRITZ_EXCEPTIONS, DATA_FRITZ, \
    DEFAULT_DEVICE_NAME
from homeassistant.helpers import (
    device_registry as dr,
    entity_registry as er,
    update_coordinator,
)

from homeassistant.components.device_tracker.const import (
    CONF_CONSIDER_HOME,
    DEFAULT_CONSIDER_HOME, SOURCE_TYPE_ROUTER,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
        hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up device tracker for FRITZ!Box component."""
    _LOGGER.debug("Starting FRITZ!Box device tracker")
    router: FritzRouter = hass.data[DOMAIN][entry.entry_id]
    data_fritz: FritzData = hass.data[DATA_FRITZ]

    @callback
    def update_fritzbox_device() -> None:
        """Update the values of AVM device."""
        _async_add_entities(router, async_add_entities, data_fritz)

    entry.async_on_unload(
        async_dispatcher_connect(hass, router.signal_device_new, update_fritzbox_device)
    )

    update_fritzbox_device()


@callback
def _async_add_entities(
        fritzbox: FritzRouter,
        async_add_entities: AddEntitiesCallback,
        data_fritz: FritzData,
) -> None:
    """Add new tracker entities from the AVM device."""

    new_tracked = []
    if fritzbox.unique_id not in data_fritz.tracked:
        data_fritz.tracked[fritzbox.unique_id] = set()

    for mac, device in fritzbox.devices.items():
        if device_filter_out_from_trackers(mac, device, data_fritz.tracked.values()):
            continue
        new_entity = FritzBoxTracker(fritzbox, device)
        new_tracked.append(new_entity)
        data_fritz.tracked[fritzbox.unique_id].add(mac)
        _LOGGER.debug(f"New Entity ({mac}) is going to be {'enabled' if new_entity.enabled else 'disabled'} ")
    if new_tracked:
        async_add_entities(new_tracked)


def _is_tracked(mac: str, current_devices: ValuesView) -> bool:
    """Check if device is already tracked."""
    for tracked in current_devices:
        if mac in tracked:
            return True
    return False


def device_filter_out_from_trackers(
        mac: str,
        device: FritzDevice,
        current_devices: ValuesView,
) -> bool:
    """Check if device should be filtered out from trackers."""
    reason: str | None = None
    if device.ip_address == "":
        reason = "Missing IP"
    elif _is_tracked(mac, current_devices):
        reason = "Already tracked"

    if reason:
        _LOGGER.debug(
            "Skip adding device %s [%s], reason: %s", device.hostname, mac, reason
        )
    return bool(reason)


class ExceptionClassSetupMissing(Exception):
    """Raised when a Class func is called before setup."""

    def __init__(self) -> None:
        """Init custom exception."""
        super().__init__("Function called before Class setup")


@dataclass
class FritzData:
    """Storage class for platform global data."""

    tracked: dict = field(default_factory=dict)
    # profile_switches: dict = field(default_factory=dict)


@dataclass
class Device:
    """FRITZ!Box device class."""

    connected: bool
    connected_to: str
    connection_type: str
    ip_address: str
    name: str
    ssid: str | None
    wan_access: bool | None = None


class HostInfo(TypedDict):
    """FRITZ!Box host info class."""

    mac: str
    name: str
    ip: str
    status: bool


class FritzRouter(update_coordinator.DataUpdateCoordinator):
    """FritzBox Router class."""

    def __init__(
            self,
            hass: HomeAssistant,
            password: str,
            username: str = DEFAULT_USERNAME,
            host: str = DEFAULT_HOST,
            port: int = DEFAULT_PORT,
    ) -> None:
        """Initialize FritzRouter class."""
        super().__init__(
            hass=hass,
            logger=_LOGGER,
            name=f"{DOMAIN}-{host}-coordinator",
            update_interval=timedelta(seconds=30),
        )

        self._devices: dict[str, FritzDevice] = {}
        self._options: MappingProxyType[str, Any] | None = None
        self._unique_id: str | None = None
        self.connection: FritzConnection | None = None
        self.fritz_hosts: FritzHosts | None = None
        self.hass = hass
        self.host = host
        # self.device_conn_type: str | None = None
        self.device_is_router: bool = False
        self.password = password
        self.port = port
        self.username = username
        self._model: str | None = None
        # self._current_firmware: str | None = None
        # self._latest_firmware: str | None = None
        # self._update_available: bool = False
        # self._release_url: str | None = None

    async def async_setup(
            self, options: MappingProxyType[str, Any] | None = None
    ) -> None:
        """Wrap up FritzRouter class setup."""
        self._options = options
        await self.hass.async_add_executor_job(self.setup)

    def setup(self) -> None:
        """Set up FritzRouter class."""
        self.connection = FritzConnection(
            address=self.host,
            port=self.port,
            user=self.username,
            password=self.password,
            timeout=60.0,
            pool_maxsize=30,
        )

        if not self.connection:
            _LOGGER.error("Unable to establish a connection with %s", self.host)
            return

        _LOGGER.debug(
            "detected services on %s %s",
            self.host,
            list(self.connection.services.keys()),
        )

        self.fritz_hosts = FritzHosts(fc=self.connection)
        # Not Allowed to unprivileged user
        # info = self.connection.call_action("DeviceInfo:1", "GetInfo")

        # _LOGGER.debug(
        #     "gathered device info of %s %s",
        #     self.host,
        #     {
        #         **info,
        #         "NewDeviceLog": "***omitted***",
        #         "NewSerialNumber": "***omitted***",
        #     },
        # )

        if not self._unique_id:
            # self._unique_id = info["NewSerialNumber"]
            self._unique_id = "id-rnd-" + str(random.randint(1000, 9999))

        # Not Allowed to unprivileged user
        # self._model = info.get("NewModelName")
        self._model = "FritzBox Generic"

        # if "Layer3Forwarding1" in self.connection.services:
        #     if connection_type := self.connection.call_action(
        #             "Layer3Forwarding1", "GetDefaultConnectionService"
        #     ).get("NewDefaultConnectionService"):
        #         # Return NewDefaultConnectionService sample: "1.WANPPPConnection.1"
        #         self.device_is_router = self.connection.call_action(
        #             self.device_conn_type, "GetInfo"
        #         ).get("NewEnable")

    async def async_get_upnp_configuration(self) -> dict[str, Any]:
        """Call X_AVM-DE_UPnP service."""
        return await self.hass.async_add_executor_job(self.get_upnp_configuration)

    @callback
    async def _async_update_data(self) -> None:
        """Update FritzRouter data."""
        try:
            await self.async_scan_devices()
        except FRITZ_EXCEPTIONS as ex:
            raise update_coordinator.UpdateFailed(ex) from ex

    @property
    def unique_id(self) -> str:
        """Return unique id."""
        if not self._unique_id:
            raise ExceptionClassSetupMissing()
        return self._unique_id

    @property
    def model(self) -> str:
        """Return device model."""
        if not self._model:
            raise ExceptionClassSetupMissing()
        return self._model

    @property
    def mac(self) -> str:
        """Return device Mac address."""
        if not self._unique_id:
            raise ExceptionClassSetupMissing()
        return dr.format_mac(self._unique_id)

    @property
    def devices(self) -> dict[str, FritzDevice]:
        """Return devices."""
        return self._devices

    @property
    def signal_device_new(self) -> str:
        """Event specific per FRITZ!Box entry to signal new device."""
        return f"{DOMAIN}-device-new-{self._unique_id}"

    @property
    def signal_device_update(self) -> str:
        """Event specific per FRITZ!Box entry to signal updates in devices."""
        return f"{DOMAIN}-device-update-{self._unique_id}"

    def _update_hosts_info(self) -> list[HostInfo]:
        """Retrieve latest hosts information from the FRITZ!Box."""
        try:
            return self.fritz_hosts.get_hosts_info()
        except Exception as ex:  # pylint: disable=[broad-except]
            if not self.hass.is_stopping:
                raise HomeAssistantError("Error refreshing hosts info") from ex
        return []

    def _service_call_action(
            self,
            service_name: str,
            service_suffix: str,
            action_name: str,
            **kwargs: Any,
    ) -> dict:
        """Return service details."""

        if self.hass.is_stopping:
            """Inform that HA is stopping."""
            _LOGGER.info(f"Cannot execute can {service_name}/{action_name}: HomeAssistant is shutting down")
            return {}

        if f"{service_name}{service_suffix}" not in self.connection.services:
            return {}

        try:
            result: dict = self.connection.call_action(
                f"{service_name}:{service_suffix}",
                action_name,
                **kwargs,
            )
            return result
        except FritzSecurityError:
            _LOGGER.error(
                "Authorization Error: Please check the provided credentials and verify that you can log into the web "
                "interface",
                exc_info=True,
            )
        except FRITZ_EXCEPTIONS:
            _LOGGER.error(
                "Service/Action Error: cannot execute service %s with action %s",
                service_name,
                action_name,
                exc_info=True,
            )
        except FritzConnectionException:
            _LOGGER.error(
                "Connection Error: Please check the device is properly configured for remote login",
                exc_info=True,
            )
        return {}

    def get_upnp_configuration(self) -> dict[str, Any]:
        """Call X_AVM-DE_UPnP service."""

        return self._service_call_action("X_AVM-DE_UPnP", "1", "GetInfo")

    def _update_device_info(self) -> tuple[bool, str | None, str | None]:
        """Retrieve the latest device information from the FRITZ!Box."""
        info = self.connection.call_action("UserInterface1", "GetInfo")
        version = info.get("NewX_AVM-DE_Version")
        release_url = info.get("NewX_AVM-DE_InfoURL")
        return bool(version), version, release_url

    async def async_scan_devices(self, now: datetime | None = None) -> None:
        """Wrap up FritzRouter class scan."""
        await self.hass.async_add_executor_job(self.scan_devices, now)

    def manage_device_info(
            self, dev_info: Device, dev_mac: str, consider_home: bool
    ) -> bool:
        """Update device lists."""
        _LOGGER.debug("Client dev_info: %s", dev_info)

        if dev_mac in self._devices:
            self._devices[dev_mac].update(dev_info, consider_home)
            return False

        _LOGGER.debug(f"Found new device on the FritzBox {dev_mac}, {dev_info.name}.")
        device = FritzDevice(dev_mac, dev_info.name)
        device.update(dev_info, consider_home)
        self._devices[dev_mac] = device
        return True

    def send_signal_device_update(self, new_device: bool) -> None:
        """Signal device data updated."""
        dispatcher_send(self.hass, self.signal_device_update)
        if new_device:
            dispatcher_send(self.hass, self.signal_device_new)

    def scan_devices(self, now: datetime | None = None) -> None:
        """Scan for new devices and return a list of found device ids."""

        if self.hass.is_stopping:
            """Inform that HA is stopping."""
            _LOGGER.info("Cannot execute can devices: HomeAssistant is shutting down")

        _LOGGER.debug("Checking devices for FRITZ!Box device %s", self.host)
        _default_consider_home = DEFAULT_CONSIDER_HOME.total_seconds()
        if self._options:
            consider_home = self._options.get(
                CONF_CONSIDER_HOME, _default_consider_home
            )
        else:
            consider_home = _default_consider_home

        new_device = False
        hosts = {}
        for host in self._update_hosts_info():
            if not host.get("mac"):
                continue

            hosts[host["mac"]] = Device(
                name=host["name"],
                connected=host["status"],
                connected_to="",
                connection_type="",
                ip_address=host["ip"],
                ssid=None,
                wan_access=None,
            )

        _LOGGER.debug(
            "Using old hosts discovery method. (Mesh not supported or user option)"
        )
        for mac, info in hosts.items():
            if self.manage_device_info(info, mac, consider_home):
                new_device = True
        self.send_signal_device_update(new_device)
        return

    @callback
    def _async_remove_empty_devices(
            self, entity_reg: er.EntityRegistry, config_entry: ConfigEntry
    ) -> None:
        """Remove devices with no entities."""

        device_reg = dr.async_get(self.hass)
        device_list = dr.async_entries_for_config_entry(
            device_reg, config_entry.entry_id
        )
        for device_entry in device_list:
            if not er.async_entries_for_device(
                    entity_reg,
                    device_entry.id,
                    include_disabled_entities=True,
            ):
                _LOGGER.info("Removing device: %s", device_entry.name)
                device_reg.async_remove_device(device_entry.id)


class FritzDevice:
    """Representation of a device connected to the FRITZ!Box without Home assistant overhead."""

    def __init__(self, mac: str, name: str) -> None:
        """Initialize device info."""
        self._connected = False
        self._connected_to: str | None = None
        self._connection_type: str | None = None
        self._ip_address: str | None = None
        self._last_activity: datetime | None = None
        self._mac = mac
        self._name = name
        self._ssid: str | None = None
        self._wan_access: bool | None = False

    def update(self, dev_info: Device, consider_home: float) -> None:
        """Update device info."""
        utc_point_in_time = dt_util.utcnow()

        if self._last_activity:
            consider_home_evaluated = (
                                              utc_point_in_time - self._last_activity
                                      ).total_seconds() < consider_home
        else:
            consider_home_evaluated = dev_info.connected

        if not self._name:
            self._name = dev_info.name or self._mac.replace(":", "_")

        self._connected = dev_info.connected or consider_home_evaluated

        if dev_info.connected:
            self._last_activity = utc_point_in_time

        self._connected_to = dev_info.connected_to
        self._connection_type = dev_info.connection_type
        self._ip_address = dev_info.ip_address
        # self._ssid = dev_info.ssid

    @property
    def connected_to(self) -> str | None:
        """Return connected status."""
        return self._connected_to

    @property
    def connection_type(self) -> str | None:
        """Return connected status."""
        return self._connection_type

    @property
    def is_connected(self) -> bool:
        """Return connected status."""
        return self._connected

    @property
    def mac_address(self) -> str:
        """Get MAC address."""
        return self._mac

    @property
    def hostname(self) -> str:
        """Get Name."""
        return self._name

    @property
    def ip_address(self) -> str | None:
        """Get IP address."""
        return self._ip_address

    @property
    def last_activity(self) -> datetime | None:
        """Return device last activity."""
        return self._last_activity

    # property
    # ef ssid(self) -> str | None:
    #    """Return device connected SSID."""
    #    return self._ssid


class FritzDeviceBase(update_coordinator.CoordinatorEntity[FritzRouter]):
    """Entity base class as meant by home assistant for a device connected
        to a FRITZ!Box."""

    def __init__(self, avm_wrapper: FritzRouter, device: FritzDevice) -> None:
        """Initialize a FRITZ!Box device."""
        super().__init__(avm_wrapper)
        self._avm_wrapper = avm_wrapper
        self._mac: str = device.mac_address
        self._name: str = device.hostname or DEFAULT_DEVICE_NAME

    @property
    def name(self) -> str:
        """Return device name."""
        return self._name

    @property
    def ip_address(self) -> str | None:
        """Return the primary ip address of the device."""
        if self._mac:
            return self._avm_wrapper.devices[self._mac].ip_address
        return None

    @property
    def mac_address(self) -> str:
        """Return the mac address of the device."""
        return self._mac

    @property
    def hostname(self) -> str | None:
        """Return hostname of the device."""
        if self._mac:
            return self._avm_wrapper.devices[self._mac].hostname
        return None

    @property
    def should_poll(self) -> bool:
        """No polling needed."""
        return False

    async def async_process_update(self) -> None:
        """Update device."""
        raise NotImplementedError()

    async def async_on_demand_update(self) -> None:
        """Update state."""
        await self.async_process_update()
        self.async_write_ha_state()


class FritzBoxTracker(FritzDeviceBase, ScannerEntity):
    """This represent a tracked device(entity) on the network."""

    def __init__(self, avm_wrapper: FritzRouter, device: FritzDevice) -> None:
        """Initialize a FRITZ!Box device."""
        super().__init__(avm_wrapper, device)
        self._last_activity: datetime | None = device.last_activity

    @property
    def is_connected(self) -> bool:
        """Return device status."""
        return self._avm_wrapper.devices[self._mac].is_connected

    @property
    def unique_id(self) -> str:
        """Return device unique id."""
        return f"{self._mac}_tracker"

    @property
    def mac_address(self) -> str:
        """Return mac_address."""
        return self._mac

    @property
    def icon(self) -> str:
        """Return device icon."""
        if self.is_connected:
            return "mdi:lan-connect"
        return "mdi:lan-disconnect"

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Return the attributes."""
        attrs: dict[str, str] = {}
        device = self._avm_wrapper.devices[self._mac]
        self._last_activity = device.last_activity
        if self._last_activity is not None:
            attrs["last_time_reachable"] = self._last_activity.isoformat(
                timespec="seconds"
            )
        if device.connected_to:
            attrs["connected_to"] = device.connected_to
        if device.connection_type:
            attrs["connection_type"] = device.connection_type
        # if device.ssid:
        #     attrs["ssid"] = device.ssid
        return attrs

    @property
    def source_type(self) -> str:
        """Return tracker source type."""
        return SOURCE_TYPE_ROUTER

    @property
    def entity_registry_enabled_default(self) -> bool:
        return True
