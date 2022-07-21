### TODOs
#### Domain
- [ ] create a device for the router(s)
- [ ] used the mac from host to set router_unique_id
- [ ] use devices that result present and disconnected to understand potential subnet(s) assuming /24
- [ ] the gui on http knows the model of the router without login
- [ ] move storage of device data class from _devices to hass.data
- [ ] remove user and password from config
#### Devices
- [ ] consider device that disappear and not members of subnet(s) as guest lan /24
- [ ] consider device that disappear as disconnected, goal is to have always a readable mac
- [ ] implement removal of disconnected devices
- [ ] consider reverse look-up of the mac for having device manufacturer attributes
#### Other
- [ ] add a cleanup service to just clean the data (i hope only for debug purposes)


#### issues
- [ ] modified names are lost when integration reloads ( or after delete and re-add, not sure) 