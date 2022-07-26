### TODOs
#### Domain
- [ ] create a device for the router(s)
- [x] used the mac from host to set router_unique_id
- [ ] use devices that result present and disconnected to understand potential subnet(s) assuming /24
- [x] the gui on http knows the model of the router without login
- [ ] remove user and password from config
#### Devices
- [ ] consider device that disappear and not members of subnet(s) as guest lan /24
- [x] consider device that disappear as disconnected, goal is to have always a readable mac
- [ ] implement removal of disconnected devices, workaround (reload the integration or restart ha) 
- [ ] consider reverse look-up of the mac for having device manufacturer attributes
- [ ] remove clear ip attribute of disconnected devices, and maybe try with "last ip"
#### Other

#### issues
- [ ] restored entities are connected, mark them as not at home.
- [ ] hass.data does not persist on reboot, now looks redundant to _devices. maybe use-less. find more info
- [x] Minimize the number of extra_state_attributes by removing non-critical attributes, removed last_activity.