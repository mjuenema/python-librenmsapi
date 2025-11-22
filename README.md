# librenmsapi

**librenmsapi** is Python client library for the [LibreNMS API](https://docs.librenms.org/API/). 

The Python code (``librenmsapi.py``) is auto-generated from the Markdown files for the LibreNMS API documentation. 
It should therefore be complete, assuming that the LibreNMS API documentation is complete. 

```python
import librenmsapi

URL = 'http://192.168.1.1'
TOKEN = '3231554f57c1d0d05c5c3c0a2da3ba8f6a1b67f2'

client = librenmsapi.LibreNMS(URL, TOKEN):
```

The endpoint categories (Devices, Inventory, Locations, etc.) are available as attributes of the ``LibreNMS`` class
(in lower-case) and the actual endpoints as their methods().

Required inputs must be provided as arguments, optional inputs can be supplied as keyword arguments.

All methods return a Python dictionary, equivalent to the JSON output shown in the [LibreNMS API](https://docs.librenms.org/API/) documentation.

Any API calls that result in an error will raise ``librenmsapi.ApiException``.

```python

result = client.devices.add_device(hostname='localhost', community='public')
print(result)
# {'count': 1,
# 'devices': [{'agent_uptime': 0,
#              'authalgo': None,
#              'authlevel': None,
#              'authname': None,
#              'authpass': None,
#              ...
#              'transport': 'udp',
#              'type': '',
#              'uptime': None,
#              'version': None}],
# 'status': 'ok'}

result = client.devices.get_device('localhost')
print(result)
# {
#    "status": "ok",
#    "devices": [
#        {
#            "device_id": "1",
#            "hostname": "localhost",
#            ...
#            "serial": null,
#            "icon": null
#        }
#    ]
# }
```
