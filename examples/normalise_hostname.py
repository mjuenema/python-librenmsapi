#!/usr/bin/env python3

"""Rename all devices whose "hostname" is currently an IP Address
   to their actual hostname if known. Also remove the domain
   name from the host name.

   WARNING: This script is just an example and may not be safe
            to use unless adapted to your specific environment!

   NOTE TO SELF: Does not currently work in lab environment :-(

   MJ, 23-Nov-2025

"""

import ipaddress
import librenmsapi
from pprint import pprint

URL = 'http://localhost:8087'
TOKEN = '890bfcacc9d187089c425658c470513f'

# Set-up client
client = librenmsapi.LibreNMS(URL, TOKEN)

# Iterate over all devices
result = client.devices.list_devices()

# {'count': 489,
#  'devices': [{'agent_uptime': 0,
#              'authalgo': 'md5',
#              'authlevel': 'authPriv',
#              ...,
#              'hostname': '192.168.4.7',
#              ...,
#              'sysname': 'host.example.net',
#              ...},
#              {...}]
#  'status': 'ok'}

for device in result['devices']:

    oldhostname = device['hostname']
    newhostname = oldhostname

    # Simple check if the hostname is an IP address
    try:
        ipaddress.ip_address(oldhostname)
        newhostname = device.get('sysName') 
        # or try to resolve the IP address in DNS
    except ValueError:
        pass

    # Strip domain name from host name.
    if newhostname:
        newhostname = newhostname.split('.')[0]

    #    client.devices.update_device_field(oldhostname, field='override_ip', data=ip.exploded)   # arrays!

    # Rename the device if necessary
    if newhostname != oldhostname and newhostname:
        client.devices.rename_device(oldhostname, newhostname)

