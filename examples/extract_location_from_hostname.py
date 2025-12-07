#!/usr/bin/env python3

"""Assume that the location is encoded in the hostname as a
   five digit number. Update the location attribute to match
   the number in the hostname.

   This is very specific to the infrastructure I work on
   professionally. I copied the script here as others
   may find it useful, or not ;-)

   MJ, 27-Nov-2025

"""

import re
import librenmsapi
from pprint import pprint

URL = 'http://localhost:8087'
TOKEN = '890bfcacc9d187089c425658c470513f'

# Set-up client
client = librenmsapi.LibreNMS(URL, TOKEN)

for device in client.devices.list_devices()['devices']:

    # Extract the numeric location name from the hostname
    try:
        location_name = str(int(re.findall(r'\d{5}', device['hostname'])[0]))
    except IndexError:
        # No five digit location number encoded in the hostname
        continue

    # Find a matching location or create one
    try:
        location = client.locations.get_location(location_name)
    except librenmsapi.ApiException as e:
        client.locations.add_location(location=location_name, )
        location = client.locations.get_location(location_name)

    print(location)


    sys.exit()






