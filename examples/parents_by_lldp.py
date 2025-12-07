#!/usr/bin/env python3

"""Model parent/child relationships based on LLDP data.

   This script deliberately only adds parent/child relationships 
   but does not remove existing ones. This is to prevent them
   from being removed if a parent device is down. In that case
   the parent/child relationship is to be preserved for the 
   purpose of detecting device dependencies for alarming.

   Outdated parent/child relationships must be removed either
   manually in the GUI or through a separate script and the
   applocable logic.

   Calling the `add_parents_to_host()` method seems to overwrite
   existing parent/child relationships so we have to collect 
   all parents first before making the API call.

"""

import collections
import librenmsapi
from pprint import pprint

URL = 'http://localhost:8087'
TOKEN = '890bfcacc9d187089c425658c470513f'

client = librenmsapi.LibreNMS(URL, TOKEN)


parents = {}


# Initialise the `parents` dictionary with all existing parents for each device.
for device in client.devices.list_devices():
    # {'device_id': 609,
    #  ...
    #  'dependency_parent_id': '140,141',
    #  ...}

    if device['dependency_parent_id']:
        # The string is split and converted into integers,
        parent_ids = set([int(i) for i in device['dependency_parent_id'].split(',')])
        parents[device['device_id']] = parent_ids


# Collect all LLDP links.
#
for link in client.switching.list_links():
    # {'active': 1,
    #  'id': 28393,
    #  'local_device_id': 544,       <---
    #  'local_port_id': 28695,
    #  'protocol': 'lldp',
    #  'remote_device_id': 355,      <---
    #  'remote_hostname': 'switch2',
    #  'remote_platform': None,
    #  'remote_port': 'Gi1/2',
    #  'remote_port_id': 29059,
    #  'remote_version': 'Cisco IOS Software, IE4000  Software '
    #                    '(IE4000-UNIVERSALK9-M), Version 15.2(8)E5, RELEASE '
    #                    'SOFTWARE (fc2)\n'
    #                    'Technical Support: http://www.cisco.com/techsupport\n'
    #                    'Copyright (c) 1986-2023 by Cisco Systems, Inc.\n'
    #                    'Compiled Tue 07-Nov-23 22:59 by mcpre'},

    # In this particular scenario we are only interested in LLDP data
    # but not others, e.g. CDP.
    if link['protocol'] != 'lldp':
        continue

    # We are also skipping parent devices that are not monitored by LibreNMS.
    if link['remote_device_id'] == 0:
        continue

    # Add the parent/child relationship.
    parents[link['local_device_id']].add(link['remote_device_id'])


# Make the API call for each device.
for device_id, parent_ids in parents.items():
    # Convert the parent ids into a string seperated by comma,
    parent_ids = ','.join([str(i) for i in parent_ids])
    client.devices.add_parents_to_host(device_id, parent_ids=parent_ids)

