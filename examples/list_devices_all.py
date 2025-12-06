#!/usr/bin/env python3

import ipaddress
import librenmsapi
from pprint import pprint

URL = 'http://localhost:8087'
TOKEN = '890bfcacc9d187089c425658c470513f'

client = librenmsapi.LibreNMS(URL, TOKEN)
devices = client.devices.list_devices()

pprint(devices)

