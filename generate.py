#!/usr/bin/env python3

import re
import glob
import pathlib
import io
import os
import sys
import jinja2
import caseconverter

PATH_TO_API_DOC='librenms.git/doc/API/'


def route_to_fstring(route):
    return re.sub(r':([a-z_]+)', '{\g<1>}', re.sub(r'\(/:([a-z_]+)\)', '{"/" + \g<1> if \g<1> else ""}', route))


j2loader = jinja2.FileSystemLoader(searchpath='./')
j2env = jinja2.Environment(loader=j2loader)
j2env.filters['snakecase'] = caseconverter.snakecase
j2env.filters['pascalcase'] = caseconverter.pascalcase
j2env.filters['route_to_fstring'] = route_to_fstring
j2template = j2env.get_template('librenmsapi.j2')


parsed = []

for fn in glob.glob(f"{PATH_TO_API_DOC}/*.md"):
    path = pathlib.Path(fn)

    category = path.stem

    # Skip index.md
    if category == 'index':
        continue

    # The "parser" is line-oriented but the Markdown input may contain continuation
    # characters '\' which cause some of the parsing logic below to fail. The
    # approach taken here is to merge continued lines into a single line.
    # 
    # Example:
    #
    #     curl -H 'X-Auth-Token: YOURAPITOKENHERE' \
    #         -X POST https://foo.example/api/v0/devices/localhost/maintenance/ \
    #         --data-raw 
    #
    with open(path, 'rt') as fp:
        text = fp.read()
    text = text.replace('\\\n', '')

    fs = io.StringIO(text)

    parsed.append({
        'name': category,
        'endpoints': []
        })


    STATE_NONE = 0
    STATE_OPERATION = 1
    STATE_DESCRIPTION = 2
    STATE_ROUTE = 3
    STATE_ROUTE_ARGUMENTS = 4

    state = STATE_NONE
    for line in fs:

        if line.startswith('###'):
            ### `get_graph_by_port_hostname`

            if state != STATE_NONE:
                parsed[-1]['endpoints'].append({
                    'name': endpoint,
                    'route': route,
                    'required': required,
                    'optional': optional,
                    'description': description,
                    'method': method,
                })

            endpoint = re.search(r'([a-z_]+)', line).groups()[0]
            required = []
            optional = []
            description = ''
            method = ''
            state = STATE_OPERATION

        elif line.startswith('Route:'):
            # Route: `/api/v0/devices/:hostname/ports/:ifname/:type`
            route = re.search(r'(/[a-z0-9_/:\(\)]+)', line).groups()[0]
            required = re.findall(r'(?<!\(/):([a-z0-9_]+)', line)
            optional = re.findall(r'\(/:([a-z0-9_]+)', line)
            state = STATE_ROUTE 

        elif line.startswith('curl'):
            if '-X DELETE' in line:
                method = 'DELETE'
            elif '-X POST' in line:
                method = 'POST'
            elif '-X PATCH' in line:
                method = 'PATCH'
            elif '-X PUT' in line:
                method = 'PUT'
            else:
                method = 'GET'

        elif state == STATE_OPERATION:
            description += f"           {line}"

    parsed[-1]['endpoints'].append({
        'name': endpoint,
        'route': route,
        'required': required,
        'optional': optional,
        'description': description,
        'method': method,
    })


print(j2template.render(parsed=parsed))

