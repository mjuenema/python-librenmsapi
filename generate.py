#!/usr/bin/env python3

import re
import glob
import pathlib
import io
import os
import sys
import jinja2
import caseconverter
import mistune

PATH_TO_API_DOC='librenms.mjuenema.git/doc/API/'


# Parser states. Set to the previous(!) type of information processed.
# For example, the state is STATE_HEADING when a Markdown heading has just been
# encountered and the description of an Endpoint comes next.
#
STATE_NONE = 0
STATE_HEADING = 1
STATE_DESCRIPTION = 2
STATE_ROUTE = 3
STATE_ROUTE_DESCR = 4
STATE_INPUT = 5
STATE_EXAMPLE = 6
STATE_OUTPUT = 7


# Endpoints that will not be implemented
SKIPPED_ENDPOINTS = (
    'list_parents_of_host',
)


def route_to_fstring(route):
    print(route)
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

    print('CATEGORY', category, file=sys.stderr)

    # Skip index.md
    if category == 'index':
        continue

    # Skip some others we fail to parse at the moment.
    if category in ('Logs', 'PortGroups', 'Port_Groups'):
        # Logs: Because of general arguments description at the beginning.
        # PortGroups: stumbling over Params in get_ports_by_group
        # Port_Groups: need to distinguish between PortGroups and Port_Groups with pascalcase.
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

        # Parse the Markdown file into tokens.
        #
        parser = mistune.create_markdown(renderer='ast')


        # Append a category (of API endpoints) to the parse results.
        #
        parsed.append({
            'name': category,
            'endpoints': []
        })


        # Iterate and process the Markdown tokens.
        #
        state = STATE_NONE
        for token in parser(fp.read()):
            # token['type'] is one of 
            # - blank_line
            # - block_code
            # - block_quote
            # - heading
            # - list
            # - paragraph

            print('TOKEN', state, token, file=sys.stderr)


            # "Copy" blank lines if they are part of the route or input arguments
            # description, otherwise ignore them.
            #
            if token['type'] == 'blank_line':
                # {'type': 'blank_line'}

                if state == STATE_ROUTE:
                    route_descr += '\n'
                elif state == STATE_ROUTE:
                    input_descr += '\n'

            # There are only level 3 headings in the Markdown input each of which
            # equals an API endpoint.
            #
            elif token['type'] == 'heading':
                # {'type': 'heading', 'attrs': {'level': 3}, 'style': 'atx', 'children': [{'type': 'codespan', 'raw': 'del_device'}]}

                if token['attrs']['level'] != 3:
                    continue

                # Have we completed parsing the Markdown for an endpoint?
                #
                if state != STATE_NONE:
                    if endpoint not in SKIPPED_ENDPOINTS:
                        parsed[-1]['endpoints'].append({
                            'name': endpoint,
                            'route': route,
                            'required': required,
                            'optional': optional,
                            'description': description.strip(),
                            'method': method,
                            'route_descr': route_descr.strip(),
                            'input_descr': input_descr.strip(),
                        })

                    #print(f"---> {parsed[-1]['endpoints'][-1]}")


                # Start parsing the next section.
                #
                endpoint = token['children'][0]['raw']
                route = None        # API route.
                required = []       # List of 'route' required arguments.
                optional = []       # List of 'route' optional arguments.
                description = ''    # Description of the endpoint.
                method = ''         # HTTP method: GET, POST, DELET, PATCH, PUT
                route_descr = ''    # Markdown text descripbing the route arguments.
                input_descr = ''    # Markdown text describing the input arguments.
                state = STATE_HEADING

            elif token['type'] == 'paragraph':
                # {'type': 'paragraph', 'children': [{'type': 'text', 'raw': 'Delete a given device.'}]}
                # {'type': 'paragraph', 'children': [{'type': 'text', 'raw': 'Route: '}, {'type': 'codespan', 'raw': '/api/v0/devices/:hostname'}]}
                # {'type': 'paragraph', 'children': [{'type': 'text', 'raw': 'Input:'}]}
                # {'type': 'paragraph', 'children': [{'type': 'text', 'raw': 'Example:'}]}
                # {'type': 'paragraph', 'children': [{'type': 'text', 'raw': 'Output:'}]}


                # Progress parsing state if specific text has been encountered
                #
                if token['children'][0].get('raw', '').startswith('Route'):
                    state = STATE_ROUTE
                elif token['children'][0].get('raw', '').startswith('Input'):
                    state = STATE_INPUT
                elif token['children'][0].get('raw', '').startswith('Example'):
                    state = STATE_EXAMPLE
                elif token['children'][0].get('raw', '').startswith('Output'):
                    state = STATE_OUTPUT

                # Process the "text" of the paragraph for some states
                #
                if state == STATE_HEADING or state == STATE_DESCRIPTION:
                    description = token['children'][0]['raw']
                    state = STATE_DESCRIPTION
                elif state == STATE_ROUTE:
                    route = token['children'][1]['raw']
                    required = re.findall(r'(?<!\(/):([a-z0-9_]+)', route)
                    optional = re.findall(r'\(/:([a-z0-9_]+)', route)
                    state = STATE_ROUTE_DESCR
                elif state == STATE_DESCRIPTION:
                    description = token['children'][0]['raw']

            elif token['type'] == 'list':
                # {'type': 'list', 'children': [{'type': 'list_item',
                #                              'children': [{'type': 'block_text',
                #                                          'children': [{'type': 'text', 'raw': 'hostname can be either the device hostname or id'}]}]}],
                #  'tight': True, 'bullet': '-', 'attrs': {'depth': 0, 'ordered': False}}
                # {'type': 'list', 'children': [{'type': 'list_item', 'children': [{'type': 'blank_line'}]}], 'tight': False, 'bullet': '-', 'attrs': {'depth': 0, 'ordered': False}}

                try:
                    if state == STATE_ROUTE_DESCR:
                        route_descr += f"\n- {token['children'][0]['children'][0]['children'][0]['raw']}"
                    elif state == STATE_INPUT:
                        input_descr += f"\n- {token['children'][0]['children'][0]['children'][0]['raw']}"
                except KeyError:
                    # This happens when the list item is empty!
                    pass

            elif token['type'] == 'block_code':
                # {'type': 'block_code', 'raw': "curl -X DELETE -H 'X-Auth-Token: YOURAPITOKENHERE' https://foo.example/api/v0/devices/localhost\n", 'style': 'fenced', 'marker': '```', 'attrs': {'info': 'curl'}}

                if state == STATE_EXAMPLE:
                    if '-X DELETE' in token['raw']:
                        method = 'DELETE'
                    elif '-X POST' in token['raw']:
                        method = 'POST'
                    elif '-X PATCH' in token['raw']:
                        method = 'PATCH'
                    elif '-X PUT' in token['raw']:
                        method = 'PUT'
                    else:
                        method = 'GET'

            elif token['type'] == 'block_quote':
                # {'type': 'block_quote', 'children': [{'type': 'paragraph',
                #                                       'children': [{'type': 'text', 'raw': 'LibreNMS will automatically map the OS to the Oxidized model name if'},
                #                                            {'type': 'softbreak'}, {'type': 'text', 'raw': "they don't match."}]}]}

                if state == STATE_ROUTE_DESCR:
                    route_descr += f"\n{token['children'][0]['children'][0]['raw']}"
                elif state == STATE_ROUTE:
                    input_descr += f"\n{token['children'][0]['children'][0]['raw']}"

            else:
                raise ValueError(str(token))

    # Appaned last endpoint in Markdown file
    #
    if endpoint not in SKIPPED_ENDPOINTS:
        parsed[-1]['endpoints'].append({
            'name': endpoint,
            'route': route,
            'required': required,
            'optional': optional,
            'description': description.strip(),
            'method': method,
            'route_descr': route_descr.strip(),
            'input_descr': input_descr.strip(),
        })



#    STATE_NONE = 0
#    STATE_OPERATION = 1
#    STATE_DESCRIPTION = 2
#    STATE_ROUTE = 3
#    STATE_ROUTE_ARGUMENTS = 4
#
#    state = STATE_NONE
#    for line in fs:
#
#        if line.startswith('###'):
#            ### `get_graph_by_port_hostname`
#
#            if state != STATE_NONE:
#                parsed[-1]['endpoints'].append({
#                    'name': endpoint,
#                    'route': route,
#                    'required': required,
#                    'optional': optional,
#                    'description': description,
#                    'method': method,
#                })
#
#            endpoint = re.search(r'([a-z_]+)', line).groups()[0]
#            required = []
#            optional = []
#            description = ''
#            method = ''
#            state = STATE_OPERATION
#
#        elif line.startswith('Route:'):
#            # Route: `/api/v0/devices/:hostname/ports/:ifname/:type`
#            route = re.search(r'(/[a-z0-9_/:\(\)]+)', line).groups()[0]
#            required = re.findall(r'(?<!\(/):([a-z0-9_]+)', line)
#            optional = re.findall(r'\(/:([a-z0-9_]+)', line)
#            state = STATE_ROUTE 
#
#        elif line.startswith('curl'):
#            if '-X DELETE' in line:
#                method = 'DELETE'
#            elif '-X POST' in line:
#                method = 'POST'
#            elif '-X PATCH' in line:
#                method = 'PATCH'
#            elif '-X PUT' in line:
#                method = 'PUT'
#            else:
#                method = 'GET'
#
#        elif state == STATE_OPERATION:
#            description += f"           {line}"
#
#    parsed[-1]['endpoints'].append({
#        'name': endpoint,
#        'route': route,
#        'required': required,
#        'optional': optional,
#        'description': description,
#        'method': method,
#    })
#
#
print(j2template.render(parsed=parsed))

#from pprint import pprint
#pprint(parsed)

