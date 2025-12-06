#!/usr/bin/env python3

import urllib.parse
import functools
import requests
import logging

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

NON_VALUE_KEYS = ("status", "count", "message")


class ApiException(Exception):
    def __init__(self, resp):
        self.resp = resp
        self.code = resp.status_code
        self.message = resp.json()["message"]
        super().__init__(self.message)


def api_call(http_method):
    def decorator(func):
        # func(route, **kwargs)
        def wrapper(self, route, *args, **kwargs):
            if http_method in ("POST", "PUT", "PATCH"):
                route = f"{self.parent.url}{route}"
            else:
                route = f"{self.parent.url}/{route}{'?' + urllib.parse.urlencode(kwargs) if kwargs else ''}"

            resp = func(self, route, **kwargs)

            # Raise an exception if the HTTP request failed.
            if resp.status_code >= 400:
                raise ApiException(resp)

            content_type = resp.headers.get("Content-Type")
            if content_type == "application/json":
                content = resp.json()

                # Raise an exception if the status is not ok
                if content["status"] != "ok":
                    raise ApiException(resp)

                # Remove all top-level keys that are not the actual "value" and
                # return only the "value".
                for key in NON_VALUE_KEYS:
                    try:
                        del content[key]
                    except KeyError:
                        continue

                if content == {}:
                    return None
                elif len(content) != 1:
                    raise ApiException(resp)
                else:
                    value_key = list(content.keys())[0]
                    return content[value_key]

            elif content_type == "image/png":
                return resp.content
            else:
                raise ValueError(content_type)

        return wrapper

    return decorator


class Endpoint:
    def __init__(self, parent):
        self.parent = parent

    @api_call("GET")
    def _get(self, route, **kwargs):
        return requests.get(route, headers={"X-Auth-Token": self.parent.token})

    @api_call("POST")
    def _post(self, route, **kwargs):
        return requests.post(
            route, json=kwargs, headers={"X-Auth-Token": self.parent.token}
        )

    @api_call("PATCH")
    def _patch(self, route, **kwargs):
        return requests.patch(
            route, json=kwargs, headers={"X-Auth-Token": self.parent.token}
        )

    @api_call("PUT")
    def _put(self, route, **kwargs):
        return requests.put(
            route, json=kwargs, headers={"X-Auth-Token": self.parent.token}
        )

    @api_call("DELETE")
    def _delete(self, route, **kwargs):
        return requests.delete(route, headers={"X-Auth-Token": self.parent.token})


class System(Endpoint):

    def system(self, **kwargs):
        """Display Librenms instance information."""
        # route=/api/v0/system
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/system"""
        return self._get(route, **kwargs)


class Inventory(Endpoint):

    def get_inventory(self, hostname, **kwargs):
        """Retrieve the inventory for a device. If you call this without any

        Arguments:
        - hostname can be either the device hostname or the device id


        """
        # route=/api/v0/inventory/:hostname
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/inventory/{hostname}"""
        return self._get(route, **kwargs)

    def get_inventory_for_device(self, hostname, **kwargs):
        """Retrieve the flattened inventory for a device.  This retrieves all

        Arguments:
        - hostname can be either the device hostname or the device id


        """
        # route=/api/v0/inventory/:hostname/all
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/inventory/{hostname}/all"""
        return self._get(route, **kwargs)


class Bills(Endpoint):

    def list_bills(self, **kwargs):
        """Retrieve the list of bills currently in the system."""
        # route=/api/v0/bills
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/bills"""
        return self._get(route, **kwargs)

    def get_bill(self, id, **kwargs):
        """Retrieve a specific bill

        Arguments:
        - id is the specific bill id


        """
        # route=/api/v0/bills/:id
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/bills/{id}"""
        return self._get(route, **kwargs)

    def get_bill_graph(self, **kwargs):
        """NB: The graphs returned from this will always be png as they do not"""
        # route=`
        # required=[]
        # optional=[]
        # method=GET
        route = f"""`"""
        return self._get(route, **kwargs)

    def get_bill_graphdata(self, id, graph_type, **kwargs):
        """Retrieve the data used to draw a graph so it can be rendered in an external system

        Arguments:



        """
        # route=/api/v0/bills/:id/graphdata/:graph_type
        # required=['id', 'graph_type']
        # optional=[]
        # method=GET
        route = f"""/api/v0/bills/{id}/graphdata/{graph_type}"""
        return self._get(route, **kwargs)

    def get_bill_history(self, id, **kwargs):
        """Retrieve the history of specific bill

        Arguments:



        """
        # route=/api/v0/bills/:id/history
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/bills/{id}/history"""
        return self._get(route, **kwargs)

    def get_bill_history_graph(self, id, bill_hist_id, graph_type, **kwargs):
        """NB: The graphs returned from this will always be png as they do not

        Arguments:



        """
        # route=/api/v0/bills/:id/history/:bill_hist_id/graphs/:graph_type
        # required=['id', 'bill_hist_id', 'graph_type']
        # optional=[]
        # method=GET
        route = f"""/api/v0/bills/{id}/history/{bill_hist_id}/graphs/{graph_type}"""
        return self._get(route, **kwargs)

    def get_bill_history_graphdata(self, id, bill_hist_id, graph_type, **kwargs):
        """Retrieve the data for a graph of a previous period of a bill, to be

        Arguments:



        """
        # route=/api/v0/bills/:id/history/:bill_hist_id/graphdata/:graph_type
        # required=['id', 'bill_hist_id', 'graph_type']
        # optional=[]
        # method=GET
        route = f"""/api/v0/bills/{id}/history/{bill_hist_id}/graphdata/{graph_type}"""
        return self._get(route, **kwargs)

    def delete_bill(self, id, **kwargs):
        """Delete a specific bill and all dependent data

        Arguments:
        - id is the specific bill id


        """
        # route=/api/v0/bills/:id
        # required=['id']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/bills/{id}"""
        return self._delete(route, **kwargs)

    def create_edit_bill(self, **kwargs):
        """Creates a new bill or updates an existing one"""
        # route=/api/v0/bills
        # required=[]
        # optional=[]
        # method=POST
        route = f"""/api/v0/bills"""
        return self._post(route, **kwargs)


class DeviceGroups(Endpoint):

    def get_devicegroups(self, **kwargs):
        """List all device groups."""
        # route=/api/v0/devicegroups
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/devicegroups"""
        return self._get(route, **kwargs)

    def add_devicegroup(self, **kwargs):
        """Add a new device group. Upon success, the ID of the new device group is returned"""
        # route=/api/v0/devicegroups
        # required=[]
        # optional=[]
        # method=POST
        route = f"""/api/v0/devicegroups"""
        return self._post(route, **kwargs)

    def update_devicegroup(self, name, **kwargs):
        """Updates a device group.

        Arguments:
        - name Is the name of the device group which can be obtained using


        """
        # route=/api/v0/devicegroups/:name
        # required=['name']
        # optional=[]
        # method=PATCH
        route = f"""/api/v0/devicegroups/{name}"""
        return self._patch(route, **kwargs)

    def delete_devicegroup(self, name, **kwargs):
        """Deletes a device group.

        Arguments:
        - name Is the name of the device group which can be obtained using


        """
        # route=/api/v0/devicegroups/:name
        # required=['name']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/devicegroups/{name}"""
        return self._delete(route, **kwargs)

    def get_devices_by_group(self, name, **kwargs):
        """List all devices matching the group provided.

        Arguments:
        - name Is the name of the device group which can be obtained using


        """
        # route=/api/v0/devicegroups/:name
        # required=['name']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devicegroups/{name}"""
        return self._get(route, **kwargs)

    def maintenance_devicegroup(self, name, **kwargs):
        """Set a device group into maintenance mode.

        Arguments:



        """
        # route=/api/v0/devicegroups/:name/maintenance
        # required=['name']
        # optional=[]
        # method=POST
        route = f"""/api/v0/devicegroups/{name}/maintenance"""
        return self._post(route, **kwargs)

    def add_devices_to_group(self, name, **kwargs):
        """Add devices to a device group.

        Arguments:
        - name Is the name of the device group which can be obtained using


        """
        # route=/api/v0/devicegroups/:name/devices
        # required=['name']
        # optional=[]
        # method=POST
        route = f"""/api/v0/devicegroups/{name}/devices"""
        return self._post(route, **kwargs)

    def remove_devices_from_group(self, name, **kwargs):
        """Removes devices from a device group.

        Arguments:
        - name Is the name of the device group which can be obtained using


        """
        # route=/api/v0/devicegroups/:name/devices
        # required=['name']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/devicegroups/{name}/devices"""
        return self._delete(route, **kwargs)


class PollerGroups(Endpoint):

    def remove_devices_from_group(self, poller_group, **kwargs):
        """Removes devices from a device group.

                  Arguments:
                  - name Is the name of the device group which can be obtained using
        - poller_group: optional name or id of the poller group to get


        """
        # route=/api/v0/poller_group/:poller_group
        # required=['poller_group']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/poller_group/{poller_group}"""
        return self._delete(route, **kwargs)


class Alerts(Endpoint):

    def get_alert(self, id, **kwargs):
        """Get details of an alert

        Arguments:
        - id is the alert id, you can obtain a list of alert ids from


        """
        # route=/api/v0/alerts/:id
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/alerts/{id}"""
        return self._get(route, **kwargs)

    def ack_alert(self, id, **kwargs):
        """Acknowledge an alert

        Arguments:
        - id is the alert id, you can obtain a list of alert ids from


        """
        # route=/api/v0/alerts/:id
        # required=['id']
        # optional=[]
        # method=PUT
        route = f"""/api/v0/alerts/{id}"""
        return self._put(route, **kwargs)

    def unmute_alert(self, id, **kwargs):
        """Unmute an alert

        Arguments:
        - id is the alert id, you can obtain a list of alert ids from


        """
        # route=/api/v0/alerts/unmute/:id
        # required=['id']
        # optional=[]
        # method=PUT
        route = f"""/api/v0/alerts/unmute/{id}"""
        return self._put(route, **kwargs)

    def list_alerts(self, **kwargs):
        """List all alerts"""
        # route=/api/v0/alerts
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/alerts"""
        return self._get(route, **kwargs)

    def get_alert_rule(self, id, **kwargs):
        """Get the alert rule details.

        Arguments:
        - id is the rule id.


        """
        # route=/api/v0/rules/:id
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/rules/{id}"""
        return self._get(route, **kwargs)

    def delete_rule(self, id, **kwargs):
        """Delete an alert rule by id

        Arguments:
        - id is the rule id.


        """
        # route=/api/v0/rules/:id
        # required=['id']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/rules/{id}"""
        return self._delete(route, **kwargs)

    def list_alert_rules(self, **kwargs):
        """List the alert rules."""
        # route=/api/v0/rules
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/rules"""
        return self._get(route, **kwargs)

    def add_rule(self, **kwargs):
        """Add a new alert rule."""
        # route=/api/v0/rules
        # required=[]
        # optional=[]
        # method=POST
        route = f"""/api/v0/rules"""
        return self._post(route, **kwargs)

    def edit_rule(self, **kwargs):
        """Edit an existing alert rule"""
        # route=/api/v0/rules
        # required=[]
        # optional=[]
        # method=PUT
        route = f"""/api/v0/rules"""
        return self._put(route, **kwargs)


class Routing(Endpoint):

    def list_bgp(self, **kwargs):
        """List the current BGP sessions."""
        # route=/api/v0/bgp
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/bgp"""
        return self._get(route, **kwargs)

    def get_bgp(self, id, **kwargs):
        """Retrieves a BGP session by ID

        Arguments:



        """
        # route=/api/v0/bgp/:id
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/bgp/{id}"""
        return self._get(route, **kwargs)

    def edit_bgp_descr(self, id, **kwargs):
        """This is a POST type request

        Arguments:



        """
        # route=/api/v0/bgp/:id
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/bgp/{id}"""
        return self._get(route, **kwargs)

    def list_cbgp(self, **kwargs):
        """List the current BGP sessions counters."""
        # route=/api/v0/routing/bgp/cbgp
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/routing/bgp/cbgp"""
        return self._get(route, **kwargs)

    def list_ip_addresses(self, address_family, **kwargs):
        """List all IPv4 and IPv6 or only version specific addresses.

        Arguments:



        """
        # route=/api/v0/resources/ip/addresses/:address_family
        # required=['address_family']
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/ip/addresses/{address_family}"""
        return self._get(route, **kwargs)

    def get_network_ip_addresses(self, id, **kwargs):
        """Get all IPv4 and IPv6 addresses for particular network.

        Arguments:
        - id must be integer


        """
        # route=/api/v0/resources/ip/networks/:id/ip
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/ip/networks/{id}/ip"""
        return self._get(route, **kwargs)

    def list_ip_networks(self, address_family, **kwargs):
        """List all IPv4 and IPv6 or only version specific networks.

        Arguments:



        """
        # route=/api/v0/resources/ip/networks/:address_family
        # required=['address_family']
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/ip/networks/{address_family}"""
        return self._get(route, **kwargs)

    def list_ipsec(self, hostname, **kwargs):
        """List the current IPSec tunnels which are active.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/routing/ipsec/data/:hostname
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/routing/ipsec/data/{hostname}"""
        return self._get(route, **kwargs)

    def list_ospf(self, **kwargs):
        """List the current OSPF neighbours."""
        # route=/api/v0/ospf
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/ospf"""
        return self._get(route, **kwargs)

    def list_ospf_ports(self, **kwargs):
        """List the current OSPF ports."""
        # route=/api/v0/ospf_ports
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/ospf_ports"""
        return self._get(route, **kwargs)

    def list_ospfv3(self, **kwargs):
        """List the current OSPFv3 neighbours."""
        # route=/api/v0/ospfv3
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/ospfv3"""
        return self._get(route, **kwargs)

    def list_ospfv3_ports(self, **kwargs):
        """List the current OSPFv3 ports."""
        # route=/api/v0/ospfv3_ports
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/ospfv3_ports"""
        return self._get(route, **kwargs)

    def list_vrf(self, **kwargs):
        """List the current VRFs."""
        # route=/api/v0/routing/vrf
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/routing/vrf"""
        return self._get(route, **kwargs)

    def get_vrf(self, id, **kwargs):
        """Retrieves VRF by ID

        Arguments:



        """
        # route=/api/v0/routing/vrf/:id
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/routing/vrf/{id}"""
        return self._get(route, **kwargs)

    def list_mpls_services(self, **kwargs):
        """List MPLS services"""
        # route=/api/v0/routing/mpls/services
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/routing/mpls/services"""
        return self._get(route, **kwargs)

    def list_mpls_saps(self, **kwargs):
        """List MPLS SAPs"""
        # route=/api/v0/routing/mpls/saps
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/routing/mpls/saps"""
        return self._get(route, **kwargs)


class Switching(Endpoint):

    def list_vlans(self, **kwargs):
        """Get a list of all VLANs."""
        # route=/api/v0/resources/vlans
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/vlans"""
        return self._get(route, **kwargs)

    def get_vlans(self, hostname, **kwargs):
        """Get a list of all VLANs for a given device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/vlans
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/vlans"""
        return self._get(route, **kwargs)

    def list_links(self, **kwargs):
        """Get a list of all Links."""
        # route=/api/v0/resources/links
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/links"""
        return self._get(route, **kwargs)

    def get_links(self, hostname, **kwargs):
        """Get a list of Links per giver device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/links
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/links"""
        return self._get(route, **kwargs)

    def get_link(self, id, **kwargs):
        """Retrieves Link by ID

        Arguments:



        """
        # route=/api/v0/resources/links/:id
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/links/{id}"""
        return self._get(route, **kwargs)

    def list_fdb(self, mac, **kwargs):
        """Get a list of all ports FDB.

        Arguments:
        - mac is the specific MAC address you would like to query


        """
        # route=/api/v0/resources/fdb/:mac
        # required=['mac']
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/fdb/{mac}"""
        return self._get(route, **kwargs)

    def list_fdb_detail(self, mac, **kwargs):
        """Get a list of all ports FDB with human readable device  and interface names.

        Arguments:
        - mac is the specific MAC address you would like to query


        """
        # route=/api/v0/resources/fdb/:mac/detail
        # required=['mac']
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/fdb/{mac}/detail"""
        return self._get(route, **kwargs)

    def list_nac(self, mac, **kwargs):
        """Get a list of all ports NAC.

        Arguments:
        - mac is the specific MAC address you would like to query


        """
        # route=/api/v0/resources/nac/:mac
        # required=['mac']
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/nac/{mac}"""
        return self._get(route, **kwargs)


class PortSecurity(Endpoint):

    def get_all_port_security(self, **kwargs):
        """Get all port security info by inputting port_id"""
        # route=/api/v0/port_security
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/port_security"""
        return self._get(route, **kwargs)

    def get_port_security_by_port(self, port_id, **kwargs):
        """Get all port security info by inputting port_id

        Arguments:
        - portid must be an integer


        """
        # route=/api/v0/port_security/port/:port_id
        # required=['port_id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/port_security/port/{port_id}"""
        return self._get(route, **kwargs)

    def get_port_security_by_hostname(self, hostname, **kwargs):
        """Get all port security info by inputting port_id

        Arguments:
        - hostname can be str hostname or int device_id


        """
        # route=/api/v0/port_security/:hostname
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/port_security/{hostname}"""
        return self._get(route, **kwargs)


class Services(Endpoint):

    def list_services(self, **kwargs):
        """Retrieve all services"""
        # route=/api/v0/services
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/services"""
        return self._get(route, **kwargs)

    def get_service_for_host(self, hostname, **kwargs):
        """Retrieve services for device

        Arguments:
        - id or hostname is the specific device


        """
        # route=/api/v0/services/:hostname
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/services/{hostname}"""
        return self._get(route, **kwargs)

    def add_service_for_host(self, hostname, **kwargs):
        """Add a service for device

        Arguments:
        - id or hostname is the specific device


        """
        # route=/api/v0/services/:hostname
        # required=['hostname']
        # optional=[]
        # method=POST
        route = f"""/api/v0/services/{hostname}"""
        return self._post(route, **kwargs)

    def edit_service_from_host(self, service_id, **kwargs):
        """Edits a service

        Arguments:
        - service id


        """
        # route=/api/v0/services/:service_id
        # required=['service_id']
        # optional=[]
        # method=PATCH
        route = f"""/api/v0/services/{service_id}"""
        return self._patch(route, **kwargs)

    def delete_service_from_host(self, service_id, **kwargs):
        """Deletes service from device

        Arguments:
        - service id


        """
        # route=/api/v0/services/:service_id
        # required=['service_id']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/services/{service_id}"""
        return self._delete(route, **kwargs)


class Devices(Endpoint):

    def del_device(self, hostname, **kwargs):
        """Delete a given device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname
        # required=['hostname']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/devices/{hostname}"""
        return self._delete(route, **kwargs)

    def get_device(self, hostname, **kwargs):
        """Get details of a given device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}"""
        return self._get(route, **kwargs)

    def discover_device(self, hostname, **kwargs):
        """Trigger a discovery of given device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/discover
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/discover"""
        return self._get(route, **kwargs)

    def availability(self, hostname, **kwargs):
        """Get calculated availabilities of given device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/availability
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/availability"""
        return self._get(route, **kwargs)

    def outages(self, hostname, **kwargs):
        """Get detected outages of given device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/outages
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/outages"""
        return self._get(route, **kwargs)

    def get_graphs(self, hostname, **kwargs):
        """Get a list of available graphs for a device, this does not include ports.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/graphs
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/graphs"""
        return self._get(route, **kwargs)

    def list_available_health_graphs(self, hostname, type="", sensor_id="", **kwargs):
        """This function allows to do three things:

        Arguments:
        - hostname can be either the device hostname or id


        Keyword arguments:


        """
        # route=/api/v0/devices/:hostname/health(/:type)(/:sensor_id)
        # required=['hostname']
        # optional=['type', 'sensor_id']
        # method=GET
        route = f"""/api/v0/devices/{hostname}/health{"/" + type if type else ""}{"/" + sensor_id if sensor_id else ""}"""
        return self._get(route, **kwargs)

    def list_available_wireless_graphs(self, hostname, type="", sensor_id="", **kwargs):
        """This function allows to do three things:

        Arguments:
        - hostname can be either the device hostname or id


        Keyword arguments:


        """
        # route=/api/v0/devices/:hostname/wireless(/:type)(/:sensor_id)
        # required=['hostname']
        # optional=['type', 'sensor_id']
        # method=GET
        route = f"""/api/v0/devices/{hostname}/wireless{"/" + type if type else ""}{"/" + sensor_id if sensor_id else ""}"""
        return self._get(route, **kwargs)

    def get_health_graph(self, hostname, type, sensor_id="", **kwargs):
        """Get a particular health class graph for a device, if you provide a

        Arguments:
        - hostname can be either the device hostname or id


        Keyword arguments:


        """
        # route=/api/v0/devices/:hostname/graphs/health/:type(/:sensor_id)
        # required=['hostname', 'type']
        # optional=['sensor_id']
        # method=GET
        route = f"""/api/v0/devices/{hostname}/graphs/health/{type}{"/" + sensor_id if sensor_id else ""}"""
        return self._get(route, **kwargs)

    def get_wireless_graph(self, hostname, type, sensor_id="", **kwargs):
        """Get a particular wireless class graph for a device, if you provide a

        Arguments:
        - hostname can be either the device hostname or id


        Keyword arguments:


        """
        # route=/api/v0/devices/:hostname/graphs/wireless/:type(/:sensor_id)
        # required=['hostname', 'type']
        # optional=['sensor_id']
        # method=GET
        route = f"""/api/v0/devices/{hostname}/graphs/wireless/{type}{"/" + sensor_id if sensor_id else ""}"""
        return self._get(route, **kwargs)

    def get_graph_generic_by_hostname(self, hostname, type, **kwargs):
        """Get a specific graph for a device, this does not include ports.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/:type
        # required=['hostname', 'type']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/{type}"""
        return self._get(route, **kwargs)

    def get_graph_by_service(self, hostname, service_id, datasource, **kwargs):
        """Get the graph for a service

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/services/:service_id/graphs/:datasource
        # required=['hostname', 'service_id', 'datasource']
        # optional=[]
        # method=
        route = (
            f"""/api/v0/devices/{hostname}/services/{service_id}/graphs/{datasource}"""
        )
        return self._(route, **kwargs)

    def get_device_ports(self, hostname, **kwargs):
        """Get a list of ports for a particular device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/ports
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/ports"""
        return self._get(route, **kwargs)

    def get_device_fdb(self, hostname, **kwargs):
        """Get a list of FDB entries associated with a device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/fdb
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/fdb"""
        return self._get(route, **kwargs)

    def get_device_nac(self, hostname, **kwargs):
        """Get a list of NAC entries associated with a device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/nac
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/nac"""
        return self._get(route, **kwargs)

    def get_device_ip_addresses(self, hostname, **kwargs):
        """Get a list of IP addresses (v4 and v6) associated with a device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/ip
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/ip"""
        return self._get(route, **kwargs)

    def get_port_stack(self, hostname, **kwargs):
        """Get a list of port mappings for a device.  This is useful for showing

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/port_stack
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/port_stack"""
        return self._get(route, **kwargs)

    def get_device_transceivers(self, hostname, **kwargs):
        """Get a list of FDB entries associated with a device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/transceivers
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/transceivers"""
        return self._get(route, **kwargs)

    def get_components(self, hostname, **kwargs):
        """Get a list of components for a particular device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/components
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/components"""
        return self._get(route, **kwargs)

    def add_components(self, hostname, type, **kwargs):
        """Create a new component of a type on a particular device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/components/:type
        # required=['hostname', 'type']
        # optional=[]
        # method=POST
        route = f"""/api/v0/devices/{hostname}/components/{type}"""
        return self._post(route, **kwargs)

    def edit_components(self, hostname, **kwargs):
        """Edit an existing component on a particular device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/components
        # required=['hostname']
        # optional=[]
        # method=PUT
        route = f"""/api/v0/devices/{hostname}/components"""
        return self._put(route, **kwargs)

    def delete_components(self, hostname, component, **kwargs):
        """Delete an existing component on a particular device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/components/:component
        # required=['hostname', 'component']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/devices/{hostname}/components/{component}"""
        return self._delete(route, **kwargs)

    def get_port_stats_by_port_hostname(self, hostname, ifname, **kwargs):
        """Get information about a particular port for a device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/ports/:ifname
        # required=['hostname', 'ifname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/ports/{ifname}"""
        return self._get(route, **kwargs)

    def get_graph_by_port_hostname(self, hostname, ifname, type, **kwargs):
        """Get a graph of a port for a particular device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/ports/:ifname/:type
        # required=['hostname', 'ifname', 'type']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/ports/{ifname}/{type}"""
        return self._get(route, **kwargs)

    def list_sensors(self, **kwargs):
        """Get a list of all Sensors."""
        # route=/api/v0/resources/sensors
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/sensors"""
        return self._get(route, **kwargs)

    def list_devices(self, **kwargs):
        """Return a list of devices."""
        # route=/api/v0/devices
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices"""
        return self._get(route, **kwargs)

    def device_under_maintenance(self, hostname, **kwargs):
        """Get the current maintenance status of a device.

        Arguments:



        """
        # route=/api/v0/devices/:hostname/maintenance
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/maintenance"""
        return self._get(route, **kwargs)

    def maintenance_device(self, hostname, **kwargs):
        """Set a device into maintenance mode.

        Arguments:



        """
        # route=/api/v0/devices/:hostname/maintenance
        # required=['hostname']
        # optional=[]
        # method=POST
        route = f"""/api/v0/devices/{hostname}/maintenance"""
        return self._post(route, **kwargs)

    def add_device(self, **kwargs):
        """To guarantee device is added, use force_add. This will skip checks"""
        # route=/api/v0/devices
        # required=[]
        # optional=[]
        # method=POST
        route = f"""/api/v0/devices"""
        return self._post(route, **kwargs)

    def list_oxidized(self, hostname="", **kwargs):
        """List devices for use with Oxidized. If you have group support enabled


        Keyword arguments:


        """
        # route=/api/v0/oxidized(/:hostname)
        # required=[]
        # optional=['hostname']
        # method=GET
        route = f"""/api/v0/oxidized{"/" + hostname if hostname else ""}"""
        return self._get(route, **kwargs)

    def update_device_field(self, hostname, **kwargs):
        """Update devices field in the database.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname
        # required=['hostname']
        # optional=[]
        # method=PATCH
        route = f"""/api/v0/devices/{hostname}"""
        return self._patch(route, **kwargs)

    def update_device_port_notes(self, hostname, portid, **kwargs):
        """Update a device port notes field in the devices_attrs database.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/port/:portid
        # required=['hostname', 'portid']
        # optional=[]
        # method=PATCH
        route = f"""/api/v0/devices/{hostname}/port/{portid}"""
        return self._patch(route, **kwargs)

    def rename_device(self, hostname, new_hostname, **kwargs):
        """Rename device.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/rename/:new_hostname
        # required=['hostname', 'new_hostname']
        # optional=[]
        # method=PATCH
        route = f"""/api/v0/devices/{hostname}/rename/{new_hostname}"""
        return self._patch(route, **kwargs)

    def get_device_groups(self, hostname, **kwargs):
        """List the device groups that a device is matched on.

        Arguments:
        - hostname can be either the device hostname or id


        """
        # route=/api/v0/devices/:hostname/groups
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/groups"""
        return self._get(route, **kwargs)

    def search_oxidized(self, searchstring, **kwargs):
        """search all oxidized device configs for a string.

        Arguments:
        - searchstring is the specific string you would like to search for.


        """
        # route=api/v0/oxidized/config/search/:searchstring
        # required=['searchstring']
        # optional=[]
        # method=GET
        route = f"""api/v0/oxidized/config/search/{searchstring}"""
        return self._get(route, **kwargs)

    def get_oxidized_config(self, hostname, **kwargs):
        """Returns a specific device's config from oxidized.

        Arguments:
        - hostname is the Hostname or IP of the device used when adding the device to librenms.


        """
        # route=api/v0/oxidized/config/:hostname
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""api/v0/oxidized/config/{hostname}"""
        return self._get(route, **kwargs)

    def add_parents_to_host(self, device, **kwargs):
        """Add one or more parents to a host.

        Arguments:



        """
        # route=/api/v0/devices/:device/parents
        # required=['device']
        # optional=[]
        # method=POST
        route = f"""/api/v0/devices/{device}/parents"""
        return self._post(route, **kwargs)

    def delete_parents_from_host(self, device, **kwargs):
        """Deletes some or all the parents from a host.

        Arguments:



        """
        # route=/api/v0/devices/:device/parents
        # required=['device']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/devices/{device}/parents"""
        return self._delete(route, **kwargs)


class Ports(Endpoint):

    def get_all_ports(self, **kwargs):
        """Get info for all ports on all devices. Strongly recommend that you use"""
        # route=/api/v0/ports
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports"""
        return self._get(route, **kwargs)

    def search_ports(self, search, **kwargs):
        """Search for ports matching the query.

        Arguments:
        - search string to search in fields: ifAlias, ifDescr, and ifName


        """
        # route=/api/v0/ports/search/:search
        # required=['search']
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports/search/{search}"""
        return self._get(route, **kwargs)

    def search_ports_in_specific_fields(self, field, search, **kwargs):
        """Specific search for ports matching the query.

        Arguments:
        - field: comma separated list of field(s) to search


        """
        # route=/api/v0/ports/search/:field/:search
        # required=['field', 'search']
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports/search/{field}/{search}"""
        return self._get(route, **kwargs)

    def ports_with_associated_mac(self, search, **kwargs):
        """Search for ports matching the search mac.

        Arguments:
        - search a mac address in fdb and print the ports ordered by the mac count of the associated port.


        """
        # route=/api/v0/ports/mac/:search?filter=first
        # required=['search']
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports/mac/{search}?filter=first"""
        return self._get(route, **kwargs)

    def get_port_info(self, portid, **kwargs):
        """Get all info for a particular port.

        Arguments:
        - portid must be an integer


        """
        # route=/api/v0/ports/:portid?with=vlans
        # required=['portid']
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports/{portid}?with=vlans"""
        return self._get(route, **kwargs)

    def get_port_ip_info(self, portid, **kwargs):
        """Get all IP info (v4 and v6) for a given port id.

        Arguments:
        - portid must be an integer


        """
        # route=/api/v0/ports/:portid/ip
        # required=['portid']
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports/{portid}/ip"""
        return self._get(route, **kwargs)

    def get_port_transceiver(self, portid, **kwargs):
        """Get transceiver info with metrics

        Arguments:
        - portid must be an integer


        """
        # route=/api/v0/ports/:portid/transceiver
        # required=['portid']
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports/{portid}/transceiver"""
        return self._get(route, **kwargs)

    def get_port_description(self, portid, **kwargs):
        """Get the description (

        Arguments:



        """
        # route=/api/v0/ports/:portid/description
        # required=['portid']
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports/{portid}/description"""
        return self._get(route, **kwargs)

    def update_port_description(self, portid, **kwargs):
        """Change the description (

        Arguments:



        """
        # route=/api/v0/ports/:portid/description
        # required=['portid']
        # optional=[]
        # method=PATCH
        route = f"""/api/v0/ports/{portid}/description"""
        return self._patch(route, **kwargs)


class Locations(Endpoint):

    def list_locations(self, **kwargs):
        """Return a list of locations."""
        # route=/api/v0/resources/locations
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/locations"""
        return self._get(route, **kwargs)

    def add_location(self, **kwargs):
        """Add a new location"""
        # route=/api/v0/locations/
        # required=[]
        # optional=[]
        # method=POST
        route = f"""/api/v0/locations/"""
        return self._post(route, **kwargs)

    def delete_location(self, location, **kwargs):
        """Deletes an existing location

        Arguments:
        - location: name or id of the location to delete


        """
        # route=/api/v0/locations/:location
        # required=['location']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/locations/{location}"""
        return self._delete(route, **kwargs)

    def edit_location(self, location, **kwargs):
        """Edits a location

                  Arguments:
                  - location: name or id of the location to edit
        - location: name or id of the location to get


        """
        # route=/api/v0/location/:location
        # required=['location']
        # optional=[]
        # method=PATCH
        route = f"""/api/v0/location/{location}"""
        return self._patch(route, **kwargs)

    def maintenance_location(self, location, **kwargs):
        """Set a location into maintenance mode.

        Arguments:
        - location: name or id of the location to set


        """
        # route=/api/v0/locations/:location/maintenance
        # required=['location']
        # optional=[]
        # method=POST
        route = f"""/api/v0/locations/{location}/maintenance"""
        return self._post(route, **kwargs)


class Arp(Endpoint):

    def list_arp(self, query, **kwargs):
        """Retrieve a specific ARP entry or all ARP entries for a device

        Arguments:
        - An IP address


        """
        # route=/api/v0/resources/ip/arp/:query
        # required=['query']
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/ip/arp/{query}"""
        return self._get(route, **kwargs)


class LibreNMS:

    def __init__(self, url, token):
        # verify_ssl and other possible arguments to the requests methods.
        self.url = url
        self.token = token
        self.devices = Devices(self)
        self.system = System(self)
        self.inventory = Inventory(self)
        self.bills = Bills(self)
        self.device_groups = DeviceGroups(self)
        self.poller_groups = PollerGroups(self)
        self.alerts = Alerts(self)
        self.routing = Routing(self)
        self.switching = Switching(self)
        self.port_security = PortSecurity(self)
        self.services = Services(self)
        self.devices = Devices(self)
        self.ports = Ports(self)
        self.locations = Locations(self)
        self.arp = Arp(self)
