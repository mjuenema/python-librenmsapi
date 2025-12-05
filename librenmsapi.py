#!/usr/bin/env python3

import urllib.parse
import functools
import requests
import logging

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())


# Global variables that will be available to all methods.
# Currently only supports a single LibreNMS() instance.
# How


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

            if resp.status_code >= 400:
                print(route, kwargs)
                raise ApiException(resp)
            else:
                content_type = resp.headers.get("Content-Type")
                if content_type == "application/json":
                    return resp.json()
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


class Logs(Endpoint):

    def list_eventlog(self, hostname, **kwargs):
        # route=/api/v0/logs/eventlog/:hostname
        # required=['hostname']
        # optional=[]
        # method=
        route = f"""/api/v0/logs/eventlog/{hostname}"""
        return self._(route, **kwargs)

    def list_syslog(self, hostname, **kwargs):
        # route=/api/v0/logs/syslog/:hostname
        # required=['hostname']
        # optional=[]
        # method=
        route = f"""/api/v0/logs/syslog/{hostname}"""
        return self._(route, **kwargs)

    def list_alertlog(self, hostname, **kwargs):
        # route=/api/v0/logs/alertlog/:hostname
        # required=['hostname']
        # optional=[]
        # method=
        route = f"""/api/v0/logs/alertlog/{hostname}"""
        return self._(route, **kwargs)

    def list_authlog(self, hostname, **kwargs):
        # route=/api/v0/logs/authlog/:hostname
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/logs/authlog/{hostname}"""
        return self._get(route, **kwargs)

    def syslogsink(self, **kwargs):
        # route=/api/v0/logs/syslogsink
        # required=[]
        # optional=[]
        # method=POST
        route = f"""/api/v0/logs/syslogsink"""
        return self._post(route, **kwargs)

    def add_eventlog(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/eventlog
        # required=['hostname']
        # optional=[]
        # method=POST
        route = f"""/api/v0/devices/{hostname}/eventlog"""
        return self._post(route, **kwargs)


class PortGroups(Endpoint):

    def get_graph_by_portgroup(self, group, **kwargs):
        # route=/api/v0/portgroups/:group
        # required=['group']
        # optional=[]
        # method=GET
        route = f"""/api/v0/portgroups/{group}"""
        return self._get(route, **kwargs)

    def get_graph_by_portgroup_multiport_bits(self, id, **kwargs):
        # route=/api/v0/portgroups/multiport/bits/:id
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/portgroups/multiport/bits/{id}"""
        return self._get(route, **kwargs)


class System(Endpoint):

    def system(self, **kwargs):
        # route=/api/v0/system
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/system"""
        return self._get(route, **kwargs)


class Inventory(Endpoint):

    def get_inventory(self, hostname, **kwargs):
        # route=/api/v0/inventory/:hostname
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/inventory/{hostname}"""
        return self._get(route, **kwargs)

    def get_inventory_for_device(self, hostname, **kwargs):
        # route=/api/v0/inventory/:hostname/all
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/inventory/{hostname}/all"""
        return self._get(route, **kwargs)


class Bills(Endpoint):

    def list_bills(self, **kwargs):
        # route=/api/v0/bills
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/bills"""
        return self._get(route, **kwargs)

    def get_bill(self, id, **kwargs):
        # route=/api/v0/bills/:id
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/bills/{id}"""
        return self._get(route, **kwargs)

    def get_bill_graph(self, id, graph_type, **kwargs):
        # route=/api/v0/bills/:id/graphs/:graph_type
        # required=['id', 'graph_type']
        # optional=[]
        # method=GET
        route = f"""/api/v0/bills/{id}/graphs/{graph_type}"""
        return self._get(route, **kwargs)

    def get_bill_graphdata(self, id, graph_type, **kwargs):
        # route=/api/v0/bills/:id/graphdata/:graph_type
        # required=['id', 'graph_type']
        # optional=[]
        # method=GET
        route = f"""/api/v0/bills/{id}/graphdata/{graph_type}"""
        return self._get(route, **kwargs)

    def get_bill_history(self, id, **kwargs):
        # route=/api/v0/bills/:id/history
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/bills/{id}/history"""
        return self._get(route, **kwargs)

    def get_bill_history_graph(self, id, bill_hist_id, graph_type, **kwargs):
        # route=/api/v0/bills/:id/history/:bill_hist_id/graphs/:graph_type
        # required=['id', 'bill_hist_id', 'graph_type']
        # optional=[]
        # method=GET
        route = f"""/api/v0/bills/{id}/history/{bill_hist_id}/graphs/{graph_type}"""
        return self._get(route, **kwargs)

    def get_bill_history_graphdata(self, id, bill_hist_id, graph_type, **kwargs):
        # route=/api/v0/bills/:id/history/:bill_hist_id/graphdata/:graph_type
        # required=['id', 'bill_hist_id', 'graph_type']
        # optional=[]
        # method=GET
        route = f"""/api/v0/bills/{id}/history/{bill_hist_id}/graphdata/{graph_type}"""
        return self._get(route, **kwargs)

    def delete_bill(self, id, **kwargs):
        # route=/api/v0/bills/:id
        # required=['id']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/bills/{id}"""
        return self._delete(route, **kwargs)

    def create_edit_bill(self, **kwargs):
        # route=/api/v0/bills
        # required=[]
        # optional=[]
        # method=POST
        route = f"""/api/v0/bills"""
        return self._post(route, **kwargs)


class DeviceGroups(Endpoint):

    def get_devicegroups(self, **kwargs):
        # route=/api/v0/devicegroups
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/devicegroups"""
        return self._get(route, **kwargs)

    def add_devicegroup(self, **kwargs):
        # route=/api/v0/devicegroups
        # required=[]
        # optional=[]
        # method=POST
        route = f"""/api/v0/devicegroups"""
        return self._post(route, **kwargs)

    def update_devicegroup(self, name, **kwargs):
        # route=/api/v0/devicegroups/:name
        # required=['name']
        # optional=[]
        # method=PATCH
        route = f"""/api/v0/devicegroups/{name}"""
        return self._patch(route, **kwargs)

    def delete_devicegroup(self, name, **kwargs):
        # route=/api/v0/devicegroups/:name
        # required=['name']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/devicegroups/{name}"""
        return self._delete(route, **kwargs)

    def get_devices_by_group(self, name, **kwargs):
        # route=/api/v0/devicegroups/:name
        # required=['name']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devicegroups/{name}"""
        return self._get(route, **kwargs)

    def maintenance_devicegroup(self, name, **kwargs):
        # route=/api/v0/devicegroups/:name/maintenance
        # required=['name']
        # optional=[]
        # method=POST
        route = f"""/api/v0/devicegroups/{name}/maintenance"""
        return self._post(route, **kwargs)

    def dd(self, name, **kwargs):
        # route=/api/v0/devicegroups/:name/devices
        # required=['name']
        # optional=[]
        # method=POST
        route = f"""/api/v0/devicegroups/{name}/devices"""
        return self._post(route, **kwargs)

    def emove(self, name, **kwargs):
        # route=/api/v0/devicegroups/:name/devices
        # required=['name']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/devicegroups/{name}/devices"""
        return self._delete(route, **kwargs)


class PollerGroups(Endpoint):

    def get_poller_group(self, poller_group, **kwargs):
        # route=/api/v0/poller_group/:poller_group
        # required=['poller_group']
        # optional=[]
        # method=
        route = f"""/api/v0/poller_group/{poller_group}"""
        return self._(route, **kwargs)


class Alerts(Endpoint):

    def get_alert(self, id, **kwargs):
        # route=/api/v0/alerts/:id
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/alerts/{id}"""
        return self._get(route, **kwargs)

    def ack_alert(self, id, **kwargs):
        # route=/api/v0/alerts/:id
        # required=['id']
        # optional=[]
        # method=PUT
        route = f"""/api/v0/alerts/{id}"""
        return self._put(route, **kwargs)

    def unmute_alert(self, id, **kwargs):
        # route=/api/v0/alerts/unmute/:id
        # required=['id']
        # optional=[]
        # method=PUT
        route = f"""/api/v0/alerts/unmute/{id}"""
        return self._put(route, **kwargs)

    def list_alerts(self, **kwargs):
        # route=/api/v0/alerts
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/alerts"""
        return self._get(route, **kwargs)

    def get_alert_rule(self, id, **kwargs):
        # route=/api/v0/rules/:id
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/rules/{id}"""
        return self._get(route, **kwargs)

    def delete_rule(self, id, **kwargs):
        # route=/api/v0/rules/:id
        # required=['id']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/rules/{id}"""
        return self._delete(route, **kwargs)

    def list_alert_rules(self, **kwargs):
        # route=/api/v0/rules
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/rules"""
        return self._get(route, **kwargs)

    def add_rule(self, **kwargs):
        # route=/api/v0/rules
        # required=[]
        # optional=[]
        # method=POST
        route = f"""/api/v0/rules"""
        return self._post(route, **kwargs)

    def edit_rule(self, **kwargs):
        # route=/api/v0/rules
        # required=[]
        # optional=[]
        # method=PUT
        route = f"""/api/v0/rules"""
        return self._put(route, **kwargs)


class Routing(Endpoint):

    def list_bgp(self, **kwargs):
        # route=/api/v0/bgp
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/bgp"""
        return self._get(route, **kwargs)

    def get_bgp(self, id, **kwargs):
        # route=/api/v0/bgp/:id
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/bgp/{id}"""
        return self._get(route, **kwargs)

    def edit_bgp_descr(self, id, **kwargs):
        # route=/api/v0/bgp/:id
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/bgp/{id}"""
        return self._get(route, **kwargs)

    def list_cbgp(self, **kwargs):
        # route=/api/v0/routing/bgp/cbgp
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/routing/bgp/cbgp"""
        return self._get(route, **kwargs)

    def list_ip_addresses(self, address_family, **kwargs):
        # route=/api/v0/resources/ip/addresses/:address_family
        # required=['address_family']
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/ip/addresses/{address_family}"""
        return self._get(route, **kwargs)

    def get_network_ip_addresses(self, id, **kwargs):
        # route=/api/v0/resources/ip/networks/:id/ip
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/ip/networks/{id}/ip"""
        return self._get(route, **kwargs)

    def list_ip_networks(self, address_family, **kwargs):
        # route=/api/v0/resources/ip/networks/:address_family
        # required=['address_family']
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/ip/networks/{address_family}"""
        return self._get(route, **kwargs)

    def list_ipsec(self, hostname, **kwargs):
        # route=/api/v0/routing/ipsec/data/:hostname
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/routing/ipsec/data/{hostname}"""
        return self._get(route, **kwargs)

    def list_ospf(self, **kwargs):
        # route=/api/v0/ospf
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/ospf"""
        return self._get(route, **kwargs)

    def list_ospf_ports(self, **kwargs):
        # route=/api/v0/ospf_ports
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/ospf_ports"""
        return self._get(route, **kwargs)

    def list_ospfv(self, **kwargs):
        # route=/api/v0/ospfv3
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/ospfv3"""
        return self._get(route, **kwargs)

    def list_ospfv(self, **kwargs):
        # route=/api/v0/ospfv3_ports
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/ospfv3_ports"""
        return self._get(route, **kwargs)

    def list_vrf(self, **kwargs):
        # route=/api/v0/routing/vrf
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/routing/vrf"""
        return self._get(route, **kwargs)

    def get_vrf(self, id, **kwargs):
        # route=/api/v0/routing/vrf/:id
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/routing/vrf/{id}"""
        return self._get(route, **kwargs)

    def list_mpls_services(self, **kwargs):
        # route=/api/v0/routing/mpls/services
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/routing/mpls/services"""
        return self._get(route, **kwargs)

    def list_mpls_saps(self, **kwargs):
        # route=/api/v0/routing/mpls/saps
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/routing/mpls/saps"""
        return self._get(route, **kwargs)


class PortGroups(Endpoint):

    def get_port_groups(self, **kwargs):
        # route=/api/v0/port_groups
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/port_groups"""
        return self._get(route, **kwargs)

    def get_ports_by_group(self, name, **kwargs):
        # route=/api/v0/port_groups/:name
        # required=['name']
        # optional=[]
        # method=GET
        route = f"""/api/v0/port_groups/{name}"""
        return self._get(route, **kwargs)

    def add_port_group(self, **kwargs):
        # route=/api/v0/port_groups
        # required=[]
        # optional=[]
        # method=POST
        route = f"""/api/v0/port_groups"""
        return self._post(route, **kwargs)

    def assign_port_group(self, port_group_id, **kwargs):
        # route=/api/v0/port_groups/:port_group_id/assign
        # required=['port_group_id']
        # optional=[]
        # method=POST
        route = f"""/api/v0/port_groups/{port_group_id}/assign"""
        return self._post(route, **kwargs)

    def remove_port_group(self, port_group_id, **kwargs):
        # route=/api/v0/port_groups/:port_group_id/remove
        # required=['port_group_id']
        # optional=[]
        # method=POST
        route = f"""/api/v0/port_groups/{port_group_id}/remove"""
        return self._post(route, **kwargs)


class Switching(Endpoint):

    def list_vlans(self, **kwargs):
        # route=/api/v0/resources/vlans
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/vlans"""
        return self._get(route, **kwargs)

    def get_vlans(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/vlans
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/vlans"""
        return self._get(route, **kwargs)

    def list_links(self, **kwargs):
        # route=/api/v0/resources/links
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/links"""
        return self._get(route, **kwargs)

    def get_links(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/links
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/links"""
        return self._get(route, **kwargs)

    def get_link(self, id, **kwargs):
        # route=/api/v0/resources/links/:id
        # required=['id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/links/{id}"""
        return self._get(route, **kwargs)

    def list_fdb(self, mac, **kwargs):
        # route=/api/v0/resources/fdb/:mac
        # required=['mac']
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/fdb/{mac}"""
        return self._get(route, **kwargs)

    def list_fdb_detail(self, mac, **kwargs):
        # route=/api/v0/resources/fdb/:mac/detail
        # required=['mac']
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/fdb/{mac}/detail"""
        return self._get(route, **kwargs)

    def list_nac(self, mac, **kwargs):
        # route=/api/v0/resources/nac/:mac
        # required=['mac']
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/nac/{mac}"""
        return self._get(route, **kwargs)


class PortSecurity(Endpoint):

    def get_all_port_security(self, **kwargs):
        # route=/api/v0/port_security
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/port_security"""
        return self._get(route, **kwargs)

    def get_port_security_by_port(self, port_id, **kwargs):
        # route=/api/v0/port_security/port/:port_id
        # required=['port_id']
        # optional=[]
        # method=GET
        route = f"""/api/v0/port_security/port/{port_id}"""
        return self._get(route, **kwargs)

    def get_port_security_by_hostname(self, hostname, **kwargs):
        # route=/api/v0/port_security/:hostname
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/port_security/{hostname}"""
        return self._get(route, **kwargs)


class Services(Endpoint):

    def list_services(self, **kwargs):
        # route=/api/v0/services
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/services"""
        return self._get(route, **kwargs)

    def get_service_for_host(self, hostname, **kwargs):
        # route=/api/v0/services/:hostname
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/services/{hostname}"""
        return self._get(route, **kwargs)

    def add_service_for_host(self, hostname, **kwargs):
        # route=/api/v0/services/:hostname
        # required=['hostname']
        # optional=[]
        # method=POST
        route = f"""/api/v0/services/{hostname}"""
        return self._post(route, **kwargs)

    def edit_service_from_host(self, service_id, **kwargs):
        # route=/api/v0/services/:service_id
        # required=['service_id']
        # optional=[]
        # method=PATCH
        route = f"""/api/v0/services/{service_id}"""
        return self._patch(route, **kwargs)

    def delete_service_from_host(self, service_id, **kwargs):
        # route=/api/v0/services/:service_id
        # required=['service_id']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/services/{service_id}"""
        return self._delete(route, **kwargs)


class Devices(Endpoint):

    def del_device(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname
        # required=['hostname']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/devices/{hostname}"""
        return self._delete(route, **kwargs)

    def get_device(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}"""
        return self._get(route, **kwargs)

    def discover_device(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/discover
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/discover"""
        return self._get(route, **kwargs)

    def availability(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/availability
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/availability"""
        return self._get(route, **kwargs)

    def outages(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/outages
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/outages"""
        return self._get(route, **kwargs)

    def get_graphs(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/graphs
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/graphs"""
        return self._get(route, **kwargs)

    def list_available_health_graphs(self, hostname, type="", sensor_id="", **kwargs):
        # route=/api/v0/devices/:hostname/health(/:type)(/:sensor_id)
        # required=['hostname']
        # optional=['type', 'sensor_id']
        # method=GET
        route = f"""/api/v0/devices/{hostname}/health{"/" + type if type else ""}{"/" + sensor_id if sensor_id else ""}"""
        return self._get(route, **kwargs)

    def list_available_wireless_graphs(self, hostname, type="", sensor_id="", **kwargs):
        # route=/api/v0/devices/:hostname/wireless(/:type)(/:sensor_id)
        # required=['hostname']
        # optional=['type', 'sensor_id']
        # method=GET
        route = f"""/api/v0/devices/{hostname}/wireless{"/" + type if type else ""}{"/" + sensor_id if sensor_id else ""}"""
        return self._get(route, **kwargs)

    def get_health_graph(self, hostname, type, sensor_id="", **kwargs):
        # route=/api/v0/devices/:hostname/graphs/health/:type(/:sensor_id)
        # required=['hostname', 'type']
        # optional=['sensor_id']
        # method=GET
        route = f"""/api/v0/devices/{hostname}/graphs/health/{type}{"/" + sensor_id if sensor_id else ""}"""
        return self._get(route, **kwargs)

    def get_wireless_graph(self, hostname, type, sensor_id="", **kwargs):
        # route=/api/v0/devices/:hostname/graphs/wireless/:type(/:sensor_id)
        # required=['hostname', 'type']
        # optional=['sensor_id']
        # method=GET
        route = f"""/api/v0/devices/{hostname}/graphs/wireless/{type}{"/" + sensor_id if sensor_id else ""}"""
        return self._get(route, **kwargs)

    def get_graph_generic_by_hostname(self, hostname, type, **kwargs):
        # route=/api/v0/devices/:hostname/:type
        # required=['hostname', 'type']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/{type}"""
        return self._get(route, **kwargs)

    def get_graph_by_service(self, hostname, service_id, datasource, **kwargs):
        # route=/api/v0/devices/:hostname/services/:service_id/graphs/:datasource
        # required=['hostname', 'service_id', 'datasource']
        # optional=[]
        # method=GET
        route = (
            f"""/api/v0/devices/{hostname}/services/{service_id}/graphs/{datasource}"""
        )
        return self._get(route, **kwargs)

    def get_device_ports(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/ports
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/ports"""
        return self._get(route, **kwargs)

    def get_device_fdb(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/fdb
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/fdb"""
        return self._get(route, **kwargs)

    def get_device_nac(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/nac
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/nac"""
        return self._get(route, **kwargs)

    def get_device_ip_addresses(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/ip
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/ip"""
        return self._get(route, **kwargs)

    def get_port_stack(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/port_stack
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/port_stack"""
        return self._get(route, **kwargs)

    def get_device_transceivers(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/transceivers
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/transceivers"""
        return self._get(route, **kwargs)

    def get_components(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/components
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/components"""
        return self._get(route, **kwargs)

    def add_components(self, hostname, type, **kwargs):
        # route=/api/v0/devices/:hostname/components/:type
        # required=['hostname', 'type']
        # optional=[]
        # method=POST
        route = f"""/api/v0/devices/{hostname}/components/{type}"""
        return self._post(route, **kwargs)

    def edit_components(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/components
        # required=['hostname']
        # optional=[]
        # method=PUT
        route = f"""/api/v0/devices/{hostname}/components"""
        return self._put(route, **kwargs)

    def delete_components(self, hostname, component, **kwargs):
        # route=/api/v0/devices/:hostname/components/:component
        # required=['hostname', 'component']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/devices/{hostname}/components/{component}"""
        return self._delete(route, **kwargs)

    def get_port_stats_by_port_hostname(self, hostname, ifname, **kwargs):
        # route=/api/v0/devices/:hostname/ports/:ifname
        # required=['hostname', 'ifname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/ports/{ifname}"""
        return self._get(route, **kwargs)

    def get_graph_by_port_hostname(self, hostname, ifname, type, **kwargs):
        # route=/api/v0/devices/:hostname/ports/:ifname/:type
        # required=['hostname', 'ifname', 'type']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/ports/{ifname}/{type}"""
        return self._get(route, **kwargs)

    def list_sensors(self, **kwargs):
        # route=/api/v0/resources/sensors
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/sensors"""
        return self._get(route, **kwargs)

    def list_devices(self, **kwargs):
        # route=/api/v0/devices
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices"""
        return self._get(route, **kwargs)

    def device_under_maintenance(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/maintenance
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/maintenance"""
        return self._get(route, **kwargs)

    def maintenance_device(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/maintenance
        # required=['hostname']
        # optional=[]
        # method=POST
        route = f"""/api/v0/devices/{hostname}/maintenance"""
        return self._post(route, **kwargs)

    def add_device(self, **kwargs):
        # route=/api/v0/devices
        # required=[]
        # optional=[]
        # method=POST
        route = f"""/api/v0/devices"""
        return self._post(route, **kwargs)

    def list_oxidized(self, hostname="", **kwargs):
        # route=/api/v0/oxidized(/:hostname)
        # required=[]
        # optional=['hostname']
        # method=GET
        route = f"""/api/v0/oxidized{"/" + hostname if hostname else ""}"""
        return self._get(route, **kwargs)

    def update_device_field(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname
        # required=['hostname']
        # optional=[]
        # method=PATCH
        route = f"""/api/v0/devices/{hostname}"""
        return self._patch(route, **kwargs)

    def update_device_port_notes(self, hostname, portid, **kwargs):
        # route=/api/v0/devices/:hostname/port/:portid
        # required=['hostname', 'portid']
        # optional=[]
        # method=PATCH
        route = f"""/api/v0/devices/{hostname}/port/{portid}"""
        return self._patch(route, **kwargs)

    def rename_device(self, hostname, new_hostname, **kwargs):
        # route=/api/v0/devices/:hostname/rename/:new_hostname
        # required=['hostname', 'new_hostname']
        # optional=[]
        # method=PATCH
        route = f"""/api/v0/devices/{hostname}/rename/{new_hostname}"""
        return self._patch(route, **kwargs)

    def get_device_groups(self, hostname, **kwargs):
        # route=/api/v0/devices/:hostname/groups
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{hostname}/groups"""
        return self._get(route, **kwargs)

    def search_oxidized(self, searchstring, **kwargs):
        # route=/v0/oxidized/config/search/:searchstring
        # required=['searchstring']
        # optional=[]
        # method=GET
        route = f"""/v0/oxidized/config/search/{searchstring}"""
        return self._get(route, **kwargs)

    def get_oxidized_config(self, hostname, **kwargs):
        # route=/v0/oxidized/config/:hostname
        # required=['hostname']
        # optional=[]
        # method=GET
        route = f"""/v0/oxidized/config/{hostname}"""
        return self._get(route, **kwargs)

    def add_parents_to_host(self, device, **kwargs):
        # route=/api/v0/devices/:device/parents
        # required=['device']
        # optional=[]
        # method=POST
        route = f"""/api/v0/devices/{device}/parents"""
        return self._post(route, **kwargs)

    def delete_parents_from_host(self, device, **kwargs):
        # route=/api/v0/devices/:device/parents
        # required=['device']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/devices/{device}/parents"""
        return self._delete(route, **kwargs)

    def list_parents_of_host(self, **kwargs):
        # route=/api/v0/devices/:device/parents
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/devices/{device}/parents"""
        return self._get(route, **kwargs)


class Ports(Endpoint):

    def get_all_ports(self, **kwargs):
        # route=/api/v0/ports
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports"""
        return self._get(route, **kwargs)

    def search_ports(self, search, **kwargs):
        # route=/api/v0/ports/search/:search
        # required=['search']
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports/search/{search}"""
        return self._get(route, **kwargs)

    def search_ports(self, field, search, **kwargs):
        # route=/api/v0/ports/search/:field/:search
        # required=['field', 'search']
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports/search/{field}/{search}"""
        return self._get(route, **kwargs)

    def ports_with_associated_mac(self, search, **kwargs):
        # route=/api/v0/ports/mac/:search
        # required=['search']
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports/mac/{search}"""
        return self._get(route, **kwargs)

    def get_port_info(self, portid, **kwargs):
        # route=/api/v0/ports/:portid
        # required=['portid']
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports/{portid}"""
        return self._get(route, **kwargs)

    def get_port_ip_info(self, portid, **kwargs):
        # route=/api/v0/ports/:portid/ip
        # required=['portid']
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports/{portid}/ip"""
        return self._get(route, **kwargs)

    def get_port_transceiver(self, portid, **kwargs):
        # route=/api/v0/ports/:portid/transceiver
        # required=['portid']
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports/{portid}/transceiver"""
        return self._get(route, **kwargs)

    def get_port_description(self, portid, **kwargs):
        # route=/api/v0/ports/:portid/description
        # required=['portid']
        # optional=[]
        # method=GET
        route = f"""/api/v0/ports/{portid}/description"""
        return self._get(route, **kwargs)

    def update_port_description(self, portid, **kwargs):
        # route=/api/v0/ports/:portid/description
        # required=['portid']
        # optional=[]
        # method=PATCH
        route = f"""/api/v0/ports/{portid}/description"""
        return self._patch(route, **kwargs)


class Locations(Endpoint):

    def list_locations(self, **kwargs):
        # route=/api/v0/resources/locations
        # required=[]
        # optional=[]
        # method=GET
        route = f"""/api/v0/resources/locations"""
        return self._get(route, **kwargs)

    def add_location(self, **kwargs):
        # route=/api/v0/locations/
        # required=[]
        # optional=[]
        # method=POST
        route = f"""/api/v0/locations/"""
        return self._post(route, **kwargs)

    def delete_location(self, location, **kwargs):
        # route=/api/v0/locations/:location
        # required=['location']
        # optional=[]
        # method=DELETE
        route = f"""/api/v0/locations/{location}"""
        return self._delete(route, **kwargs)

    def edit_location(self, location, **kwargs):
        # route=/api/v0/locations/:location
        # required=['location']
        # optional=[]
        # method=PATCH
        route = f"""/api/v0/locations/{location}"""
        return self._patch(route, **kwargs)

    def get_location(self, location, **kwargs):
        # route=/api/v0/location/:location
        # required=['location']
        # optional=[]
        # method=
        route = f"""/api/v0/location/{location}"""
        return self._get(route, **kwargs)

    def maintenance_location(self, location, **kwargs):
        # route=/api/v0/locations/:location/maintenance
        # required=['location']
        # optional=[]
        # method=POST
        route = f"""/api/v0/locations/{location}/maintenance"""
        return self._post(route, **kwargs)


class Arp(Endpoint):

    def list_arp(self, query, **kwargs):
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
        self.logs = Logs(self)
        self.port_groups = PortGroups(self)
        self.system = System(self)
        self.inventory = Inventory(self)
        self.bills = Bills(self)
        self.device_groups = DeviceGroups(self)
        self.poller_groups = PollerGroups(self)
        self.alerts = Alerts(self)
        self.routing = Routing(self)
        self.port_groups = PortGroups(self)
        self.switching = Switching(self)
        self.port_security = PortSecurity(self)
        self.services = Services(self)
        self.devices = Devices(self)
        self.ports = Ports(self)
        self.locations = Locations(self)
        self.arp = Arp(self)
