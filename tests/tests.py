import pytest
import librenmsapi
import time


URL = 'http://10.1.1.101:8087'
TOKEN = '890bfcacc9d187089c425658c470513f'
HOSTNAME = 'snmpsim'
COMMUNITY = 'iosxr'
SHORTWAIT = 5
LONGWAIT = 20
SCOPE = 'module'

@pytest.fixture
def librenms():
    conn = librenmsapi.LibreNMS(URL, TOKEN)
    conn.devices.add_device(hostname=HOSTNAME, community=COMMUNITY)
    #time.sleep(WAIT)   # Allow LibreNMS to do some initial processing
    yield conn
    conn.devices.del_device(HOSTNAME)

@pytest.fixture
def shortwait():
    time.sleep(SHORTWAIT)

@pytest.fixture
def longwait():
    time.sleep(LONGWAIT)


class TestDevices:

    # add_device() and del_device() are being "tested" in the conftest.py:device() fixture.

    def test_get_device(self, librenms):
        result = librenms.devices.get_device(HOSTNAME)
        assert result[0]['hostname'] == HOSTNAME
        assert result[0]['community'] == COMMUNITY

    def test_update_device_field(self, librenms):
        result = librenms.devices.update_device_field(HOSTNAME, field='community', data='private') 
        result = librenms.devices.get_device(HOSTNAME)
        assert result[0]['community'] == 'private'

    def test_update_device_field_array(self, librenms):
        result = librenms.devices.update_device_field(HOSTNAME, field=['community', 'snmpver'], data=['private', '1']) 
        #assert result['status'] == 'ok'
        result = librenms.devices.get_device(HOSTNAME)
        assert result[0]['community'] == 'private'
        assert result[0]['snmpver'] == '1'

    def test_maintenance_device(self, librenms):
        result = librenms.devices.maintenance_device(HOSTNAME, duration='0:01')
        assert result is None

    def test_rename_device(self, librenms, longwait):
        result = librenms.devices.rename_device(HOSTNAME, "renamed"+HOSTNAME)
        assert result is None

        result = librenms.devices.get_device("renamed"+HOSTNAME)
        assert result[0]['hostname'] == "renamed"+HOSTNAME

        result = librenms.devices.rename_device("renamed"+HOSTNAME, HOSTNAME)
        assert result is None

        result = librenms.devices.get_device(HOSTNAME)
        assert result[0]['hostname'] == HOSTNAME

    def test_discover_device(self, librenms):
        result = librenms.devices.discover_device(HOSTNAME)
        assert result == {'status': 0, 'message': 'Device will be rediscovered'}

    def test_availability(self, librenms):
        result = librenms.devices.availability(HOSTNAME)
        assert isinstance(result, list)

    def test_outages(self, librenms):
        result = librenms.devices.outages(HOSTNAME)
        assert isinstance(result, list)

    def test_get_graphs(self, librenms):
        result = librenms.devices.get_graphs(HOSTNAME)
        assert isinstance(result, list)

    def test_list_available_health_graphs(self, librenms):
        result = librenms.devices.list_available_health_graphs(HOSTNAME)
        assert isinstance(result, list)

    def test_list_available_health_graphs_type(self, librenms):
        result = librenms.devices.list_available_health_graphs(HOSTNAME, 'health')
        assert isinstance(result, list)

    def test_list_available_wireless_graphs(self, librenms):
        result = librenms.devices.list_available_wireless_graphs(HOSTNAME)
        assert isinstance(result, list)

    #def test_get_health_graph(self, librenms):
    #    result = librenms.devices.get_health_graph(HOSTNAME, 'device_voltage')
    #    assert result['status'] == 'ok'

    def test_get_device_ports(self, librenms, shortwait):
        result = librenms.devices.get_device_ports(HOSTNAME)
        assert len(result) == 67


