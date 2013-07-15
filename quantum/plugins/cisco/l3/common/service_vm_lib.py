# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Cisco Systems, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Hareesh Puthalath, Cisco Systems, Inc.
# @author: Bob Melander, Cisco Systems, Inc.

from novaclient.v1_1 import client
from novaclient import exceptions as n_exc
from quantum.api.v2 import attributes
from quantum.common import exceptions as q_exc
from quantum import context as q_context
from quantum import manager
from quantum.openstack.common import uuidutils
from quantum.openstack.common import log as logging
from quantum.plugins.cisco.l3.common import constants

LOG = logging.getLogger(__name__)


# TODO(bob-melander): This should be used as a driver and fake version should
# be created for unit tests.
class ServiceVMManager:

    def __init__(self, user=None, passwd=None, l3_admin_tenant=None,
                 auth_url=None):
        self._nclient = client.Client(user, passwd, l3_admin_tenant, auth_url,
                                     service_type="compute")
        self._context = q_context.get_admin_context()
        #self._context.tenant_id=tenant_id
        self._core_plugin = manager.QuantumManager.get_plugin()

    def dispatch_service_vm(self, vm_image, vm_flavor, mgmt_port,
                            ports=None):
        nics = [{'port-id': mgmt_port['id']}]

        for port in ports:
            nics.append({'port-id': port['id']})

        try:
            server = self._nclient.servers.create('csr1kv_nrouter', vm_image,
                                                  vm_flavor, nics=nics)
        except (n_exc.UnsupportedVersion, n_exc.CommandError,
                n_exc.AuthorizationFailure, n_exc.NoUniqueMatch,
                n_exc.AuthSystemNotFound, n_exc.NoTokenLookupException,
                n_exc.EndpointNotFound, n_exc.AmbiguousEndpoints,
                n_exc.ConnectionRefused, n_exc.ClientException) as e:
            LOG.error(_('Failed to create service VM instance: %s'), e)
            return None
        return server['server']

    def delete_service_vm(self, id, mgmt_nw_id, delete_networks=False):
        nets_to_delete = []
        if delete_networks:
            ports = self._core_plugin.get_ports(self._context,
                                                filters={'device_id': [id]})

            for port in ports:
                if port['network_id'] != mgmt_nw_id:
                    nets_to_delete.append(port['network_id'])
        result = True
        try:
            self._nclient.servers.delete(id)
        except (n_exc.UnsupportedVersion, n_exc.CommandError,
                n_exc.AuthorizationFailure, n_exc.NoUniqueMatch,
                n_exc.AuthSystemNotFound, n_exc.NoTokenLookupException,
                n_exc.EndpointNotFound, n_exc.AmbiguousEndpoints,
                n_exc.ConnectionRefused, n_exc.ClientException) as e:
            LOG.error(_('Failed to delete service VM instance %(id)s, '
                        'due to %(err)s'), {'id': id, 'err': e})
            result = False
        for net in nets_to_delete:
            try:
                self._core_plugin.delete_network(self._context, net)
            except q_exc.QuantumException as e:
                LOG.error(_('Failed to delete network %(net_id)s for service '
                            'VM %(vm_id) due to %(err)s'), {'net_id': net,
                                                            'vm_id': id,
                                                            'err': e})
        return result

    def cleanup_for_service_vm(self, mgmt_port, t1_n, t2_n, t1_p, t2_p):
         # Remove anything created.
        if mgmt_port is not None:
            try:
                self._core_plugin.delete_port(self._context, mgmt_port['id'])
            except q_exc.QuantumException as e:
                LOG.error(_('Failed to delete management port %(port_id)s for '
                            'service vm due to %(err)s'),
                          {'port_id': mgmt_port['id'], 'err': e})
        for item in t1_p + t2_p:
            try:
                self._core_plugin.delete_port(self._context, item['id'])
            except q_exc.QuantumException as e:
                LOG.error(_('Failed to delete trunk port %(port_id)s for '
                            'service vm due to %(err)s'),
                          {'port_id': item['id'], 'err': e})
        for item in t1_n + t2_n:
            try:
                self._core_plugin.delete_network(self._context, item['id'])
            except q_exc.QuantumException as e:
                LOG.error(_('Failed to delete trunk network %(net_id)s for '
                            'service vm due to %(err)s'),
                          {'net_id': item['id'], 'err': e})

    def create_service_vm_resources(self, mgmt_nw_id, tenant_id, max_hosted):
        mgmt_port = None
        t1_n, t1_p, t2_n, t2_p = [], [], [], []
        if mgmt_nw_id is not None and tenant_id is not None:
            # Create port for mgmt interface
            p_spec = {'port': {'tenant_id': tenant_id,
                               'admin_state_up': True,
                               'name': 'mgmt',
                               'network_id': mgmt_nw_id,
                               'mac_address': attributes.ATTR_NOT_SPECIFIED,
                               'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                               'device_id': "",
                               'device_owner': ""}}
            try:
                mgmt_port = self._core_plugin.create_port(self._context, p_spec)
                # No security groups on the trunk ports since
                # they have no IP address
                p_spec['port']['security_groups'] = []
                # The trunk networks
                n_spec = {'network': {'tenant_id': tenant_id,
                                      'admin_state_up': True,
                                      'name': constants.T1_NETWORK_NAME,
                                      'shared': False,
                                      'trunkport:trunked_networks': {}}}
                for i in xrange(0, max_hosted):
                    # Create T1 trunk network for this router
                    indx = str(i + 1)
                    n_spec['network']['name'] = (constants.T1_NETWORK_NAME +
                                                 indx)
                    t1_n.append(self._core_plugin.create_network(
                        self._context, n_spec))
                    # Create T1 port for this router
                    p_spec['port']['name'] = constants.T1_PORT_NAME + indx
                    p_spec['port']['network_id'] = t1_n[i]['id']
                    t1_p.append(self._core_plugin.create_port(self._context,
                                                              p_spec))
                    # Create trunk network for this router
                    n_spec['network']['name'] = (constants.T2_NETWORK_NAME +
                                                 indx)
                    t2_n.append(self._core_plugin.create_network(self._context,
                                                                 n_spec))
                    # Create T2 port for this router
                    p_spec['port']['name'] = constants.T2_PORT_NAME + indx
                    p_spec['port']['network_id'] = t2_n[i]['id']
                    t2_p.append(self._core_plugin.create_port(self._context,
                                                              p_spec))
            except q_exc.QuantumException:
                self.cleanup_for_service_vm(mgmt_port, t1_n, t2_n, t1_p, t2_p)
                mgmt_port = None
                t1_n, t1_p, t2_n, t2_p = [], [], [], []
        return (mgmt_port, t1_n, t1_p, t2_n, t2_p)

    # TODO(bob-melander): Move this to fake_service_vm_lib.py file
    # with FakeServiceVMManager
    def dispatch_service_vm_fake(self, vm_image, vm_flavor, mgmt_port, ports):
        vm_id = uuidutils.generate_uuid()

        if mgmt_port is not None:
            p_dict = {'port': {'device_id': vm_id,
                               'device_owner': 'nova'}}
            self._core_plugin.update_port(self._context, mgmt_port['id'],
                                          p_dict)

        for port in ports:
            p_dict = {'port': {'device_id': vm_id,
                               'device_owner': 'nova'}}
            self._core_plugin.update_port(self._context, port['id'], p_dict)

        myserver = {'server': {'adminPass': "MVk5HPrazHcG",
                    'id': vm_id,
                    'links': [{'href': "http://openstack.example.com/v2/"
                                        "openstack/servers/" + vm_id,
                               'rel': "self"},
                                {'href': "http://openstack.example.com/"
                                          "openstack/servers/" + vm_id,
                                 'rel': "bookmark"}]}}

        return myserver['server']

    def delete_service_vm_fake(self, id, mgmt_nw_id, delete_networks=False):
        ports = self._core_plugin.get_ports(self._context,
                                            filters={'device_id': [id]})

        nets_to_delete = []
        for port in ports:
            if delete_networks and port['network_id'] != mgmt_nw_id:
                nets_to_delete.append(port['network_id'])
            self._core_plugin.delete_port(self._context, port['id'])
        for net_id in nets_to_delete:
            self._core_plugin.delete_network(self._context, net_id)
        return True
