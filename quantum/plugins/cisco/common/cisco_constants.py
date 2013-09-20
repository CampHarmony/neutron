# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
# @author: Sumit Naiksatam, Cisco Systems, Inc.


PLUGINS = 'PLUGINS'
INVENTORY = 'INVENTORY'

PORT_STATE = 'port-state'
PORT_UP = "ACTIVE"
PORT_DOWN = "DOWN"

UUID = 'uuid'
TENANTID = 'tenant_id'
NETWORKID = 'network_id'
NETWORKNAME = 'name'
NETWORKPORTS = 'ports'
INTERFACEID = 'interface_id'
PORTSTATE = 'state'
PORTID = 'port_id'
PPNAME = 'name'
PPVLANID = 'vlan_id'
PPQOS = 'qos'
VLANID = 'vlan_id'
VLANNAME = 'vlan_name'
QOS = 'qos'

ATTACHMENT = 'attachment'
PORT_ID = 'port-id'

NET_ID = 'net-id'
NET_NAME = 'net-name'
NET_PORTS = 'net-ports'
NET_VLAN_NAME = 'net-vlan-name'
NET_VLAN_ID = 'net-vlan-id'
NET_TENANTS = 'net-tenants'

TENANT_ID = 'tenant-id'
TENANT_NETWORKS = 'tenant-networks'
TENANT_NAME = 'tenant-name'
TENANT_QOS_LEVELS = 'tenant-qos-levels'
TENANT_CREDENTIALS = 'tenant-credentials'

QOS_LEVEL_ID = 'qos_id'
QOS_LEVEL_NAME = 'qos_name'
QOS_LEVEL_ASSOCIATIONS = 'qos-level-associations'
QOS_LEVEL_DESCRIPTION = 'qos_desc'

CREDENTIAL_ID = 'credential_id'
CREDENTIAL_NAME = 'credential_name'
CREDENTIAL_USERNAME = 'user_name'
CREDENTIAL_PASSWORD = 'password'
CREDENTIAL_TYPE = 'type'
MASKED_PASSWORD = '********'

USERNAME = 'username'
PASSWORD = 'password'

LOGGER_COMPONENT_NAME = "cisco_plugin"

RESERVED_NIC_HOSTNAME = "reserved-dynamic-nic-hostname"
RESERVED_NIC_NAME = "reserved-dynamic-nic-device-name"

RHEL_DEVICE_NAME_REPFIX = "eth"

NEXUS_PLUGIN = 'nexus_plugin'
VSWITCH_PLUGIN = 'vswitch_plugin'

PLUGIN_OBJ_REF = 'plugin-obj-ref'
PARAM_LIST = 'param-list'

DEVICE_IP = 'device_ip'

NO_VLAN_ID = 0

HOST_LIST = 'host_list'
HOST_1 = 'host_1'

VIF_DESC = 'vif_desc'
DEVICENAME = 'device'

IP_ADDRESS = 'ip_address'
CHASSIS_ID = 'chassis_id'
BLADE_ID = 'blade_id'
HOST_NAME = 'host_name'

INSTANCE_ID = 'instance_id'
VIF_ID = 'vif_id'
PROJECT_ID = 'project_id'

NETWORK_ADMIN = 'network_admin'

NETID_LIST = 'net_id_list'

DELIMITERS = "[,;:\b\s]"

UUID_LENGTH = 36

UNPLUGGED = '(detached)'

ASSOCIATION_STATUS = 'association_status'

ATTACHED = 'attached'

DETACHED = 'detached'

NETWORK = 'network'
PORT = 'port'
BASE_PLUGIN_REF = 'base_plugin_ref'
CONTEXT = 'context'
SUBNET = 'subnet'

#### N1Kv CONSTANTS
# Special vlan_id value in n1kv_vlan_allocations table indicating flat network
FLAT_VLAN_ID = -1

# Topic for tunnel notifications between the plugin and agent
TUNNEL = 'tunnel'

# Values for network_type
NETWORK_TYPE_FLAT = 'flat'
NETWORK_TYPE_VLAN = 'vlan'
NETWORK_TYPE_VXLAN = 'vxlan'
NETWORK_TYPE_LOCAL = 'local'
NETWORK_TYPE_NONE = 'none'
NETWORK_TYPE_TRUNK = 'trunk'
NETWORK_TYPE_MULTI_SEGMENT = 'multi-segment'

# Values for network subtypes
NETWORK_SUBTYPE_TRUNK_VLAN = NETWORK_TYPE_VLAN
NETWORK_SUBTYPE_TRUNK_VXLAN = NETWORK_TYPE_VXLAN

# Values for VXLAN subtypes
TYPE_VXLAN_UNICAST = 'unicast'
TYPE_VXLAN_MULTICAST = 'multicast'

SET = 'set'
INSTANCE = 'instance'
PROPERTIES = 'properties'
NAME = 'name'
ID = 'id'
POLICY = 'policy'
DEFAULT_TENANT_ID = '000'
URL = 'url'
ENCAPSULATIONS = 'encapsulations'
STATE = 'state'
ONLINE = 'online'
MAPPINGS = 'mappings'
MAPPING = 'mapping'
SEGMENTS = 'segments'
SEGMENT = 'segment'
BRIDGE_DOMAIN_SUFFIC = '_bd'
ENCAPSULATION_PROFILE_SUFFIX = '_profile'

UUID_LENGTH = 36
