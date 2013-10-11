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
# @author: Aruna Kushwaha, Cisco Systems, Inc.
# @author: Rudrajit Tapadar, Cisco Systems, Inc.
# @author: Abhishek Raut, Cisco Systems, Inc.
# @author: Sergey Sudakovich, Cisco Systems, Inc.


import eventlet

from oslo.config import cfg as q_conf

from quantum.agent import securitygroups_rpc as sg_rpc
from quantum.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from quantum.api.rpc.agentnotifiers import l3_rpc_agent_api
from quantum.api.v2 import attributes
from quantum.common import constants as q_const
from quantum.common import exceptions as q_exc
from quantum.common import rpc as q_rpc
from quantum.common import topics
from quantum.db import agents_db
from quantum.db import agentschedulers_db
from quantum.db import db_base_plugin_v2
from quantum.db import dhcp_rpc_base
from quantum.db import extraroute_db
from quantum.db import l3_rpc_base
from quantum.db import securitygroups_rpc_base as sg_db_rpc
from quantum.extensions import portbindings
from quantum.extensions import providernet
from quantum.openstack.common import excutils
from quantum.openstack.common import importutils
from quantum.openstack.common import log as logging
from quantum.openstack.common import rpc
from quantum.openstack.common import uuidutils as uuidutils
from quantum.openstack.common.rpc import proxy
from quantum.plugins.cisco.common import cisco_constants as c_const
from quantum.plugins.cisco.common import cisco_credentials_v2 as c_cred
from quantum.plugins.cisco.common import cisco_exceptions
from quantum.plugins.cisco.common import config as c_conf
from quantum.plugins.cisco.db import n1kv_db_v2
from quantum.plugins.cisco.db import network_db_v2
from quantum.plugins.cisco.extensions import n1kv_profile
from quantum.plugins.cisco.l3.db import composite_agentschedulers_db as agt_sch_db
from quantum.plugins.cisco.l3.db import l3_cfg_rpc_base
from quantum.plugins.cisco.l3.db import l3_router_appliance_db
from quantum.plugins.cisco.n1kv import n1kv_client
from quantum import policy


LOG = logging.getLogger(__name__)


class N1kvRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin,
                       l3_rpc_base.L3RpcCallbackMixin,
                       l3_cfg_rpc_base.L3CfgRpcCallbackMixin,
                       sg_db_rpc.SecurityGroupServerRpcCallbackMixin):

    """Class to handle agent RPC calls."""
    # Set RPC API version to 1.1 by default.
    RPC_API_VERSION = '1.1'

    def __init__(self, notifier):
        self.notifier = notifier

    def create_rpc_dispatcher(self):
        """Get the rpc dispatcher for this rpc manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        """
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])

    def get_port_from_device(cls, device):
        port = n1kv_db_v2.get_port_from_device(device)
        if port:
            port['device'] = device
        return port

    def get_device_details(self, rpc_context, **kwargs):
        """Agent requests device details."""
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug(_("Device %(device)s details requested from %(agent_id)s"),
                  locals())
        port = n1kv_db_v2.get_port(device)
        if port:
            binding = n1kv_db_v2.get_network_binding(None, port['network_id'])
            entry = {'device': device,
                     'network_id': port['network_id'],
                     'port_id': port['id'],
                     'admin_state_up': port['admin_state_up'],
                     'network_type': binding.network_type,
                     'segmentation_id': binding.segmentation_id,
                     'physical_network': binding.physical_network}
            # Set the port status to UP
            n1kv_db_v2.set_port_status(port['id'], q_const.PORT_STATUS_ACTIVE)
        else:
            entry = {'device': device}
            LOG.debug(_("%s can not be found in database"), device)
        return entry

    def update_device_down(self, rpc_context, **kwargs):
        """Device no longer exists on agent"""
        # (TODO) garyk - live migration and port status
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug(_("Device %(device)s no longer exists on %(agent_id)s"),
                  locals())
        port = n1kv_db_v2.get_port(device)
        if port:
            entry = {'device': device,
                     'exists': True}
            # Set port status to DOWN
            n1kv_db_v2.set_port_status(port['id'], q_const.PORT_STATUS_DOWN)
        else:
            entry = {'device': device,
                     'exists': False}
            LOG.debug(_("%s can not be found in database"), device)
        return entry


class AgentNotifierApi(proxy.RpcProxy,
                       sg_rpc.SecurityGroupAgentRpcApiMixin):

    '''Agent side of the N1kv rpc API.

    API version history:
        1.0 - Initial version.

    '''

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic):
        super(AgentNotifierApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.topic_network_delete = topics.get_topic_name(topic,
                                                          topics.NETWORK,
                                                          topics.DELETE)
        self.topic_port_update = topics.get_topic_name(topic,
                                                       topics.PORT,
                                                       topics.UPDATE)
        self.topic_vxlan_update = topics.get_topic_name(topic,
                                                        c_const.TUNNEL,
                                                        topics.UPDATE)

    def network_delete(self, context, network_id):
        self.fanout_cast(context,
                         self.make_msg('network_delete',
                                       network_id=network_id),
                         topic=self.topic_network_delete)

    def port_update(self, context, port, network_type, segmentation_id,
                    physical_network):
        self.fanout_cast(context,
                         self.make_msg('port_update',
                                       port=port,
                                       network_type=network_type,
                                       segmentation_id=segmentation_id,
                                       physical_network=physical_network),
                         topic=self.topic_port_update)

    def vxlan_update(self, context, vxlan_ip, vxlan_id):
        self.fanout_cast(context,
                         self.make_msg('vxlan_update',
                                       vxlan_ip=vxlan_ip,
                                       vxlan_id=vxlan_id),
                         topic=self.topic_vxlan_update)


class N1kvQuantumPluginV2(db_base_plugin_v2.QuantumDbPluginV2,
                          l3_router_appliance_db.L3_router_appliance_db_mixin,
                          n1kv_db_v2.NetworkProfile_db_mixin,
                          n1kv_db_v2.PolicyProfile_db_mixin,
                          network_db_v2.Credential_db_mixin,
                          agt_sch_db.CompositeAgentSchedulerDbMixin):

    """
    Implement the Quantum abstractions using Cisco Nexus1000V

    Refer README file for the architecture, new features, and
    workflow

    """

    # This attribute specifies whether the plugin supports or not
    # bulk operations.
    __native_bulk_support = False
    supported_extension_aliases = ["provider", "agent", "binding",
                                   "policy_profile_binding",
                                   "network_profile_binding",
                                   "n1kv_profile", "network_profile",
                                   "policy_profile", "router", "credential",
                                   "agent_scheduler"]

    binding_view = "extension:port_binding:view"
    binding_set = "extension:port_binding:set"

    def __init__(self, configfile=None):
        """
        Initialize Nexus1000V Quantum plugin

        1. Initialize Nexus1000v and Credential DB
        2. Establish communication with Cisco Nexus1000V
        """
        n1kv_db_v2.initialize()
        c_cred.Store.initialize()
        # If no api_extensions_path is provided set the following
        if not q_conf.CONF.api_extensions_path:
            q_conf.CONF.set_override(
                'api_extensions_path',
                'extensions:quantum/plugins/cisco/extensions')
        self._setup_vsm()
        self._setup_rpc()
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver)
        self.router_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver)
        self.hosting_scheduler = importutils.import_object(
            cfg.CONF.hosting_scheduler_driver)

    def _setup_rpc(self):
        # RPC support
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.notifier = AgentNotifierApi(topics.AGENT)
        self.callbacks = N1kvRpcCallbacks(self.notifier)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.dhcp_agent_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        self.l3_agent_notifier = l3_rpc_agent_api.L3AgentNotify
        self.conn.consume_in_thread()

    def _setup_vsm(self):
        """
        Setup Cisco Nexus 1000V related parameters and pull policy profiles.

        Retreive all the policy profiles from the VSM when the plugin is
        is instantiated for the first time and then continue to poll for
        policy profile updates.
        """
        LOG.debug(_('_setup_vsm'))
        self.agent_vsm = True
        # Poll VSM for create/delete of policy profiles.
        eventlet.spawn(self._poll_policy_profiles)

    def _poll_policy_profiles(self):
        """Start a green thread to pull policy profiles from VSM."""
        while True:
            self._populate_policy_profiles()
            eventlet.sleep(int(c_conf.CISCO_N1K.poll_duration))

    def _populate_policy_profiles(self):
        """
        Populate all the policy profiles from VSM.


        The tenant id is not available when the policy profiles are polled
        from the VSM. Hence we associate the policy profiles with fake
        tenant-ids.
        """
        LOG.debug(_('_populate_policy_profiles'))
        try:
            n1kvclient = n1kv_client.Client()
            policy_profiles = n1kvclient.list_port_profiles()
            vsm_profiles = {}
            plugin_profiles = {}
            # Fetch policy profiles from VSM
            if policy_profiles:
                for profile in policy_profiles['body'][c_const.SET]:
                    if c_const.ID and c_const.NAME in profile:
                        vsm_profiles[profile[c_const.PROPERTIES][c_const.ID]] =\
                            profile[c_const.PROPERTIES][c_const.NAME]
                # Fetch policy profiles previously populated
                for profile in n1kv_db_v2._get_policy_profiles():
                    plugin_profiles[profile.id] = profile.name
                vsm_profiles_set = set(vsm_profiles)
                plugin_profiles_set = set(plugin_profiles)
                # Update database if the profile sets differ.
                if vsm_profiles_set ^ plugin_profiles_set:
                    # Add profiles in database if new profiles were created in VSM
                    for pid in vsm_profiles_set - plugin_profiles_set:
                        self._add_policy_profile(vsm_profiles[pid], pid)
                    # Delete profiles from database if profiles were deleted in VSM
                    for pid in plugin_profiles_set - vsm_profiles_set:
                        self._delete_policy_profile(pid)
            self._remove_all_fake_policy_profiles()
        except (cisco_exceptions.VSMError,
                cisco_exceptions.VSMConnectionFailed):
            LOG.warning(_('No policy profile populated from VSM'))

    def _check_provider_view_auth(self, context, network):
        return policy.check(context,
                            "extension:provider_network:view",
                            network)

    def _enforce_provider_set_auth(self, context, network):
        return policy.enforce(context,
                              "extension:provider_network:set",
                              network)

    def _extend_network_dict_provider(self, context, network):
        """Add extended network parameters."""
        binding = n1kv_db_v2.get_network_binding(context.session,
                                                 network['id'])
        network[providernet.NETWORK_TYPE] = binding.network_type
        if binding.network_type == c_const.NETWORK_TYPE_VXLAN:
            network[providernet.PHYSICAL_NETWORK] = None
            network[providernet.SEGMENTATION_ID] = binding.segmentation_id
            network[n1kv_profile.MULTICAST_IP] = binding.multicast_ip
        elif binding.network_type == c_const.NETWORK_TYPE_VLAN:
            network[providernet.PHYSICAL_NETWORK] = binding.physical_network
            network[providernet.SEGMENTATION_ID] = binding.segmentation_id
        elif binding.network_type == c_const.NETWORK_TYPE_TRUNK:
            network[providernet.PHYSICAL_NETWORK] = binding.physical_network
            network[providernet.SEGMENTATION_ID] = None
            network[n1kv_profile.MULTICAST_IP] = None
        elif binding.network_type == c_const.NETWORK_TYPE_MULTI_SEGMENT:
            network[providernet.PHYSICAL_NETWORK] = None
            network[providernet.SEGMENTATION_ID] = None
            network[n1kv_profile.MULTICAST_IP] = None

    def _process_provider_create(self, context, attrs):
        network_type = attrs.get(providernet.NETWORK_TYPE)
        physical_network = attrs.get(providernet.PHYSICAL_NETWORK)
        segmentation_id = attrs.get(providernet.SEGMENTATION_ID)

        network_type_set = attributes.is_attr_set(network_type)
        physical_network_set = attributes.is_attr_set(physical_network)
        segmentation_id_set = attributes.is_attr_set(segmentation_id)

        if not (network_type_set or physical_network_set or
                segmentation_id_set):
            return (None, None, None)

        # Authorize before exposing plugin details to client
        self._enforce_provider_set_auth(context, attrs)

        if not network_type_set:
            msg = _("provider:network_type required")
            raise q_exc.InvalidInput(error_message=msg)
        elif network_type == c_const.NETWORK_TYPE_VLAN:
            if not segmentation_id_set:
                msg = _("provider:segmentation_id required")
                raise q_exc.InvalidInput(error_message=msg)
            if segmentation_id < 1 or segmentation_id > 4094:
                msg = _("provider:segmentation_id out of range "
                        "(1 through 4094)")
                raise q_exc.InvalidInput(error_message=msg)
        elif network_type == c_const.NETWORK_TYPE_VXLAN:
            if physical_network_set:
                msg = _("provider:physical_network specified for VXLAN "
                        "network")
                raise q_exc.InvalidInput(error_message=msg)
            else:
                physical_network = None
            if not segmentation_id_set:
                msg = _("provider:segmentation_id required")
                raise q_exc.InvalidInput(error_message=msg)
            if segmentation_id < 5000:
                msg = _("provider:segmentation_id out of range "
                        "(5000+)")
                raise q_exc.InvalidInput(error_message=msg)
        else:
            msg = _("provider:network_type %s not supported"), network_type
            raise q_exc.InvalidInput(error_message=msg)

        if network_type in [c_const.NETWORK_TYPE_VLAN]:
            if physical_network_set:
                network_profiles = n1kv_db_v2._get_network_profiles()
                for network_profile in network_profiles:
                    if physical_network == network_profile["physical_network"]:
                        break
                else:
                    msg = (_("unknown provider:physical_network %s"),
                           physical_network)
                    raise q_exc.InvalidInput(error_message=msg)
            else:
                msg = _("provider:physical_network required")
                raise q_exc.InvalidInput(error_message=msg)

        return (network_type, physical_network, segmentation_id)

    def _check_provider_update(self, context, attrs):
        """Handle Provider network updates."""
        network_type = attrs.get(providernet.NETWORK_TYPE)
        physical_network = attrs.get(providernet.PHYSICAL_NETWORK)
        segmentation_id = attrs.get(providernet.SEGMENTATION_ID)

        network_type_set = attributes.is_attr_set(network_type)
        physical_network_set = attributes.is_attr_set(physical_network)
        segmentation_id_set = attributes.is_attr_set(segmentation_id)

        if not (network_type_set or physical_network_set or
                segmentation_id_set):
            return

        # Authorize before exposing plugin details to client
        self._enforce_provider_set_auth(context, attrs)

        # TBD : Need to handle provider network updates
        msg = _("plugin does not support updating provider attributes")
        raise q_exc.InvalidInput(error_message=msg)

    def _send_add_multi_segment_request(self, context, segment_pairs):
        """
        Send Add multi-segment network request to VSM.

        :param context: quantum api request context
        :param segment_pairs: List of segments in UUID pairs
                              that need to be bridged
        """

        if segment_pairs == []:
            return

        # GET list of VXLAN gateway clusters
        n1kvclient = n1kv_client.Client()
        clusters = n1kvclient.get_vxlan_gw_clusters()
        #FIXME: Below six lines to be removed
        encap_dict = {}
        encap_dict['serviceInstance'] = 1
        encap_dict['segment1'] = 100
        encap_dict['segment2'] = 200
        n1kvclient.add_multi_segment(context, 0, encap_dict)
        return
        # Select the first cluster with no encapsulation
        for cluster in clusters['body'][c_const.SET]:
            if c_const.ENCAPSULATIONS not in \
                    cluster[c_const.
                            PROPERTIES][c_const.
                                    SERVICEINSTANCES][c_const.
                                            SERVICEINSTANCE]:
                    cluster_id = cluster[c_const.NAME]
                    service_instance = cluster[c_const.PROPERTIES]
                    [c_const.SERVICEINSTANCES][c_const.SERVICEINSTANCE]
                    [c_const.ID]
                    break
        # Pair the VLAN and VXLAN segment
        for (segment1, segment2) in segment_pairs:
            encap_dict = {}
            encap_dict['serviceInstance'] = service_instance
            encap_dict['segment1'] = segment1
            encap_dict['segment2'] = segment2
            n1kvclient.add_multi_segment(context, cluster_id, encap_dict)
            LOG.debug('_send_add_multi_segment_request: %s '
                      'cluster_id %s', segment_pairs, cluster_id)

    def _send_del_multi_segment_request(self, context, segment_pairs):
        """
        Send Delete multi-segment network request to VSM.

        :param context: quantum api request context
        :param segment_pairs: List of segments in UUID pairs
                              whose bridging needs to be removed
        """
        if segment_pairs == []:
            return
        # Check on which cluster segments are mapped
        n1kvclient = n1kv_client.Client()
        clusters = n1kvclient.get_vxlan_gw_clusters()
        #FIXME: Following two lines to be deleted
        n1kvclient.del_multi_segment(context, 0, 1)
        return
        for (segment1, segment2) in segment_pairs:
            for cluster in clusters['body'][c_const.SET]:
                service_instances = \
                    cluster[c_const.PROPERTIES][c_const.SERVICEINSTANCES]
                if (segment1, segment2) in \
                    service_instances[c_const.
                                      SERVICEINSTANCE][c_const.
                                                       ENCAPSULTATIONS]:
                    cluster_id = cluster[c_const.NAME]
                    service_instance = \
                        service_instances[c_const.SERVICEINSTANCE][c_const.ID]
                    n1kvclient.del_multi_segment(context,
                                                 cluster_id, service_instance)
                    LOG.debug('_send_del_multi_segment_request:'
                              ' cluster_id %s segments %s %s',
                              cluster_id, segment1, segment2)

    def _extend_network_dict_member_segments(self, context, network):
        """Add the extended parameter member segments to the network."""
        members = []
        binding = n1kv_db_v2.get_network_binding(context.session,
                                                 network['id'])
        if binding.network_type == c_const.NETWORK_TYPE_TRUNK:
            members = n1kv_db_v2.get_trunk_members(context.session,
                                                   network['id'])
        elif binding.network_type == c_const.NETWORK_TYPE_MULTI_SEGMENT:
            members = n1kv_db_v2.get_multi_segment_members(context.session,
                                                           network['id'])
        network[n1kv_profile.MEMBER_SEGMENTS] = members

    def _extend_network_dict_profile(self, context, network):
        """Add the extended parameter network profile to the network."""
        binding = n1kv_db_v2.get_network_binding(context.session,
                                                 network['id'])
        network[n1kv_profile.PROFILE_ID] = binding.profile_id

    def _extend_port_dict_profile(self, context, port):
        """Add the extended parameter port profile to the port."""
        binding = n1kv_db_v2.get_port_binding(context.session,
                                              port['id'])
        port[n1kv_profile.PROFILE_ID] = binding.profile_id

    def _process_network_profile(self, context, attrs):
        """Validate network profile exists."""
        profile_id = attrs.get(n1kv_profile.PROFILE_ID)
        profile_id_set = attributes.is_attr_set(profile_id)
        if not profile_id_set:
            raise cisco_exceptions.NetworkProfileIdNotFound(
                profile_id=profile_id)
        if not self.network_profile_exists(context, profile_id):
            raise cisco_exceptions.NetworkProfileIdNotFound(
                profile_id=profile_id)
        return profile_id

    def _process_policy_profile(self, context, attrs):
        """Validates whether policy profile exists."""
        profile_id = attrs.get(n1kv_profile.PROFILE_ID)
        profile_id_set = attributes.is_attr_set(profile_id)
        if not profile_id_set:
            msg = _("n1kv:profile_id does not exist")
            raise q_exc.InvalidInput(error_message=msg)
        if not self.policy_profile_exists(context, profile_id):
            msg = _("n1kv:profile_id does not exist")
            raise q_exc.InvalidInput(error_message=msg)

        return profile_id

    def _check_view_auth(self, context, resource, action):
        return policy.check(context, action, resource)

    def _enforce_set_auth(self, context, resource, action):
        policy.enforce(context, action, resource)

    def _extend_port_dict_binding(self, context, port):
        if self._check_view_auth(context, port, self.binding_view):
            port[portbindings.VIF_TYPE] = portbindings.VIF_TYPE_OVS
        return port

    def _send_create_logical_network_request(self, network_profile, tenant_id):
        """
        Send create logical network request to VSM.

        :param network_profile: network profile dictionary
        :param tenant_id: UUID representing tenant
        """
        LOG.debug(_('_send_create_logical_network'))
        n1kvclient = n1kv_client.Client()
        n1kvclient.create_logical_network(network_profile, tenant_id)

    def _send_delete_logical_network_request(self, network_profile):
        """
        Send delete logical network request to VSM.
        """
        LOG.debug(_('_send_delete_logical_network'))
        n1kvclient = n1kv_client.Client()
        logical_network_name = network_profile['id'] + "_log_net"
        n1kvclient.delete_logical_network(logical_network_name)

    def _send_delete_fabric_network_request(self, profile):
        """
        Send delete fabric network request to VSM.
        """
        LOG.debug('_send_delete_fabric_network')
        n1kvclient = n1kv_client.Client()
        n1kvclient.delete_fabric_network(profile)

    def _send_create_network_profile_request(self, context, profile):
        """
        Send create network profile request to VSM.

        :param context: neutron api request context
        :param profile: network profile dictionary
        """
        LOG.debug(_('_send_create_network_profile_request: %s'), profile['id'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.create_network_segment_pool(profile, context.tenant_id)

    def _send_update_network_profile_request(self, profile):
        """
        Send update network profile request to VSM.

        :param profile: network profile dictionary
        """
        LOG.debug(_('_send_update_network_profile_request: %s'), profile['id'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.update_network_segment_pool(profile)

    def _send_delete_network_profile_request(self, profile):
        """
        Send delete network profile request to VSM.

        :param profile: network profile dictionary
        """
        LOG.debug(_('_send_delete_network_profile_request: %s'),
                  profile['name'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.delete_network_segment_pool(profile['id'])

    def _populate_member_segments(self, context, network, segment_pairs, oper):
        """
        Populate trunk network dict with member segments.

        :param context: neutron api request context
        :param network: Dictionary containing the trunk network information
        :param segment_pairs: List of segments in UUID pairs
                              that needs to be trunked
        :param oper: Operation to be performed
        """
        LOG.debug('_populate_member_segments: %s ', segment_pairs)
        trunk_list = []
        for (segment, dot1qtag) in segment_pairs:
            member_dict = {}
            net = self.get_network(context, segment)
            member_dict['segment'] = net['name']
            member_dict['dot1qtag'] = dot1qtag
            trunk_list.append(member_dict)
        if oper == n1kv_profile.SEGMENT_ADD:
            network['add_segment_list'] = trunk_list
        elif oper == n1kv_profile.SEGMENT_DEL:
            network['del_segment_list'] = trunk_list

    def _send_create_network_request(self, context, network, segment_pairs):
        """
        Send create network request to VSM.

        Create a bridge domain if network is of type VXLAN.
        :param context: neutron api request context
        :param network: network dictionary
        """
        LOG.debug(_('_send_create_network_request: %s'), network['id'])
        profile = self.get_network_profile(context,
                                           network[n1kv_profile.PROFILE_ID])
        n1kvclient = n1kv_client.Client()
        if network[providernet.NETWORK_TYPE] == c_const.NETWORK_TYPE_VXLAN:
            if profile['sub_type'] == c_const.TYPE_VXLAN_MULTICAST:
                n1kvclient.create_bridge_domain(network, profile['sub_type'])
        if network[providernet.NETWORK_TYPE] == c_const.NETWORK_TYPE_TRUNK:
            self._populate_member_segments(context, network, segment_pairs,
                    n1kv_profile.SEGMENT_ADD)
            network['del_segment_list'] = []
        try:
            n1kvclient.create_network_segment(network, profile)
        except(cisco_exceptions.VSMError,
               cisco_exceptions.VSMConnectionFailed):
            with excutils.save_and_reraise_exception():
                if network[providernet.NETWORK_TYPE] == c_const.NETWORK_TYPE_VXLAN:
                    if profile['sub_type'] == c_const.TYPE_VXLAN_MULTICAST:
                        bridge_domain_name = network['name'] + '_bd'
                        n1kvclient.delete_bridge_domain(bridge_domain_name)

    def _send_update_network_request(self, context, network, add_segments,
                                     del_segments):
        """
        Send update network request to VSM

        :param network: network dictionary
        """
        LOG.debug(_('_send_update_network_request: %s'), network['id'])
        profile = n1kv_db_v2.get_network_profile(context.session,
                                                 network[n1kv_profile.PROFILE_ID])
        body = {'publishName': network['name'],
                'id': network['id'],
                'networkSegmentPool': profile['id'],
                'vlan': network[providernet.SEGMENTATION_ID]}
        if network[providernet.NETWORK_TYPE] == c_const.NETWORK_TYPE_TRUNK:
            self._populate_member_segments(context, network, add_segments,
                                           n1kv_profile.SEGMENT_ADD)
            self._populate_member_segments(context, network, del_segments,
                                           n1kv_profile.SEGMENT_DEL)
            body['mode'] = c_const.NETWORK_TYPE_TRUNK
            body['segmentType'] = profile['sub_type']
            body['addSegments'] = network['add_segment_list']
            body['delSegments'] = network['del_segment_list']
            LOG.debug("add_segments=%s", body['addSegments'])
            LOG.debug("del_segments=%s", body['delSegments'])
        else:
            body['mode'] = 'access'
            body['segmentType'] = profile['segment_type']
        n1kvclient = n1kv_client.Client()
        n1kvclient.update_network_segment(network['id'], body)

    def _send_delete_network_request(self, context, network):
        """
        Send delete network request to VSM

        Delete bridge domain if network is of type VXLAN.
        :param network: network dictionary
        """
        LOG.debug(_('_send_delete_network_request: %s'), network['id'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.delete_network_segment(network['id'])
        if network[providernet.NETWORK_TYPE] == c_const.NETWORK_TYPE_VXLAN:
            profile = self.get_network_profile(context,
                                               network[n1kv_profile.PROFILE_ID])
            if profile["sub_type"] == c_const.TYPE_VXLAN_MULTICAST:
                name = network['id'] + '_bd'
                n1kvclient.delete_bridge_domain(name)

    def _send_create_subnet_request(self, context, subnet):
        """
        Send create subnet request to VSM

        :param context: neutron api request context
        :param subnet: subnet dictionary
        """
        LOG.debug(_('_send_create_subnet_request: %s'), subnet['id'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.create_ip_pool(subnet)
        body = {'ipPool': subnet['id']}
        try:
            n1kvclient.update_network_segment(subnet['network_id'], body=body)
        except(cisco_exceptions.VSMError,
               cisco_exceptions.VSMConnectionFailed):
            with excutils.save_and_reraise_exception():
                n1kvclient.delete_ip_pool(subnet['id'])

    # TBD Begin : Need to implement this function
    def _send_update_subnet_request(self, subnet):
        """
        Send update subnet request to VSM

        :param subnet: subnet dictionary
        """
        LOG.debug(_('_send_update_subnet_request: %s'), subnet['id'])
    # TBD End.

    def _send_delete_subnet_request(self, context, subnet):
        """
        Send delete subnet request to VSM

        :param subnet: subnet dictionary
        """
        LOG.debug(_('_send_delete_subnet_request: %s'), subnet)
        body = {'ipPool': subnet['id'], 'deleteSubnet': True}
        n1kvclient = n1kv_client.Client()
        n1kvclient.update_network_segment(subnet['network_id'], body=body)
        try:
            n1kvclient.delete_ip_pool(subnet['id'])
        except(cisco_exceptions.VSMError,
               cisco_exceptions.VSMConnectionFailed):
            with excutils.save_and_reraise_exception():
                body['deleteSubnet'] = False
                n1kvclient.update_network_segment(subnet['network_id'], body=body)

    def _send_create_port_request(self, context, port):
        """
        Send create port request to VSM

        Create a VM network for a network and policy profile combination.
        If the VM network already exists, bind this port to the existing
        VM network and increment its port count.
        :param context: neutron api request context
        :param port: port dictionary
        """
        LOG.debug(_('_send_create_port_request: %s'), port)
        n1kvclient = n1kv_client.Client()
        with context.session.begin(subtransactions=True):
            try:
                vm_network = n1kv_db_v2.get_vm_network(
                    context.session,
                    port[n1kv_profile.PROFILE_ID],
                    port['network_id'])
            except cisco_exceptions.VMNetworkNotFound:
                policy_profile = n1kv_db_v2.get_policy_profile(
                    port[n1kv_profile.PROFILE_ID])
                vm_network_name = "vmn_" + str(port[n1kv_profile.PROFILE_ID]) +\
                                  "_" + str(port['network_id'])
                port_count = 1
                n1kv_db_v2.add_vm_network(context.session,
                                          vm_network_name,
                                          port[n1kv_profile.PROFILE_ID],
                                          port['network_id'],
                                          port_count)
                n1kvclient.create_vm_network(port,
                                             vm_network_name,
                                             policy_profile)
                try:
                    n1kvclient.create_n1kv_port(port, vm_network_name)
                except(cisco_exceptions.VSMError,
                       cisco_exceptions.VSMConnectionFailed):
                    with excutils.save_and_reraise_exception():
                        n1kvclient.delete_vm_network(vm_network_name)
            else:
                vm_network_name = vm_network['name']
                vm_network['port_count'] += 1
                n1kv_db_v2.update_vm_network(context.session,
                                             vm_network_name,
                                             vm_network['port_count'])
                LOG.debug(_('Abhishek: %s'), port["fixed_ips"][0]["ip_address"])
                n1kvclient.create_n1kv_port(port, vm_network_name)

    def _send_update_port_request(self, port_id, mac_address, vm_network_name):
        """
        Send update port request to VSM

        :param port_id: UUID representing port to update
        :param mac_address: string representing the mac address
        :param vm_network_name: VM network name to which the port is bound
        """
        LOG.debug(_('_send_update_port_request: %s'), port_id)
        body = {'portId': port_id,
                'macAddress': mac_address}
        n1kvclient = n1kv_client.Client()
        n1kvclient.update_n1kv_port(vm_network_name, port_id, body)

    def _send_delete_port_request(self, context, id):
        """
        Send delete port request to VSM

        Decrement the port count of the VM network after deleting the port.
        If the port count reaches zero, delete the VM network.
        :param context: neutron api request context
        :param id: UUID of the port to be deleted
        """
        LOG.debug(_('_send_delete_port_request: %s'), id)
        with context.session.begin(subtransactions=True):
            port = self.get_port(context, id)
            vm_network = n1kv_db_v2.get_vm_network(context.session,
                                                   port[n1kv_profile.PROFILE_ID],
                                                   port['network_id'])
            vm_network['port_count'] -= 1
            n1kv_db_v2.update_vm_network(context.session,
                                         vm_network['name'],
                                         vm_network['port_count'])
            n1kvclient = n1kv_client.Client()
            n1kvclient.delete_n1kv_port(vm_network['name'], id)
            if vm_network['port_count'] == 0:
                n1kv_db_v2.delete_vm_network(context.session,
                                             port[n1kv_profile.PROFILE_ID],
                                             port['network_id'])
                try:
                    n1kvclient.delete_vm_network(vm_network['name'])
                except(cisco_exceptions.VSMError,
                       cisco_exceptions.VSMConnectionFailed):
                    with excutils.save_and_reraise_exception():
                        n1kvclient.create_n1kv_port(port, vm_network['name'])

    def _get_segmentation_id(self, context, id):
        """
        Retreive segmentation ID for a given network

        :param context: neutron api request context
        :param id: UUID of the network
        :returns: segmentation ID for the network
        """
        session = context.session
        binding = n1kv_db_v2.get_network_binding(session, id)
        return binding.segmentation_id

    def _parse_multi_segments(self, context, attrs, param):
        """
        Parse the multi-segment network attributes

        :param context: quantum api request context
        :param attrs: Attributes of the network
        :param param: Additional parameter indicating an add
                            or del operation
        :returns: List of segment UUIDs in set pairs
        """
        pair_list = []
        segments = attrs.get(param)
        if not attributes.is_attr_set(segments):
            return pair_list
        for pair in segments.split(','):
            segment1 = pair[0:36]
            segment2 = pair[37:73]
            if uuidutils.is_uuid_like(segment1) and \
                    uuidutils.is_uuid_like(segment2):
                if self.get_network(context, segment1) and \
                        self.get_network(context, segment2):
                    #TODO: Validate that the segment pairs adjacent are
                    #not of same type
                    #TODO: Add bridge-domain and vlan tag
                    pair_list.append((segment1, segment2))
                else:
                    msg = _("Network does not exist")
            else:
                LOG.debug("%s or %s is not a valid uuid", segment1, segment2)
                msg = _("Invalid UUID supplied")
                raise q_exc.InvalidInput(error_message=msg)
        return pair_list

    def _parse_trunk_segments(self, context, attrs, param, physical_network):
        """
        Parse the trunk network attributes

        :param context: quantum api request context
        :param attrs: Attributes of the network
        :param param: Additional parameter indicating an add
                        or del operation
        :param attrs: Physical network of the trunk segment
        :returns: List of segment UUIDs and dot1qtag (for vxlan) in set pairs
        """
        pair_list = []
        LOG.debug("attrs=%s", attrs)
        segments = attrs.get(param)
        if not attributes.is_attr_set(segments):
            return pair_list
        for pair in segments.split(','):
            segment = pair[0:36]
            dot1qtag = pair[37:]
            if uuidutils.is_uuid_like(segment):
                binding = n1kv_db_v2.get_network_binding(context.session,
                                                         segment)
                if binding.network_type == c_const.NETWORK_TYPE_TRUNK:
                    msg = _("Cannot add a trunk segment as a member of"
                            " another trunk segment")
                    raise q_exc.InvalidInput(error_message=msg)
                else:
                    if physical_network == "":
                        physical_network = binding.physical_network
                    elif physical_network != binding.physical_network:
                        msg = _("Network UUID %s belongs to a different "
                                "physical network." % segment)
                        raise q_exc.InvalidInput(error_message=msg)
                    pair_list.append((segment, dot1qtag))
            else:
                LOG.debug("%s is not a valid uuid", segment)
                msg = _("Invalid UUID supplied")
                raise q_exc.InvalidInput(error_message=msg)
        return pair_list

    def create_network(self, context, network):
        """
        Create network based on network profile

        :param context: neutron api request context
        :param network: network dictionary
        :returns: network object
        """
        (network_type, physical_network,
         segmentation_id) = self._process_provider_create(context,
                                                          network['network'])
        self._add_dummy_profile_only_if_testing(network)
        profile_id = self._process_network_profile(context, network['network'])
        segment_pairs = None

        LOG.debug(_('create network: profile_id=%s'), profile_id)
        session = context.session
        with session.begin(subtransactions=True):
            if not network_type:
                # tenant network
                (physical_network, network_type, segmentation_id,
                    multicast_ip) = n1kv_db_v2.alloc_network(session,
                                                             profile_id)
                LOG.debug(_('Physical_network %(phy_net)s, '
                            'seg_type %(net_type)s, '
                            'seg_id %(seg_id)s, '
                            'multicast_ip %(multicast_ip)s'),
                          {'phy_net': physical_network,
                           'net_type': network_type,
                           'seg_id': segmentation_id,
                           'multicast_ip': multicast_ip})
                if network_type == c_const.NETWORK_TYPE_MULTI_SEGMENT:
                    segment_pairs = \
                        self._parse_multi_segments(context, network['network'],
                                                   n1kv_profile.SEGMENT_ADD)
                    LOG.debug("seg list %s ", segment_pairs)
                elif network_type == c_const.NETWORK_TYPE_TRUNK:
                    segment_pairs = \
                        self._parse_trunk_segments(context, network['network'],
                                                   n1kv_profile.SEGMENT_ADD,
                                                   physical_network)
                    LOG.debug("seg list %s ", segment_pairs)
                else:
                    if not segmentation_id:
                        raise q_exc.TenantNetworksDisabled()
            else:
                # provider network
                if network_type == c_const.NETWORK_TYPE_VLAN:
                    network_profile = self.get_network_profile(context,
                                                               profile_id)
                    seg_min, seg_max = self._get_segment_range(
                        network_profile['segment_range'])
                    if not seg_min <= segmentation_id <= seg_max:
                        raise cisco_exceptions.VlanIDOutsidePool
                    else:
                        n1kv_db_v2.reserve_specific_vlan(session,
                                                         physical_network,
                                                         segmentation_id)
                        multicast_ip = '0.0.0.0'
            net = super(N1kvQuantumPluginV2, self).create_network(context,
                                                                  network)
            n1kv_db_v2.add_network_binding(session,
                                           net['id'],
                                           network_type,
                                           physical_network,
                                           segmentation_id,
                                           multicast_ip,
                                           profile_id,
                                           segment_pairs)
            self._process_l3_create(context, network['network'], net['id'])
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_profile(context, net)
            self._extend_network_dict_l3(context, net)
            if network_type not in [c_const.NETWORK_TYPE_MULTI_SEGMENT]:
                self._send_create_network_request(context, net, segment_pairs)
                # note - exception will rollback entire transaction
            elif network_type == c_const.NETWORK_TYPE_MULTI_SEGMENT:
                self._send_add_multi_segment_request(context, segment_pairs)
            # note - exception will rollback entire transaction
            LOG.debug(_("Created network: %s"), net['id'])
            return net

    def update_network(self, context, id, network):
        """
        Update network parameters

        :param context: neutron api request context
        :param id: UUID representing the network to update
        :returns: updated network object
        """
        self._check_provider_update(context, network['network'])
        add_segments = []
        del_segments = []

        session = context.session
        with session.begin(subtransactions=True):
            net = super(N1kvQuantumPluginV2, self).update_network(context, id,
                                                                  network)
            binding = n1kv_db_v2.get_network_binding(session, id)
            LOG.debug("network type is %s", binding.network_type)
            if binding.network_type == c_const.NETWORK_TYPE_MULTI_SEGMENT:
                add_segments = \
                        self._parse_multi_segments(context, network['network'],
                                                   n1kv_profile.SEGMENT_ADD)
                n1kv_db_v2.add_multi_segment_binding(session,
                                                     net['id'], add_segments)
                del_segments = \
                        self._parse_multi_segments(context, network['network'],
                                                   n1kv_profile.SEGMENT_DEL)
                n1kv_db_v2.del_multi_segment_binding(session,
                                                     net['id'], del_segments)
                self._send_add_multi_segment_request(context, add_segments)
                self._send_del_multi_segment_request(context, del_segments)
            elif binding.network_type == c_const.NETWORK_TYPE_TRUNK:
                add_segments = \
                    self._parse_trunk_segments(context, network['network'],
                                               n1kv_profile.SEGMENT_ADD,
                                               binding.physical_network)
                n1kv_db_v2.add_trunk_segment_binding(session,
                                                     net['id'], add_segments)
                del_segments = \
                    self._parse_trunk_segments(context, network['network'],
                                               n1kv_profile.SEGMENT_DEL,
                                               binding.physical_network)
                n1kv_db_v2.del_trunk_segment_binding(session,
                                                     net['id'], del_segments)
            self._process_l3_update(context, network['network'], id)
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_profile(context, net)
            self._extend_network_dict_l3(context, net)
            if binding.network_type not in [c_const.NETWORK_TYPE_MULTI_SEGMENT]:
                self._send_update_network_request(context, net, add_segments,
                                                  del_segments)
            LOG.debug(_("Updated network: %s"), net['id'])
            return net

    def delete_network(self, context, id):
        """
        Delete a network

        :param context: neutron api request context
        :param id: UUID representing the network to delete
        """
        session = context.session
        with session.begin(subtransactions=True):
            binding = n1kv_db_v2.get_network_binding(session, id)
            network = self.get_network(context, id)
            if n1kv_db_v2.is_trunk_member(session, id):
                msg = _("Cannot delete a network "
                        "that is a member of a trunk segment")
                raise q_exc.InvalidInput(error_message=msg)
            if binding.network_type == c_const.NETWORK_TYPE_VXLAN:
                n1kv_db_v2.release_vxlan(session, binding.segmentation_id)
            elif binding.network_type == c_const.NETWORK_TYPE_VLAN:
                n1kv_db_v2.release_vlan(session, binding.physical_network,
                                        binding.segmentation_id)
                # the network_binding record is deleted via cascade from
                # the network record, so explicit removal is not necessary
            self._send_delete_network_request(context, network)
            super(N1kvQuantumPluginV2, self).delete_network(context, id)
            LOG.debug(_("Deleted network: %s"), id)

    def get_network(self, context, id, fields=None):
        """
        Retreive a Network

        :param context: neutron api request context
        :param id: UUID representing the network to fetch
        :returns: requested network dictionary
        """
        LOG.debug(_("Get network: %s"), id)
        net = super(N1kvQuantumPluginV2, self).get_network(context, id, None)
        self._extend_network_dict_provider(context, net)
        self._extend_network_dict_profile(context, net)
        self._extend_network_dict_member_segments(context, net)
        self._extend_network_dict_l3(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None):
        """ Read All Networks """
        LOG.debug("Get networks")
        nets = super(N1kvQuantumPluginV2, self).get_networks(context, filters,
                                                             None)
        for net in nets:
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_profile(context, net)
            self._extend_network_dict_l3(context, net)

        return [self._fields(net, fields) for net in nets]

    def create_port(self, context, port):
        """
        Create neutron port.

        Create a port. Use a default policy profile for ports created for dhcp
        and router interface. Default policy profile name is configured in the
        /etc/neutron/cisco_plugins.ini file.
        :param context: neutron api request context
        :param port: port dictionary
        :returns: port object
        """
        self._add_dummy_profile_only_if_testing(port)

        if ('device_id' in port['port'] and port['port']['device_owner'] in
            ['network:dhcp', 'network:router_interface']):
            p_profile_name = c_conf.CISCO_N1K.default_policy_profile
            p_profile = self._get_policy_profile_by_name(p_profile_name)
            if p_profile:
                port['port']['n1kv:profile_id'] = p_profile['id']

        profile_id_set = False
        if n1kv_profile.PROFILE_ID in port['port']:
            profile_id = port['port'].get(n1kv_profile.PROFILE_ID)
            profile_id_set = attributes.is_attr_set(profile_id)

        if profile_id_set:
            profile_id = self._process_policy_profile(context,
                                                      port['port'])
            LOG.debug(_('create port: profile_id=%s'), profile_id)
            session = context.session
            with session.begin(subtransactions=True):
                pt = super(N1kvQuantumPluginV2, self).create_port(context,
                                                                  port)
                n1kv_db_v2.add_port_binding(session, pt['id'], profile_id)
                self._extend_port_dict_profile(context, pt)
                self._send_create_port_request(context, pt)
                LOG.debug(_("Created port: %s"), pt)
                self._extend_port_dict_binding(context, pt)
            return pt

    def _add_dummy_profile_only_if_testing(self, obj):
        """
        Method to be patched by the test_n1kv_plugin module to
        inject n1kv:profile_id into the network/port object, since the plugin
        tests for its existence. This method does not affect
        the plugin code in any way.
        """
        pass

    def update_port(self, context, id, port):
        """
        Update port parameters

        :param context: neutron api request context
        :param id: UUID representing the port to update
        :returns: updated port object
        """
        LOG.debug(_("Update port: %s"), id)
        port = super(N1kvQuantumPluginV2, self).update_port(context, id, port)
        self._extend_port_dict_profile(context, port)
        self._extend_port_dict_binding(context, port)
        return port

    def delete_port(self, context, id, l3_port_check=True):
        """
        Delete port

        :param context: neutron api request context
        :param id: UUID representing the port to delete
        :returns: deleted port object
        """
        # if needed, check to see if this is a port owned by
        # and l3-router. If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)

        with context.session.begin(subtransactions=True):
            self.disassociate_floatingips(context, id)
            self._send_delete_port_request(context, id)
            pt = super(N1kvQuantumPluginV2, self).delete_port(context, id)
            return pt

    def get_port(self, context, id, fields=None):
        """
        Retrieve a port
        :param context: neutron api request context
        :param id: UUID representing the port to retrieve
        :param fields: a list of strings that are valid keys in a port
                       dictionary. Only these fields will be returned.
        :returns: port dictionary
        """
        LOG.debug(_("Get port: %s"), id)
        port = super(N1kvQuantumPluginV2, self).get_port(context, id, fields)
        self._extend_port_dict_profile(context, port)
        self._extend_port_dict_binding(context, port)
        return self._fields(port, fields)

    def get_ports(self, context, filters=None, fields=None):
        """
        Retrieve a list of ports

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for a
                        port object. Values in this dictiontary are an
                        iterable containing values that will be used for an
                        exact match comparison for that value. Each result
                        returned by this function will have matched one of the
                        values for each key in filters
        :params fields: a list of strings that are valid keys in a port
                        dictionary. Only these fields will be returned.
        :returns: list of port dictionaries
        """
        LOG.debug(_("Get ports"))
        ports = super(N1kvQuantumPluginV2, self).get_ports(context, filters,
                                                           fields)
        for port in ports:
            self._extend_port_dict_profile(context, port)
            self._extend_port_dict_binding(context, port)

        return [self._fields(port, fields) for port in ports]

    def create_subnet(self, context, subnet):
        """
        Create subnet for a given network

        :param context: neutron api request context
        :param subnet: subnet dictionary
        :returns: subnet object
        """
        LOG.debug(_('Create subnet'))
        # Verify whether subnet name is populated.
        if not subnet['subnet']['name']:
            # If subnet name is not populated, auto-generate it for VSM.
            subnet['subnet']['name'] = c_const.SUBNET + "_" + str(
                subnet['subnet']['network_id'])
        session = context.session
        with session.begin(subtransactions=True):
            sub = super(N1kvQuantumPluginV2, self).create_subnet(context, subnet)
            self._send_create_subnet_request(context, sub)
            LOG.debug(_("Created subnet: %s"), sub['id'])
            return sub

    def update_subnet(self, context, id, subnet):
        """
        Update a subnet

        :param context: neutron api request context
        :param id: UUID representing subnet to update
        :returns: updated subnet object
        """
        LOG.debug(_('Update subnet'))
        sub = super(N1kvQuantumPluginV2, self).update_subnet(context, id, subnet)
        self._send_update_subnet_request(sub)
        LOG.debug(_("Updated subnet: %s"), sub['id'])
        return sub

    def delete_subnet(self, context, id):
        """
        Delete a subnet

        :param context: neutron api request context
        :param id: UUID representing subnet to delete
        :returns: deleted subnet object
        """
        LOG.debug(_('Delete subnet: %s'), id)
        with context.session.begin(subtransactions=True):
            subnet = self.get_subnet(context, id)
            self._send_delete_subnet_request(context, subnet)
            sub = super(N1kvQuantumPluginV2, self).delete_subnet(context, id)
            return sub

    def get_subnet(self, context, id, fields=None):
        """
        Retrieve a subnet

        :param context: neutron api request context
        :param id: UUID representing subnet to retrieve
        :params fields: a list of strings that are valid keys in a subnet
                        dictionary. Only these fields will be returned.
        :returns: subnet object
        """
        LOG.debug(_("Get subnet: %s"), id)
        subnet = super(N1kvQuantumPluginV2, self).get_subnet(context, id,
                                                             fields)
        return self._fields(subnet, fields)

    def get_subnets(self, context, filters=None, fields=None):
        """
        Retrieve a list of subnets

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for a
                        subnet object. Values in this dictiontary are an
                        iterable containing values that will be used for an
                        exact match comparison for that value. Each result
                        returned by this function will have matched one of the
                        values for each key in filters
        :params fields: a list of strings that are valid keys in a subnet
                        dictionary. Only these fields will be returned.
        :returns: list of dictionaries of subnets
        """
        LOG.debug(_("Get subnets"))
        subnets = super(N1kvQuantumPluginV2, self).get_subnets(context,
                                                               filters,
                                                               fields)
        return [self._fields(subnet, fields) for subnet in subnets]

    def create_network_profile(self, context, network_profile):
        """
        Create a network profile

        Create a network profile, which represents a pool of networks
        belonging to one type (VLAN or VXLAN). On creation of network
        profile, we retrieve the admin tenant-id which we use to replace
        the previously stored fake tenant-id in tenant-profile bindings.
        :param context: neutron api request context
        :param network_profile: network profile dictionary
        :returns: network profile object
        """
        self._replace_fake_tenant_id_with_real(context)
        session = context.session
        with session.begin(subtransactions=True):
            net_p = (super(N1kvQuantumPluginV2, self).
                    create_network_profile(context, network_profile))
            try:
                self._send_create_logical_network_request(net_p, context.tenant_id)
            except(cisco_exceptions.VSMError,
                   cisco_exceptions.VSMConnectionFailed):
                with excutils.save_and_reraise_exception():
                    n1kv_db_v2.delete_profile_binding(context.tenant_id,
                                                      net_p["id"])
            try:
                self._send_create_network_profile_request(context, net_p)
            except(cisco_exceptions.VSMError,
                   cisco_exceptions.VSMConnectionFailed):
                with excutils.save_and_reraise_exception():
                    n1kv_db_v2.delete_profile_binding(context.tenant_id,
                                                      net_p["id"])
                    self._send_delete_logical_network_request(net_p)
            return net_p

    def delete_network_profile(self, context, id):
        """
        Delete a network profile.

        :param context: neutron api request context
        :param id: UUID of the network profile to delete
        :returns: deleted network profile object
        """
        session = context.session
        with session.begin(subtransactions=True):
            net_p = (super(N1kvQuantumPluginV2, self).
                     delete_network_profile(context, id))
            self._send_delete_network_profile_request(net_p)
            self._send_delete_logical_network_request(net_p)

    def update_network_profile(self, context, id, network_profile):
        """
        Update a network profile.

        :param context: quantum api request context
        :param id: UUID of the network profile to update
        :param network_profile: dictionary containing network profile object
        """
        session = context.session
        with session.begin(subtransactions=True):
            net_p = (super(N1kvQuantumPluginV2, self).
                     update_network_profile(context, id, network_profile))
            self._send_update_network_profile_request(net_p)
        return net_p
