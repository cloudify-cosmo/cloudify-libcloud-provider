__author__ = 'Oleksandr_Raskosov'

from cloudify_libcloud_common import *
from libcloud.compute.types import NodeState

from os.path import expanduser
import os
import time

from libcloud.compute.types import KeyPairDoesNotExistError


CREATE_IF_MISSING = 'create_if_missing'


# declare which ports should be opened during provisioning
EXTERNAL_MGMT_PORTS = (22, 8100, 80)  # SSH, REST service (TEMP), REST and UI
INTERNAL_MGMT_PORTS = (5555, 5672, 53229)  # Riemann, RabbitMQ, FileServer
INTERNAL_AGENT_PORTS = (22,)


class EC2CosmoOnLibcloudDriver(CosmoOnLibcloudDriver):

    def __init__(self, provider_config, provider_context, connector):
        super(EC2CosmoOnLibcloudDriver, self)\
            .__init__(provider_config, provider_context)
        self.keypair_controller = EC2LibcloudKeypairController(connector)
        # self.network_controller = EC2LibcloudNetworkController(connector)
        # self.subnet_controller = EC2LibcloudSubnetController(connector)
        # self.network_interface_controller =\
        #     EC2LibcloudNetworkInterfaceController(connector)
        self.sg_controller = EC2LibcloudSGController(connector)
        self.floating_ip_controller =\
            EC2LibcloudFloatingIpController(connector)
        self.util_controller = EC2LibcloudUtilController(connector)
        self.server_controller = EC2LibcloudServerController(
            connector, util_controller=self.util_controller)

    def create_topology(self):
        resources = {}
        self.provider_context['resources'] = resources

        compute_config = self.config['compute']
        mng_conf = compute_config['management_server']
        inst_conf = mng_conf['instance']

        # TODO will be supported later
        # int_net_conf = self.config['networking']['int_network']
        # int_net, created = self.network_controller\
        #     .create_or_ensure_exists_log_resources(int_net_conf,
        #                                            int_net_conf['name'],
        #                                            resources,
        #                                            'int_network',
        #                                            cidr=int_net_conf['cidr'])
        #
        # subnet_conf = self.config['networking']['subnet']
        # zone = subnet_conf['availability_zone']
        # subnet, created = self.subnet_controller\
        #     .create_or_ensure_exists_log_resources(subnet_conf,
        #                                            subnet_conf['name'],
        #                                            resources,
        #                                            'subnet',
        #                                            vpc_id=int_net.id,
        #                                            cidr=subnet_conf['cidr'],
        #                                            a_zone=zone)

        # Security group for Cosmo created instances
        asgconf = self.config['networking']['agents_security_group']
        description = 'Cosmo created machines'
        asg, agent_sg_created = self.sg_controller\
            .create_or_ensure_exists_log_resources(asgconf,
                                                   asgconf['name'],
                                                   resources,
                                                   'agents_security_group',
                                                   description=description)
        asg_id = asg['group_id'] if agent_sg_created else asg.id
        # Security group for Cosmo manager, allows created
        # instances -> manager communication
        msgconf = self.config['networking']['management_security_group']
        sg_rules = \
            [{'port': p, 'group_id': asg_id} for p in INTERNAL_MGMT_PORTS] + \
            [{'port': p, 'cidr': msgconf['cidr']} for p in EXTERNAL_MGMT_PORTS]
        rsrc_name = 'management_security_group'
        description = 'Cosmo Manager'
        msg, msg_created = self.sg_controller\
            .create_or_ensure_exists_log_resources(msgconf,
                                                   msgconf['name'],
                                                   resources,
                                                   rsrc_name,
                                                   description=description,
                                                   rules=sg_rules)
        msg_id = msg['group_id'] if msg_created else msg.id
        # Add rules to agent security group. (Happens here because we need
        # the management security group id)
        if agent_sg_created:
            self.sg_controller.add_rules(
                [{'port': port, 'group_id': msg_id}
                 for port in INTERNAL_AGENT_PORTS], asg_id)

        # Keypairs setup
        mgr_kp_conf = mng_conf['management_keypair']
        self.keypair_controller.create_or_ensure_exists_log_resources(
            mgr_kp_conf,
            mgr_kp_conf['name'],
            resources,
            'management_keypair',
            private_key_target_path=mgr_kp_conf['private_key_target_path']
        )
        agents_kp_conf = compute_config['agent_servers']['agents_keypair']
        self.keypair_controller.create_or_ensure_exists_log_resources(
            agents_kp_conf,
            agents_kp_conf['name'],
            resources,
            'agents_keypair',
            private_key_target_path=agents_kp_conf['private_key_target_path']
        )

        node, created = self.server_controller.\
            create_or_ensure_exists_log_resources(
                inst_conf,
                inst_conf['name'],
                resources,
                'management_server',
                image=inst_conf['image'],
                size=inst_conf['size'],
                keypair_name=mgr_kp_conf['name']
            )

        # network_interface, created = self.network_interface_controller.\
        #     create_or_ensure_exists_log_resources(
        #         None,
        #         'management_network_interface',
        #         resources,
        #         'management_network_interface',
        #         subnet=subnet
        #     )

        if 'floating_ip' in mng_conf:
            floating_ip_conf = mng_conf['floating_ip']
            res_name = 'management_floating_ip'
            ip_name = floating_ip_conf['ip']\
                if 'ip' in floating_ip_conf else res_name
            floating_ip, created = self.floating_ip_controller\
                .create_or_ensure_exists_log_resources(floating_ip_conf,
                                                       ip_name,
                                                       resources,
                                                       res_name)

            self.floating_ip_controller.associate(node, floating_ip)

        ssh_key = mgr_kp_conf['private_key_target_path']
        ssh_user = mng_conf['user_on_management']

        node = self.server_controller.get_by_id(node.id)
        public_ip = node.public_ips[0]
        private_ip = node.private_ips[0]
        return public_ip, private_ip, ssh_key, ssh_user, self.provider_context

    def _delete_resources(self, resources):
        deleted_resources = []
        not_found_resources = []
        failed_to_delete_resources = []

        def del_server_resource(resource_name, resource_data):
            if resource_data['created']:
                resource =\
                    self.server_controller.get_by_id(resource_data['id'])
                if resource is None:
                    not_found_resources.append(resource_data)
                else:
                    try:
                        self.server_controller.kill(resource)
                        deleted_resources.append(resource_data)
                        del(resources[resource_name])
                    except:
                        failed_to_delete_resources.append(resource_data)

        def del_floating_ip_resource(resource_name, resource_data):
            if resource_data['created']:
                resource = self.floating_ip_controller\
                    .get_by_id(resource_data['id'])
                if resource is None:
                    not_found_resources.append(resource_data)
                else:
                    try:
                        self.floating_ip_controller.kill(resource)
                        deleted_resources.append(resource_data)
                        del(resources[resource_name])
                    except:
                        failed_to_delete_resources.append(resource_data)

        def del_security_group_resources(sg_resources):
            to_delete = []
            for key, value in sg_resources.items():
                if value['created']:
                    resource = self.sg_controller.get_by_id(value['id'])
                    if resource is None:
                        not_found_resources.append(value)
                    else:
                        try:
                            self.sg_controller.remove_rules(resource)
                            to_delete.append({'key': key,
                                              'value': value,
                                              'resource': resource})
                        except:
                            failed_to_delete_resources.append(value)
            for item in to_delete:
                try:
                    self.sg_controller.kill(item['resource'])
                    deleted_resources.append(item['value'])
                    del(resources[item['key']])
                except Exception:
                    failed_to_delete_resources.append(item['value'])

        def del_key_pair_resource(resource_name, resource_data):
            if resource_data['created']:
                resource = self.keypair_controller\
                    .get_by_id(resource_data['id'])
                if resource is None:
                    not_found_resources.append(resource_data)
                else:
                    try:
                        self.keypair_controller.kill(resource)
                        deleted_resources.append(resource_data)
                        del(resources[resource_name])
                    except:
                        failed_to_delete_resources.append(resource_data)

        # deleting in reversed order to creation order
        server_resources = {}
        floating_ip_resources = {}
        security_group_resources = {}
        key_pair_resources = {}
        for key, value in resources.items():
            resource_type = value['type']
            if resource_type == 'key_pair':
                key_pair_resources[key] = value
            elif resource_type == 'security_group':
                security_group_resources[key] = value
            elif resource_type == 'floating_ip':
                floating_ip_resources[key] = value
            elif resource_type == 'server':
                server_resources[key] = value

        for key, value in server_resources.items():
            del_server_resource(key, value)
        for key, value in floating_ip_resources.items():
            del_floating_ip_resource(key, value)
        del_security_group_resources(security_group_resources)
        for key, value in key_pair_resources.items():
            del_key_pair_resource(key, value)

        return (deleted_resources, not_found_resources,
                failed_to_delete_resources)


# class EC2LibcloudNetworkController(core.LibcloudNetworkController):
#
#     def _ensure_exist(self, name):
#         networks = self.driver.ex_list_networks()
#         if networks:
#             for item in networks:
#                 if item.name.lower() == name.lower():
#                     return item
#
#     def _create(self, name, cidr=None):
#         network = self.driver.ex_create_network(cidr_block=cidr, name=name)
#         return network
#
#
# class EC2LibcloudSubnetController(core.LibcloudSubnetController):
#
#     def _ensure_exist(self, name):
#         subnets = self.driver.ex_list_subnets()
#         if subnets:
#             for item in subnets:
#                 if item.name.lower() == name.lower():
#                     return item
#
#     def _create(self, name, vpc_id=None, cidr=None, a_zone=None):
#         subnet = self.driver.ex_create_subnet(name=name,
#                                               vpc_id=vpc_id,
#                                               cidr_block=cidr,
#                                               availability_zone=a_zone)
#         return subnet
#
#
# class EC2LibcloudNetworkInterfaceController(core.LibcloudNetworkInterfaceController):
#
#     def _ensure_exist(self, name):
#         network_interfaces = self.driver.ex_list_network_interfaces()
#         if network_interfaces:
#             for item in network_interfaces:
#                 if item.name.lower() == name.lower():
#                     return item
#
#     def _create(self, name, subnet=None):
#         # TODO security group should be set here
#         network_interface = self.driver\
#             .ex_create_network_interface(name=name, subnet=subnet)
#         return network_interface


class EC2LibcloudKeypairController(LibcloudKeypairController):

    def _ensure_exist(self, name):
        keypair = None
        try:
            keypair = self.driver.get_key_pair(name)
        except KeyPairDoesNotExistError:
            pass
        if keypair:
            return keypair.name, keypair
        else:
            return None, None

    def _create(self, name, private_key_target_path=None):
        if not private_key_target_path:
            raise RuntimeError("Must provide private key target path"
                               " to create keypair")

        keypair = self.driver.create_key_pair(name)
        pk_target_path = expanduser(private_key_target_path)
        self._mkdir(os.path.dirname(private_key_target_path))
        with open(pk_target_path, 'w') as f:
            f.write(keypair.private_key)
            os.system('chmod 600 {0}'.format(pk_target_path))
        return name, keypair

    def get_by_id(self, ident):
        key_pair_id, key_pair = self._ensure_exist(ident)
        return key_pair

    def kill(self, item):
        self.driver.delete_key_pair(item)

    def list(self):
        return self.driver.list_key_pairs()


class EC2LibcloudSGController(LibcloudSGController):

    def _ensure_exist(self, name):
        try:
            security_group = self.driver\
                .ex_get_security_groups(group_names=[name])
            if security_group and security_group[0]:
                return security_group[0].id, security_group[0]
        except Exception:
            pass
        return None, None

    def add_rules(self, rules, security_group_id):
        for rule in rules:
            if 'cidr' in rule:
                self.driver.ex_authorize_security_group_ingress(
                    security_group_id,
                    rule['port'],
                    rule['port'],
                    cidr_ips=[rule['cidr']])
            elif 'group_id' in rule:
                self.driver.ex_authorize_security_group_ingress(
                    security_group_id,
                    rule['port'],
                    rule['port'],
                    group_pairs=[{'group_id': rule['group_id']}])

    # def _create(self, name, description=None, rules=None, vpc_id=None):
    def _create(self, name, description=None, rules=None):
        if not description:
            raise RuntimeError("Must provide description"
                               " to create security group")

        security_group = self.driver.ex_create_security_group(
            name,
            description)
        if security_group and rules:
            self.add_rules(rules, security_group['group_id'])
        return security_group['group_id'], security_group

    def get_by_id(self, ident):
        result = self.driver.ex_get_security_groups(group_ids=[ident])
        if result:
            return result[0]

    def remove_rules(self, item):
        for rule in item.ingress_rules:
            for pair in rule['group_pairs']:
                if ('group_id' in pair) and ('group_name' in pair):
                    pair['group_name'] = ''
            self.driver.ex_revoke_security_group_ingress(
                id=item.id,
                from_port=rule['from_port'],
                to_port=rule['to_port'],
                group_pairs=rule['group_pairs'],
                cidr_ips=rule['cidr_ips'])
        for rule in item.egress_rules:
            for pair in rule['group_pairs']:
                if ('group_id' in pair) and ('group_name' in pair):
                    pair['group_name'] = ''
            self.driver.ex_revoke_security_group_egress(
                id=item.id,
                from_port=rule['from_port'],
                to_port=rule['to_port'],
                group_pairs=rule['group_pairs'],
                cidr_ips=rule['cidr_ips'])

    def kill(self, item):
        self.driver.ex_delete_security_group_by_id(item.id)

    def list(self):
        return self.driver.ex_list_security_groups()


class EC2LibcloudFloatingIpController(LibcloudFloatingIpController):

    def _ensure_exist(self, name):
        addresses = self.driver.ex_describe_all_addresses()
        if addresses:
            for item in addresses:
                if item.ip.lower() == name.lower():
                    return item.ip, item
        return None, None

    def _create(self, name):
        address = self.driver.ex_allocate_address()
        return address.ip, address

    def associate(self, node, ip):
        self.driver.ex_associate_address_with_node(node, ip)

    def get_by_id(self, ident):
        ip_id, ip = self._ensure_exist(ident)
        return ip

    def kill(self, item):
        self.driver.ex_disassociate_address(item)
        self.driver.ex_release_address(item)


class EC2LibcloudServerController(LibcloudServerController):

    def __init__(self, connector, util_controller=None):
        super(LibcloudServerController, self).__init__(connector)
        self.util_controller = util_controller

    def _ensure_exist(self, name):
        nodes = self.driver.list_nodes()
        if nodes:
            for node in nodes:
                if (node.name.lower() == name.lower())\
                        and (node.state is NodeState.RUNNING):
                    return node.id, node
        return None, None

    def _create(self, name, image=None, size=None, keypair_name=None):
        selected_size = self.util_controller.get_size(size)
        selected_image = self.util_controller.get_image(image)

        node = self.driver.create_node(name=name,
                                       image=selected_image,
                                       size=selected_size,
                                       ex_keyname=keypair_name)
        node = self._wait_for_node_to_become_active(node, name)
        return node.id, node

    def _wait_for_node_to_become_active(self, node, name):
        timeout = 300
        while node.state is not NodeState.RUNNING:
            timeout -= 5
            if timeout <= 0:
                raise RuntimeError('Node failed to start in time')
            time.sleep(5)
            node = self.get_by_name(node.name)

        return node

    def get_by_id(self, ident):
        result = self.driver.list_nodes(ex_node_ids=[ident])
        if result:
            return result[0]

    def get_by_name(self, name):
        nodes = self.driver.list_nodes()
        if nodes:
            for node in nodes:
                if node.name.lower() == name.lower():
                    return node

    def kill(self, item):
        self.driver.destroy_node(item)

    def list(self):
        return self.driver.list_nodes()


class EC2LibcloudUtilController(object):

    def __init__(self, connector):
        self.driver = connector.get_driver()

    def get_size(self, name):
        sizes = self.driver.list_sizes()
        if sizes:
            for item in sizes:
                if item.id.lower() == name.lower():
                    return item

    def get_image(self, name):
        images = self.driver.list_images(ex_image_ids=[name])
        if images:
            if images[0]:
                return images[0]


class EC2LibcloudValidator(LibcloudValidator):

    def __init__(self,
                 provider_config,
                 validation_errors,
                 util_controller=None,
                 floating_ip_controller=None,
                 server_controller=None):
        super(EC2LibcloudValidator, self)\
            .__init__(provider_config, validation_errors)
        self.util_controller = util_controller
        self.floating_ip_controller = floating_ip_controller
        self.server_controller = server_controller

    def _validate_connection(self, connection_config):
        if 'access_id' not in connection_config:
            err = 'config file validation error: connection:' \
                  ' access_id should be set for EC2 cloud'
            self.validation_errors.setdefault('connection', []).append(err)
        if 'secret_key' not in connection_config:
            err = 'config file validation error: connection:' \
                  ' secret_key should be set for EC2 cloud'
            self.validation_errors.setdefault('connection', []).append(err)

    def _validate_networking(self, networking_config):
        cidr = networking_config['management_security_group']['cidr']
        if not self.validate_cidr_syntax(cidr):
            err = 'config file validation error:' \
                  ' networking/management_security_group:' \
                  ' cidr wrong format'
            self.validation_errors.setdefault('networking', []).append(err)

    def _validate_floating_ip(self, mng_config):
        ip_config = mng_config['floating_ip']
        if CREATE_IF_MISSING not in ip_config:
            err = 'config file validation error:' \
                  ' management_server/floating_ip:' \
                  ' create_if_missing should be set for EC2 cloud'
            self.validation_errors.setdefault('management_server', [])\
                .append(err)
        else:
            if not ip_config[CREATE_IF_MISSING]:
                if 'ip' not in ip_config:
                    err = 'config file validation error:' \
                          ' management_server/floating_ip:' \
                          ' ip should be set for EC2 cloud'
                    self.validation_errors.setdefault('management_server', [])\
                        .append(err)
                else:
                    ip = ip_config['ip']
                    if not self.validate_cidr_syntax(ip):
                        err = 'config file validation error:' \
                              ' management_server/floating_ip:' \
                              ' ip wrong format'
                        self.validation_errors\
                            .setdefault('management_server', []).append(err)
                    if not self.floating_ip_controller.get(ip):
                        err = 'config file validation error:' \
                              ' management_server/floating_ip:' \
                              ' can\'t find ip {0} on EC2'.format(ip)
                        self.validation_errors\
                            .setdefault('management_server', []).append(err)

    def _validate_instance(self, instance_config):
        if 'size' not in instance_config:
            err = 'config file validation error:' \
                  ' management_server/instance:' \
                  ' size should be set for EC2 cloud'
            self.validation_errors.setdefault('management_server', [])\
                .append(err)
        image_name = instance_config['image']
        image = self.util_controller.get_image(image_name)
        if not image:
            err = 'config file validation error:' \
                  ' management_server/instance:' \
                  ' image \'{0}\' does not exist on EC2'\
                .format(image_name)
            self.validation_errors.setdefault('management_server', [])\
                .append(err)
        size_name = instance_config['size']
        size = self.util_controller.get_size(size_name)
        if not size:
            err = 'config file validation error:' \
                  ' management_server/instance:' \
                  ' size \'{0}\' does not exist on EC2'\
                .format(size_name)
            self.validation_errors.setdefault('management_server', [])\
                .append(err)
        instance_name = instance_config['name']
        instance = self.server_controller.get_by_name(instance_name)
        if instance and (instance.state is not NodeState.RUNNING):
            err = 'config file validation error:' \
                  ' management_server should be in state Running'
            self.validation_errors.setdefault('management_server', [])\
                .append(err)

    def _validate_compute(self, compute_config):
        mng_config = compute_config['management_server']
        if 'floating_ip' in mng_config:
            self._validate_floating_ip(mng_config)
        instance_config = mng_config['instance']
        self._validate_instance(instance_config)

    def validate(self):
        connection_config = self.provider_config['connection']
        self._validate_connection(connection_config)

        networking_config = self.provider_config['networking']
        self._validate_networking(networking_config)

        compute_config = self.provider_config['compute']
        self._validate_compute(compute_config)
