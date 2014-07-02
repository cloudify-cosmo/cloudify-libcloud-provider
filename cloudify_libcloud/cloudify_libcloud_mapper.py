__author__ = 'Oleksandr_Raskosov'


from cloudify_libcloud import cloudify_libcloud_ec2 as ec2
from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver


class Mapper(object):

    def __init__(self, provider_name):
        self.initialized = True
        if provider_name == Provider.EC2_AP_NORTHEAST:
            self.core_provider = Provider.EC2
            self.provider = Provider.EC2_AP_NORTHEAST
        elif provider_name == Provider.EC2_AP_SOUTHEAST:
            self.core_provider = Provider.EC2
            self.provider = Provider.EC2_AP_SOUTHEAST
        elif provider_name == Provider.EC2_AP_SOUTHEAST2:
            self.core_provider = Provider.EC2
            self.provider = Provider.EC2_AP_SOUTHEAST2
        elif provider_name == Provider.EC2_EU:
            self.core_provider = Provider.EC2
            self.provider = Provider.EC2_EU
        elif provider_name == Provider.EC2_EU_WEST:
            self.core_provider = Provider.EC2
            self.provider = Provider.EC2_EU_WEST
        elif provider_name == Provider.EC2_SA_EAST:
            self.core_provider = Provider.EC2
            self.provider = Provider.EC2_SA_EAST
        elif provider_name == Provider.EC2_US_EAST:
            self.core_provider = Provider.EC2
            self.provider = Provider.EC2_US_EAST
        elif provider_name == Provider.EC2_US_WEST:
            self.core_provider = Provider.EC2
            self.provider = Provider.EC2_US_WEST
        elif provider_name == Provider.EC2_US_WEST_OREGON:
            self.core_provider = Provider.EC2
            self.provider = Provider.EC2_US_WEST_OREGON
        else:
            self.initialized = False

    def is_initialized(self):
        return self.initialized

    def connect(self, connection_config):
        if self.core_provider == Provider.EC2:
            return get_driver(self.provider)(connection_config['access_id'],
                                             connection_config['secret_key'])

    def generate_cosmo_driver(self,
                              connector,
                              provider_context,
                              provider_config):
        if self.core_provider == Provider.EC2:
            driver = ec2.EC2CosmoOnLibcloudDriver(provider_config,
                                                  provider_context,
                                                  connector)
            return driver

    def generate_validator(self,
                           connector,
                           provider_config,
                           validation_errors):
        if self.core_provider == Provider.EC2:
            util_controller = ec2.EC2LibcloudUtilController(connector)
            floating_ip_controller =\
                ec2.EC2LibcloudFloatingIpController(connector)
            server_controller = ec2.EC2LibcloudServerController(connector)
            validator = ec2.EC2LibcloudValidator(
                provider_config,
                validation_errors,
                util_controller=util_controller,
                floating_ip_controller=floating_ip_controller,
                server_controller=server_controller)
            return validator
