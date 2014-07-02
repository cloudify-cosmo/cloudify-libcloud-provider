__author__ = 'Oleksandr_Raskosov'


from cosmo_cli.cosmo_cli import init_logger
from cosmo_cli.provider_common import BaseProviderClass
from schemas import PROVIDER_CONFIG_SCHEMA

import libcloud.security

import abc
import os
from copy import deepcopy
import yaml
from os.path import expanduser
import errno
from IPy import IP


libcloud.security.VERIFY_SSL_CERT = False

CREATE_IF_MISSING = 'create_if_missing'

verbose_output = False

# initialize logger
lgr, flgr = init_logger()


class ProviderManager(BaseProviderClass):

    def __init__(self,
                 provider_config=None,
                 is_verbose_output=False,
                 schema=None):
        super(ProviderManager, self).\
            __init__(provider_config,
                     is_verbose_output,
                     PROVIDER_CONFIG_SCHEMA)
        provider_name = provider_config['connection']['cloud_provider_name']
        self.mapper = mapper.Mapper(provider_name)

    def validate(self, validation_errors={}):
        connection_conf = self.provider_config['connection']
        if not self.mapper.is_initialized():
            raise RuntimeError(
                'Error during trying to create context'
                ' for a cloud provider: {0}'
                .format(connection_conf['cloud_provider_name'])
            )

        connector = LibcloudConnector(connection_conf)

        validator = self.mapper.generate_validator(
            connector, self.provider_config, validation_errors)

        validator.validate()

        lgr.error('resource validation failed!') if validation_errors \
            else lgr.info('resources validated successfully')

        return validation_errors

    def provision(self):
        driver = self.get_driver(self.provider_config)
        public_ip, private_ip, ssh_key, ssh_user, provider_context = \
            driver.create_topology()
        # TODO
        # driver.copy_files_to_manager(public_ip, ssh_key, ssh_user)
        return public_ip, private_ip, ssh_key, ssh_user, provider_context

    def teardown(self, provider_context, ignore_validation=False):
        driver = self.get_driver(self.provider_config)
        driver.delete_topology(ignore_validation,
                               provider_context['resources'])

    # TODO think about public for unit testing
    def get_driver(self, provider_config, provider_context=None):
        provider_context = provider_context if provider_context else {}
        connector = LibcloudConnector(provider_config['connection'])
        return self.mapper.generate_cosmo_driver(connector,
                                                 provider_context,
                                                 provider_config)


def _format_resource_name(res_type, res_id, res_name=None):
    if res_name:
        return "{0} - {1} - {2}".format(res_type, res_id, res_name)
    else:
        return "{0} - {1}".format(res_type, res_id)


class CosmoOnLibcloudDriver(object):

    def __init__(self, provider_config, provider_context):
        self.config = provider_config
        self.provider_context = provider_context
        global verbose_output
        self.verbose_output = verbose_output

    @abc.abstractmethod
    def create_topology(self):
        return

    @abc.abstractmethod
    def _delete_resources(self, resources):
        return

    def delete_topology(self, ignore_validation, resources):
        deleted_resources, not_found_resources, failed_to_delete_resources =\
            self._delete_resources(resources)

        def format_resources_data_for_print(resources_data):
            return '\t'.join(['{0}\n'.format(
                _format_resource_name(
                    resource_data['name'] if 'name' in resource_data else
                    resource_data['ip'],
                    resource_data['type'],
                    resource_data['id'])) for resource_data in resources_data])

        deleted_resources_print = \
            'Successfully deleted the following resources:\n\t{0}\n' \
            .format(format_resources_data_for_print(deleted_resources))
        not_found_resources_print = \
            "The following resources weren't found:\n\t{0}\n" \
            .format(format_resources_data_for_print(not_found_resources))
        failed_to_delete_resources_print = \
            'Failed to delete the following resources:\n\t{0}' \
            .format(format_resources_data_for_print(
                failed_to_delete_resources))

        lgr.info(
            'Finished deleting topology;\n'
            '{0}{1}{2}'
            .format(
                deleted_resources_print if deleted_resources else '',
                not_found_resources_print if not_found_resources else '',
                failed_to_delete_resources_print if
                failed_to_delete_resources else ''))


class LibcloudConnector(object):

    def __init__(self, connection_config):
        self.connection_config = connection_config
        provider_name = self.connection_config['cloud_provider_name']
        self.mapper = mapper.Mapper(provider_name)
        self.driver = self.mapper.connect(self.connection_config)

    def get_driver(self):
        return self.driver


class LibcloudValidator(object):

    def __init__(self, provider_config, validation_errors, **kwargs):
        self.provider_config = provider_config
        self.validation_errors = validation_errors

    @abc.abstractmethod
    def validate(self):
        return

    def validate_cidr_syntax(self, cidr):
        try:
            IP(cidr)
            return True
        except ValueError:
            return False


class BaseController(object):

    def __init__(self, connector, **kwargs):
        self.driver = connector.get_driver()

    @abc.abstractmethod
    def _ensure_exist(self, name):
        return

    @abc.abstractmethod
    def _create(self, name, **kwargs):
        return

    @abc.abstractmethod
    def kill(self, item):
        return

    @abc.abstractmethod
    def get_by_id(self, ident):
        return

    def _create_or_ensure_exists(self, config, name, **kwargs):
        res_id, result = self._ensure_exist(name)
        if result:
            created = False
        else:
            if CREATE_IF_MISSING in config and not config[CREATE_IF_MISSING]:
                raise RuntimeError("{0} '{1}' is not configured to"
                                   " create_if_missing but does not"
                                   " exist."
                                   .format(self.__class__.WHAT, name))
            res_id, result = self._create(name, **kwargs)
            created = True
        return res_id, result, created

    def create_or_ensure_exists_log_resources(self, config, name, resources,
                                              resource_name, **kwargs):
        res_id, result, created =\
            self._create_or_ensure_exists(config, name, **kwargs)
        resources[resource_name] = {
            'id': str(res_id),
            'type': self.__class__.WHAT,
            'name': name,
            'created': created
        }
        return result, created


# class LibcloudNetworkController(BaseController):
#
#     WHAT = "network"
#
#
# class LibcloudSubnetController(BaseController):
#
#     WHAT = "subnet"
#
#
# class LibcloudNetworkInterfaceController(BaseController):
#
#     WHAT = "network_interface"
#
#
class LibcloudKeypairController(BaseController):

    WHAT = "key_pair"

    def _mkdir(self, path):
        path = expanduser(path)
        try:
            lgr.debug('creating dir {0}'
                      .format(path))
            os.makedirs(path)
        except OSError, exc:
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                return
            raise


class LibcloudSGController(BaseController):

    WHAT = "security_group"


class LibcloudFloatingIpController(BaseController):

    WHAT = "floating_ip"


class LibcloudServerController(BaseController):

    WHAT = "server"


# if __name__ == "__main__":
#     CONFIG_FILE_NAME = 'cloudify-config.yaml'
#     DEFAULTS_CONFIG_FILE_NAME = 'cloudify-config.defaults.yaml'
#
#     def _read_config(config_file_path):
#
#         if not config_file_path:
#             config_file_path = CONFIG_FILE_NAME
#         defaults_config_file_path = os.path.join(
#             os.path.dirname(os.path.realpath(__file__)),
#             DEFAULTS_CONFIG_FILE_NAME)
#
#         if not os.path.exists(config_file_path) or not os.path.exists(
#                 defaults_config_file_path):
#             if not os.path.exists(defaults_config_file_path):
#                 raise ValueError('Missing the defaults configuration file; '
#                                  'expected to find it at {0}'.format(
#                                      defaults_config_file_path))
#             raise ValueError('Missing the configuration file;'
#                              ' expected to find it at {0}'
#                              .format(config_file_path))
#
#         lgr.debug('reading provider config files')
#         with open(config_file_path, 'r') as config_file, \
#                 open(defaults_config_file_path, 'r') as defaults_config_file:
#
#             lgr.debug('safe loading user config')
#             user_config = yaml.safe_load(config_file.read())
#
#             lgr.debug('safe loading default config')
#             defaults_config = yaml.safe_load(defaults_config_file.read())
#
#         lgr.debug('merging configs')
#         merged_config = _deep_merge_dictionaries(user_config, defaults_config) \
#             if user_config else defaults_config
#         return merged_config
#
#     def _deep_merge_dictionaries(overriding_dict, overridden_dict):
#         merged_dict = deepcopy(overridden_dict)
#         for k, v in overriding_dict.iteritems():
#             if k in merged_dict and isinstance(v, dict):
#                 if isinstance(merged_dict[k], dict):
#                     merged_dict[k] =\
#                         _deep_merge_dictionaries(v, merged_dict[k])
#                 else:
#                     raise RuntimeError('type conflict at key {0}'.format(k))
#             else:
#                 merged_dict[k] = deepcopy(v)
#         return merged_dict
#
#     provider_config = _read_config("D:\projects\GitHub\cloudify-libcloud-provider\cloudify_libcloud\cloudify-config.yaml")
#     manager = ProviderManager(provider_config=provider_config)
#     validation_errors = manager.validate()
#     if validation_errors:
#         print(validation_errors)
#     else:
#         public_ip, private_ip, ssh_key, ssh_user, provider_context =\
#             manager.provision()
#         print(public_ip, private_ip, ssh_key, ssh_user, provider_context)
#         manager.teardown(provider_context=provider_context)

from cloudify_libcloud import cloudify_libcloud_mapper as mapper
