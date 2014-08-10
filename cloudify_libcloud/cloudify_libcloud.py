########
# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

from cosmo_cli.cosmo_cli import init_logger
from cosmo_cli.provider_common import BaseProviderClass
from schemas import PROVIDER_CONFIG_SCHEMA

import libcloud.security

import abc
import os
from os.path import expanduser
import errno
from IPy import IP


libcloud.security.VERIFY_SSL_CERT = False

CREATE_IF_MISSING = 'create_if_missing'

verbose_output = False

# initialize logger
lgr, flgr = init_logger()


class ProviderManager(BaseProviderClass):

    schema = PROVIDER_CONFIG_SCHEMA

    CONFIG_NAMES_TO_MODIFY = (
        ('networking', 'agents_security_group'),
        ('networking', 'management_security_group'),
        ('compute', 'management_server', 'instance'),
        ('compute', 'management_server', 'management_keypair'),
        ('compute', 'agent_servers', 'agents_keypair'),
    )

    CONFIG_FILES_PATHS_TO_MODIFY = (
        ('compute', 'agent_servers', 'private_key_path'),
        ('compute', 'management_server', 'management_keypair',
            'private_key_path'),
    )

    def __init__(self,
                 provider_config=None,
                 is_verbose_output=False):
        super(ProviderManager, self).\
            __init__(provider_config,
                     is_verbose_output)
        provider_name = provider_config['connection']['cloud_provider_name']
        provider_name = transfer_cloud_provider_name(provider_name)
        from mapper import Mapper
        self.mapper = Mapper(provider_name)

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
        driver.copy_files_to_manager(public_ip, ssh_key, ssh_user)
        return public_ip, private_ip, ssh_key, ssh_user, provider_context

    def teardown(self, provider_context, ignore_validation=False):
        driver = self.get_driver(self.provider_config)
        driver.delete_topology(ignore_validation,
                               provider_context['resources'])

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
        provider_name = transfer_cloud_provider_name(provider_name)
        from mapper import Mapper
        self.mapper = Mapper(provider_name)
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


def transfer_cloud_provider_name(provider_name):
    return provider_name.replace('-', '_')
