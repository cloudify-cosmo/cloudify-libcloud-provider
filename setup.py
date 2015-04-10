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


from setuptools import setup


setup(
    name='cloudify-libcloud-provider',
    version='3.2rc1',
    author='Gigaspaces',
    author_email='cosmo-admin@gigaspaces.com',
    packages=['cloudify_libcloud'],
    license='LICENSE',
    description='Cloudify Libcloud provider',
    package_data={'cloudify_libcloud': ['cloudify-config.yaml',
                                        'cloudify-config.defaults.yaml']},
    install_requires=[
        'apache-libcloud==0.15.1',
        'IPy==0.81',
        'cloudify==3.2rc1'
    ]
)
