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

__author__ = 'Oleksandr_Raskosov'


from setuptools import setup


setup(
    name='cloudify-libcloud-provider',
    version='1.0',
    author='Oleksandr_Raskosov',
    author_email='Oleksandr_Raskosov@epam.com',
    packages=['cloudify_libcloud'],
    license='LICENSE',
    description='Cloudify Libclouod provider',
    package_data={'cloudify_libcloud': ['cloudify-config.yaml',
                                        'cloudify-config.defaults.yaml']},
    install_requires=[
        'apache-libcloud==0.15.0',
        'IPy==0.81',
        'cloudify-cli==3.0'
    ]
)
