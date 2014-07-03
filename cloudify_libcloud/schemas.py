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


PROVIDER_CONFIG_SCHEMA = {
    "type": "object",
    "required": [
        'connection',
        'networking',
        'compute',
        'cloudify'
    ],
    "properties": {
        "connection": {
            "type": "object",
            "required": ['cloud_provider_name'],
            "properties": {
                "cloud_provider_name": {
                    "type": "string",
                }
            }
        },
        "networking": {
            "type": "object",
            "required": [],
            "properties": {
                "agents_security_group": {
                    "type": "object",
                    "required": ['create_if_missing', 'name'],
                    "properties": {
                        "create_if_missing": {
                            "enum": [True, False],
                        },
                        "name": {
                            "type": "string",
                        }
                    }
                },
                "management_security_group": {
                    "type": "object",
                    "required": ['create_if_missing', 'name'],
                    "properties": {
                        "create_if_missing": {
                            "enum": [True, False],
                        },
                        "name": {
                            "type": "string",
                        },
                        "cidr": {
                            "type": "string",
                        }
                    }
                }
            }
        },
        "compute": {
            "type": "object",
            "required": [
                'management_server',
                'agent_servers'
            ],
            "properties": {
                "management_server": {
                    "type": "object",
                    "required": [
                        'user_on_management',
                        'userhome_on_management'
                    ],
                    "properties": {
                        "user_on_management": {
                            "type": "string",
                        },
                        "userhome_on_management": {
                            "type": "string",
                        },
                        "instance": {
                            "type": "object",
                            "required": [
                                'create_if_missing',
                                'name',
                                'image'
                            ],
                            "properties": {
                                "create_if_missing": {
                                    "enum": [True, False],
                                },
                                "name": {
                                    "type": "string",
                                },
                                "image": {
                                    "type": ["number", "string"],
                                }
                            }
                        },
                        "management_keypair": {
                            "type": "object",
                            "required": [
                                'create_if_missing',
                                'name',
                                'private_key_target_path'
                            ],
                            "properties": {
                                "create_if_missing": {
                                    "enum": [True, False],
                                },
                                "name": {
                                    "type": "string",
                                },
                                "private_key_target_path": {
                                    "type": "string",
                                }
                            }
                        }
                    }
                },
                "agent_servers": {
                    "type": "object",
                    "required": ['agents_keypair'],
                    "properties": {
                        "agents_keypair": {
                            "type": "object",
                            "required": [
                                'create_if_missing',
                                'name',
                                'private_key_target_path'
                            ],
                            "properties": {
                                "create_if_missing": {
                                    "enum": [True, False],
                                },
                                "name": {
                                    "type": "string",
                                },
                                "private_key_target_path": {
                                    "type": "string",
                                }
                            }
                        }
                    }
                }
            }
        },
        "cloudify": {
            "type": "object",
            "required": [
                'cloudify_components_package_url',
                'cloudify_core_package_url',
            ],
            "properties": {
                "cloudify_components_package_path": {
                    "type": "string",
                },
                "cloudify_components_package_url": {
                    "type": "string",
                },
                "cloudify_package_path": {
                    "type": "string",
                },
                "cloudify_core_package_url": {
                    "type": "string",
                },
                "cloudify_packages_path": {
                    "type": "string",
                }
            }
        }
    }
}
