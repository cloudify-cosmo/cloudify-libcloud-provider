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
                            "required": ["private_key_path", "name",
                                         "create_if_missing"],
                            "properties": {
                                "private_key_path": {
                                    "type": "string",
                                },
                                "create_if_missing": {
                                    "enum": [True, False],
                                },
                                "name": {
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
                            "required": ["private_key_path", "name",
                                         "create_if_missing"],
                            "properties": {
                                "private_key_path": {
                                    "type": "string",
                                },
                                "create_if_missing": {
                                    "enum": [True, False],
                                },
                                "name": {
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
                'server',
                'agents',
                'workflows',
                'bootstrap'
            ],
            "properties": {
                "resources_prefix": {
                    "type": "string"
                },
                "server": {
                    "type": "object",
                    "required": [
                        'packages',
                    ],
                    "properties": {
                        "packages": {
                            "type": "object",
                            "required": [
                                'components_package_url',
                                'core_package_url',
                            ],
                            "properties": {
                                "components_package_url": {
                                    "type": "string",
                                },
                                "core_package_url": {
                                    "type": "string",
                                },
                                "ui_package_url": {
                                    "type": "string",
                                }
                            },
                            "additionalProperties": False
                        },
                    },
                    "additionalProperties": False
                },
                "agents": {
                    "type": "object",
                    "required": [
                        'packages',
                        'config',
                    ],
                    "properties": {
                        "packages": {
                            "type": "object",
                            'minProperties': 1,
                        },
                        "config": {
                            "type": "object",
                            "required": ["min_workers", "max_workers",
                                         "remote_execution_port"],
                            "properties": {
                                "min_workers": {
                                    "type": "number"
                                },
                                "max_workers": {
                                    "type": "number"
                                },
                                "remote_execution_port": {
                                    "type": "number"
                                },
                                "user": {
                                    "type": "string"
                                }
                            },
                            "additionalProperties": False
                        },
                    "additionalProperties": False
                    }
                },
                "workflows": {
                    "type": "object",
                    "required": ["task_retries", "retry_interval"],
                    "properties": {
                        "task_retries": {
                            "type": "number"
                        },
                        "retry_interval": {
                            "type": "number"
                        }
                    },
                    "additionalProperties": False
                },
                "bootstrap": {
                    "type": "object",
                    "properties": {
                        "ssh": {
                            "type": "object",
                            "properties": {
                                "initial_connectivity_retries": {
                                    "type": "number"
                                },
                                "initial_connectivity_retries_interval": {
                                    "type": "number"
                                },
                                "command_retries": {
                                    "type": "number"
                                },
                                "retries_interval": {
                                    "type": "number"
                                },
                                "connection_attempts": {
                                    "type": "number"
                                },
                                "socket_timeout": {
                                    "type": "number"
                                }
                            },
                            "additionalProperties": False
                        }
                    },
                    "additionalProperties": False
                }
            },
            "additionalProperties": False
        },
    }
}
