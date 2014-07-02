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
