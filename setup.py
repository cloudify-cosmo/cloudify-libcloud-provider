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
        'apache-libcloud==0.14.1',
        'IPy==0.81',
        'cloudify-cli==3.0'
    ]
)
