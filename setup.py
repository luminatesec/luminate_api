from setuptools import setup

setup(
    name='luminateapi',
    version='1.0',
    packages=['luminateapi'],
    url='https://github.com/luminatesec/luminate_api',
    license='Apache-2.0',
    author='Luminate',
    author_email='info@luminate.io',
    description='Python implementation of Lumiante REST API',
    install_requires=[
        'oauthlib==2.0.4',
        'requests-oauthlib==0.8.0',
    ],
)