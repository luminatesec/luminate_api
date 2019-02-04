from setuptools import setup

setup(
    name='luminateapi',
    version='2.1',
    packages=['luminateapi'],
    url='https://github.com/luminatesec/luminate_api',
    license='Apache-2.0',
    author='Luminate',
    author_email='info@luminate.io',
    description='Python implementation of Luminate V2 REST API',
    install_requires=[
        'oauthlib==2.1.0',
        'requests-oauthlib==1.0.0',
        'dateparser'
    ],
)
