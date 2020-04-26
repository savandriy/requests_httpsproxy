#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='requests_httpsproxy',
    version='1.1.0',
    description='allow http/https requests through https proxy',
    long_description=open('README.rst').read(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet :: WWW/HTTP',
    ],
    keywords='requests https-proxy',
    url='https://github.com/phuslu/requests_httpsproxy',
    license='MIT',
    author='Phus Lu',
    author_email='phuslu@hotmail.com',
    packages=find_packages(),
    install_requires=[
        'requests>=2.19.0',
        'pyOpenSSL>=0.11',
        'tlslite-ng'
    ],
    platforms='any',
    include_package_data=True,
    zip_safe=True,
)
