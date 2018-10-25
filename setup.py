# -*- coding: utf-8 -*-

from distutils.core import setup
from setuptools import find_packages


setup(
    name='dj-security-middleware',
    version='0.5.0',
    description=(
        "Adds a layer to interact with a paste enabled, Django based, "
        "security service typically a dj_security app"
    ),
    long_description=open('README.md').read(),
    author='Maurizio Nagni',
    author_email='maurizio.nagni@stfc.ac.uk',
    maintainer='William Tucker',
    maintainer_email='william.tucker@stfc.ac.uk',
    url='https://github.com/cedadev/dj-security-middleware',
    package_dir = {'dj_security_middleware':'dj_security_middleware'},
    packages=find_packages(),
    include_package_data=True,
    license='BSD licence, see LICENSE file in root package',
    zip_safe=False,
    classifiers=(
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
    ),
    install_requires = ['django', 'crypto-cookie'],
)
