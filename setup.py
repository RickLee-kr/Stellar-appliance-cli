#!/usr/bin/env python
"""
Setup configuration for dp-cli package
"""

from setuptools import setup

setup(
    name='dp-cli',
    version='1.0.0',
    description='DP CLI',
    python_requires='>=3.10',
    py_modules=['appliance_cli'],
    entry_points={
        'console_scripts': [
            'aella_cli = appliance_cli:main',
        ],
    },
    install_requires=[],
)
