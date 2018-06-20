#!/usr/bin/env python

import io
from setuptools import setup
from setuptools import find_packages

version = '0.0.2'

install_requires = [
    'six',
    'llsmartcard-ph4',
    'psutil',
    'pyhashxx',
]

afl_extras = [
    'python-afl-ph4',
]

dev_extras = [
    'pep8',
    'tox',
    'pypandoc',
    'jupyter',
]


try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
    long_description = long_description.replace("\r", '')

except Exception:  # (IOError, ImportError):
    import io
    with io.open('README.md', encoding='utf-8') as f:
        long_description = f.read()


setup(
    name='apdu-fuzzer',
    version=version,
    description='APDU fuzzer',
    long_description=long_description,
    url='https://github.com/petrs/APDUFuzzer',
    author='Petr Svenda',
    author_email='svenda@fi.muni.cz',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'dev': dev_extras,
        'afl': afl_extras,
    },
    entry_points={
        'console_scripts': [
            'apdu-fuzz = apdu_fuzzer.main:main',
            'apdu-afl-fuzz = apdu_fuzzer.main_afl:main',
        ],
    }
)
