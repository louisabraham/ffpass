#!/usr/bin/env python3

import os
from setuptools import setup


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name="ffpass",
    version="0.4.4",
    author="Louis Abraham",
    license="MIT",
    author_email="louis.abraham@yahoo.fr",
    description="Import and Export passwords for Firefox",
    long_description=read("README.rst"),
    url="https://github.com/louisabraham/ffpass",
    packages=["ffpass"],
    install_requires=["pyasn1", "pycryptodome"],
    python_requires=">=3.6",
    entry_points={"console_scripts": ["ffpass = ffpass:main"]},
    classifiers=["Topic :: Utilities", "Topic :: Security :: Cryptography"],
)
