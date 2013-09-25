from ez_setup import use_setuptools
use_setuptools()
from setuptools import setup, find_packages

setup(
    name="python-gssapi",
    version="0.2.0",
    packages=find_packages(exclude=["tests.*", "tests"]),

    install_requires=[
        'pyasn1==0.1.6',
    ],

    # metadata for upload to PyPI
    author="Hugh Cole-Baker",
    author_email="hugh@sigmaris.info",
    description="An object-oriented interface to GSSAPI for Python",
    license="BSD",
    keywords="gssapi kerberos",
    url="https://github.com/sigmaris/python-gssapi",
)
