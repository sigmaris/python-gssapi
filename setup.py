try:
    from setuptools import setup, find_packages
except ImportError:
    from gssapi_ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

from distutils.command.build import build
from setuptools.command.install import install


def get_ext_modules():
    from gssapi.bindings import ffi
    return [ffi.verifier.get_extension()]


class CFFIBuild(build):

    def finalize_options(self):
        self.distribution.ext_modules = get_ext_modules()
        build.finalize_options(self)


class CFFIInstall(install):

    def finalize_options(self):
        self.distribution.ext_modules = get_ext_modules()
        install.finalize_options(self)


CFFI_REQUIREMENT = 'cffi>=0.8'
SIX_REQUIREMENT = 'six>=1.5.0',


setup(
    name="python-gssapi",
    version="0.6.0-pre",
    packages=find_packages(exclude=["tests.*", "tests"]),
    py_modules=['gssapi_ez_setup'],

    # package_data specifies what is included in a bdist
    package_data={
        'gssapi.bindings': ['*.cdef']
    },

    setup_requires=[
        CFFI_REQUIREMENT,
        SIX_REQUIREMENT,
    ],
    install_requires=[
        'pyasn1>=0.1.2',
        SIX_REQUIREMENT,
        CFFI_REQUIREMENT
    ],

    # for cffi
    zip_safe=False,
    ext_package="gssapi.bindings",
    cmdclass={
        "build": CFFIBuild,
        "install": CFFIInstall,
    },

    # metadata for upload to PyPI
    author="Hugh Cole-Baker",
    author_email="hugh@sigmaris.info",
    description="An object-oriented interface to GSSAPI for Python",
    license="BSD",
    keywords="gssapi kerberos",
    url="https://github.com/sigmaris/python-gssapi",
)
