import os
import os.path
import platform
import re
import subprocess

try:
    from setuptools import setup, find_packages
except ImportError:
    from gssapi_ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages
import pkg_resources

from setuptools.command.build_py import build_py as _build_py


class build_py(_build_py):

    def _strip_unknown_cflags(self, cflags):
        """Strip out cflags that ctypesgen doesn't understand."""
        return tuple(
            flag for flag in cflags
            if any(flag.startswith(prefix) for prefix in (
                "-Wl,-L", "-Wl,-R", "-Wl,--rpath", "-l", "-I", "-L", "-R", "--rpath",
            ))
        )

    def _find_gssapi_h(self, cflags):
        gcc_target = subprocess.check_output(["gcc", "-dumpmachine"])
        default_paths = [
            "/usr/local/include",
            "/usr/{target}/include".format(target=gcc_target),
            "/usr/include"
        ]
        extra_paths = [
            flag[2:]
            for flag in cflags
            if flag.startswith('-I')
        ]
        for include_path in (os.path.join("gssapi", "gssapi.h"), "gssapi.h"):
            for search_path in (extra_paths + default_paths):
                full_header = os.path.join(search_path, include_path)
                if os.path.isfile(full_header):
                    return full_header

    def _patch_struct_packing(self, headerpath, filename, packing):
        comment_matcher = re.compile(r"^# {path}: \d+$".format(path=re.escape(headerpath)))
        struct_matcher = re.compile(r"^class [a-zA-Z_][a-zA-Z0-9_]*\(Structure\):$")
        expect_struct = False
        with open(filename, 'r') as infile:
            for line in infile:
                yield line
                if expect_struct:
                    if struct_matcher.match(line):
                        yield '    _pack_ = {0}\n'.format(packing)
                    expect_struct = False
                if comment_matcher.match(line):
                    expect_struct = True

    def initialize_options(self):
        _build_py.initialize_options(self)
        self.compile_flags = ()
        self.patch_struct_pack = None
        self.ctypesgen_cpp = "gcc -E"
        self.gssapi_h_location = None

    def finalize_options(self):
        _build_py.finalize_options(self)
        try:
            config_compile_flags = subprocess.check_output(["krb5-config", "--cflags", "gssapi"]).split()
            config_link_flags = subprocess.check_output(["krb5-config", "--libs", "gssapi"]).split()
        except subprocess.CalledProcessError:
            try:
                config_compile_flags = subprocess.check_output(["pkg-config", "--cflags", "gss"]).split()
                config_link_flags = subprocess.check_output(["pkg-config", "--libs", "gss"]).split()
            except subprocess.CalledProcessError:
                config_compile_flags = []
                config_link_flags = []

        self.compile_flags = (self._strip_unknown_cflags(config_compile_flags)
                              + self._strip_unknown_cflags(config_link_flags))

        currentplatform = platform.system()
        if currentplatform == 'Darwin':
            self.patch_struct_pack = 2
            machine = platform.machine()
            define = {
                "x86_64": "TARGET_CPU_X86_64",
                "i386": "TARGET_CPU_X86",
                "ppc64": "TARGET_CPU_PPC64",
                "ppc": "TARGET_CPU_PPC",
            }[machine]
            self.ctypesgen_cpp = "gcc -E -D{0}".format(define)

        self.compile_flags += ("-i", "uid_t")

        self.gssapi_h_location = self._find_gssapi_h(self.compile_flags)

    def run(self):
        target = _build_py.get_module_outfile(self, self.build_lib, ['gssapi', 'headers'], "gssapi_h")
        target_dir = os.path.dirname(target)
        _build_py.mkpath(self, target_dir)

        ctypesgen_dist = pkg_resources.get_distribution(
            pkg_resources.Requirement.parse('ctypesgen==0.r125')
        )
        try:
            script_str = ctypesgen_dist.get_metadata('scripts/ctypesgen.py')
            ctypesgen_command = ["python", "-", "--cpp", self.ctypesgen_cpp]
        except:
            script_str = None
            ctypesgen_command = ["ctypesgen.py", "--cpp", self.ctypesgen_cpp]

        new_env = dict(os.environ)
        new_env['PYTHONPATH'] = ctypesgen_dist.location

        ctypesgen_command.extend(self.compile_flags)
        ctypesgen_command.extend(["-o", target])
        ctypesgen_command.append(self.gssapi_h_location)

        if script_str:
            ctypesgen_proc = subprocess.Popen(ctypesgen_command, stdin=subprocess.PIPE, env=new_env)
            ctypesgen_proc.communicate(script_str)
            if ctypesgen_proc.returncode != 0:
                raise subprocess.CalledProcessError(ctypesgen_proc.returncode, ctypesgen_command)
        else:
            subprocess.check_call(ctypesgen_command)

        if self.patch_struct_pack is not None:
            patched_source = "".join(self._patch_struct_packing(
                self.gssapi_h_location, target, self.patch_struct_pack
            ))
            with open(target, 'w') as outfile:
                outfile.write(patched_source)
        _build_py.run(self)


setup(
    name="python-gssapi",
    version="0.2.5",
    cmdclass={
        "build_py": build_py,
    },
    packages=find_packages(exclude=["tests.*", "tests"]),
    py_modules=['gssapi_ez_setup'],

    setup_requires=[
        'ctypesgen==0.r125',
    ],
    install_requires=[
        'pyasn1>=0.1.6',
    ],

    # metadata for upload to PyPI
    author="Hugh Cole-Baker",
    author_email="hugh@sigmaris.info",
    description="An object-oriented interface to GSSAPI for Python",
    license="BSD",
    keywords="gssapi kerberos",
    url="https://github.com/sigmaris/python-gssapi",
)
