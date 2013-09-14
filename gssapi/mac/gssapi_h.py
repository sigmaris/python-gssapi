'''Wrapper for gssapi.h

Generated with:
ctypesgen.py --cpp "gcc -E -DTARGET_CPU_X86_64=1" -lkrb5 /usr/include/gssapi/gssapi.h -o gssapi/gssapi_h.py

Modified for Mac to add packing to structs.

For reference the invocation for Linux is:
ctypesgen.py (output of krb5-config --libs gssapi here) /usr/include/gssapi/gssapi.h -o gssapi/gssapi_h.py
'''

__docformat__ =  'restructuredtext'

# Begin preamble

import ctypes, os, sys
from ctypes import *

# _int_types = (c_int16, c_int32)
# if hasattr(ctypes, 'c_int64'):
#     # Some builds of ctypes apparently do not have c_int64
#     # defined; it's a pretty good bet that these builds do not
#     # have 64-bit pointers.
#     _int_types += (c_int64,)
# for t in _int_types:
#     if sizeof(t) == sizeof(c_size_t):
#         c_ptrdiff_t = t
# del t
# del _int_types

# class c_void(Structure):
#     # c_void_p is a buggy return type, converting to int, so
#     # POINTER(None) == c_void_p is actually written as
#     # POINTER(c_void), so it can be treated as a real pointer.
#     _fields_ = [('dummy', c_int)]

# def POINTER(obj):
#     p = ctypes.POINTER(obj)

#     # Convert None to a real NULL pointer to work around bugs
#     # in how ctypes handles None on 64-bit platforms
#     if not isinstance(p.from_param, classmethod):
#         def from_param(cls, x):
#             if x is None:
#                 return cls()
#             else:
#                 return x
#         p.from_param = classmethod(from_param)

#     return p

class UserString:
    def __init__(self, seq):
        if isinstance(seq, basestring):
            self.data = seq
        elif isinstance(seq, UserString):
            self.data = seq.data[:]
        else:
            self.data = str(seq)
    def __str__(self): return str(self.data)
    def __repr__(self): return repr(self.data)
    def __int__(self): return int(self.data)
    def __long__(self): return long(self.data)
    def __float__(self): return float(self.data)
    def __complex__(self): return complex(self.data)
    def __hash__(self): return hash(self.data)

    def __cmp__(self, string):
        if isinstance(string, UserString):
            return cmp(self.data, string.data)
        else:
            return cmp(self.data, string)
    def __contains__(self, char):
        return char in self.data

    def __len__(self): return len(self.data)
    def __getitem__(self, index): return self.__class__(self.data[index])
    def __getslice__(self, start, end):
        start = max(start, 0); end = max(end, 0)
        return self.__class__(self.data[start:end])

    def __add__(self, other):
        if isinstance(other, UserString):
            return self.__class__(self.data + other.data)
        elif isinstance(other, basestring):
            return self.__class__(self.data + other)
        else:
            return self.__class__(self.data + str(other))
    def __radd__(self, other):
        if isinstance(other, basestring):
            return self.__class__(other + self.data)
        else:
            return self.__class__(str(other) + self.data)
    def __mul__(self, n):
        return self.__class__(self.data*n)
    __rmul__ = __mul__
    def __mod__(self, args):
        return self.__class__(self.data % args)

    # the following methods are defined in alphabetical order:
    def capitalize(self): return self.__class__(self.data.capitalize())
    def center(self, width, *args):
        return self.__class__(self.data.center(width, *args))
    def count(self, sub, start=0, end=sys.maxint):
        return self.data.count(sub, start, end)
    def decode(self, encoding=None, errors=None): # XXX improve this?
        if encoding:
            if errors:
                return self.__class__(self.data.decode(encoding, errors))
            else:
                return self.__class__(self.data.decode(encoding))
        else:
            return self.__class__(self.data.decode())
    def encode(self, encoding=None, errors=None): # XXX improve this?
        if encoding:
            if errors:
                return self.__class__(self.data.encode(encoding, errors))
            else:
                return self.__class__(self.data.encode(encoding))
        else:
            return self.__class__(self.data.encode())
    def endswith(self, suffix, start=0, end=sys.maxint):
        return self.data.endswith(suffix, start, end)
    def expandtabs(self, tabsize=8):
        return self.__class__(self.data.expandtabs(tabsize))
    def find(self, sub, start=0, end=sys.maxint):
        return self.data.find(sub, start, end)
    def index(self, sub, start=0, end=sys.maxint):
        return self.data.index(sub, start, end)
    def isalpha(self): return self.data.isalpha()
    def isalnum(self): return self.data.isalnum()
    def isdecimal(self): return self.data.isdecimal()
    def isdigit(self): return self.data.isdigit()
    def islower(self): return self.data.islower()
    def isnumeric(self): return self.data.isnumeric()
    def isspace(self): return self.data.isspace()
    def istitle(self): return self.data.istitle()
    def isupper(self): return self.data.isupper()
    def join(self, seq): return self.data.join(seq)
    def ljust(self, width, *args):
        return self.__class__(self.data.ljust(width, *args))
    def lower(self): return self.__class__(self.data.lower())
    def lstrip(self, chars=None): return self.__class__(self.data.lstrip(chars))
    def partition(self, sep):
        return self.data.partition(sep)
    def replace(self, old, new, maxsplit=-1):
        return self.__class__(self.data.replace(old, new, maxsplit))
    def rfind(self, sub, start=0, end=sys.maxint):
        return self.data.rfind(sub, start, end)
    def rindex(self, sub, start=0, end=sys.maxint):
        return self.data.rindex(sub, start, end)
    def rjust(self, width, *args):
        return self.__class__(self.data.rjust(width, *args))
    def rpartition(self, sep):
        return self.data.rpartition(sep)
    def rstrip(self, chars=None): return self.__class__(self.data.rstrip(chars))
    def split(self, sep=None, maxsplit=-1):
        return self.data.split(sep, maxsplit)
    def rsplit(self, sep=None, maxsplit=-1):
        return self.data.rsplit(sep, maxsplit)
    def splitlines(self, keepends=0): return self.data.splitlines(keepends)
    def startswith(self, prefix, start=0, end=sys.maxint):
        return self.data.startswith(prefix, start, end)
    def strip(self, chars=None): return self.__class__(self.data.strip(chars))
    def swapcase(self): return self.__class__(self.data.swapcase())
    def title(self): return self.__class__(self.data.title())
    def translate(self, *args):
        return self.__class__(self.data.translate(*args))
    def upper(self): return self.__class__(self.data.upper())
    def zfill(self, width): return self.__class__(self.data.zfill(width))

class MutableString(UserString):
    """mutable string objects

    Python strings are immutable objects.  This has the advantage, that
    strings may be used as dictionary keys.  If this property isn't needed
    and you insist on changing string values in place instead, you may cheat
    and use MutableString.

    But the purpose of this class is an educational one: to prevent
    people from inventing their own mutable string class derived
    from UserString and than forget thereby to remove (override) the
    __hash__ method inherited from UserString.  This would lead to
    errors that would be very hard to track down.

    A faster and better solution is to rewrite your program using lists."""
    def __init__(self, string=""):
        self.data = string
    def __hash__(self):
        raise TypeError("unhashable type (it is mutable)")
    def __setitem__(self, index, sub):
        if index < 0:
            index += len(self.data)
        if index < 0 or index >= len(self.data): raise IndexError
        self.data = self.data[:index] + sub + self.data[index+1:]
    def __delitem__(self, index):
        if index < 0:
            index += len(self.data)
        if index < 0 or index >= len(self.data): raise IndexError
        self.data = self.data[:index] + self.data[index+1:]
    def __setslice__(self, start, end, sub):
        start = max(start, 0); end = max(end, 0)
        if isinstance(sub, UserString):
            self.data = self.data[:start]+sub.data+self.data[end:]
        elif isinstance(sub, basestring):
            self.data = self.data[:start]+sub+self.data[end:]
        else:
            self.data =  self.data[:start]+str(sub)+self.data[end:]
    def __delslice__(self, start, end):
        start = max(start, 0); end = max(end, 0)
        self.data = self.data[:start] + self.data[end:]
    def immutable(self):
        return UserString(self.data)
    def __iadd__(self, other):
        if isinstance(other, UserString):
            self.data += other.data
        elif isinstance(other, basestring):
            self.data += other
        else:
            self.data += str(other)
        return self
    def __imul__(self, n):
        self.data *= n
        return self

class String(MutableString, Union):

    _fields_ = [('raw', POINTER(c_char)),
                ('data', c_char_p)]

    def __init__(self, obj=""):
        if isinstance(obj, (str, unicode, UserString)):
            self.data = str(obj)
        else:
            self.raw = obj

    def __len__(self):
        return self.data and len(self.data) or 0

    def from_param(cls, obj):
        # Convert None or 0
        if obj is None or obj == 0:
            return cls(POINTER(c_char)())

        # Convert from String
        elif isinstance(obj, String):
            return obj

        # Convert from str
        elif isinstance(obj, str):
            return cls(obj)

        # Convert from c_char_p
        elif isinstance(obj, c_char_p):
            return obj

        # Convert from POINTER(c_char)
        elif isinstance(obj, POINTER(c_char)):
            return obj

        # Convert from raw pointer
        elif isinstance(obj, int):
            return cls(cast(obj, POINTER(c_char)))

        # Convert from object
        else:
            return String.from_param(obj._as_parameter_)
    from_param = classmethod(from_param)

def ReturnString(obj, func=None, arguments=None):
    return String.from_param(obj)

# As of ctypes 1.0, ctypes does not support custom error-checking
# functions on callbacks, nor does it support custom datatypes on
# callbacks, so we must ensure that all callbacks return
# primitive datatypes.
#
# Non-primitive return values wrapped with UNCHECKED won't be
# typechecked, and will be converted to c_void_p.
def UNCHECKED(type):
    if (hasattr(type, "_type_") and isinstance(type._type_, str)
        and type._type_ != "P"):
        return type
    else:
        return c_void_p

# ctypes doesn't have direct support for variadic functions, so we have to write
# our own wrapper class
class _variadic_function(object):
    def __init__(self,func,restype,argtypes):
        self.func=func
        self.func.restype=restype
        self.argtypes=argtypes
    def _as_parameter_(self):
        # So we can pass this variadic function as a function pointer
        return self.func
    def __call__(self,*args):
        fixed_args=[]
        i=0
        for argtype in self.argtypes:
            # Typecheck what we can
            fixed_args.append(argtype.from_param(args[i]))
            i+=1
        return self.func(*fixed_args+list(args[i:]))

# End preamble

_libs = {}
_libdirs = []

# Begin loader

# ----------------------------------------------------------------------------
# Copyright (c) 2008 David James
# Copyright (c) 2006-2008 Alex Holkner
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of pyglet nor the names of its
#    contributors may be used to endorse or promote products
#    derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ----------------------------------------------------------------------------

import os.path, re, sys, glob
import ctypes
import ctypes.util

def _environ_path(name):
    if name in os.environ:
        return os.environ[name].split(":")
    else:
        return []

class LibraryLoader(object):
    def __init__(self):
        self.other_dirs=[]

    def load_library(self,libname):
        """Given the name of a library, load it."""
        paths = self.getpaths(libname)

        for path in paths:
            if os.path.exists(path):
                return self.load(path)

        raise ImportError("%s not found." % libname)

    def load(self,path):
        """Given a path to a library, load it."""
        try:
            # Darwin requires dlopen to be called with mode RTLD_GLOBAL instead
            # of the default RTLD_LOCAL.  Without this, you end up with
            # libraries not being loadable, resulting in "Symbol not found"
            # errors
            if sys.platform == 'darwin':
                return ctypes.CDLL(path, ctypes.RTLD_GLOBAL)
            else:
                return ctypes.cdll.LoadLibrary(path)
        except OSError,e:
            raise ImportError(e)

    def getpaths(self,libname):
        """Return a list of paths where the library might be found."""
        if os.path.isabs(libname):
            yield libname
        else:
            # FIXME / TODO return '.' and os.path.dirname(__file__)
            for path in self.getplatformpaths(libname):
                yield path

            path = ctypes.util.find_library(libname)
            if path: yield path

    def getplatformpaths(self, libname):
        return []

# Darwin (Mac OS X)

class DarwinLibraryLoader(LibraryLoader):
    name_formats = ["lib%s.dylib", "lib%s.so", "lib%s.bundle", "%s.dylib",
                "%s.so", "%s.bundle", "%s"]

    def getplatformpaths(self,libname):
        if os.path.pathsep in libname:
            names = [libname]
        else:
            names = [format % libname for format in self.name_formats]

        for dir in self.getdirs(libname):
            for name in names:
                yield os.path.join(dir,name)

    def getdirs(self,libname):
        '''Implements the dylib search as specified in Apple documentation:

        http://developer.apple.com/documentation/DeveloperTools/Conceptual/
            DynamicLibraries/Articles/DynamicLibraryUsageGuidelines.html

        Before commencing the standard search, the method first checks
        the bundle's ``Frameworks`` directory if the application is running
        within a bundle (OS X .app).
        '''

        dyld_fallback_library_path = _environ_path("DYLD_FALLBACK_LIBRARY_PATH")
        if not dyld_fallback_library_path:
            dyld_fallback_library_path = [os.path.expanduser('~/lib'),
                                          '/usr/local/lib', '/usr/lib']

        dirs = []

        if '/' in libname:
            dirs.extend(_environ_path("DYLD_LIBRARY_PATH"))
        else:
            dirs.extend(_environ_path("LD_LIBRARY_PATH"))
            dirs.extend(_environ_path("DYLD_LIBRARY_PATH"))

        dirs.extend(self.other_dirs)
        dirs.append(".")
        dirs.append(os.path.dirname(__file__))

        if hasattr(sys, 'frozen') and sys.frozen == 'macosx_app':
            dirs.append(os.path.join(
                os.environ['RESOURCEPATH'],
                '..',
                'Frameworks'))

        dirs.extend(dyld_fallback_library_path)

        return dirs

# Posix

class PosixLibraryLoader(LibraryLoader):
    _ld_so_cache = None

    def _create_ld_so_cache(self):
        # Recreate search path followed by ld.so.  This is going to be
        # slow to build, and incorrect (ld.so uses ld.so.cache, which may
        # not be up-to-date).  Used only as fallback for distros without
        # /sbin/ldconfig.
        #
        # We assume the DT_RPATH and DT_RUNPATH binary sections are omitted.

        directories = []
        for name in ("LD_LIBRARY_PATH",
                     "SHLIB_PATH", # HPUX
                     "LIBPATH", # OS/2, AIX
                     "LIBRARY_PATH", # BE/OS
                    ):
            if name in os.environ:
                directories.extend(os.environ[name].split(os.pathsep))
        directories.extend(self.other_dirs)
        directories.append(".")
        directories.append(os.path.dirname(__file__))

        try: directories.extend([dir.strip() for dir in open('/etc/ld.so.conf')])
        except IOError: pass

        directories.extend(['/lib', '/usr/lib', '/lib64', '/usr/lib64'])

        cache = {}
        lib_re = re.compile(r'lib(.*)\.s[ol]')
        ext_re = re.compile(r'\.s[ol]$')
        for dir in directories:
            try:
                for path in glob.glob("%s/*.s[ol]*" % dir):
                    file = os.path.basename(path)

                    # Index by filename
                    if file not in cache:
                        cache[file] = path

                    # Index by library name
                    match = lib_re.match(file)
                    if match:
                        library = match.group(1)
                        if library not in cache:
                            cache[library] = path
            except OSError:
                pass

        self._ld_so_cache = cache

    def getplatformpaths(self, libname):
        if self._ld_so_cache is None:
            self._create_ld_so_cache()

        result = self._ld_so_cache.get(libname)
        if result: yield result

        path = ctypes.util.find_library(libname)
        if path: yield os.path.join("/lib",path)

# Windows

class _WindowsLibrary(object):
    def __init__(self, path):
        self.cdll = ctypes.cdll.LoadLibrary(path)
        self.windll = ctypes.windll.LoadLibrary(path)

    def __getattr__(self, name):
        try: return getattr(self.cdll,name)
        except AttributeError:
            try: return getattr(self.windll,name)
            except AttributeError:
                raise

class WindowsLibraryLoader(LibraryLoader):
    name_formats = ["%s.dll", "lib%s.dll", "%slib.dll"]

    def load_library(self, libname):
        try:
            result = LibraryLoader.load_library(self, libname)
        except ImportError:
            result = None
            if os.path.sep not in libname:
                for name in self.name_formats:
                    try:
                        result = getattr(ctypes.cdll, name % libname)
                        if result:
                            break
                    except WindowsError:
                        result = None
            if result is None:
                try:
                    result = getattr(ctypes.cdll, libname)
                except WindowsError:
                    result = None
            if result is None:
                raise ImportError("%s not found." % libname)
        return result

    def load(self, path):
        return _WindowsLibrary(path)

    def getplatformpaths(self, libname):
        if os.path.sep not in libname:
            for name in self.name_formats:
                dll_in_current_dir = os.path.abspath(name % libname)
                if os.path.exists(dll_in_current_dir):
                    yield dll_in_current_dir
                path = ctypes.util.find_library(name % libname)
                if path:
                    yield path

# Platform switching

# If your value of sys.platform does not appear in this dict, please contact
# the Ctypesgen maintainers.

loaderclass = {
    "darwin":   DarwinLibraryLoader,
    "cygwin":   WindowsLibraryLoader,
    "win32":    WindowsLibraryLoader
}

loader = loaderclass.get(sys.platform, PosixLibraryLoader)()

def add_library_search_dirs(other_dirs):
    loader.other_dirs = other_dirs

load_library = loader.load_library

del loaderclass

# End loader

add_library_search_dirs([])

# Begin libraries

_libs["krb5"] = load_library("krb5")

# 1 libraries
# End libraries

# No modules

# /usr/include/gssapi/gssapi.h: 85
class struct_gss_name_struct(Structure):
    _pack_ = 2

gss_name_t = POINTER(struct_gss_name_struct) # /usr/include/gssapi/gssapi.h: 86

# /usr/include/gssapi/gssapi.h: 88
class struct_gss_cred_id_struct(Structure):
    _pack_ = 2

gss_cred_id_t = POINTER(struct_gss_cred_id_struct) # /usr/include/gssapi/gssapi.h: 89

# /usr/include/gssapi/gssapi.h: 91
class struct_gss_ctx_id_struct(Structure):
    _pack_ = 2

gss_ctx_id_t = POINTER(struct_gss_ctx_id_struct) # /usr/include/gssapi/gssapi.h: 92

gss_uint32 = c_uint32 # /usr/include/gssapi/gssapi.h: 98

gss_int32 = c_int32 # /usr/include/gssapi/gssapi.h: 99

OM_uint32 = gss_uint32 # /usr/include/gssapi/gssapi.h: 111

# /usr/include/gssapi/gssapi.h: 116
class struct_gss_OID_desc_struct(Structure):
    _pack_ = 2

struct_gss_OID_desc_struct.__slots__ = [
    'length',
    'elements',
]
struct_gss_OID_desc_struct._fields_ = [
    ('length', OM_uint32),
    ('elements', POINTER(None)),
]

gss_OID_desc = struct_gss_OID_desc_struct # /usr/include/gssapi/gssapi.h: 116

gss_OID = POINTER(struct_gss_OID_desc_struct) # /usr/include/gssapi/gssapi.h: 116

# /usr/include/gssapi/gssapi.h: 122
class struct_gss_OID_set_desc_struct(Structure):
    _pack_ = 2

struct_gss_OID_set_desc_struct.__slots__ = [
    'count',
    'elements',
]
struct_gss_OID_set_desc_struct._fields_ = [
    ('count', c_size_t),
    ('elements', gss_OID),
]

gss_OID_set_desc = struct_gss_OID_set_desc_struct # /usr/include/gssapi/gssapi.h: 122

gss_OID_set = POINTER(struct_gss_OID_set_desc_struct) # /usr/include/gssapi/gssapi.h: 122

# /usr/include/gssapi/gssapi.h: 127
class struct_gss_buffer_desc_struct(Structure):
    _pack_ = 2

struct_gss_buffer_desc_struct.__slots__ = [
    'length',
    'value',
]
struct_gss_buffer_desc_struct._fields_ = [
    ('length', c_size_t),
    ('value', POINTER(None)),
]

gss_buffer_desc = struct_gss_buffer_desc_struct # /usr/include/gssapi/gssapi.h: 127

gss_buffer_t = POINTER(struct_gss_buffer_desc_struct) # /usr/include/gssapi/gssapi.h: 127

# /usr/include/gssapi/gssapi.h: 129
class struct_gss_channel_bindings_struct(Structure):
    _pack_ = 2

struct_gss_channel_bindings_struct.__slots__ = [
    'initiator_addrtype',
    'initiator_address',
    'acceptor_addrtype',
    'acceptor_address',
    'application_data',
]
struct_gss_channel_bindings_struct._fields_ = [
    ('initiator_addrtype', OM_uint32),
    ('initiator_address', gss_buffer_desc),
    ('acceptor_addrtype', OM_uint32),
    ('acceptor_address', gss_buffer_desc),
    ('application_data', gss_buffer_desc),
]

gss_channel_bindings_t = POINTER(struct_gss_channel_bindings_struct) # /usr/include/gssapi/gssapi.h: 135

gss_qop_t = OM_uint32 # /usr/include/gssapi/gssapi.h: 141

gss_cred_usage_t = c_int # /usr/include/gssapi/gssapi.h: 142

# /usr/include/gssapi/gssapi.h: 344
try:
    GSS_C_NT_USER_NAME = (gss_OID).in_dll(_libs['krb5'], 'GSS_C_NT_USER_NAME')
except:
    pass

# /usr/include/gssapi/gssapi.h: 356
try:
    GSS_C_NT_MACHINE_UID_NAME = (gss_OID).in_dll(_libs['krb5'], 'GSS_C_NT_MACHINE_UID_NAME')
except:
    pass

# /usr/include/gssapi/gssapi.h: 368
try:
    GSS_C_NT_STRING_UID_NAME = (gss_OID).in_dll(_libs['krb5'], 'GSS_C_NT_STRING_UID_NAME')
except:
    pass

# /usr/include/gssapi/gssapi.h: 387
try:
    GSS_C_NT_HOSTBASED_SERVICE_X = (gss_OID).in_dll(_libs['krb5'], 'GSS_C_NT_HOSTBASED_SERVICE_X')
except:
    pass

# /usr/include/gssapi/gssapi.h: 400
try:
    GSS_C_NT_HOSTBASED_SERVICE = (gss_OID).in_dll(_libs['krb5'], 'GSS_C_NT_HOSTBASED_SERVICE')
except:
    pass

# /usr/include/gssapi/gssapi.h: 412
try:
    GSS_C_NT_ANONYMOUS = (gss_OID).in_dll(_libs['krb5'], 'GSS_C_NT_ANONYMOUS')
except:
    pass

# /usr/include/gssapi/gssapi.h: 425
try:
    GSS_C_NT_EXPORT_NAME = (gss_OID).in_dll(_libs['krb5'], 'GSS_C_NT_EXPORT_NAME')
except:
    pass

# /usr/include/gssapi/gssapi.h: 430
if hasattr(_libs['krb5'], 'gss_acquire_cred'):
    gss_acquire_cred = _libs['krb5'].gss_acquire_cred
    gss_acquire_cred.argtypes = [POINTER(OM_uint32), gss_name_t, OM_uint32, gss_OID_set, gss_cred_usage_t, POINTER(gss_cred_id_t), POINTER(gss_OID_set), POINTER(OM_uint32)]
    gss_acquire_cred.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 441
if hasattr(_libs['krb5'], 'gss_release_cred'):
    gss_release_cred = _libs['krb5'].gss_release_cred
    gss_release_cred.argtypes = [POINTER(OM_uint32), POINTER(gss_cred_id_t)]
    gss_release_cred.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 446
if hasattr(_libs['krb5'], 'gss_init_sec_context'):
    gss_init_sec_context = _libs['krb5'].gss_init_sec_context
    gss_init_sec_context.argtypes = [POINTER(OM_uint32), gss_cred_id_t, POINTER(gss_ctx_id_t), gss_name_t, gss_OID, OM_uint32, OM_uint32, gss_channel_bindings_t, gss_buffer_t, POINTER(gss_OID), gss_buffer_t, POINTER(OM_uint32), POINTER(OM_uint32)]
    gss_init_sec_context.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 462
if hasattr(_libs['krb5'], 'gss_accept_sec_context'):
    gss_accept_sec_context = _libs['krb5'].gss_accept_sec_context
    gss_accept_sec_context.argtypes = [POINTER(OM_uint32), POINTER(gss_ctx_id_t), gss_cred_id_t, gss_buffer_t, gss_channel_bindings_t, POINTER(gss_name_t), POINTER(gss_OID), gss_buffer_t, POINTER(OM_uint32), POINTER(OM_uint32), POINTER(gss_cred_id_t)]
    gss_accept_sec_context.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 476
if hasattr(_libs['krb5'], 'gss_process_context_token'):
    gss_process_context_token = _libs['krb5'].gss_process_context_token
    gss_process_context_token.argtypes = [POINTER(OM_uint32), gss_ctx_id_t, gss_buffer_t]
    gss_process_context_token.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 483
if hasattr(_libs['krb5'], 'gss_delete_sec_context'):
    gss_delete_sec_context = _libs['krb5'].gss_delete_sec_context
    gss_delete_sec_context.argtypes = [POINTER(OM_uint32), POINTER(gss_ctx_id_t), gss_buffer_t]
    gss_delete_sec_context.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 490
if hasattr(_libs['krb5'], 'gss_context_time'):
    gss_context_time = _libs['krb5'].gss_context_time
    gss_context_time.argtypes = [POINTER(OM_uint32), gss_ctx_id_t, POINTER(OM_uint32)]
    gss_context_time.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 498
if hasattr(_libs['krb5'], 'gss_get_mic'):
    gss_get_mic = _libs['krb5'].gss_get_mic
    gss_get_mic.argtypes = [POINTER(OM_uint32), gss_ctx_id_t, gss_qop_t, gss_buffer_t, gss_buffer_t]
    gss_get_mic.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 508
if hasattr(_libs['krb5'], 'gss_verify_mic'):
    gss_verify_mic = _libs['krb5'].gss_verify_mic
    gss_verify_mic.argtypes = [POINTER(OM_uint32), gss_ctx_id_t, gss_buffer_t, gss_buffer_t, POINTER(gss_qop_t)]
    gss_verify_mic.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 517
if hasattr(_libs['krb5'], 'gss_wrap'):
    gss_wrap = _libs['krb5'].gss_wrap
    gss_wrap.argtypes = [POINTER(OM_uint32), gss_ctx_id_t, c_int, gss_qop_t, gss_buffer_t, POINTER(c_int), gss_buffer_t]
    gss_wrap.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 529
if hasattr(_libs['krb5'], 'gss_unwrap'):
    gss_unwrap = _libs['krb5'].gss_unwrap
    gss_unwrap.argtypes = [POINTER(OM_uint32), gss_ctx_id_t, gss_buffer_t, gss_buffer_t, POINTER(c_int), POINTER(gss_qop_t)]
    gss_unwrap.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 539
if hasattr(_libs['krb5'], 'gss_display_status'):
    gss_display_status = _libs['krb5'].gss_display_status
    gss_display_status.argtypes = [POINTER(OM_uint32), OM_uint32, c_int, gss_OID, POINTER(OM_uint32), gss_buffer_t]
    gss_display_status.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 549
if hasattr(_libs['krb5'], 'gss_indicate_mechs'):
    gss_indicate_mechs = _libs['krb5'].gss_indicate_mechs
    gss_indicate_mechs.argtypes = [POINTER(OM_uint32), POINTER(gss_OID_set)]
    gss_indicate_mechs.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 555
if hasattr(_libs['krb5'], 'gss_compare_name'):
    gss_compare_name = _libs['krb5'].gss_compare_name
    gss_compare_name.argtypes = [POINTER(OM_uint32), gss_name_t, gss_name_t, POINTER(c_int)]
    gss_compare_name.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 563
if hasattr(_libs['krb5'], 'gss_display_name'):
    gss_display_name = _libs['krb5'].gss_display_name
    gss_display_name.argtypes = [POINTER(OM_uint32), gss_name_t, gss_buffer_t, POINTER(gss_OID)]
    gss_display_name.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 571
if hasattr(_libs['krb5'], 'gss_import_name'):
    gss_import_name = _libs['krb5'].gss_import_name
    gss_import_name.argtypes = [POINTER(OM_uint32), gss_buffer_t, gss_OID, POINTER(gss_name_t)]
    gss_import_name.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 578
if hasattr(_libs['krb5'], 'gss_release_name'):
    gss_release_name = _libs['krb5'].gss_release_name
    gss_release_name.argtypes = [POINTER(OM_uint32), POINTER(gss_name_t)]
    gss_release_name.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 583
if hasattr(_libs['krb5'], 'gss_release_buffer'):
    gss_release_buffer = _libs['krb5'].gss_release_buffer
    gss_release_buffer.argtypes = [POINTER(OM_uint32), gss_buffer_t]
    gss_release_buffer.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 588
if hasattr(_libs['krb5'], 'gss_release_oid_set'):
    gss_release_oid_set = _libs['krb5'].gss_release_oid_set
    gss_release_oid_set.argtypes = [POINTER(OM_uint32), POINTER(gss_OID_set)]
    gss_release_oid_set.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 593
if hasattr(_libs['krb5'], 'gss_inquire_cred'):
    gss_inquire_cred = _libs['krb5'].gss_inquire_cred
    gss_inquire_cred.argtypes = [POINTER(OM_uint32), gss_cred_id_t, POINTER(gss_name_t), POINTER(OM_uint32), POINTER(gss_cred_usage_t), POINTER(gss_OID_set)]
    gss_inquire_cred.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 603
if hasattr(_libs['krb5'], 'gss_inquire_context'):
    gss_inquire_context = _libs['krb5'].gss_inquire_context
    gss_inquire_context.argtypes = [POINTER(OM_uint32), gss_ctx_id_t, POINTER(gss_name_t), POINTER(gss_name_t), POINTER(OM_uint32), POINTER(gss_OID), POINTER(OM_uint32), POINTER(c_int), POINTER(c_int)]
    gss_inquire_context.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 616
if hasattr(_libs['krb5'], 'gss_wrap_size_limit'):
    gss_wrap_size_limit = _libs['krb5'].gss_wrap_size_limit
    gss_wrap_size_limit.argtypes = [POINTER(OM_uint32), gss_ctx_id_t, c_int, gss_qop_t, OM_uint32, POINTER(OM_uint32)]
    gss_wrap_size_limit.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 626
for _lib in _libs.itervalues():
    if not hasattr(_lib, 'gss_import_name_object'):
        continue
    gss_import_name_object = _lib.gss_import_name_object
    gss_import_name_object.argtypes = [POINTER(OM_uint32), POINTER(None), gss_OID, POINTER(gss_name_t)]
    gss_import_name_object.restype = OM_uint32
    break

# /usr/include/gssapi/gssapi.h: 634
for _lib in _libs.itervalues():
    if not hasattr(_lib, 'gss_export_name_object'):
        continue
    gss_export_name_object = _lib.gss_export_name_object
    gss_export_name_object.argtypes = [POINTER(OM_uint32), gss_name_t, gss_OID, POINTER(POINTER(None))]
    gss_export_name_object.restype = OM_uint32
    break

# /usr/include/gssapi/gssapi.h: 642
if hasattr(_libs['krb5'], 'gss_add_cred'):
    gss_add_cred = _libs['krb5'].gss_add_cred
    gss_add_cred.argtypes = [POINTER(OM_uint32), gss_cred_id_t, gss_name_t, gss_OID, gss_cred_usage_t, OM_uint32, OM_uint32, POINTER(gss_cred_id_t), POINTER(gss_OID_set), POINTER(OM_uint32), POINTER(OM_uint32)]
    gss_add_cred.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 657
if hasattr(_libs['krb5'], 'gss_inquire_cred_by_mech'):
    gss_inquire_cred_by_mech = _libs['krb5'].gss_inquire_cred_by_mech
    gss_inquire_cred_by_mech.argtypes = [POINTER(OM_uint32), gss_cred_id_t, gss_OID, POINTER(gss_name_t), POINTER(OM_uint32), POINTER(OM_uint32), POINTER(gss_cred_usage_t)]
    gss_inquire_cred_by_mech.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 668
if hasattr(_libs['krb5'], 'gss_export_sec_context'):
    gss_export_sec_context = _libs['krb5'].gss_export_sec_context
    gss_export_sec_context.argtypes = [POINTER(OM_uint32), POINTER(gss_ctx_id_t), gss_buffer_t]
    gss_export_sec_context.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 675
if hasattr(_libs['krb5'], 'gss_import_sec_context'):
    gss_import_sec_context = _libs['krb5'].gss_import_sec_context
    gss_import_sec_context.argtypes = [POINTER(OM_uint32), gss_buffer_t, POINTER(gss_ctx_id_t)]
    gss_import_sec_context.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 682
if hasattr(_libs['krb5'], 'gss_release_oid'):
    gss_release_oid = _libs['krb5'].gss_release_oid
    gss_release_oid.argtypes = [POINTER(OM_uint32), POINTER(gss_OID)]
    gss_release_oid.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 688
if hasattr(_libs['krb5'], 'gss_create_empty_oid_set'):
    gss_create_empty_oid_set = _libs['krb5'].gss_create_empty_oid_set
    gss_create_empty_oid_set.argtypes = [POINTER(OM_uint32), POINTER(gss_OID_set)]
    gss_create_empty_oid_set.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 694
if hasattr(_libs['krb5'], 'gss_add_oid_set_member'):
    gss_add_oid_set_member = _libs['krb5'].gss_add_oid_set_member
    gss_add_oid_set_member.argtypes = [POINTER(OM_uint32), gss_OID, POINTER(gss_OID_set)]
    gss_add_oid_set_member.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 701
if hasattr(_libs['krb5'], 'gss_test_oid_set_member'):
    gss_test_oid_set_member = _libs['krb5'].gss_test_oid_set_member
    gss_test_oid_set_member.argtypes = [POINTER(OM_uint32), gss_OID, gss_OID_set, POINTER(c_int)]
    gss_test_oid_set_member.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 709
if hasattr(_libs['krb5'], 'gss_str_to_oid'):
    gss_str_to_oid = _libs['krb5'].gss_str_to_oid
    gss_str_to_oid.argtypes = [POINTER(OM_uint32), gss_buffer_t, POINTER(gss_OID)]
    gss_str_to_oid.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 716
if hasattr(_libs['krb5'], 'gss_oid_to_str'):
    gss_oid_to_str = _libs['krb5'].gss_oid_to_str
    gss_oid_to_str.argtypes = [POINTER(OM_uint32), gss_OID, gss_buffer_t]
    gss_oid_to_str.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 723
if hasattr(_libs['krb5'], 'gss_inquire_names_for_mech'):
    gss_inquire_names_for_mech = _libs['krb5'].gss_inquire_names_for_mech
    gss_inquire_names_for_mech.argtypes = [POINTER(OM_uint32), gss_OID, POINTER(gss_OID_set)]
    gss_inquire_names_for_mech.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 730
if hasattr(_libs['krb5'], 'gss_inquire_mechs_for_name'):
    gss_inquire_mechs_for_name = _libs['krb5'].gss_inquire_mechs_for_name
    gss_inquire_mechs_for_name.argtypes = [POINTER(OM_uint32), gss_name_t, POINTER(gss_OID_set)]
    gss_inquire_mechs_for_name.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 743
if hasattr(_libs['krb5'], 'gss_sign'):
    gss_sign = _libs['krb5'].gss_sign
    gss_sign.argtypes = [POINTER(OM_uint32), gss_ctx_id_t, c_int, gss_buffer_t, gss_buffer_t]
    gss_sign.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 751
if hasattr(_libs['krb5'], 'gss_verify'):
    gss_verify = _libs['krb5'].gss_verify
    gss_verify.argtypes = [POINTER(OM_uint32), gss_ctx_id_t, gss_buffer_t, gss_buffer_t, POINTER(c_int)]
    gss_verify.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 759
if hasattr(_libs['krb5'], 'gss_seal'):
    gss_seal = _libs['krb5'].gss_seal
    gss_seal.argtypes = [POINTER(OM_uint32), gss_ctx_id_t, c_int, c_int, gss_buffer_t, POINTER(c_int), gss_buffer_t]
    gss_seal.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 769
if hasattr(_libs['krb5'], 'gss_unseal'):
    gss_unseal = _libs['krb5'].gss_unseal
    gss_unseal.argtypes = [POINTER(OM_uint32), gss_ctx_id_t, gss_buffer_t, gss_buffer_t, POINTER(c_int), POINTER(c_int)]
    gss_unseal.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 779
if hasattr(_libs['krb5'], 'gss_export_name'):
    gss_export_name = _libs['krb5'].gss_export_name
    gss_export_name.argtypes = [POINTER(OM_uint32), gss_name_t, gss_buffer_t]
    gss_export_name.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 786
if hasattr(_libs['krb5'], 'gss_duplicate_name'):
    gss_duplicate_name = _libs['krb5'].gss_duplicate_name
    gss_duplicate_name.argtypes = [POINTER(OM_uint32), gss_name_t, POINTER(gss_name_t)]
    gss_duplicate_name.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 793
if hasattr(_libs['krb5'], 'gss_canonicalize_name'):
    gss_canonicalize_name = _libs['krb5'].gss_canonicalize_name
    gss_canonicalize_name.argtypes = [POINTER(OM_uint32), gss_name_t, gss_OID, POINTER(gss_name_t)]
    gss_canonicalize_name.restype = OM_uint32

# /usr/include/gssapi/gssapi.h: 147
try:
    GSS_C_DELEG_FLAG = 1
except:
    pass

# /usr/include/gssapi/gssapi.h: 148
try:
    GSS_C_MUTUAL_FLAG = 2
except:
    pass

# /usr/include/gssapi/gssapi.h: 149
try:
    GSS_C_REPLAY_FLAG = 4
except:
    pass

# /usr/include/gssapi/gssapi.h: 150
try:
    GSS_C_SEQUENCE_FLAG = 8
except:
    pass

# /usr/include/gssapi/gssapi.h: 151
try:
    GSS_C_CONF_FLAG = 16
except:
    pass

# /usr/include/gssapi/gssapi.h: 152
try:
    GSS_C_INTEG_FLAG = 32
except:
    pass

# /usr/include/gssapi/gssapi.h: 153
try:
    GSS_C_ANON_FLAG = 64
except:
    pass

# /usr/include/gssapi/gssapi.h: 154
try:
    GSS_C_PROT_READY_FLAG = 128
except:
    pass

# /usr/include/gssapi/gssapi.h: 155
try:
    GSS_C_TRANS_FLAG = 256
except:
    pass

# /usr/include/gssapi/gssapi.h: 156
try:
    GSS_C_DELEG_POLICY_FLAG = 32768
except:
    pass

# /usr/include/gssapi/gssapi.h: 157
try:
    GSS_C_NO_UI_FLAG = 2147483648
except:
    pass

# /usr/include/gssapi/gssapi.h: 162
try:
    GSS_C_BOTH = 0
except:
    pass

# /usr/include/gssapi/gssapi.h: 163
try:
    GSS_C_INITIATE = 1
except:
    pass

# /usr/include/gssapi/gssapi.h: 164
try:
    GSS_C_ACCEPT = 2
except:
    pass

# /usr/include/gssapi/gssapi.h: 166
try:
    GSS_C_OPTION_MASK = 65535
except:
    pass

# /usr/include/gssapi/gssapi.h: 167
try:
    GSS_C_CRED_NO_UI = 65536
except:
    pass

# /usr/include/gssapi/gssapi.h: 173
try:
    GSS_C_GSS_CODE = 1
except:
    pass

# /usr/include/gssapi/gssapi.h: 174
try:
    GSS_C_MECH_CODE = 2
except:
    pass

# /usr/include/gssapi/gssapi.h: 179
try:
    GSS_C_AF_UNSPEC = 0
except:
    pass

# /usr/include/gssapi/gssapi.h: 180
try:
    GSS_C_AF_LOCAL = 1
except:
    pass

# /usr/include/gssapi/gssapi.h: 181
try:
    GSS_C_AF_INET = 2
except:
    pass

# /usr/include/gssapi/gssapi.h: 182
try:
    GSS_C_AF_IMPLINK = 3
except:
    pass

# /usr/include/gssapi/gssapi.h: 183
try:
    GSS_C_AF_PUP = 4
except:
    pass

# /usr/include/gssapi/gssapi.h: 184
try:
    GSS_C_AF_CHAOS = 5
except:
    pass

# /usr/include/gssapi/gssapi.h: 185
try:
    GSS_C_AF_NS = 6
except:
    pass

# /usr/include/gssapi/gssapi.h: 186
try:
    GSS_C_AF_NBS = 7
except:
    pass

# /usr/include/gssapi/gssapi.h: 187
try:
    GSS_C_AF_ECMA = 8
except:
    pass

# /usr/include/gssapi/gssapi.h: 188
try:
    GSS_C_AF_DATAKIT = 9
except:
    pass

# /usr/include/gssapi/gssapi.h: 189
try:
    GSS_C_AF_CCITT = 10
except:
    pass

# /usr/include/gssapi/gssapi.h: 190
try:
    GSS_C_AF_SNA = 11
except:
    pass

# /usr/include/gssapi/gssapi.h: 191
try:
    GSS_C_AF_DECnet = 12
except:
    pass

# /usr/include/gssapi/gssapi.h: 192
try:
    GSS_C_AF_DLI = 13
except:
    pass

# /usr/include/gssapi/gssapi.h: 193
try:
    GSS_C_AF_LAT = 14
except:
    pass

# /usr/include/gssapi/gssapi.h: 194
try:
    GSS_C_AF_HYLINK = 15
except:
    pass

# /usr/include/gssapi/gssapi.h: 195
try:
    GSS_C_AF_APPLETALK = 16
except:
    pass

# /usr/include/gssapi/gssapi.h: 196
try:
    GSS_C_AF_BSC = 17
except:
    pass

# /usr/include/gssapi/gssapi.h: 197
try:
    GSS_C_AF_DSS = 18
except:
    pass

# /usr/include/gssapi/gssapi.h: 198
try:
    GSS_C_AF_OSI = 19
except:
    pass

# /usr/include/gssapi/gssapi.h: 199
try:
    GSS_C_AF_X25 = 21
except:
    pass

# /usr/include/gssapi/gssapi.h: 201
try:
    GSS_C_AF_NULLADDR = 255
except:
    pass

# /usr/include/gssapi/gssapi.h: 206
try:
    GSS_C_NO_NAME = 0
except:
    pass

# /usr/include/gssapi/gssapi.h: 207
try:
    GSS_C_NO_BUFFER = 0
except:
    pass

# /usr/include/gssapi/gssapi.h: 208
try:
    GSS_C_NO_OID = 0
except:
    pass

# /usr/include/gssapi/gssapi.h: 209
try:
    GSS_C_NO_OID_SET = 0
except:
    pass

# /usr/include/gssapi/gssapi.h: 210
try:
    GSS_C_NO_CONTEXT = 0
except:
    pass

# /usr/include/gssapi/gssapi.h: 211
try:
    GSS_C_NO_CREDENTIAL = 0
except:
    pass

# /usr/include/gssapi/gssapi.h: 212
try:
    GSS_C_NO_CHANNEL_BINDINGS = 0
except:
    pass

# /usr/include/gssapi/gssapi.h: 219
try:
    GSS_C_NULL_OID = GSS_C_NO_OID
except:
    pass

# /usr/include/gssapi/gssapi.h: 220
try:
    GSS_C_NULL_OID_SET = GSS_C_NO_OID_SET
except:
    pass

# /usr/include/gssapi/gssapi.h: 230
try:
    GSS_C_QOP_DEFAULT = 0
except:
    pass

# /usr/include/gssapi/gssapi.h: 236
try:
    GSS_C_INDEFINITE = 4294967295
except:
    pass

# /usr/include/gssapi/gssapi.h: 241
try:
    GSS_S_COMPLETE = 0
except:
    pass

# /usr/include/gssapi/gssapi.h: 246
try:
    GSS_C_CALLING_ERROR_OFFSET = 24
except:
    pass

# /usr/include/gssapi/gssapi.h: 247
try:
    GSS_C_ROUTINE_ERROR_OFFSET = 16
except:
    pass

# /usr/include/gssapi/gssapi.h: 248
try:
    GSS_C_SUPPLEMENTARY_OFFSET = 0
except:
    pass

# /usr/include/gssapi/gssapi.h: 249
try:
    GSS_C_CALLING_ERROR_MASK = 255
except:
    pass

# /usr/include/gssapi/gssapi.h: 250
try:
    GSS_C_ROUTINE_ERROR_MASK = 255
except:
    pass

# /usr/include/gssapi/gssapi.h: 251
try:
    GSS_C_SUPPLEMENTARY_MASK = 65535
except:
    pass

# /usr/include/gssapi/gssapi.h: 258
def GSS_CALLING_ERROR(x):
    return (x & (GSS_C_CALLING_ERROR_MASK << GSS_C_CALLING_ERROR_OFFSET))

# /usr/include/gssapi/gssapi.h: 260
def GSS_ROUTINE_ERROR(x):
    return (x & (GSS_C_ROUTINE_ERROR_MASK << GSS_C_ROUTINE_ERROR_OFFSET))

# /usr/include/gssapi/gssapi.h: 262
def GSS_SUPPLEMENTARY_INFO(x):
    return (x & (GSS_C_SUPPLEMENTARY_MASK << GSS_C_SUPPLEMENTARY_OFFSET))

# /usr/include/gssapi/gssapi.h: 264
def GSS_ERROR(x):
    return (x & ((GSS_C_CALLING_ERROR_MASK << GSS_C_CALLING_ERROR_OFFSET) | (GSS_C_ROUTINE_ERROR_MASK << GSS_C_ROUTINE_ERROR_OFFSET)))

# /usr/include/gssapi/gssapi.h: 275
try:
    GSS_S_CALL_INACCESSIBLE_READ = (1 << GSS_C_CALLING_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 277
try:
    GSS_S_CALL_INACCESSIBLE_WRITE = (2 << GSS_C_CALLING_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 279
try:
    GSS_S_CALL_BAD_STRUCTURE = (3 << GSS_C_CALLING_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 285
try:
    GSS_S_BAD_MECH = (1 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 286
try:
    GSS_S_BAD_NAME = (2 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 287
try:
    GSS_S_BAD_NAMETYPE = (3 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 288
try:
    GSS_S_BAD_BINDINGS = (4 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 289
try:
    GSS_S_BAD_STATUS = (5 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 290
try:
    GSS_S_BAD_SIG = (6 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 291
try:
    GSS_S_NO_CRED = (7 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 292
try:
    GSS_S_NO_CONTEXT = (8 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 293
try:
    GSS_S_DEFECTIVE_TOKEN = (9 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 294
try:
    GSS_S_DEFECTIVE_CREDENTIAL = (10 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 296
try:
    GSS_S_CREDENTIALS_EXPIRED = (11 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 298
try:
    GSS_S_CONTEXT_EXPIRED = (12 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 300
try:
    GSS_S_FAILURE = (13 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 301
try:
    GSS_S_BAD_QOP = (14 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 302
try:
    GSS_S_UNAUTHORIZED = (15 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 303
try:
    GSS_S_UNAVAILABLE = (16 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 304
try:
    GSS_S_DUPLICATE_ELEMENT = (17 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 306
try:
    GSS_S_NAME_NOT_MN = (18 << GSS_C_ROUTINE_ERROR_OFFSET)
except:
    pass

# /usr/include/gssapi/gssapi.h: 312
try:
    GSS_S_CONTINUE_NEEDED = (1 << (GSS_C_SUPPLEMENTARY_OFFSET + 0))
except:
    pass

# /usr/include/gssapi/gssapi.h: 313
try:
    GSS_S_DUPLICATE_TOKEN = (1 << (GSS_C_SUPPLEMENTARY_OFFSET + 1))
except:
    pass

# /usr/include/gssapi/gssapi.h: 314
try:
    GSS_S_OLD_TOKEN = (1 << (GSS_C_SUPPLEMENTARY_OFFSET + 2))
except:
    pass

# /usr/include/gssapi/gssapi.h: 315
try:
    GSS_S_UNSEQ_TOKEN = (1 << (GSS_C_SUPPLEMENTARY_OFFSET + 3))
except:
    pass

# /usr/include/gssapi/gssapi.h: 316
try:
    GSS_S_GAP_TOKEN = (1 << (GSS_C_SUPPLEMENTARY_OFFSET + 4))
except:
    pass

# /usr/include/gssapi/gssapi.h: 809
def GSS_CALLING_ERROR_FIELD(x):
    return ((x >> GSS_C_CALLING_ERROR_OFFSET) & GSS_C_CALLING_ERROR_MASK)

# /usr/include/gssapi/gssapi.h: 811
def GSS_ROUTINE_ERROR_FIELD(x):
    return ((x >> GSS_C_ROUTINE_ERROR_OFFSET) & GSS_C_ROUTINE_ERROR_MASK)

# /usr/include/gssapi/gssapi.h: 813
def GSS_SUPPLEMENTARY_INFO_FIELD(x):
    return ((x >> GSS_C_SUPPLEMENTARY_OFFSET) & GSS_C_SUPPLEMENTARY_MASK)

# /usr/include/gssapi/gssapi.h: 817
try:
    GSS_S_CRED_UNAVAIL = GSS_S_FAILURE
except:
    pass

gss_name_struct = struct_gss_name_struct # /usr/include/gssapi/gssapi.h: 85

gss_cred_id_struct = struct_gss_cred_id_struct # /usr/include/gssapi/gssapi.h: 88

gss_ctx_id_struct = struct_gss_ctx_id_struct # /usr/include/gssapi/gssapi.h: 91

gss_OID_desc_struct = struct_gss_OID_desc_struct # /usr/include/gssapi/gssapi.h: 116

gss_OID_set_desc_struct = struct_gss_OID_set_desc_struct # /usr/include/gssapi/gssapi.h: 122

gss_buffer_desc_struct = struct_gss_buffer_desc_struct # /usr/include/gssapi/gssapi.h: 127

gss_channel_bindings_struct = struct_gss_channel_bindings_struct # /usr/include/gssapi/gssapi.h: 129

# No inserted files
