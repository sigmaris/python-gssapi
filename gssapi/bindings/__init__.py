from __future__ import absolute_import

import base64
from collections import defaultdict
import json
import os.path
import subprocess

from cffi import FFI, VerificationError
from pkg_resources import resource_string, resource_exists, resource_filename
import six


def _detect_verify_args():
    source = '#include <gssapi/gssapi.h>'
    kwargs = defaultdict(list)
    if os.path.isdir('/System/Library/Frameworks/GSS.framework'):
        # Build using GSS.framework on Mac OS X 10.7+
        source = '#include <GSS/GSS.h>'
        kwargs['extra_compile_args'].extend(['-framework', 'GSS', '-Wno-error=unused-command-line-argument-hard-error-in-future'])
        kwargs['extra_link_args'].extend(['-framework', 'GSS'])
    else:
        # Build using libgssapi on other POSIX systems
        try:
            config_compile_flags = subprocess.check_output(["krb5-config", "--cflags", "gssapi"]).split()
            config_link_flags = subprocess.check_output(["krb5-config", "--libs", "gssapi"]).split()
        except:
            try:
                config_compile_flags = subprocess.check_output(["pkg-config", "--cflags", "gss"]).split()
                config_link_flags = subprocess.check_output(["pkg-config", "--libs", "gss"]).split()
            except:
                config_compile_flags = []
                config_link_flags = []
        config_compile_flags = [f.decode() for f in config_compile_flags]
        config_link_flags = [f.decode() for f in config_link_flags]
        if len(config_compile_flags) > 0:
            kwargs['extra_compile_args'].extend(config_compile_flags)
        if len(config_link_flags) > 0:
            kwargs['extra_link_args'].extend(config_link_flags)
        else:
            # This is just guessing...
            kwargs['libraries'].append('gss')

    final_kwargs = dict(kwargs)
    final_kwargs['ext_package'] = 'gssapi.bindings'
    return source, final_kwargs


def _is_defined(define, verify_args, verify_kwargs):
    ffi = FFI()
    ffi.cdef("#define {0} ...".format(define))
    try:
        ffi.verify(*verify_args, **verify_kwargs)
    except VerificationError:
        return False
    else:
        return True


def _detect_type(typedef, verify_args, verify_kwargs):
    # First, check if it is a pointer
    ffi = FFI()
    ffi.cdef("int isptr();")
    try:
        lib = ffi.verify(
            verify_args[0] + '\n' + '''
                void dont_call_this() {
                    ''' + typedef + ''' foo = NULL;
                    void *bar = &(*foo);
                }
                int isptr() {
                    return (sizeof(''' + typedef + ''') == sizeof(void *));
                }
            ''',
            *verify_args[1:],
            **verify_kwargs
        )
        if lib.isptr() != 0:
            return '... *'
    except VerificationError:
        pass
    # OK, it's not a pointer, check if it's an arithmetic type
    ffi = FFI()
    ffi.cdef("size_t type_size();")
    try:
        lib = ffi.verify(
            verify_args[0] + '\n' + '''
                size_t type_size() {
                    ''' + typedef + ''' foo = (''' + typedef + ''') 1;
                    return sizeof(foo);
                }
            ''',
            *verify_args[1:],
            **verify_kwargs
        )
        size = lib.type_size()
        # OK, it's an arithmetic type, is it signed or unsigned
        ffi = FFI()
        ffi.cdef("size_t type_size();")
        try:
            lib = ffi.verify(
                verify_args[0] + '\n' + '''
                    size_t type_size() {
                        char arr[((''' + typedef + ''') -1 < 0) * -1];
                        return sizeof(''' + typedef + ''');
                    }
                ''',
                *verify_args[1:],
                **verify_kwargs
            )
            size = lib.type_size()
        except VerificationError:
            # It's a signed type
            unsigned = ''
        else:
            unsigned = 'unsigned '
        # Now we know it's an arithmetic type, what's the best size
        if size <= ffi.sizeof(unsigned + 'char'):
            return unsigned + 'char'
        if size <= ffi.sizeof(unsigned + 'short'):
            return unsigned + 'short'
        if size <= ffi.sizeof(unsigned + 'int'):
            return unsigned + 'int'
        if size <= ffi.sizeof(unsigned + 'long'):
            return unsigned + 'long'
        if size <= ffi.sizeof(unsigned + 'long long'):
            return unsigned + 'long long'
        else:
            raise TypeError("Can't figure out the type of {0} with size {1}!".format(typedef, size))
    except VerificationError:
        # it's some kind of struct
        return 'struct { ...; }'


def GSS_CALLING_ERROR(x):
    return (x & (C.GSS_C_CALLING_ERROR_MASK << C.GSS_C_CALLING_ERROR_OFFSET))


def GSS_ROUTINE_ERROR(x):
    return (x & (C.GSS_C_ROUTINE_ERROR_MASK << C.GSS_C_ROUTINE_ERROR_OFFSET))


def GSS_SUPPLEMENTARY_INFO(x):
    return (x & (C.GSS_C_SUPPLEMENTARY_MASK << C.GSS_C_SUPPLEMENTARY_OFFSET))


def GSS_ERROR(x):
    return (x & ((C.GSS_C_CALLING_ERROR_MASK << C.GSS_C_CALLING_ERROR_OFFSET) |
                 (C.GSS_C_ROUTINE_ERROR_MASK << C.GSS_C_ROUTINE_ERROR_OFFSET)))


def _json_to_bytes(input):
    if isinstance(input, dict):
        return {_json_to_bytes(key): _json_to_bytes(value) for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [_json_to_bytes(element) for element in input]
    elif isinstance(input, six.text_type):
        return input.encode('utf-8')
    else:
        return input


def _buf_to_str(buf):
    """Converts a gss_buffer_desc containing a char * string to Python bytes"""
    return bytes(ffi.buffer(buf.value, buf.length))


def _read_header():
    cdefs = resource_string(__name__, 'cffi_gssapi.cdef')

    if resource_exists(__name__, 'autogenerated.cdef'):
        generated_cdefs = resource_string(__name__, 'autogenerated.cdef')
        # The first line (comment) is the verify settings, encoded
        line = generated_cdefs.splitlines()[0]
        settings = _json_to_bytes(json.loads(base64.b64decode(line[3:-3])))
        source = settings['source']
        kwargs = settings['kwargs']
    else:
        source, kwargs = _detect_verify_args()
        optional_defines = ('GSS_C_DELEG_POLICY_FLAG',)
        types_to_detect = ('gss_ctx_id_t', 'gss_cred_id_t', 'gss_name_t', 'uid_t')
        generated_cdefs = '/* {0} */\n'.format(base64.b64encode(json.dumps({
            'source': source,
            'kwargs': kwargs
        })))
        for define in optional_defines:
            if _is_defined(define, [source], kwargs):
                generated_cdefs += '#define {0} ...\n'.format(define)
        for t in types_to_detect:
            generated_cdefs += "typedef {0} {1};\n".format(_detect_type(t, [source], kwargs), t)
        with open(resource_filename(__name__, 'autogenerated.cdef'), 'w') as settings_file:
            settings_file.write(generated_cdefs)
    return generated_cdefs + cdefs, source, kwargs


_cdefs, _source, _kwargs = _read_header()
ffi = FFI()
ffi.cdef(_cdefs)
C = ffi.verify(_source, **_kwargs)
