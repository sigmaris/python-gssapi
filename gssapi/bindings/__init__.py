from __future__ import absolute_import

import base64
from collections import defaultdict
import json
import os.path
import subprocess

from cffi import FFI, VerificationError
from pkg_resources import resource_string, resource_exists, resource_filename
import six


_OPTIONAL_FUNCTIONS = (
'''
OM_uint32 gss_acquire_cred_with_password(
  OM_uint32          *minor_status,
  const gss_name_t   desired_name,
  const gss_buffer_t password,
  OM_uint32          time_req,
  const gss_OID_set  desired_mechs,
  gss_cred_usage_t   cred_usage,
  gss_cred_id_t      *output_cred_handle,
  gss_OID_set        *actual_mechs,
  OM_uint32          *time_rec);
''',
'''
OM_uint32 gss_export_cred(
  OM_uint32 *minor_status,
  gss_cred_id_t cred_handle,
  gss_buffer_t token);
''',
'''
OM_uint32 gss_import_cred(
  OM_uint32 *minor_status,
  gss_buffer_t token,
  gss_cred_id_t *cred_handle);
''',
)
_OPTIONAL_DEFINES = ('GSS_C_DELEG_POLICY_FLAG', 'GSS_C_AF_INET6')


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
        config_compile_flags = [
            f.encode('utf-8') if isinstance(f, six.text_type) else f
            for f in config_compile_flags
        ]
        config_link_flags = [
            f.encode('utf-8') if isinstance(f, six.text_type) else f
            for f in config_link_flags
        ]
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


def _is_verifiable(cdef, verify_args, verify_kwargs):
    ffi = FFI()
    ffi.cdef(cdef)
    try:
        ffi.verify(*verify_args, **verify_kwargs)
    except VerificationError:
        return False
    else:
        return True


def _is_pointer_sized(typedef, verify_args, verify_kwargs):
    ffi = FFI()
    ffi.cdef("int isptr();")
    try:
        lib = ffi.verify(
            verify_args[0] + '\n' + '''
                int isptr() {
                    return (sizeof(''' + typedef + ''') == sizeof(void *));
                }
            ''',
            *verify_args[1:],
            **verify_kwargs
        )
        return lib.isptr() != 0
    except VerificationError:
        # if the above fails to compile, 'typedef' is not a pointer type
        return False

def _guess_type(typedef, verify_args, verify_kwargs, assume_pointer=True):

    if assume_pointer and _is_pointer_sized(typedef, verify_args, verify_kwargs):
        return '... *'

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
        if size == ffi.sizeof('void *'):
            return '... *'
        else:
            raise TypeError("Can't figure out the type of {0} with size {1}!".format(typedef, size))
    except VerificationError:
        # it's some kind of struct
        return 'struct { ...; }'


def _kwargs_decode(input):
    if isinstance(input, dict):
        return {_kwargs_decode(key): _kwargs_decode(value) for key, value in input.items()}
    elif isinstance(input, list):
        return [_kwargs_decode(element) for element in input]
    elif six.PY2 and isinstance(input, unicode):
        return input.encode()
    elif six.PY3 and isinstance(input, bytes):
        return input.decode()
    else:
        return input


def _read_header():
    if resource_exists(__name__, 'autogenerated.cdef'):
        generated_cdefs = resource_string(__name__, 'autogenerated.cdef').decode('utf-8')
        # The first line (comment) is the verify settings, encoded
        line = generated_cdefs.splitlines()[0]
        settings = json.loads(base64.b64decode(line[3:-3].encode('ascii')).decode('utf-8'))
        source = settings['source']
        kwargs = _kwargs_decode(settings['kwargs'])
    else:
        cdefs = resource_string(__name__, 'cffi_gssapi.cdef').decode('utf-8')
        source, kwargs = _detect_verify_args()
        kwargs = _kwargs_decode(kwargs)
        ptr_types_to_detect = ('gss_ctx_id_t', 'gss_cred_id_t', 'gss_name_t')
        gen_types_to_detect = ('uid_t',)
        generated_cdefs = '/* '
        generated_cdefs += base64.b64encode(json.dumps({
            'source': source,
            'kwargs': kwargs
        }).encode('utf-8')).decode('ascii')
        generated_cdefs += ' */\n'
        for define in _OPTIONAL_DEFINES:
            test_cdef = '#define {0} ...\n'.format(define)
            if _is_verifiable(test_cdef, [source], kwargs):
                generated_cdefs += test_cdef
        for p in ptr_types_to_detect:
            guessed = _guess_type(p, [source], kwargs, True)
            generated_cdefs += "typedef {0} {1};\n".format(guessed, p)
        for t in gen_types_to_detect:
            guessed = _guess_type(t, [source], kwargs, False)
            generated_cdefs += "typedef {0} {1};\n".format(guessed, t)
        # Now copy in the pre-written cdefs
        generated_cdefs += "\n"
        generated_cdefs += cdefs
        generated_cdefs += "\n\n"
        # Now add any optional functions which must come after main cdefs
        for func in _OPTIONAL_FUNCTIONS:
            test_cdefs = generated_cdefs + func
            if _is_verifiable(test_cdefs, [source], kwargs):
                generated_cdefs = test_cdefs
        with open(resource_filename(__name__, 'autogenerated.cdef'), 'wb') as settings_file:
            settings_file.write(generated_cdefs.encode('utf-8'))
    return generated_cdefs, source, kwargs


_cdefs, _source, _kwargs = _read_header()
ffi = FFI()
ffi.cdef(_cdefs)
C = ffi.verify(_source, **_kwargs)


def GSS_CALLING_ERROR(x):
    return (x & (C.GSS_C_CALLING_ERROR_MASK << C.GSS_C_CALLING_ERROR_OFFSET))


def GSS_ROUTINE_ERROR(x):
    return (x & (C.GSS_C_ROUTINE_ERROR_MASK << C.GSS_C_ROUTINE_ERROR_OFFSET))


def GSS_SUPPLEMENTARY_INFO(x):
    return (x & (C.GSS_C_SUPPLEMENTARY_MASK << C.GSS_C_SUPPLEMENTARY_OFFSET))


def GSS_ERROR(x):
    return (x & ((C.GSS_C_CALLING_ERROR_MASK << C.GSS_C_CALLING_ERROR_OFFSET) |
                 (C.GSS_C_ROUTINE_ERROR_MASK << C.GSS_C_ROUTINE_ERROR_OFFSET)))


def _buf_to_str(buf):
    """Converts a gss_buffer_desc containing a char * string to Python bytes"""
    return ffi.buffer(buf.value, buf.length)[:]
