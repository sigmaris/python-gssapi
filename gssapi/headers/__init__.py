from __future__ import absolute_import

import os.path

from cffi import FFI

ffi = FFI()
with open(os.path.join(os.path.dirname(__file__), 'cffi_gssapi.h'), 'r') as hdr:
    ffi.cdef(hdr.read())
C = ffi.verify(
    '#include <GSS/GSS.h>',
    extra_compile_args=['-framework', 'GSS'],
    extra_link_args=['-framework', 'GSS']
)


def GSS_CALLING_ERROR(x):
    return (x & (C.GSS_C_CALLING_ERROR_MASK << C.GSS_C_CALLING_ERROR_OFFSET))


def GSS_ROUTINE_ERROR(x):
    return (x & (C.GSS_C_ROUTINE_ERROR_MASK << C.GSS_C_ROUTINE_ERROR_OFFSET))


def GSS_SUPPLEMENTARY_INFO(x):
    return (x & (C.GSS_C_SUPPLEMENTARY_MASK << C.GSS_C_SUPPLEMENTARY_OFFSET))


def GSS_ERROR(x):
    return (x & ((C.GSS_C_CALLING_ERROR_MASK << C.GSS_C_CALLING_ERROR_OFFSET) |
                 (C.GSS_C_ROUTINE_ERROR_MASK << C.GSS_C_ROUTINE_ERROR_OFFSET)))
