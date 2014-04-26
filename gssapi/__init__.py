from __future__ import absolute_import

from .__about__ import __title__, __author__, __version__, __license__, __copyright__
from . import bindings

C_DELEG_FLAG = bindings.C.GSS_C_DELEG_FLAG
C_MUTUAL_FLAG = bindings.C.GSS_C_MUTUAL_FLAG
C_REPLAY_FLAG = bindings.C.GSS_C_REPLAY_FLAG
C_SEQUENCE_FLAG = bindings.C.GSS_C_SEQUENCE_FLAG
C_CONF_FLAG = bindings.C.GSS_C_CONF_FLAG
C_INTEG_FLAG = bindings.C.GSS_C_INTEG_FLAG
C_ANON_FLAG = bindings.C.GSS_C_ANON_FLAG
C_PROT_READY_FLAG = bindings.C.GSS_C_PROT_READY_FLAG
C_TRANS_FLAG = bindings.C.GSS_C_TRANS_FLAG

C_BOTH = bindings.C.GSS_C_BOTH
C_INITIATE = bindings.C.GSS_C_INITIATE
C_ACCEPT = bindings.C.GSS_C_ACCEPT

C_INDEFINITE = bindings.C.GSS_C_INDEFINITE

C_NT_USER_NAME = bindings.C.GSS_C_NT_USER_NAME
C_NT_MACHINE_UID_NAME = bindings.C.GSS_C_NT_MACHINE_UID_NAME
C_NT_STRING_UID_NAME = bindings.C.GSS_C_NT_STRING_UID_NAME
C_NT_HOSTBASED_SERVICE = bindings.C.GSS_C_NT_HOSTBASED_SERVICE
C_NT_ANONYMOUS = bindings.C.GSS_C_NT_ANONYMOUS
C_NT_EXPORT_NAME = bindings.C.GSS_C_NT_EXPORT_NAME

C_AF_UNSPEC = bindings.C.GSS_C_AF_UNSPEC
C_AF_LOCAL = bindings.C.GSS_C_AF_LOCAL
C_AF_INET = bindings.C.GSS_C_AF_INET
C_AF_IMPLINK = bindings.C.GSS_C_AF_IMPLINK
C_AF_PUP = bindings.C.GSS_C_AF_PUP
C_AF_CHAOS = bindings.C.GSS_C_AF_CHAOS
C_AF_NS = bindings.C.GSS_C_AF_NS
C_AF_NBS = bindings.C.GSS_C_AF_NBS
C_AF_ECMA = bindings.C.GSS_C_AF_ECMA
C_AF_DATAKIT = bindings.C.GSS_C_AF_DATAKIT
C_AF_CCITT = bindings.C.GSS_C_AF_CCITT
C_AF_SNA = bindings.C.GSS_C_AF_SNA
C_AF_DECnet = bindings.C.GSS_C_AF_DECnet
C_AF_DLI = bindings.C.GSS_C_AF_DLI
C_AF_LAT = bindings.C.GSS_C_AF_LAT
C_AF_HYLINK = bindings.C.GSS_C_AF_HYLINK
C_AF_APPLETALK = bindings.C.GSS_C_AF_APPLETALK
C_AF_BSC = bindings.C.GSS_C_AF_BSC
C_AF_DSS = bindings.C.GSS_C_AF_DSS
C_AF_OSI = bindings.C.GSS_C_AF_OSI
C_AF_X25 = bindings.C.GSS_C_AF_X25
try:
    # Only Heimdal defines this, not MIT
    C_AF_INET6 = bindings.C.GSS_C_AF_INET6
except AttributeError:
    pass
C_AF_NULLADDR = bindings.C.GSS_C_AF_NULLADDR

S_COMPLETE = bindings.C.GSS_S_COMPLETE
S_CALL_INACCESSIBLE_READ = bindings.C.GSS_S_CALL_INACCESSIBLE_READ
S_CALL_INACCESSIBLE_WRITE = bindings.C.GSS_S_CALL_INACCESSIBLE_WRITE
S_CALL_BAD_STRUCTURE = bindings.C.GSS_S_CALL_BAD_STRUCTURE
S_BAD_MECH = bindings.C.GSS_S_BAD_MECH
S_BAD_NAME = bindings.C.GSS_S_BAD_NAME
S_BAD_NAMETYPE = bindings.C.GSS_S_BAD_NAMETYPE
S_BAD_BINDINGS = bindings.C.GSS_S_BAD_BINDINGS
S_BAD_STATUS = bindings.C.GSS_S_BAD_STATUS
S_BAD_SIG = bindings.C.GSS_S_BAD_SIG
S_NO_CRED = bindings.C.GSS_S_NO_CRED
S_NO_CONTEXT = bindings.C.GSS_S_NO_CONTEXT
S_DEFECTIVE_TOKEN = bindings.C.GSS_S_DEFECTIVE_TOKEN
S_DEFECTIVE_CREDENTIAL = bindings.C.GSS_S_DEFECTIVE_CREDENTIAL
S_CREDENTIALS_EXPIRED = bindings.C.GSS_S_CREDENTIALS_EXPIRED
S_CONTEXT_EXPIRED = bindings.C.GSS_S_CONTEXT_EXPIRED
S_FAILURE = bindings.C.GSS_S_FAILURE
S_BAD_QOP = bindings.C.GSS_S_BAD_QOP
S_UNAUTHORIZED = bindings.C.GSS_S_UNAUTHORIZED
S_UNAVAILABLE = bindings.C.GSS_S_UNAVAILABLE
S_DUPLICATE_ELEMENT = bindings.C.GSS_S_DUPLICATE_ELEMENT
S_NAME_NOT_MN = bindings.C.GSS_S_NAME_NOT_MN
S_CONTINUE_NEEDED = bindings.C.GSS_S_CONTINUE_NEEDED
S_DUPLICATE_TOKEN = bindings.C.GSS_S_DUPLICATE_TOKEN
S_OLD_TOKEN = bindings.C.GSS_S_OLD_TOKEN
S_UNSEQ_TOKEN = bindings.C.GSS_S_UNSEQ_TOKEN
S_GAP_TOKEN = bindings.C.GSS_S_GAP_TOKEN
S_CRED_UNAVAIL = bindings.C.GSS_S_CRED_UNAVAIL

# this flag doesn't exist in MIT Kerberos 5 before Release 1.7
try:
    C_DELEG_POLICY_FLAG = bindings.C.GSS_C_DELEG_POLICY_FLAG
except AttributeError:
    pass
from .creds import Credential
from .ctx import Context, InitContext, AcceptContext
from .error import (
    GSSException, GSSCException, GSSMechException, GSSCallingError, GSSRoutineError,
    InaccessibleRead, InaccessibleWrite, BadStructure, BadMechanism, BadName, BadNameType,
    BadBindings, BadStatus, BadSignature, NoCredential, NoContext, DefectiveToken,
    DefectiveCredential, CredentialsExpired, ContextExpired, Failure, BadQOP, Unauthorized,
    Unavailable, DuplicateElement, NameNotMechName
)
from .names import Name, MechName
from .oids import OID, OIDSet, MutableOIDSet, get_all_mechs
from .chanbind import ChannelBindings, IPv4ChannelBindings
try:
    from .chanbind import IPv6ChannelBindings
except ImportError:
    pass
