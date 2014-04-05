/*
 * We should really look for the smallest 32bit integer type,
 * but this will do for prototyping on a 32-bit OS
*/
typedef uint32_t gss_uint32;
typedef uint32_t OM_uint32;

/*
 * Now define the three implementation-dependent types.
 */
typedef ... *gss_ctx_id_t;
typedef ... *gss_cred_id_t;
typedef ... *gss_name_t;

/*
 * Assumes that the X/Open definitions aren't used!
 */
typedef struct gss_OID_desc_struct {
  OM_uint32 length;
  void      *elements;
  ...;
} gss_OID_desc, *gss_OID;

typedef struct gss_OID_set_desc_struct  {
  size_t     count;
  gss_OID    elements;
  ...;
} gss_OID_set_desc, *gss_OID_set;

typedef struct gss_buffer_desc_struct {
  size_t length;
  void *value;
  ...;
} gss_buffer_desc, *gss_buffer_t;

typedef struct gss_channel_bindings_struct {
  OM_uint32 initiator_addrtype;
  gss_buffer_desc initiator_address;
  OM_uint32 acceptor_addrtype;
  gss_buffer_desc acceptor_address;
  gss_buffer_desc application_data;
  ...;
} *gss_channel_bindings_t;

/*
 * For now, define a QOP-type as an OM_uint32
 */
typedef OM_uint32 gss_qop_t;

typedef int gss_cred_usage_t;

/*
 * Flag bits for context-level services.
 */
#define GSS_C_DELEG_FLAG      ...
#define GSS_C_MUTUAL_FLAG     ...
#define GSS_C_REPLAY_FLAG     ...
#define GSS_C_SEQUENCE_FLAG   ...
#define GSS_C_CONF_FLAG       ...
#define GSS_C_INTEG_FLAG      ...
#define GSS_C_ANON_FLAG       ...
#define GSS_C_PROT_READY_FLAG ...
#define GSS_C_TRANS_FLAG      ...

/*
 * Credential usage options
 */
#define GSS_C_BOTH     ...
#define GSS_C_INITIATE ...
#define GSS_C_ACCEPT   ...

/*
 * Status code types for gss_display_status
 */
#define GSS_C_GSS_CODE  ...
#define GSS_C_MECH_CODE ...

/*
 * The constant definitions for channel-bindings address families
 */
#define GSS_C_AF_UNSPEC     ...
#define GSS_C_AF_LOCAL      ...
#define GSS_C_AF_INET       ...
#define GSS_C_AF_IMPLINK    ...
#define GSS_C_AF_PUP        ...
#define GSS_C_AF_CHAOS      ...
#define GSS_C_AF_NS         ...
#define GSS_C_AF_NBS        ...
#define GSS_C_AF_ECMA       ...
#define GSS_C_AF_DATAKIT    ...
#define GSS_C_AF_CCITT      ...
#define GSS_C_AF_SNA        ...
#define GSS_C_AF_DECnet     ...
#define GSS_C_AF_DLI        ...
#define GSS_C_AF_LAT        ...
#define GSS_C_AF_HYLINK     ...
#define GSS_C_AF_APPLETALK  ...
#define GSS_C_AF_BSC        ...
#define GSS_C_AF_DSS        ...
#define GSS_C_AF_OSI        ...
#define GSS_C_AF_X25        ...
#define GSS_C_AF_NULLADDR   ...

/*
 * Various Null values
 */
#define GSS_C_NO_NAME             ...
#define GSS_C_NO_BUFFER           ...
#define GSS_C_NO_OID              ...
#define GSS_C_NO_OID_SET          ...
#define GSS_C_NO_CONTEXT          ...
#define GSS_C_NO_CREDENTIAL       ...
#define GSS_C_NO_CHANNEL_BINDINGS ...
/* #define l        ... */

/*
 * Some alternate names for a couple of the above
 * values.  These are defined for V1 compatibility.
 */
#define GSS_C_NULL_OID     ...
#define GSS_C_NULL_OID_SET ...

/*
 * Define the default Quality of Protection for per-message
 * services.  Note that an implementation that offers multiple
 * levels of QOP may define GSS_C_QOP_DEFAULT to be either zero
 * (as done here) to mean "default protection", or to a specific
 * explicit QOP value.  However, a value of 0 should always be
 * interpreted by a GSS-API implementation as a request for the
 * default protection level.
 */
#define GSS_C_QOP_DEFAULT ...

/*
 * Expiration time of 2^32-1 seconds means infinite lifetime for a
 * credential or security context
 */
#define GSS_C_INDEFINITE  ...

/*
 * The implementation must reserve static storage for a
 * gss_OID_desc object containing the value
 * {10, (void *)"\x2a\x86\x48\x86\xf7\x12"
 * "\x01\x02\x01\x01"},
 * corresponding to an object-identifier value of
 * {iso(1) member-body(2) United States(840) mit(113554)
 * infosys(1) gssapi(2) generic(1) user_name(1)}.  The constant
 * GSS_C_NT_USER_NAME should be initialized to point
 * to that gss_OID_desc.
 */
extern gss_OID const GSS_C_NT_USER_NAME;

/*
 * The implementation must reserve static storage for a
 * gss_OID_desc object containing the value
 * {10, (void *)"\x2a\x86\x48\x86\xf7\x12"
 *              "\x01\x02\x01\x02"},
 * corresponding to an object-identifier value of
 * {iso(1) member-body(2) United States(840) mit(113554)
 * infosys(1) gssapi(2) generic(1) machine_uid_name(2)}.
 * The constant GSS_C_NT_MACHINE_UID_NAME should be
 * initialized to point to that gss_OID_desc.
 */
extern gss_OID const GSS_C_NT_MACHINE_UID_NAME;

/*
 * The implementation must reserve static storage for a
 * gss_OID_desc object containing the value
 * {10, (void *)"\x2a\x86\x48\x86\xf7\x12"
 *              "\x01\x02\x01\x03"},
 * corresponding to an object-identifier value of
 * {iso(1) member-body(2) United States(840) mit(113554)
 * infosys(1) gssapi(2) generic(1) string_uid_name(3)}.
 * The constant GSS_C_NT_STRING_UID_NAME should be
 * initialized to point to that gss_OID_desc.
 */
extern gss_OID const GSS_C_NT_STRING_UID_NAME;

/*
 * The implementation must reserve static storage for a
 * gss_OID_desc object containing the value
 * {6, (void *)"\x2b\x06\x01\x05\x06\x02"},
 * corresponding to an object-identifier value of
 * {iso(1) org(3) dod(6) internet(1) security(5)
 * nametypes(6) gss-host-based-services(2)).  The constant
 * GSS_C_NT_HOSTBASED_SERVICE_X should be initialized to point
 * to that gss_OID_desc.  This is a deprecated OID value, and
 * implementations wishing to support hostbased-service names
 * should instead use the GSS_C_NT_HOSTBASED_SERVICE OID,
 * defined below, to identify such names;
 * GSS_C_NT_HOSTBASED_SERVICE_X should be accepted a synonym
 * for GSS_C_NT_HOSTBASED_SERVICE when presented as an input
 * parameter, but should not be emitted by GSS-API
 * implementations
 */
extern gss_OID const GSS_C_NT_HOSTBASED_SERVICE_X;

/*
 * The implementation must reserve static storage for a
 * gss_OID_desc object containing the value
 * {10, (void *)"\x2a\x86\x48\x86\xf7\x12"
 *              "\x01\x02\x01\x04"}, corresponding to an
 * object-identifier value of {iso(1) member-body(2)
 * Unites States(840) mit(113554) infosys(1) gssapi(2)
 * generic(1) service_name(4)}.  The constant
 * GSS_C_NT_HOSTBASED_SERVICE should be initialized
 * to point to that gss_OID_desc.
 */
extern gss_OID const GSS_C_NT_HOSTBASED_SERVICE;

/*
 * The implementation must reserve static storage for a
 * gss_OID_desc object containing the value
 * {6, (void *)"\x2b\x06\01\x05\x06\x03"},
 * corresponding to an object identifier value of
 * {1(iso), 3(org), 6(dod), 1(internet), 5(security),
 * 6(nametypes), 3(gss-anonymous-name)}.  The constant
 * and GSS_C_NT_ANONYMOUS should be initialized to point
 * to that gss_OID_desc.
 */
extern gss_OID const GSS_C_NT_ANONYMOUS;


/*
 * The implementation must reserve static storage for a
 * gss_OID_desc object containing the value
 * {6, (void *)"\x2b\x06\x01\x05\x06\x04"},
 * corresponding to an object-identifier value of
 * {1(iso), 3(org), 6(dod), 1(internet), 5(security),
 * 6(nametypes), 4(gss-api-exported-name)}.  The constant
 * GSS_C_NT_EXPORT_NAME should be initialized to point
 * to that gss_OID_desc.
 */
extern gss_OID const GSS_C_NT_EXPORT_NAME;

/* Major status codes */

#define GSS_S_COMPLETE ...

/*
 * Some "helper" definitions to make the status code macros obvious.
 */
#define GSS_C_CALLING_ERROR_OFFSET ...
#define GSS_C_ROUTINE_ERROR_OFFSET ...

#define GSS_C_SUPPLEMENTARY_OFFSET ...
#define GSS_C_CALLING_ERROR_MASK   ...
#define GSS_C_ROUTINE_ERROR_MASK   ...
#define GSS_C_SUPPLEMENTARY_MASK   ...

/*
 * The macros that test status codes for error conditions.
 * Note that the GSS_ERROR() macro has changed slightly from
 * the V1 GSS-API so that it now evaluates its argument
 * only once.
 */

/*
 * Now the actual status code definitions
 * python-gssapi note - these were converted to "#define FOO ..."
 * as that's all that CFFI's C parser supports
 */

/*
 * Calling errors:

 */
#define GSS_S_CALL_INACCESSIBLE_READ  ...
#define GSS_S_CALL_INACCESSIBLE_WRITE ...
#define GSS_S_CALL_BAD_STRUCTURE      ...

/*
 * Routine errors:
 */
#define GSS_S_BAD_MECH             ...
#define GSS_S_BAD_NAME             ...
#define GSS_S_BAD_NAMETYPE         ...
#define GSS_S_BAD_BINDINGS         ...
#define GSS_S_BAD_STATUS           ...
#define GSS_S_BAD_SIG              ...
#define GSS_S_BAD_MIC              ...
#define GSS_S_NO_CRED              ...
#define GSS_S_NO_CONTEXT           ...
#define GSS_S_DEFECTIVE_TOKEN      ...
#define GSS_S_DEFECTIVE_CREDENTIAL ...
#define GSS_S_CREDENTIALS_EXPIRED  ...
#define GSS_S_CONTEXT_EXPIRED      ...
#define GSS_S_FAILURE              ...
#define GSS_S_BAD_QOP              ...
#define GSS_S_UNAUTHORIZED         ...
#define GSS_S_UNAVAILABLE          ...
#define GSS_S_DUPLICATE_ELEMENT    ...
#define GSS_S_NAME_NOT_MN          ...

/*
 * Supplementary info bits:
 */
#define GSS_S_CONTINUE_NEEDED      ...
#define GSS_S_DUPLICATE_TOKEN      ...
#define GSS_S_OLD_TOKEN            ...
#define GSS_S_UNSEQ_TOKEN          ...
#define GSS_S_GAP_TOKEN            ...

/*
 * Finally, function prototypes for the GSS-API routines.
 */

OM_uint32 gss_acquire_cred (
  OM_uint32         *minor_status,
  const gss_name_t  desired_name,
  OM_uint32         time_req,
  const gss_OID_set desired_mechs,
  gss_cred_usage_t  cred_usage,
  gss_cred_id_t     *output_cred_handle,
  gss_OID_set       *actual_mechs,
  OM_uint32         *time_rec);

OM_uint32 gss_add_cred (
  OM_uint32           *minor_status,
  const gss_cred_id_t input_cred_handle,
  const gss_name_t    desired_name,
  const gss_OID       desired_mech,
  gss_cred_usage_t    cred_usage,
  OM_uint32           initiator_time_req,
  OM_uint32           acceptor_time_req,
  gss_cred_id_t       *output_cred_handle,
  gss_OID_set         *actual_mechs,
  OM_uint32           *initiator_time_rec,
  OM_uint32           *acceptor_time_rec);

OM_uint32 gss_add_oid_set_member (
  OM_uint32       *minor_status,
  const gss_OID   member_oid,
  gss_OID_set     *oid_set);

OM_uint32 gss_canonicalize_name (
  OM_uint32        *minor_status,
  const gss_name_t input_name,
  const gss_OID    mech_type,
  gss_name_t       *output_name);

OM_uint32 gss_compare_name (
  OM_uint32        *minor_status,
  const gss_name_t name1,
  const gss_name_t name2,
  int              *name_equal);

OM_uint32 gss_context_time (
  OM_uint32          *minor_status,
  const gss_ctx_id_t context_handle,
  OM_uint32          *time_rec);

OM_uint32 gss_create_empty_oid_set (
  OM_uint32    *minor_status,
  gss_OID_set  *oid_set);

OM_uint32 gss_delete_sec_context (
  OM_uint32    *minor_status,
  gss_ctx_id_t *context_handle,
  gss_buffer_t output_token);

OM_uint32 gss_display_name (
  OM_uint32        *minor_status,
  const gss_name_t input_name,
  gss_buffer_t     output_name_buffer,
  gss_OID          *output_name_type);

OM_uint32 gss_display_status (
  OM_uint32      *minor_status,
  OM_uint32      status_value,
  int            status_type,
  const gss_OID  mech_type,
  OM_uint32      *message_context,
  gss_buffer_t   status_string);

OM_uint32 gss_duplicate_name (
  OM_uint32        *minor_status,
  const gss_name_t src_name,
  gss_name_t       *dest_name);

OM_uint32 gss_export_name (
  OM_uint32        *minor_status,
  const gss_name_t input_name,
  gss_buffer_t     exported_name);

OM_uint32 gss_export_sec_context (
  OM_uint32    *minor_status,
  gss_ctx_id_t *context_handle,
  gss_buffer_t interprocess_token);

OM_uint32 gss_get_mic (
  OM_uint32          *minor_status,
  const gss_ctx_id_t context_handle,
  gss_qop_t             qop_req,
  const gss_buffer_t message_buffer,
  gss_buffer_t       msg_token);

OM_uint32 gss_import_name (
  OM_uint32          *minor_status,
  const gss_buffer_t input_name_buffer,
  const gss_OID      input_name_type,
  gss_name_t         *output_name);

OM_uint32 gss_import_sec_context (
  OM_uint32          *minor_status,
  const gss_buffer_t interprocess_token,
  gss_ctx_id_t       *context_handle);

OM_uint32 gss_indicate_mechs (
  OM_uint32   *minor_status,
  gss_OID_set *mech_set);

OM_uint32 gss_init_sec_context (
  OM_uint32                    *minor_status,
  const gss_cred_id_t          initiator_cred_handle,
  gss_ctx_id_t                 *context_handle,
  const gss_name_t             target_name,
  const gss_OID                mech_type,
  OM_uint32                    req_flags,
  OM_uint32                    time_req,
  const gss_channel_bindings_t input_chan_bindings,
  const gss_buffer_t           input_token,
  gss_OID                      *actual_mech_type,
  gss_buffer_t                 output_token,
  OM_uint32                    *ret_flags,
  OM_uint32                    *time_rec );

OM_uint32 gss_inquire_context (
  OM_uint32          *minor_status,
  const gss_ctx_id_t context_handle,
  gss_name_t         *src_name,
  gss_name_t         *targ_name,
  OM_uint32          *lifetime_rec,
  gss_OID            *mech_type,
  OM_uint32          *ctx_flags,
  int                *locally_initiated,
  int                *open );

OM_uint32 gss_inquire_cred (
  OM_uint32           *minor_status,
  const gss_cred_id_t cred_handle,
  gss_name_t          *name,
  OM_uint32           *lifetime,
  gss_cred_usage_t    *cred_usage,
  gss_OID_set         *mechanisms );

OM_uint32 gss_inquire_cred_by_mech (
  OM_uint32           *minor_status,
  const gss_cred_id_t cred_handle,
  const gss_OID       mech_type,
  gss_name_t          *name,
  OM_uint32           *initiator_lifetime,
  OM_uint32           *acceptor_lifetime,
  gss_cred_usage_t    *cred_usage );

OM_uint32 gss_inquire_mechs_for_name (
  OM_uint32        *minor_status,
  const gss_name_t input_name,
  gss_OID_set      *mech_types );

OM_uint32 gss_inquire_names_for_mech (
  OM_uint32     *minor_status,
  const gss_OID mechanism,
  gss_OID_set   *name_types);

OM_uint32 gss_process_context_token (
  OM_uint32          *minor_status,
  const gss_ctx_id_t context_handle,
  const gss_buffer_t token_buffer);

OM_uint32 gss_release_buffer (
  OM_uint32    *minor_status,
  gss_buffer_t buffer);

OM_uint32 gss_release_cred (
  OM_uint32     *minor_status,
  gss_cred_id_t *cred_handle);

OM_uint32 gss_release_name (
  OM_uint32  *minor_status,
  gss_name_t *name);

OM_uint32 gss_release_oid_set (
  OM_uint32   *minor_status,
  gss_OID_set *set);

OM_uint32 gss_test_oid_set_member (
  OM_uint32         *minor_status,
  const gss_OID     member,
  const gss_OID_set set,
  int               *present);

OM_uint32 gss_unwrap (
  OM_uint32          *minor_status,
  const gss_ctx_id_t context_handle,
  const gss_buffer_t input_message_buffer,
  gss_buffer_t       output_message_buffer,
  int                *conf_state,
  gss_qop_t          *qop_state);

OM_uint32 gss_verify_mic (
  OM_uint32          *minor_status,
  const gss_ctx_id_t context_handle,
  const gss_buffer_t message_buffer,
  const gss_buffer_t token_buffer,
  gss_qop_t          *qop_state);

OM_uint32 gss_wrap (
  OM_uint32          *minor_status,
  const gss_ctx_id_t context_handle,
  int               conf_req_flag,
  gss_qop_t          qop_req,
  const gss_buffer_t input_message_buffer,
  int                *conf_state,
  gss_buffer_t       output_message_buffer );

OM_uint32 gss_wrap_size_limit (
  OM_uint32          *minor_status,
  const gss_ctx_id_t context_handle,
  int                conf_req_flag,
  gss_qop_t          qop_req,
  OM_uint32          req_output_size,
  OM_uint32          *max_input_size);
