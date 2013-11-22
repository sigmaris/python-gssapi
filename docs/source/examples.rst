Examples
========

Simple demos
------------

Initiating authentication
^^^^^^^^^^^^^^^^^^^^^^^^^

To authenticate to a service named 'demo' on a server 'example.org', that uses a simple protocol
based on exchanging raw GSSAPI tokens. If using the Kerberos mechanism, you would need to have
obtained initial credentials (a ticket-granting ticket) before running this:

.. code-block:: python

    # Create a Name identifying the target service
    service_name = gssapi.Name('demo@example.org', gssapi.C_NT_HOSTBASED_SERVICE)
    # Create an InitContext targeting the demo service
    ctx = gssapi.InitContext(self.service_name)

    # Loop sending tokens to, and receiving tokens from, the server
    # until the context is established
    in_token = None
    while not ctx.established:
        out_token = ctx.step(in_token)
        if out_token:
            send_to_server(out_token)
        if ctx.established:
            break
        in_token = receive_from_server()
        if not in_token:
            raise Exception("No response from server.")

    print("Successfully authenticated.")

Accepting authentication
^^^^^^^^^^^^^^^^^^^^^^^^

The server-side (acceptor) code for the above example. If using the Kerberos mechanism, you would
need keys for a ``demo/example.org@EXAMPLE.ORG`` principal in the default keytab, or another keytab
pointed to by the ``KRB5_KTNAME`` environment variable, when running this:

.. code-block:: python

    service_name = gssapi.Name('demo@example.org', gssapi.C_NT_HOSTBASED_SERVICE)
    server_cred = gssapi.Credential(service_name, usage=gssapi.C_ACCEPT)
    ctx = gssapi.AcceptContext(server_cred)
    while not ctx.established:
        in_token = receive_from_client()
        out_token = ctx.step(in_token)
        if out_token:
            send_to_client(out_token)

    if not ctx.peer_is_anonymous:
        print("{0} authenticated successfully.".format(ctx.peer_name))
    else:
        print("An anonymous client authenticated successfully.")

Real-World Use
--------------

HTTP Negotiate (SPNEGO) Authentication
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If your underlying GSSAPI implementation supports the
`SPNEGO <http://tools.ietf.org/html/rfc4178>`_ pseudo-mechanism, you can use this to handle the
HTTP `Negotiate <http://tools.ietf.org/html/rfc4559>`_ authentication scheme.

Note that this (simplified) code relies on the context being established in one step. The Kerberos
mechanism can do this, but NTLMSSP for example cannot and in that case the incomplete context must
be kept around for further steps (and associated with the same HTTP client connection) until the
context is fully established. If you are only interoperating with clients using Kerberos (for
example if you are running the server in a Kerberos environment on Linux) it's simpler to assume
only one step is needed.

To use GSSAPI authentication with a web browser (IE with Integrated Windows Auth, or others with
Kerberos single-sign-on), as part of a Python web-application:

.. code-block:: python

    if request.headers['Authorization'].startswith('Negotiate '):
        # The browser is authenticating using GSSAPI, trim off 'Negotiate ' and decode:
        in_token = base64.b64decode(request.headers['Authorization'][10:])

        # Select the SPNEGO mechanism and build a credential
        spnego_mech = gssapi.OID.mech_from_string('1.3.6.1.5.5.2')
        mech_set = gssapi.OIDSet.singleton_set(spnego_mech)
        # Our service name should be HTTP, in uppercase
        service_name = gssapi.Name('HTTP@example.org', gssapi.C_NT_HOSTBASED_SERVICE)
        server_cred = gssapi.Credential(service_name, desired_mechs=mech_set, usage=gssapi.C_ACCEPT)
        ctx = gssapi.AcceptContext(server_cred)

        # Feed the input token to the context, and get an output token in return
        out_token = ctx.step(in_token)
        if out_token:
            response.headers['WWW-Authenticate'] = 'Negotiate ' + base64.b64encode(out_token)
        if ctx.established:
            response.status = 200
        else:
            response.status = 401
            # Here the context establishment needs more steps / requests, as discussed above
    else:
        # Request GSSAPI / SPNEGO authentication
        response.headers['WWW-Authenticate'] = 'Negotiate'
        response.status = 401
