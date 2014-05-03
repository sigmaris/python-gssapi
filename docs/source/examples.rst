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

Integrity protection
^^^^^^^^^^^^^^^^^^^^

Integrity protection is provided by the :meth:`~gssapi.ctx.Context.get_mic` and
:meth:`~gssapi.ctx.Context.verify_mic` methods on :class:`~gssapi.ctx.Context`. The message
integrity code (MIC) is a small token which can be calculated over a message by one peer, then sent
along with that message to the other peer and verified at the other end. If the message (or the
MIC) have been modified in transit, the verification will fail.

In order to use integrity protection, the initiator should include :const:`gssapi.C_INTEG_FLAG` in
the ``req_flags`` parameter to :class:`~gssapi.ctx.InitContext`:

.. code-block:: python

    service_name = gssapi.Name('demo@example.org', gssapi.C_NT_HOSTBASED_SERVICE)
    ctx = gssapi.InitContext(self.service_name, req_flags=(gssapi.C_INTEG_FLAG,))

Then, after the context has been established, both the initiator and acceptor should check that
integrity protection has been negotiated successfully. If it can't be negotiated, the
application will normally want to stop communication. Otherwise, the
:meth:`~gssapi.ctx.Context.get_mic` method can be used to calculate a MIC for messages:

.. code-block:: python

    if not ctx.integrity_negotiated:
        peer_connection.send_msg(b"Error: Integrity protection not negotiated")
        peer_connection.close()
    else:
        message = b"This is an application message"
        mic = ctx.get_mic(message)
        peer_connection.send_msg(message)
        peer_connection.send_msg(mic)

Then, the peer on the other end of the connection can verify that MIC:

.. code-block:: python

    if not ctx.integrity_negotiated:
        peer_connection.send_msg(b"Error: Integrity protection not negotiated")
        peer_connection.close()
    else:
        message = peer_connection.recv_msg()
        mic = peer_connection.recv_msg()
        try:
            ctx.verify_mic(message, mic)
        except gssapi.GSSException:
            # MIC verification failed!
            peer_connection.close()
        else:
            # MIC is OK, continue..
            do_something_with(message)

Confidentiality and Integrity
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Confidentiality and integrity protection together are provided by the
:meth:`~gssapi.ctx.Context.wrap` and :meth:`~gssapi.ctx.Context.unwrap` methods on
:class:`~gssapi.ctx.Context`. :meth:`~gssapi.ctx.Context.wrap` takes a message and returns an
(optionally) encrypted token containing the message and a MIC. The token can then be passed to
:meth:`~gssapi.ctx.Context.unwrap` by the peer, to verify the MIC and obtain the original message.
Note the ``conf_req`` parameter to :meth:`~gssapi.ctx.Context.wrap` - if this is False, no
encryption is performed, but if it is True (the default) the wrapped message is encrypted.

In order to use confidentiality and integrity protection, the initiator should include
:const:`gssapi.C_INTEG_FLAG` and :const:`gssapi.C_CONF_FLAG` in the ``req_flags`` parameter to
:class:`~gssapi.ctx.InitContext`:

.. code-block:: python

    target_name = gssapi.Name('demo@example.org', gssapi.C_NT_HOSTBASED_SERVICE)
    ctx = gssapi.InitContext(self.target_name, req_flags=(gssapi.C_INTEG_FLAG, gssapi.C_CONF_FLAG))

Then, after the context has been established, both the initiator and acceptor should check that
confidentiality and integrity protection have been negotiated successfully. If it can't be
negotiated, the application will normally want to stop communication. Otherwise, the
:meth:`~gssapi.ctx.Context.wrap` method can be used:

.. code-block:: python

    if not ctx.integrity_negotiated or not ctx.confidentiality_negotiated:
        peer_connection.send_msg(b"Error: Confidentiality or Integrity protection not negotiated")
        peer_connection.close()
    else:
        message = b"This is an application message"
        wrapped = ctx.wrap(message)
        peer_connection.send_msg(wrapped)

The peer on the other end of the connection can unwrap the encrypted token and verify the MIC:

.. code-block:: python

    if not ctx.integrity_negotiated or not ctx.confidentiality_negotiated:
        peer_connection.send_msg(b"Error: Confidentiality or Integrity protection not negotiated")
        peer_connection.close()
    else:
        wrapped = peer_connection.recv_msg()
        try:
            message = ctx.unwrap(wrapped)
        except gssapi.GSSException:
            # Unwrapping failed!
            peer_connection.close()
        else:
            do_something_with(message)

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

        # Our service name should be HTTP, in uppercase
        service_name = gssapi.Name('HTTP@example.org', gssapi.C_NT_HOSTBASED_SERVICE)
        server_cred = gssapi.Credential(service_name, usage=gssapi.C_ACCEPT)
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
