python-gssapi
=============

Attempt at an object-oriented interface to GSSAPI for Python.
This project is licensed under the terms of the MIT license (see LICENSE.txt).


Python3 Support
---------------
Python-gssapi is able to run on Python3, but to install it you can't use the setup script right now,
because the ctypesgen module used to build the gssapi_h module is not able to run on Python3 and it
generates just Python2 code.
So to install python-gssapi on Python3 follow these steps:
- Build python-gssapi on Python2.
- Look for the generated gssapi_h module in your/build/directory/lib/gssapi/headers/ and use 2to3 to port it to py3.
- Move the converted gssapi_h module into gssapi/source/folder/headers/.
- Finally move the gssapi source folder to /path/to/your/python/installation/lib/python3.x/site-packages/.
