#!/usr/bin/env python
# Copyright (c) 2012 Cloudera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Thrift utility functions

from thrift.transport.TSocket import TSocket
from thrift.transport.TTransport import TBufferedTransport
import getpass
import sasl

def get_socket(host, port, use_ssl, ca_cert):
    # based on the Impala shell impl
    if use_ssl:
        from thrift.transport.TSSLSocket import TSSLSocket
        if ca_cert is None:
            return TSSLSocket(host, port, validate=False)
        else:
            return TSSLSocket(host, port, validate=True, ca_certs=ca_cert)
    else:
        return TSocket(host, port)


def get_transport(socket, host, kerberos_service_name, auth_mechanism="NOSASL",
                  user=None, password=None, sasl_lib="sasl"):
    """Creates a new Thrift Transport using the specified auth_mechanism.
    Supported auth_mechanisms are:
    - None or NOSASL - returns simple buffered transport (default)
    - PLAIN  - returns a SASL transport with the PLAIN mechanism
    - GSSAPI - returns a SASL transport with the GSSAPI mechanism
    """
    if auth_mechanism:
        auth_mechanism = auth_mechanism.upper()
    if not auth_mechanism or auth_mechanism == "NOSASL":
        return TBufferedTransport(socket)

    # Set defaults for PLAIN SASL / LDAP connections.
    if auth_mechanism in ["LDAP", "PLAIN"]:
        if user is None: user = getpass.getuser()
        if password is None:
            if auth_mechanism == "LDAP":
                password = ''
            else:
                # PLAIN always requires a password for HS2.
                password = "password"

    # Initializes a sasl client
    from impala.thrift_sasl import TSaslClientTransport
    from impala.sasl_compat import build_sasl_factory

    sasl_factory = build_sasl_factory(host, auth_mechanism, user, password,
                                      kerberos_service_name, sasl_lib)

    return TSaslClientTransport(sasl_factory, auth_mechanism, socket)
