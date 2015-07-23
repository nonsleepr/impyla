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
# SASL compatibility layer


def build_sasl_factory(host, auth_mechanism, username, password, service,
                       sasl_lib="sasl"):
    if sasl_lib == "sasl":

        import sasl

        def sasl_factory():
            sasl_client = sasl.Client()
            sasl_client.setAttr("host", host)
            sasl_client.setAttr("service", service)
            if auth_mechanism in ["PLAIN", "LDAP"]:
                sasl_client.setAttr("username", username)
                sasl_client.setAttr("password", password)
            sasl_client.init()
            return sasl_client

        return sasl_factory

    elif sasl_lib == "puresasl":

        from puresasl.client import SASLClient, SASLError
        from contextlib import contextmanager

        @contextmanager
        def error_catcher(self, Exc = Exception):
            try:
                self.error = None
                yield
            except Exc as e:
                self.error = e.message

                
        class WrappedSASLClient(SASLClient):
            def __init__(self, *args, **kwargs):
                self.error = None
                super(WrappedSASLClient, self).__init__(*args, **kwargs)

            def start(self, mechanism):
                with error_catcher(self, SASLError):
                    if isinstance(mechanism, list):
                        self.choose_mechanism(mechanism)
                    else:
                        self.choose_mechanism([mechanism])
                    return True, self.mechanism, self.process()
                # else
                return False, mechanism, None

            def encode(self, incoming):
                with error_catcher(self):
                    return True, self.unwrap(incoming)
                # else
                return False, None
                
            def decode(self, outgoing):
                with error_catcher(self):
                    return True, self.wrap(outgoing)
                # else
                return False, None
                
            def step(self, challenge):
                with error_catcher(self):
                    return True, self.process(challenge)
                # else
                return False, None

            def getError(self):
                return self.error

        def build_sasl_factory(host, auth_mechanism, username, password, service):
            def sasl_factory():
                return WrappedSASLClient(host, username=username,
                                         password=password, service=service)

            return sasl_factory

    else:
        raise AttributeError("Unsupported SASL library")
