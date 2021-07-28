#!/usr/bin/python
# -*- coding: utf-8 -*-
# 
# Copyright: (c) 2021, kevin-dot-g-dot-stewart-at-gmail-dot-com
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Version: 1.0.1

#### Updates:
#### 1.0.1 - added 9.0 support
#          - changed max version
#          - added clientssl "alpn" proxy support
#          - added clientssl logPublisher support
#          - added serverssl logPublisher support
#          - updated version and previousVersion keys to match target SSLO version


from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_config_ssl
short_description: Manage an SSL Orchestrator SSL configuration
description:
  - Manage an SSL Orchestrator SSL configuration
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the SSL configuration. Configuration auto-prepends "ssloT_" to service.
        Service name should be less than 14 characters and not contain dashes "-".
    type: str
    required: True
  clientSettings:
    description:
      - Specifies the client-side SSL settings
    suboptions:
      cipherType:
        description: 
            - Defines the type of cipher used, either "string" (for cipher strings), or "group" (an existing cipher group).
        type: str
        choices: 
            - string
            - group
        default: string
      cipher:
        description: 
            - Defines the actual cipher string (ex. "DEFAULT"), or existing cipher group (ex. /Common/f5-default) to use.
        type: str
        default: DEFAULT
      enableTLS1_3: 
        description: 
            - Defines whether or not to enable client-side TLSv1.3 support. When enabled, the cipherType must be "group" and cipher must indicate an existing cipher group.
        type: bool
        default: False
      cert:
        description: 
            - Defines the certificate applied in the client side settings. For a forward proxy this is the template certificate and (ex. /Common/default.crt). For a reverse proxy, this is the client-facing server certificate.
        type: str
        default: /Common/default.crt
      key:
        description: 
            - Defines the private key applied in the client side settings. For a forward proxy this is the template key and (ex. /Common/default.key). For a reverse proxy, this is the client-facing server private key.
        type: str
        default: /Common/default.key  
      chain:
        description: 
            - Defines the certificate keychain in the client side settings. 
        type: str
        default: None      
      caCert:
        description: 
            - Defines the CA certificate applied in the client side settings. This is the signing/forging CA certificate used for forward proxy TLS handling. This setting is not applicable in reverse proxy SSL.
        type: str
        default: None
      caKey:
        description: 
            - Defines the CA private key applied in the client side settings. This is the signing/forging CA private key used for forward proxy TLS handling. This setting is not applicable in reverse proxy SSL.
        type: str
        default: None  
      caChain:
        description: 
            - Defines the CA certificate keychain in the client side settings. This would contain any CA subordinated in the trust chain between the signing CA and explicitly-trusted root certificate. If required, it should contain any intermediate CA certificates, up to but not including the self-signed root CA.
        type: str
        default: None
      alpn:
        description: 
            - Requires 9.0+. Enables or disables ALPN HTTP/2 full proxy in an outbound (forward proxy) topology.
        type: bool
        default: False
      logPublisher:
        description: 
            - Requires 9.0+. Defines a specific log publisher to use for client-side SSL-related events.
        type: str
        default: /Common/sys-ssl-publisher
  serverSettings:
    description:
      - Specifies the server-side SSL settings
    suboptions:
      cipherType:
        description: 
            - Defines the type of cipher used, either "string" (for cipher strings), or "group" (an existing cipher group).
        type: str
        choices: 
            - string
            - group
        default: string
      cipher:
        description: 
            - Defines the actual cipher string (ex. "DEFAULT"), or existing cipher group (ex. /Common/f5-default) to use.
        type: str
        default: DEFAULT
      enableTLS1_3: 
        description: 
            - Defines whether or not to enable server-side TLSv1.3 support. When enabled, the cipherType must be "group" and cipher must indicate an existing cipher group.
        type: bool
        default: False
      caBundle:
        description: 
            - Defines the certificate authority bundle used to validate remote server certificates. This setting is most applicable in the forward proxy use case to validate remote (Internat) server certificates.
        type: str
        default: /Common/ca-bundle.crt
      blockExpired:
        description: 
            - Defines the action to take if an expired remote server certificate is encountered. For forward proxy the default is to ignore expired certificates (False). For reverse proxy the default is to drop expired certificates (True).
        type: bool
        default: False
      blockUntrusted:
        description: 
            - Defines the action to take if an untrusted remote server certificate is encountered, based on the defined caBundle. For forward proxy the default is to ignore untrusted certificates (False). For reverse proxy the default is to drop untrusted certificates (True).
        type: bool
        default: False
      ocsp:
        description: 
            - Defines an OCSP configuration to use to perform certificate revocation checking again remote server certificates.
        type: str
        default: None
      crl:
        description: 
            - Defines a CRL configuration to use to perform certificate revocation checking again remote server certificates.
        type: str
        default: None
      logPublisher:
        description: 
            - Requires 9.0+. Defines a specific log publisher to use for server-side SSL-related events.
        type: str
        default: /Common/sys-ssl-publisher
  bypassHandshakeFailure:
    description: 
        - Defines the action to take if a server side TLS handshake failure is detected. A value of False will cause the connection to fail. A value of True will shutdown TLS decryption and allow the connection to proceed un-decrypted.
    type: bool
    default: False
  bypassClientCertFailure:
    description: 
        - Defines the action to take if a server side TLS handshake client certificate request is detected. A value of False will cause the connection to fail. A value of True will shutdown TLS decryption and allow the connection to proceed un-decrypted.
    type: bool
    default: False
  
  mode:
    description:
      - Defines how this task is handled. With the default setting of 'update', the module performs the tasks required to update the target resource. With the 'output' setting, the resulting JSON object blocks are returned without updating the target resource. This option is useful for debugging, and when subordinate objects (ex. SSL, services, service chains, policy, resolver) are created in the same playbook, and their respectice output JSON referenced in a single Topology create task.
    type: str
    choices:
      - update
      - output
    default: update
    
  state:
    description:
        - Specifies the present/absent state required.
    type: str
    choices: 
        - absent
        - present
    default: present

extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Kevin Stewart (kevin-dot-g-dot-stewart-at-gmail-dot-com)
'''

EXAMPLES = r'''
- name: Create SSLO SSL Forward Proxy Settings (simple)
  hosts: localhost
  gather_facts: False
  connection: local

  collections:
    - kevingstewart.f5_sslo_ansible

  vars: 
    provider:
      server: 172.16.1.77
      user: admin
      password: admin
      validate_certs: no
      server_port: 443

  tasks:
    - name: SSLO SSL forward proxy settings
      bigip_sslo_config_ssl:
        provider: "{{ provider }}"
        name: "demo_ssl"
        clientSettings:
          caCert: "/Common/subrsa.f5labs.com"
          caKey: "/Common/subrsa.f5labs.com"
      delegate_to: localhost

- name: Create SSLO SSL Forward Proxy Settings
  hosts: localhost
  gather_facts: False
  connection: local

  collections:
    - kevingstewart.f5_sslo_ansible

  vars: 
    provider:
      server: 172.16.1.77
      user: admin
      password: admin
      validate_certs: no
      server_port: 443

  tasks:
    - name: SSLO SSL settings
      bigip_sslo_config_ssl:
        provider: "{{ provider }}"
        name: "demo_ssl"
        clientSettings:
          cipherType: "group"
          cipher: "/Common/f5-default"
          enableTLS1_3: True
          cert: "/Common/default.crt"
          key: "/Common/default.key"
          caCert: "/Common/subrsa.f5labs.com"
          caKey: "/Common/subrsa.f5labs.com"
          caChain: "/Common/my-ca-chain"
          alpn: True
          logPublisher: "/Common/my-ssl-publisher"
        serverSettings:
          cipherType: "group"
          cipher: "/Common/f5-default"
          enableTLS1_3: True
          caBundle: "/Common/local-ca-bundle.crt"
          blockExpired: False
          blockUntrusted: False
          ocsp: "/Common/my-ocsp"
          crl: "/Common/my-crl"
          logPublisher: "/Common/my-ssl-publisher"
        bypassHandshakeFailure: True
        bypassClientCertFailure: True
      delegate_to: localhost

- name: Create SSLO SSL Reverse Proxy Settings (simple)
  hosts: localhost
  gather_facts: False
  connection: local

  collections:
    - kevingstewart.f5_sslo_ansible

  vars: 
    provider:
      server: 172.16.1.77
      user: admin
      password: admin
      validate_certs: no
      server_port: 443

  tasks:
    - name: SSLO SSL settings
      bigip_sslo_config_ssl:
        provider: "{{ provider }}"
        name: "demo_ssl"
        clientSettings:
          cert: "/Common/myserver.f5labs.com"
          key: "/Common/myserver.f5labs.com"
      delegate_to: localhost

- name: Create SSLO SSL Reverse Proxy Settings
  hosts: localhost
  gather_facts: False
  connection: local

  collections:
    - kevingstewart.f5_sslo_ansible
    
  vars: 
    provider:
      server: 172.16.1.77
      user: admin
      password: admin
      validate_certs: no
      server_port: 443

  tasks:
    - name: SSLO SSL settings
      bigip_sslo_config_ssl:
        provider: "{{ provider }}"
        name: "demo5"
        clientSettings:
          cipherType: "group"
          cipher: "/Common/f5-default"
          enableTLS1_3: True
          cert: "/Common/myserver.f5labs.com"
          key: "/Common/myserver.f5labs.com"
          chain: "/Common/my-ca-chain"
        serverSettings:
          cipherType: "group"
          cipher: "/Common/f5-default"
          enableTLS1_3: True
          caBundle: "/Common/local-ca-bundle.crt"
          blockExpired: False
          blockUntrusted: False
      delegate_to: localhost
'''

RETURN = r'''
name:
  description:
    - Changed name of SSL configuration.
  type: str
  sample: demo_ssl
clientSettings:
  description: client-side SSL settings
  type: complex
  contains:
    cipherType:
       description: defines "string" for cipher string, or "group" for cipher group
       type: str
       sample: string
    cipher:
       description: defines the cipher string or an existing cipher group
       type: str
       sample: DEFAULT or /Common/f5-default
    enableTLS1_3:
       description: enables or disables client-side TLSv1.3
       type: bool
       sample: True
    cert:
       description: defines the client-facing certificate. For forward proxy this is the template certificate. For reverse proxy this is the server certificate.
       type: str
       sample: /Common/default.crt
    key:
       description: defines the client-facing private key. For forward proxy this is the template key. For reverse proxy this is the server private key.
       type: str
       sample: /Common/default.key
    chain:
       description: defines the client-facing CA certificate chain. For reverse proxy this is the server certificate's CA chain.
       type: str
       sample: /Common/local-ca-chain.crt
    caCert:
       description: defines the issuing CA certificate for a forward proxy.
       type: str
       sample: /Common/default.crt
    caKey:
       description: defines the issuing CA private key for a forward proxy.
       type: str
       sample: /Common/default.key
    caChain:
       description: defines the CA certificate chain for the issuing CA in a forward proxy.
       type: str
       sample: /Common/local-ca-chain.crt
    alpn:
       description: requires 9.0+. Enables or disables ALPN HTTP/2 full proxy through a forward proxy topology.
       type: bool
       sample: True
    logPublisher:
       description: requires 9.0+. Defines a specific log publisher for client-side SSL-related events.
       type: str
       sample: /Common/sys-ssl-publisher
serverSettings:
  description: network settings for for-service configuration
  type: complex
  contains:
    cipherType:
       description: defines "string" for cipher string, or "group" for cipher group
       type: str
       sample: string
    cipher:
       description: defines the cipher string or an existing cipher group
       type: str
       sample: DEFAULT or /Common/f5-default
    enableTLS1_3:
       description: enables or disables server-side TLSv1.3
       type: bool
       sample: True 
    caBundle:
       description: defines a CA bundle used to valdate remote server certificates.
       type: str
       sample: /Common/ca-bundle.crt
    blockExpired:
       description: defines the action to take on receiving an expired remote server certificate, True = block, False = ignore.
       type: bool
       sample: True
    blockUntrusted:
       description: defines the action to take on receiving an untrusted remote server certificate, True = block, False = ignore.
       type: bool
       sample: True
    ocsp:
       description: defines aan existing OCSP configuration to validate revocation of remote server certificates.
       type: str
       sample: /Common/my-ocsp
    crl:
       description: defines aan existing CRL configuration to validate revocation of remote server certificates.
       type: str
       sample: /Common/my-crl
    logPublisher:
       description: requires 9.0+. Defines a specific log publisher for server-side SSL-related events.
       type: str
       sample: /Common/sys-ssl-publisher
bypassHandshakeFailure:
  description:
    - Defines the action to take on receiving a TLS handshake alert from a server. True = bypass decryption and allow through, False = block
  type: bool
  sample: True
bypassClientCertFailure:
  description:
    - Defines the action to take on receiving a TLS handshake client certificate request from a server. True = bypass decryption and allow through, False = block
  type: bool
  sample: True

mode:
  description: describes the action to take on the task.
  type: str
  sample: update
  
state:
  description:
    - Changed state.
  type: str
  sample: present
'''

from datetime import datetime
from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ansible_collections.f5networks.f5_modules.plugins.module_utils.bigip import ( 
    F5RestClient
)
from ansible_collections.f5networks.f5_modules.plugins.module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec
)
from ansible_collections.f5networks.f5_modules.plugins.module_utils.icontrol import ( 
    tmos_version
)
from ipaddress import (
    ip_network, ip_interface
)

import json, time, re


global print_output
global json_template
global obj_attempts
global min_version
global max_version

print_output = []

## define object creation attempts count (with 1 seconds pause between each attempt)
obj_attempts = 20

## define minimum supported tmos version - min(SSLO 5.x)
min_version = 5.0

## define maximum supported tmos version - max(SSLO 8.x)
max_version = 9.0

json_template = {
    "name":"f5-ssl-orchestrator-gc",
    "inputProperties":[
       {
          "id":"f5-ssl-orchestrator-operation-context",
          "type":"JSON",
          "value":{
             "operationType":"CREATE",
             "deploymentType":"SSL_SETTINGS",
             "deploymentName":"TEMPLATE_NAME",
             "deploymentReference":"",
             "partition":"Common",
             "strictness":False
          }
       },
       {
          "id":"f5-ssl-orchestrator-tls",
          "type":"JSON",
          "value":{
             "sslSettingsReference":"",
             "sslSettingsName":"",
             "description":"",
             "previousVersion":"7.2",
             "version":"7.2",
             "generalSettings":{
                "isForwardProxy":True,
                "bypassHandshakeAlert":False,
                "bypassClientCertFailure":False
             },
             "clientSettings":{
                "ciphers":{
                   "isCipherString":True,
                   "cipherString":"DEFAULT",
                   "cipherGroup":"/Common/f5-default"
                },
                "certKeyChain":[
                   {
                      "cert":"/Common/default.crt",
                      "key":"/Common/default.key",
                      "chain":"",
                      "passphrase":"",
                      "name":"CERT_KEY_CHAIN_0"
                   }
                ],
                "caCertKeyChain":[],
                "forwardByPass":True,
                "enabledSSLProcessingOptions":[]
             },
             "serverSettings":{
                "ciphers":{
                   "isCipherString":True,
                   "cipherString":"DEFAULT",
                   "cipherGroup":"/Common/f5-default"
                },
                "caBundle":"/Common/ca-bundle.crt",
                "expiredCertificates":False,
                "untrustedCertificates":False,
                "ocsp":"",
                "crl":"",
                "enabledSSLProcessingOptions":[]
             },
             "name":"TEMPLATE_NAME",
             "advancedMode":"off",
             "strictness":False,
             "partition":"Common"
          }
       },
       {
          "id":"f5-ssl-orchestrator-topology",
          "type":"JSON"
       }
    ],
    "configurationProcessorReference":{
       "link":"https://localhost/mgmt/shared/iapp/processors/f5-iappslx-ssl-orchestrator-gc"
    },
    "configProcessorTimeoutSeconds": 120,
    "statsProcessorTimeoutSeconds": 60,
    "configProcessorAffinity": {
        "processorPolicy": "LOCAL",
        "affinityProcessorReference": {
            "link": "https://localhost/mgmt/shared/iapp/affinity/local"
        }
    },
    "state":"BINDING",
    "presentationHtmlReference":{
       "link":"https://localhost/iapps/f5-iappslx-ssl-orchestrator/sgc/sgcIndex.html"
    },
    "operation":"CREATE"
 }

json_ca_cert_template = {
    "cert":"/Common/default.crt",
    "key":"/Common/defaut.key",
    "chain":"",
    "isCa":True,
    "usage":"CA",
    "port":"0",
    "passphrase":"",
    "certKeyChainMismatch":False,
    "isDuplicateVal":False,
    "name":"CA_CERT_KEY_CHAIN_0"
}

json_enable_tls13 = {
    "name":"TLSv1.3",
    "value":"TLSv1.3"
}

class Parameters(AnsibleF5Parameters):
    api_map = {}
    updatables = []
    api_attributes = []
    returnables = []

class ApiParameters(Parameters):
    pass

class ModuleParameters(Parameters):
    global print_output

    @property
    def name(self):
        name = self._values['name']
        name = "ssloT_" + name
        return name

    @property
    def client_cipher_type(self):
        try:
            client_cipher_type = self._values['clientSettings']['cipherType']
            if client_cipher_type is None:
                return "string"
            return client_cipher_type
        except:
            return "string"

    @property
    def client_cipher(self):
        try:
            client_cipher = self._values['clientSettings']['cipher']
            if client_cipher is None:
                return "DEFAULT"
            return client_cipher
        except:
            return "DEFAULT"

    @property
    def client_enable_tls13(self):
        try:
            client_enable_tls13 = self._values['clientSettings']['enableTLS1_3']
            if client_enable_tls13 is None:
                return False
            return client_enable_tls13
        except:
            return False
    
    @property
    def client_cert(self):
        try:
            client_cert = self._values['clientSettings']['cert']
            if client_cert is None:
                return "/Common/default.crt"
            return client_cert
        except:
            return "/Common/default.crt"

    @property
    def client_key(self):
        try:
            client_key = self._values['clientSettings']['key']
            if client_key is None:
                return "/Common/default.key"
            return client_key
        except:
            return "/Common/default.key"

    @property
    def client_chain(self):
        try:
            client_chain = self._values['clientSettings']['chain']
            if client_chain is None:
                return None
            return client_chain
        except: 
            return None

    @property
    def client_ca_cert(self):
        try:
            client_ca_cert = self._values['clientSettings']['caCert']
            if client_ca_cert is None:
                return None
            return client_ca_cert
        except:
            return None

    @property
    def client_ca_key(self):
        try:
            client_ca_key = self._values['clientSettings']['caKey']
            if client_ca_key is None:
                return None
            return client_ca_key
        except:
            return None

    @property
    def client_ca_chain(self):
        try:
            client_ca_chain = self._values['clientSettings']['caChain']
            if client_ca_chain is None:
                return None
            return client_ca_chain
        except:
            return None

    @property
    def server_cipher_type(self):
        try:
            server_cipher_type = self._values['serverSettings']['cipherType']
            if server_cipher_type is None:
                return "string"
            return server_cipher_type
        except:
            return "string"

    @property
    def server_cipher(self):
        try:
            server_cipher = self._values['serverSettings']['cipher']
            if server_cipher is None:
                return "DEFAULT"
            return server_cipher
        except:
            return "DEFAULT"

    @property
    def server_enable_tls13(self):
        try:
            server_enable_tls13 = self._values['serverSettings']['enableTLS1_3']
            if server_enable_tls13 is None:
                return False
            return server_enable_tls13
        except:
            return False
    
    @property
    def server_ca_bundle(self):
        try:
            server_ca_bundle = self._values['serverSettings']['caBundle']
            if server_ca_bundle is None:
                return "/Common/ca-bundle.crt"
            return server_ca_bundle
        except:
            return "/Common/ca-bundle.crt"

    @property
    def server_block_expired(self):
        try:
            server_block_expired = self._values['serverSettings']['blockExpired']
            if server_block_expired is None:
                return None
            return server_block_expired
        except:
            return None

    @property
    def server_block_untrusted(self):
        try:
            server_block_untrusted = self._values['serverSettings']['blockUntrusted']
            if server_block_untrusted is None:
                return None
            return server_block_untrusted
        except:
            return None

    @property
    def server_ocsp(self):
        try:
            server_ocsp = self._values['serverSettings']['ocsp']
            if server_ocsp is None:
                return None
            return server_ocsp
        except:
            return None

    @property
    def server_crl(self):
        try:
            server_crl = self._values['serverSettings']['crl']
            if server_crl is None:
                return None
            return server_crl
        except:
            return None

    @property
    def bypass_handshake_failure(self):
        bypass_handshake_failure = self._values['bypassHandshakeFailure']
        if bypass_handshake_failure is None:
            return False
        return bypass_handshake_failure
    
    @property
    def bypass_clientcert_failure(self):
        bypass_clientcert_failure = self._values['bypassClientCertFailure']
        if bypass_clientcert_failure is None:
            return False
        return bypass_clientcert_failure

    @property
    def mode(self):
        mode = self._values['mode']
        return mode

    @property
    def client_alpn(self):
        try:
            client_alpn = self._values['clientSettings']['alpn']
            if client_alpn is None:
                return False
            return client_alpn
        except:
            return False

    @property
    def client_log_publisher(self):
        try:
            client_log_publisher = self._values['clientSettings']['logPublisher']
            if client_log_publisher is None:
                return "/Common/sys-ssl-publisher"
            return client_log_publisher
        except:
            return "/Common/sys-ssl-publisher"

    @property
    def server_log_publisher(self):
        try:
            server_log_publisher = self._values['clientSettings']['logPublisher']
            if server_log_publisher is None:
                return "/Common/sys-ssl-publisher"
            return server_log_publisher
        except:
            return "/Common/sys-ssl-publisher"


class ModuleManager(object):
    global print_output
    global json_template
    global obj_attempts
    global min_version
    global max_version


    def __init__(self, *args, **kwargs):
        self.module = kwargs.pop('module', None)
        self.client = F5RestClient(**self.module.params)
        self.want = ModuleParameters(params=self.module.params)


    def getSsloVersion(self):
        ## use this method to get the SSLO version (first two digits (x.y))
        uri = "https://{0}:{1}/mgmt/shared/iapp/installed-packages".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        try:
            resp = self.client.api.get(uri).json()
            for x in resp["items"]:
                if x["appName"] == "f5-iappslx-ssl-orchestrator":
                    tmpversion = x["release"].split(".")
                    version = tmpversion[0] + "." + tmpversion[1]
                    return float(version)
                    break
        except:
            raise F5ModuleError("SSL Orchestrator package does not appear to be installed. Aborting.")


    def deleteOperation(self, id):
        ## use this method to delete an operation that failed
        uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            id
        )
        resp = self.client.api.delete(uri)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        else:
            return False


    def update_json(self, operation):
        
        ## use this to method to create and return a modified copy of the JSON template
        self.config = json_template

        ## get base name
        self.local_name = re.sub('ssloT_', '', self.want.name)

        ## perform some input validation
        ## if TLS1.3 is enabled, the isCipherString value must be "false"
        if self.want.client_enable_tls13 == True and self.want.client_cipher_type == "string":
            raise F5ModuleError("Enabling client-side TLS 1.3 also requires a cipher group")
        if self.want.server_enable_tls13 == True and self.want.server_cipher_type == "string":
            raise F5ModuleError("Enabling server-side TLS 1.3 also requires a cipher group")


        ## =================================
        ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
        ## =================================
        self.config["inputProperties"][0]["value"]["version"] = self.ssloVersion
        self.config["inputProperties"][1]["value"]["version"] = self.ssloVersion
        self.config["inputProperties"][1]["value"]["previousVersion"] = self.ssloVersion


        ## general json settings for all operations
        self.config["inputProperties"][0]["value"]["deploymentName"] = self.want.name
        self.config["inputProperties"][0]["value"]["operationType"] = operation
        self.config["inputProperties"][1]["value"]["name"] = self.want.name
        self.config["inputProperties"][1]["value"]["generalSettings"]["bypassHandshakeAlert"] = self.want.bypass_handshake_failure
        self.config["inputProperties"][1]["value"]["generalSettings"]["bypassClientCertFailure"] = self.want.bypass_clientcert_failure
        if self.want.client_enable_tls13 == False:
            self.config["inputProperties"][1]["value"]["clientSettings"]["enabledSSLProcessingOptions"].append(json_enable_tls13)
        if self.want.server_enable_tls13 == False:
            self.config["inputProperties"][1]["value"]["serverSettings"]["enabledSSLProcessingOptions"].append(json_enable_tls13)

        ## generic client settings
        self.config["inputProperties"][1]["value"]["clientSettings"]["certKeyChain"][0]["cert"] = self.want.client_cert
        self.config["inputProperties"][1]["value"]["clientSettings"]["certKeyChain"][0]["key"] = self.want.client_key
        if self.want.client_chain != None:
            self.config["inputProperties"][1]["value"]["clientSettings"]["certKeyChain"][0]["chain"] = self.want.client_chain
        
        if self.want.client_cipher_type == "string":
            self.config["inputProperties"][1]["value"]["clientSettings"]["ciphers"]["isCipherString"] = True
            self.config["inputProperties"][1]["value"]["clientSettings"]["ciphers"]["cipherString"] = self.want.client_cipher
        elif self.want.client_cipher_type == "group":
            self.config["inputProperties"][1]["value"]["clientSettings"]["ciphers"]["isCipherString"] = False
            self.config["inputProperties"][1]["value"]["clientSettings"]["ciphers"]["cipherGroup"] = self.want.client_cipher

        ## generic server settings
        self.config["inputProperties"][1]["value"]["serverSettings"]["caBundle"] = self.want.server_ca_bundle

        if self.want.server_cipher_type == "string":
            self.config["inputProperties"][1]["value"]["serverSettings"]["ciphers"]["isCipherString"] = True
            self.config["inputProperties"][1]["value"]["serverSettings"]["ciphers"]["cipherString"] = self.want.server_cipher
        elif self.want.server_cipher_type == "group":
            self.config["inputProperties"][1]["value"]["serverSettings"]["ciphers"]["isCipherString"] = False
            self.config["inputProperties"][1]["value"]["serverSettings"]["ciphers"]["cipherGroup"] = self.want.server_cipher
        
        if self.want.server_ocsp != None:
            self.config["inputProperties"][1]["value"]["serverSettings"]["ocsp"] = self.want.server_ocsp

        if self.want.server_crl != None:
            self.config["inputProperties"][1]["value"]["serverSettings"]["crl"] = self.want.server_crl

        ## Test if this is a forward or reverse proxy config, based on presence of client_ca_cert value
        if self.want.client_ca_cert != None:
            ## assume this is a forward proxy
            self.config["inputProperties"][1]["value"]["generalSettings"]["isForwardProxy"] = True
            self.proxyType = "forward"

            self.ca_cert_config = json_ca_cert_template
            self.ca_cert_config["cert"] = self.want.client_ca_cert
            self.ca_cert_config["key"] = self.want.client_ca_key
            if self.want.client_ca_chain != None:
                self.ca_cert_config["chain"] = self.want.client_ca_chain
            self.config["inputProperties"][1]["value"]["clientSettings"]["caCertKeyChain"].append(self.ca_cert_config)

            ## client settings
            self.config["inputProperties"][1]["value"]["clientSettings"]["forwardByPass"] = True

            ## server settings - set defaults if none specified
            if self.want.server_block_untrusted == None:
                ## for forward proxy default to False unless specified
                self.config["inputProperties"][1]["value"]["serverSettings"]["untrustedCertificates"] = True
            else:
                self.config["inputProperties"][1]["value"]["serverSettings"]["untrustedCertificates"] = self.want.server_block_untrusted

            if self.want.server_block_expired == None:
                ## for forward proxy default to False unless specified
                self.config["inputProperties"][1]["value"]["serverSettings"]["expiredCertificates"] = True
            else:
                self.config["inputProperties"][1]["value"]["serverSettings"]["expiredCertificates"] = self.want.server_block_expired

        else:
            ## assume this is a reverse proxy
            self.config["inputProperties"][1]["value"]["generalSettings"]["isForwardProxy"] = False
            self.proxyType = "reverse"
            
            ## client settings
            self.config["inputProperties"][1]["value"]["clientSettings"]["forwardByPass"] = False

            ## server settings - set defaults if none specified
            if self.want.server_block_untrusted == None:
                ## for forward proxy default to False unless specified
                self.config["inputProperties"][1]["value"]["serverSettings"]["untrustedCertificates"] = False
            else:
                self.config["inputProperties"][1]["value"]["serverSettings"]["untrustedCertificates"] = self.want.server_block_untrusted

            if self.want.server_block_expired == None:
                ## for forward proxy default to False unless specified
                self.config["inputProperties"][1]["value"]["serverSettings"]["expiredCertificates"] = False
            else:
                self.config["inputProperties"][1]["value"]["serverSettings"]["expiredCertificates"] = self.want.server_block_expired


        ## ================================================
        ## updates: 9.0
        ## alpn - only available in 9.0+ and forward proxy
        if self.ssloVersion >= 9.0 and self.proxyType == "forward":
            self.config["inputProperties"][1]["value"]["clientSettings"]["alpn"] = self.want.client_alpn

        ## logPublisher - only available in 9.0+
        if self.ssloVersion >= 9.0:
            self.config["inputProperties"][1]["value"]["clientSettings"]["logPublisher"] = self.want.client_log_publisher
            self.config["inputProperties"][1]["value"]["serverSettings"]["logPublisher"] = self.want.server_log_publisher
        ## ================================================


        ## create operation
        if operation == "CREATE":            
            #### TO DO: update JSON code for CREATE operation
            self.config["name"] = "sslo_obj_SSL_SETTINGS_CREATE_" + self.want.name


        ## modify/delete operations
        elif operation in ["DELETE", "MODIFY"]:
            self.config["name"] = "sslo_obj_SSL_SETTINGS_MODIFY_" + self.want.name

            ## get object ID and add to deploymentReference and existingBlockId values
            uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                self.client.provider['server'],
                self.client.provider['server_port']
            )
            query = "?$filter=name+eq+'{0}'&$select=id".format(self.want.name)
            resp = self.client.api.get(uri + query)
            
            try:
                response = resp.json()
            except ValueError as ex:
                raise F5ModuleError(str(ex))

            if resp.status not in [200, 201, 202] or 'code' in response and response['code'] not in [200, 201, 202]:
                raise F5ModuleError(resp.content)

            try:
                id = response["items"][0]['id']
                self.config["inputProperties"][0]["value"]["deploymentReference"] = "https://localhost/mgmt/shared/iapp/blocks/" + id
                self.config["inputProperties"][1]["value"]["existingBlockId"] = id
            except:
                raise F5ModuleError("Failure to create/modify - unable to fetch object ID")

            
            if operation in ["MODIFY"]:
                pass
                #### TO DO: update JSON code for MODIFY operation



        return self.config

    def exec_module(self):
        start = datetime.now().isoformat()
        self.ssloVersion = self.getSsloVersion()
        changed = False
        result = dict()
        state = self.want.state

        ## test for correct TMOS version
        if self.ssloVersion < min_version or self.ssloVersion > max_version:
            raise F5ModuleError("Unsupported SSL Orchestrator version, requires a version between min(" + str(min_version) + ") and max(" + str(max_version) + ")")
        

        ## enable/disable testdev to output to JSON only for testing (1) or push config to server (0)
        testdev = 0
        if testdev:
            self.exists()
            jsonstr = self.update_json("CREATE")
            print_output.append("jsonstr = " + str(jsonstr))
        
        else:
            if state == 'present':
                changed = self.update()
            elif state == 'absent':
                changed = self.absent()


        result.update(dict(changed=changed))
        print_output.append('changed=' + str(changed))
        return result


    def update(self):
        if self.module.check_mode:
            return True

        ## use this method to create the objects (if not exists) or modify (if exists)
        if self.exists():
            ## MODIFY: object exists - perform modify - get modified json first
            jsonstr = self.update_json("MODIFY")

            if self.want.mode == "output":
                print_output.append(jsonstr)

            else:
                ## post the object modify json
                uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                    self.client.provider['server'],
                    self.client.provider['server_port']
                )
                resp = self.client.api.post(uri, json=jsonstr)
                try:
                    response = resp.json()
                except ValueError as ex:
                    raise F5ModuleError(str(ex))

                if resp.status not in [200, 201, 202] or 'code' in response and response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(resp.content)

                ## get operation id from last request and loop through check
                self.operationId = str(response["id"])
                attempts = 1
                error = ""
                while attempts <= obj_attempts:
                    uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                        self.client.provider['server'],
                        self.client.provider['server_port']
                    )
                    query = "?$filter=id+eq+'{0}'".format(self.operationId)
                    resp = self.client.api.get(uri + query).json()
                    try:
                        if resp["items"][0]["state"] == "BOUND":
                            return True
                            break
                        elif resp["items"][0]["state"] == "ERROR":
                            error = str(resp["items"][0]["error"])
                            break
                    except:
                        time.sleep(1)
                        attempts += 1
                
                if error != "":
                    ## delete attempted configuration and raise error
                    self.deleteOperation(self.operationId)
                    raise F5ModuleError("Creation error: " + error)
                else:
                    raise F5ModuleError("Object " + self.want.name + " create/modify operation timeout")

        else:
            ## CREATE: object doesn't exist - perform create - get modified json first
            jsonstr = self.update_json("CREATE")
            
            if self.want.mode == "output":
                print_output.append(jsonstr)

            else:
                ## post the object create json
                uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                    self.client.provider['server'],
                    self.client.provider['server_port']
                )
                resp = self.client.api.post(uri, json=jsonstr)
                try:
                    response = resp.json()
                except ValueError as ex:
                    raise F5ModuleError(str(ex))

                if resp.status not in [200, 201, 202] or 'code' in response and response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(resp.content)

                ## get operation id from last request and loop through check
                self.operationId = str(response["id"])
                attempts = 1
                error = ""
                while attempts <= obj_attempts:
                    uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                        self.client.provider['server'],
                        self.client.provider['server_port']
                    )
                    query = "?$filter=id+eq+'{0}'".format(self.operationId)
                    resp = self.client.api.get(uri + query).json()

                    try:
                        if resp["items"][0]["state"] == "BOUND":
                            return True
                            break
                        elif resp["items"][0]["state"] == "ERROR":
                            error = str(resp["items"][0]["error"])
                            break
                    except:
                        time.sleep(1)
                        attempts += 1
                
                if error != "":
                    ## delete attempted configuration and raise error
                    self.deleteOperation(self.operationId)
                    raise F5ModuleError("Creation error: " + self.operationId + ":" + error)
                else:
                    raise F5ModuleError("Object " + self.want.name + " create/modify operation timeout")


    def absent(self):
        ## use this method to delete the objects (if exists)
        if self.exists():
            if self.module.check_mode:
                return True

            ## DELETE: object doesn't exist - perform create - get modified json first
            jsonstr = self.update_json("DELETE")
            
            if self.want.mode == "output":
                print_output.append(jsonstr)

            else:
                ## post the object create json
                uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                    self.client.provider['server'],
                    self.client.provider['server_port']
                )
                resp = self.client.api.post(uri, json=jsonstr)
                try:
                    response = resp.json()
                except ValueError as ex:
                    raise F5ModuleError(str(ex))

                if resp.status not in [200, 201, 202] or 'code' in response and response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(resp.content)

                ## get operation id from last request and loop through check
                self.operationId = str(response["id"])
                attempts = 1
                error = ""
                while attempts <= obj_attempts:
                    uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                        self.client.provider['server'],
                        self.client.provider['server_port']
                    )
                    query = "?$filter=id+eq+'{0}'".format(self.operationId)
                    resp = self.client.api.get(uri + query).json()
                    try:
                        if resp["items"][0]["state"] == "BOUND":
                            return True
                            break
                        elif resp["items"][0]["state"] == "ERROR":
                            error = str(resp["items"][0]["error"])
                            break
                    except:
                        time.sleep(1)
                        attempts += 1
                
                if error != "":
                    ## delete attempted configuration and raise error
                    self.deleteOperation(self.operationId)
                    raise F5ModuleError("Creation error: " + self.operationId + ":" + error)
                else:
                    raise F5ModuleError("Object " + self.want.name + " create/modify operation timeout")

        else:
            ## object doesn't exit - just exit (changed = False)
            return False


    def exists(self):
        ## use this method to see if the objects already exists - queries for the respective application service object
        uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        query = "?$filter=name+eq+'{0}'".format(self.want.name)
        resp = self.client.api.get(uri + query)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            
            foundit = 0
            for i in range(0, len(response["items"])):
                try:
                    if str(response["items"][i]["name"]) == self.want.name:
                        foundit = 1
                        self.existing_config = response["items"][i]
                        break
                except:
                    pass    
            
            if foundit == 1:
                return True
            else:
                return False

        else:
            return False


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            clientSettings=dict(
                required=True,
                type='dict',
                options=dict(
                    cipherType=dict(
                        choices=['string','group'],
                        default='string'
                    ),
                    cipher=dict(default=None),
                    enableTLS1_3=dict(type='bool', default=False),
                    cert=dict(default='/Common/default.crt'),
                    key=dict(default='/Common/default.key'),
                    chain=dict(default=None),
                    caCert=dict(default=None),
                    caKey=dict(default=None),
                    caChain=dict(),
                    alpn=dict(type='bool', default=False),
                    logPublisher=dict(default='/Common/sys-ssl-publisher')
                )
            ),
            serverSettings=dict(
                type='dict',
                options=dict(
                    cipherType=dict(
                        choices=['string','group'],
                        default='string'
                    ),
                    cipher=dict(default=None),
                    enableTLS1_3=dict(type='bool', default=False),
                    caBundle=dict(default='/Common/ca-bundle.crt'),
                    blockExpired=dict(type='bool'),
                    blockUntrusted=dict(type='bool'),
                    ocsp=dict(default=None),
                    crl=dict(default=None),
                    logPublisher=dict(default='/Common/sys-ssl-publisher')
                )
            ),
            bypassHandshakeFailure=dict(type='bool', default=False),
            bypassClientCertFailure=dict(type='bool', default=False),
            state=dict(
                default='present',
                choices=['absent','present']
            ),
            mode=dict(
                choices=["update","output"],
                default="update"
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)

def main():
    ## start here

    ## define global print_output
    global print_output
    print_output = []

    ## define argumentspec
    spec = ArgumentSpec()
    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    ## send to exec_module, result contains output of tasks
    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        result = dict(
          print_output = print_output,
          **results
        )
        module.exit_json(**result)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()