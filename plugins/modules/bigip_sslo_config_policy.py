#!/usr/bin/python
# -*- coding: utf-8 -*-
# 
# Copyright: (c) 2021, kevin-dot-g-dot-stewart-at-gmail-dot-com
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Version: 1.0


from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_config_policy
short_description: Manage an SSL Orchestrator security policy
description:
  - Manage an SSL Orchestrator security policy
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the security policy. Configuration auto-prepends "ssloP_" to the policy. The policy name should be less than 14 characters and not contain dashes "-".
    type: str
    required: True
  policyType:
    description:
      - Specifies the type of policy, either "outbound" or "inbound".
    type: str
    required: True
  defaultRule:
    description:
      - Specifies the settings for the default "All Traffic" security policy rule
    suboptions:
      allowBlock:
        description: 
            - Defines the allow/block behavior for the default All Traffic rule.
        type: str
        choices: 
            - allow
            - block
        default: allow
      tlsIntercept:
        description: 
            - Defines the TLS intercept/bypass behavior for the default All Traffic rule.
        type: str
        choices:
            - bypass
            - intercept
        default: bypass
      serviceChain: 
        description: 
            - Defines the service chain to attach to the default All Traffic rule.
        type: str
        default: None
  proxyConnect:
    description:
      - Specifies the proxy-connect settings, as required, to establish an upstream proxy chain egress
    suboptions:
      enabled:
        description: 
            - Defines the type of cipher used, either "string" (for cipher strings), or "group" (an existing cipher group).
        type: bool
        default: False
      pool:
        description: 
            - Defines the upstream explicit proxy pool. This must be a pre-defined pool.
        type: str
        default: None
  serverCertValidation:
    description: 
        - Enables or disables server certificate validation. When enabled, and the SSL configuration also sets blockUntrusted and blockExpired to ignore (False), this will generate a blocking page to the user, using a valid "masked" forged server certificate, for any expired or untrusted remote server certificates.
    type: bool
    default: False
  trafficRules:
    description: 
        - Defines the traffic rules to apply to the security policy, in defined order.
    type: list
    elements: dict
    suboptions:
      name:
        description: 
            - Defines the name of the rule.
        type: str
      matchType:
        description: 
            - Defines the match type when multiple conditions are applied to a single rule.
        type: str
        choices:
            - or
            - and
        default: or
      allowBlock:
        description: 
            - Defines the allow/block behavior for this rule.
        type: str
        choices:
            - allow
            - block
        default: allow
      tlsIntercept:
        description: 
            - Defines the TLS intercept/bypass behavior for this rule.
        type: str
        choices:
            - bypass
            - intercept
        default: bypass
      serviceChain:
        description: 
            - Defines the service chain to attach to this rule.
        type: str
        default: None
      conditions:
        description:
            - Defines the list of conditions within this rule.
        type: list
        elements: dict
        suboptions:
            pinnersRule:
                description: enables the default certificate pinners condition. This condition is used alone in a rule.
            
            categoryLookupAll:
                description: enables the Category Lookup All condition.
                suboptions:
                    values:
                        description: a list of URL categories (ex. "Financial and Data Services")
                        type: str
            
            categoryLookupConnect:
                description: enables the Category Lookup HTTP Connect condition.
                suboptions:
                    values:
                        description: a list of URL categories (ex. "Financial and Data Services")
                        type: str

            categoryLookupSNI:
                description: enables the Category Lookup SNI condition.
                suboptions:
                    values:
                        description: a list of URL categories (ex. "Financial and Data Services")
                        type: str

            clientIpGeoLocation:
                description: enables the Client IP Geolocation condition.
                suboptions:
                    values:
                        description: a list of 'type' and 'value' keys, where type can be 'countryCode', 'countryName', 'continent', or 'state'
                        type: str

            serverIpGeolocation:
                description: enables the Server IP Geolocation condition.
                suboptions:
                    values:
                        description: a list of 'type' and 'value' keys, where type can be 'countryCode', 'countryName', 'continent', or 'state'
                        type: str

            clientIpReputation:
                description: enables the Client IP Reputation condition.
                suboptions:
                    value:
                        description: defines the values type as one of 'good', 'bad', or 'category'. If good or bad entered here, the 'values' key is not needed. If category is entered here, the values key must exist and contain a list of IP reputation categories (ex. "Web Attacks"). Note that IP reputation categories requires BIG-IP 16.0 and higher.
                        type: str
                    values:
                        description: when above 'value' is 'category', this key contains the list of IP reputation categories (ex. "Spam Sources")
                        type: str

            serverIpReputation:
                description: enables the Server IP Reputation condition.
                suboptions:
                    value:
                        description: defines the values type as one of 'good', 'bad', or 'category'. If good or bad entered here, the 'values' key is not needed. If category is entered here, the values key must exist and contain a list of IP reputation categories (ex. "Web Attacks"). Note that IP reputation categories requires BIG-IP 16.0 and higher.
                        type: str
                    values:
                        description: when above 'value' is 'category', this key contains the list of IP reputation categories (ex. "Spam Sources")
                        type: str

            clientIpSubnet:
                description: enables the Client IP Subnet Match condition.
                suboptions:
                    values:
                        description: a list of IP subnets, or datagroup of IP subnets. Note that IP subnet datagroups requires BIG-IP 16.0 and higher.
                        type: str

            serverIpSubnet:
                description: enables the Server IP Subnet Match condition.
                suboptions:
                    values:
                        description: a list of IP subnets, or datagroup of IP subnets. Note that IP subnet datagroups requires BIG-IP 16.0 and higher.
                        type: str

            clientPort:
                description: enables the Client Port Match condition.
                suboptions:
                    type:
                        description: defines the data as a set of static 'values' (including datagroups), or port 'range'. When the type is 'value', the 'values' key must exist and contain a list of ports or datagroups. When type is 'range', the 'fromPort' and 'toPort' keys must exists and contain integer port numbers. Note that port datagroups and port ranges requires BIG-IP 16.0 and higher.
                        type: str
                        choices:
                            - value
                            - range
                        default: value
                    values:
                        description: a list of ports, or datagroup of ports. Note that port datagroups requires BIG-IP 16.0 and higher.
                        type: str
                    fromPort:
                        description: the starting integer port number in a range of ports.
                        type: int
                    toPort:
                        description: the ending integer port number in a range of ports.
                        type: int

            serverPort:
                description: enables the Server Port Match condition.
                suboptions:
                    type:
                        description: defines the data as a set of static 'values' (including datagroups), or port 'range'. When the type is 'value', the 'values' key must exist and contain a list of ports or datagroups. When type is 'range', the 'fromPort' and 'toPort' keys must exists and contain integer port numbers. Note that port datagroups and port ranges requires BIG-IP 16.0 and higher.
                        type: str
                        choices:
                            - value
                            - range
                        default: value
                    values:
                        description: a list of ports, or datagroup of ports. Note that port datagroups requires BIG-IP 16.0 and higher.
                        type: str
                    fromPort:
                        description: the starting integer port number in a range of ports.
                        type: int
                    toPort:
                        description: the ending integer port number in a range of ports.
                        type: int

            sslCheck:
                description: enables the SSL Check condition.
                suboptions:
                    value:
                        description: enables or disables SSL check
                        type: bool
                        choices:
                            - True
                            - False

            L7ProtocolCheckTcp:
                description: enables the TCP L7 Protocol Check condition.
                suboptions:
                    values: 
                        description: a list of TCP protocols, where the options are 'dns', 'ftp', 'ftps', 'http', 'httpConnect', 'https', 'imap', 'imaps', 'smtp', 'smtps', 'pop3', 'pop3s', or 'telnet'
                        type: str

            L7ProtocolCheckUdp:
                description: enables the UDP L7 Protocol Check condition.
                suboptions:
                    values: 
                        description: a list of UDP protocols, where the options are 'dns', or 'quic'.
                        type: str

            urlMatch:
                description: enables the URL Match condition.
                suboptions:
                    values:
                        description: a list of 'type' and 'value' keys. The 'type' key can be one of 'equals', 'substring', 'prefix', 'suffix', or 'glob'. The 'value' is the corresponding string match value.
                        type: str

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
- name: Create SSLO Security Policy (simple)
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
    - name: SSLO security policy
      bigip_sslo_config_policy:
        provider: "{{ provider }}"
        name: "demoPolicy"
        policyType: "outbound"
        
        trafficRules:            
            - name: "Pinners"
              conditions:
                - condition: "pinnersRule"
            
            - name: "Bypass_Finance_Health"
              allowBlock: "allow"
              tlsIntercept: "bypass"
              serviceChain: "all_services_chain"
              conditions:
                - condition: "categoryLookupAll"
                  values:
                    - "/Common/Financial_Data_and_Services"
                    - "/Common/Health_and_Medicine"
      delegate_to: localhost

- name: Create SSLO Security Policy (complex)
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
    - name: SSLO security policy
      bigip_sslo_config_policy:
        provider: "{{ provider }}"
        name: "demoPolicy"
        policyType: "outbound"
        
        defaultRule:
            allowBlock: "allow"
            tlsIntercept: "intercept"
            serviceChain: "all_services_chain_1"
        
        trafficRules: 
            - name: "Pinners"
              conditions:
                - condition: "pinnersRule"
            
            - name: "Bypass_Finance_Health_All"
              allowBlock: "allow"
              tlsIntercept: "bypass"
              serviceChain: "all_services_chain"
              conditions:
                - condition: "categoryLookupAll"
                  values:
                    - "/Common/Financial_Data_and_Services"
                    - "/Common/Health_and_Medicine"

            - name: "Bypass_Finance_Health_SNI"
              matchType: "and"
              allowBlock: "allow"
              tlsIntercept: "bypass"
              serviceChain: "all_services_chain"
              conditions:
                - condition: "sslCheck"
                  value: True
                - condition: "categoryLookupSNI"
                  values:
                    - "/Common/Financial_Data_and_Services"
                    - "/Common/Health_and_Medicine"

            - name: "Bypass by source or destination geolocation"
              matchType: "or"
              allowBlock: "allow"
              tlsIntercept: "bypass"
              serviceChain: "all_services_chain"
              conditions:
                - condition: "clientIpGeolocation"
                  values:
                    - type: "countryCode"
                      value: "US"
                    - type: "countryCode"
                      value: "UK"
                - condition: "serverIpGeolocation"
                  values:
                    - type: "countryCode"
                      value: "/Common/remoteCountryCodes_datagroup"

            - name: "Bypass by source and destination IP subnet"
              matchType: "and"
              allowBlock: "allow"
              tlsIntercept: "bypass"
              serviceChain: "all_services_chain"
              conditions:
                - condition: "clientIpSubnet"
                  values:
                    - "10.1.10.0/24"
                    - "10.1.20.0/24"
                - condition: "serverIpSubnet"
                  values:
                    - "/Common/server-subnet-datagroup"

            - name: "Bypass by source and destination port"
              matchType: "and"
              allowBlock: "allow"
              tlsIntercept: "bypass"
              serviceChain: "all_services_chain"
              conditions:
                - condition: "clientPort"
                  type: "range"
                  fromPort: 1024
                  toPort: 65000
                - condition: "serverPort"
                  type: "value"
                  values:
                    - 80
                    - 443                    

            - name: "Block on client or server IP reputation"
              matchType: "or"
              allowBlock: "block"
              conditions:
                - condition: "clientIpReputation"
                  value: "bad"
                - condition: "serverIpReputation"
                  value: "category"
                  values:
                    - "Spam Sources"
                    - "Web Attacks"
      delegate_to: localhost

- name: Create SSLO Security Policy (with upstream proxy pool)
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
    - name: Create upstream proxy pool
      bigip_pool:
        provider: "{{ provider }}"
        name: upstream-proxy-pool
      delegate_to: localhost

    - name: Add member to upstream proxy pool
      bigip_pool_member:
        provider: "{{ provider }}"
        pool: upstream-proxy-pool
        host: "10.1.20.130"
        port: 8080
      delegate_to: localhost

    - name: SSLO security policy
      bigip_sslo_config_policy:
        provider: "{{ provider }}"
        name: "demo5"
        policyType: "outbound"
        
        trafficRules:
          - name: "pinners"
            conditions:
              - condition: "pinnersRule"
          
          - name: "Bypass_Finance_Health_All"
            matchType: "or"
            allowBlock: "allow"
            tlsIntercept: "bypass"
            serviceChain: "service_chain_1"
            conditions:
              - condition: "categoryLookupAll"
                values:
                  - "/Common/Financial_Data_and_Services"
                  - "/Common/Health_and_Medicine"

        defaultRule:
          allowBlock: "allow"
          tlsIntercept: "intercept"
          serviceChain: "service_chain_2"
        
        proxyConnect: 
          enabled: True
          pool: "/Common/upstream-proxy-pool"
      delegate_to: localhost
'''

RETURN = r'''
name:
  description:
    - Changed name of security policy.
  type: str
  sample: demoPolicy
policyType:
  description:
    - Changed the policy type. Options are 'inbound' or 'outbound'.
  type: str
  sample: outbound
defaultRule:
  description: Changed the default All Traffic security policy rule.
  type: complex
  contains:
    allowBlock:
       description: defines the allow/block behavior of the default All Traffic rule. Options are 'allow' or 'block'.
       type: str
       sample: allow
    tlsIntercept:
       description: defines the TLS intercept/bypass behavior of the default All Traffic rule. Options are 'intercept' or 'bypass'.
       type: str
       sample: bypass
    serviceChain:
       description: defines the service chain to assign to the default All Traffic rule.
       type: str
       sample: all_services_chain
proxyConnect:
  description: Changed the proxy-connect settings for upstream proxy-chain egress.
  type: complex
  contains:
    enables:
       description: enables or disables proxy-connect.
       type: bool
       sample: True
    pool:
       description: defines the upstream proxy pool
       type: str
       sample: /Common/proxy-pool
serverCertValidation:
  description: Changed the server certificate validation behavior, where True generates a blocking page on expired/untrusted remote server certificate.
  type: bool
  sample: True
trafficRules:
  description: Changed the traffic rules
  type: complex
  contains:
    name:
       description: defines the name of the traffic rule.
       type: str
       sample: rule1
    matchType:
       description: defines the match type when multiple conditions are applied to a traffic rule. Options are 'or' or 'and'.
       type: str
       sample: and
    allowBlock:
       description: defines the allow/block behavior of this traffic rule. Options are 'allow' or 'block'.
       type: str
       sample: allow
    tlsIntercept:
       description: defines the TLS intercept behavior of this traffic rule. Options are 'bypass' or 'intercept'
       type: str
       sample: intercept
    serviceChain:
       description: defines the service chain to apply to this traffic rule.
       type: str
       sample: all_services_chain
    conditions:
       description: defines the list of traffic conditions in this rule.
       type: list
       sample: categoryLookupAll

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
from ansible_collections.f5networks.f5_modules.plugins.module_utils.bigip import F5RestClient
from ansible_collections.f5networks.f5_modules.plugins.module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec
)
from ansible_collections.f5networks.f5_modules.plugins.module_utils.icontrol import tmos_version
import json, time, re, hashlib, ipaddress, copy, random

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
max_version = 8.9

json_template = {
    "name":"f5-ssl-orchestrator-gc",
    "inputProperties":[
       {
          "id":"f5-ssl-orchestrator-operation-context",
          "type":"JSON",
          "value":{
             "operationType":"TEMPLATE_OPERATION",
             "deploymentType":"SECURITY_POLICY",
             "deploymentName":"TEMPLATE_NAME",
             "deploymentReference":"",
             "partition":"Common",
             "strictness":False
          }
       },
       {
          "id":"f5-ssl-orchestrator-policy",
          "type":"JSON",
          "value":{
             "existingReference":"",
             "policyName":"",
             "description":"",
             "previousVersion":"7.2",
             "version":"7.2",
             "language":"en",
             "name":"TEMPLATE_NAME",
             "isTemplate":"",
             "rules":[],
             "defaultAction":"",
             "defaultActionOptions":{},
             "templateOptions":{},
             "policyConsumer":{
                "type":"TEMPLATE_POLICY_TYPE",
                "subType":"TEMPLATE_POLICY_TYPE"
             },
             "isDefaultPinnersSet":True,
             "proxyConfigurations":{
                "isProxyChainEnabled":False,
                "pool":{
                   "create":False,
                   "members":[],
                   "name":""
                },
                "username":"",
                "password":""
             },
             "type":"custom",
             "strictness":False,
             "partition":"Common",
             "existingBlockId":""
          }
       },
       {
         "id": "f5-ssl-orchestrator-general-settings",
         "type": "JSON",
         "value": {},
       },      
       {
          "id": "f5-ssl-orchestrator-service-chain",
          "type": "JSON",
          "value": []
       }
    ],
    "dataProperties":[
      
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

json_template_gs = {
   "name":"f5-ssl-orchestrator-gc",
   "inputProperties":[
      {
         "id":"f5-ssl-orchestrator-operation-context",
         "type":"JSON",
         "value":{
            "operationType":"CREATE",
            "deploymentType":"GENERAL_SETTINGS",
            "deploymentName":"ssloGS_Global",
            "deploymentReference":"",
            "partition":"Common",
            "strictness":False
         }
      },
      {
         "id":"f5-ssl-orchestrator-general-settings",
         "type":"JSON",
         "value": {
               "name":"ssloGS_global",
                "previousVersion":"7.2",
                "version":"7.2",
                "configModified":True,
                "ipFamily":"ipv4",
                "dns":{
                    "enableDnsSecurity":False,
                    "enableLocalDnsQueryResolution":False,
                    "enableLocalDnsZones":False,
                    "localDnsZones":[],
                    "localDnsNameservers":[]
                },
                "loggingConfig": {
                  "logLevel": 0,
                  "logPublisher": "none",
                  "statsToRecord": 0
                },
                "egressNetwork":{
                    "gatewayOptions":"useDefault",
                    "outboundGateways":{
                        "referredObj":"",
                        "ipv4OutboundGateways":[{"ip":"","ratio":1}],
                        "ipv6NonPublicGateways":[{"ip":""}],
                        "ipv6OutboundGateways":[{"ip":"","ratio":1}]
                    }
                },
                "partition":"Common",
                "strictness":False
           }
      }
   ],
   "configurationProcessorReference":{
      "link":"https://localhost/mgmt/shared/iapp/processors/f5-iappslx-ssl-orchestrator-gc"
   },
   "state":"BINDING",
   "presentationHtmlReference":{
      "link":"https://localhost/iapps/f5-iappslx-ssl-orchestrator/sgc/sgcIndex.html"
   },
   "operation":"CREATE"
}

json_rule_all_traffic = {
    "name":"All Traffic",
    "action":"allow",
    "mode":"edit",
    "actionOptions":{
       "ssl":"",
       "serviceChain":""
    },
    "isDefault":True
}

json_rule_category_lookup_all = {
    "type":"Category Lookup",
    "options":{
        "category":[],
        "url":[]
    }
}

json_rule_category_lookup_connect = {
    "type":"HTTP Connect Category Lookup",
    "options":{
        "category":[],
        "url":[]
    }
}

json_rule_category_lookup_sni = {
    "type":"SNI Category Lookup",
    "options":{
        "category":[],
        "url":[]
    }
}

json_rule_geolocation = {
    "type":"Client IP Geolocation",
    "options":{
        "geolocations":[],
        "port":[],
        "url":[]
    }
}

json_rule_ip_reputation = {
    "type":"Client IP Reputation",
    "options":{
        "category":[],
        "reputation":"bad",
        "url":[]
    }
}

json_rule_subnet_match = {
    "type":"Client IP Subnet Match",
    "options":{
        "subnet":[],
        "url":[]
    }
}

json_rule_port_match = {
    "type":"Client Port Match",
    "options":{
        "port":[]
    }
}

json_rule_L7_protocol = {
    "type":"L7 Protocol Lookup",
    "options":{
        "protocol":[],
        "url":[]
    }
}

json_rule_ssl_check = {
    "type":"SSL Check",
    "options":{
        "ssl":True,
        "url":[]
    }
}

json_rule_url_match = {
    "type":"URL Branching",
    "options":{
        "url":[]
    }
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
        name = "ssloP_" + name
        return name

    @property
    def policy_type(self):
        policy_type = self._values['policyType']
        if policy_type is None:
            return "outbound"
        return policy_type

    @property
    def traffic_rules(self):
        try:
            traffic_rules = self._values['trafficRules']
            if traffic_rules == None:
                return None
            return traffic_rules
        except:
            return None
    
    @property
    def default_rule_allow_block(self):
        try:
            default_rule_allow_block = self._values['defaultRule']['allowBlock']
            if default_rule_allow_block == None:
                return "allow"
            return default_rule_allow_block
        except:
            return "allow"

    @property
    def default_rule_tls_intercept(self):
        try:
            default_rule_tls_intercept = self._values['defaultRule']['tlsIntercept']
            if default_rule_tls_intercept == None:
                return "bypass"
            return default_rule_tls_intercept
        except:
            return "bypass"

    @property
    def default_rule_service_chain(self):
        try:
            default_rule_service_chain = self._values['defaultRule']['serviceChain']
            if default_rule_service_chain == None:
                return None
            return default_rule_service_chain
        except:
            return None

    @property
    def server_cert_validation(self):
        try:
            server_cert_validation = self._values['serverCertValidation']
            if server_cert_validation == None:
                return False
            return server_cert_validation
        except:
            return False

    @property
    def proxy_connect_enabled(self):
        try:
            proxy_connect_enabled = self._values['proxyConnect']['enabled']
            if proxy_connect_enabled == None:
                return False
            return proxy_connect_enabled
        except:
            return False

    @property
    def proxy_connect_pool(self):
        try:
            proxy_connect_pool = self._values['proxyConnect']['pool']
            if proxy_connect_pool == None:
                return None
            return proxy_connect_pool
        except:
            return None

    @property
    def mode(self):
        mode = self._values['mode']
        return mode


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
    

    def ssloGS_global_exists(self):
        ## use this method to determine if ssloGS_global exists - and if not, create it
        uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        query = "?$filter=name+eq+'ssloGS_global'"
        resp = self.client.api.get(uri + query)

        try:
            ## ssloGS_global exists - do nothing
            response = resp.json()["items"][0]["id"]
            return True
        except:
            ## ssloGS_global does not exist - attempt to create it (only if not in output mode)
            if self.want.mode != "output":
                uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                    self.client.provider['server'],
                    self.client.provider['server_port']
                )

                gs = json_template_gs
                if self.ssloVersion >= 6.0:
                    ## remove ssloGS_global loggingConfig key for SSLO >= 6.0
                    del gs["inputProperties"][1]["value"]["loggingConfig"]

                resp = self.client.api.post(uri, json=gs)
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

            return True
            

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
        self.local_name = re.sub('ssloP_', '', self.want.name)

        ## perform some input validation



        ## process general json settings for all operations
        self.config["inputProperties"][0]["value"]["deploymentName"] = self.want.name
        self.config["inputProperties"][0]["value"]["operationType"] = operation
        self.config["inputProperties"][1]["value"]["name"] = self.want.name
        self.config["inputProperties"][1]["value"]["policyConsumer"]["type"] = self.want.policy_type.capitalize()
        self.config["inputProperties"][1]["value"]["policyConsumer"]["subType"] = self.want.policy_type.capitalize()
        
        ## input validation: serverCertStatusCheck minimally requires SSLO 7.0
        if self.ssloVersion >= 7.0:
            self.config["inputProperties"][1]["value"]["serverCertStatusCheck"] = self.want.server_cert_validation


        ## process proxyConnect settings
        if self.want.proxy_connect_enabled == True:
            self.config["inputProperties"][1]["value"]["proxyConfigurations"]["isProxyChainEnabled"] = True
            
            ## input validation: if enabled, must include a pool
            if self.want.proxy_connect_pool == None:
                raise F5ModuleError("ProxyConnect minimally requires a pool.")
            else:
                self.config["inputProperties"][1]["value"]["proxyConfigurations"]["pool"]["name"] = self.want.proxy_connect_pool


        ## process traffic rules
        if self.want.traffic_rules != None:
            for rule in self.want.traffic_rules:

                ## input validation: must include name and conditions values
                if "name" not in rule:
                    raise F5ModuleError("A policy rule mst minimally contain a name and condition.")
                if "conditions" not in rule:
                    raise F5ModuleError("A policy rule mst minimally contain a name and condition.")

                if rule["conditions"][0]["condition"] == "pinnersRule":
                    ## inject the pinners rule (by itself)
                    ruleset = {}
                    ruleset["name"] = "Pinners_Rule"
                    ruleset["operation"] = "AND"
                    ruleset["mode"] = "edit"
                    ruleset["index"] = random.randint(1000000000000, 9999999999999)
                    ruleset["action"] = "allow"
                    ruleset["actionOptions"] = {}
                    ruleset["actionOptions"]["ssl"] = "bypass"
                    ruleset["actionOptions"]["serviceChain"] = ""
                    ruleset["conditions"] = []
                    
                    cond = copy.deepcopy(json_rule_ssl_check)
                    cond["index"] = random.randint(1000000000000, 9999999999999)
                    ruleset["conditions"].append(cond)

                    cond = copy.deepcopy(json_rule_category_lookup_sni)
                    cond["index"] = random.randint(1000000000000, 9999999999999)
                    cond["options"]["category"].append("Pinners")
                    ruleset["conditions"].append(cond)

                    self.config["inputProperties"][1]["value"]["rules"].append(ruleset)
                
                else:
                    ## start building rule object
                    ruleset = {}
                    ruleset["name"] = rule["name"]
                    
                    if "matchType" not in rule:
                        matchType = "OR"
                    else:
                        matchType = rule["matchType"].upper()
                    
                    ruleset["operation"] = matchType
                    ruleset["mode"] = "edit"
                    ruleset["valid"] = True
                    ruleset["index"] = random.randint(1000000000000, 9999999999999)
                    
                    if "allowBlock" not in rule:
                        allowBlock = "allow"
                    else:
                        allowBlock = rule["allowBlock"].lower()
                    
                    ruleset["action"] = allowBlock
                    
                    if "tlsIntercept" not in rule:
                        tlsIntercept = "bypass"
                    else:
                        tlsIntercept = rule["tlsIntercept"].lower()

                    ruleset["actionOptions"] = {}
                    ruleset["actionOptions"]["ssl"] = tlsIntercept
                    if "serviceChain" not in rule:
                        serviceChain = ""
                    else:
                        serviceChain = rule["serviceChain"]
                    if not serviceChain.startswith("ssloSC_"):
                        serviceChain = "ssloSC_" + serviceChain

                    ruleset["actionOptions"]["serviceChain"] = serviceChain                    
                    ruleset["conditions"] = []

                    ## loop through and process conditions, add to rule object
                    for condition in rule["conditions"]:
        
                        ## =================================
                        ## Category Lookup All
                        ## =================================
                        if condition["condition"] == "categoryLookupAll":
                            ## input validation: policy type requires a "values" key, and contents must be >= 1
                            if "values" not in condition:
                                raise F5ModuleError("The Category Lookup All condition requires a 'values' key and at least 1 category.")
                            try:
                                count = len(condition["values"])
                            except:
                                raise F5ModuleError("The Category Lookup All condition requires a 'values' key and at least 1 category.")
                            
                            cond = copy.deepcopy(json_rule_category_lookup_all)
                            cond["index"] = random.randint(1000000000000, 9999999999999)

                            for value in condition["values"]:
                                value = re.sub('/Common/', '', value)
                                value = re.sub('_', ' ', value)
                                cond["options"]["category"].append(value)
                            ruleset["conditions"].append(cond)


                        ## =================================
                        ## Category Lookup HTTP Connect
                        ## =================================
                        elif condition["condition"] == "categoryLookupConnect":
                            ## input validation: policy type requires a "values" key, and contents must be >= 1
                            if "values" not in condition:
                                raise F5ModuleError("The Category Lookup Connect condition requires a 'values' key and at least 1 category.")
                            try:
                                count = len(condition["values"])
                            except:
                                raise F5ModuleError("The Category Lookup Connect condition requires a 'values' key and at least 1 category.")

                            cond = copy.deepcopy(json_rule_category_lookup_connect)
                            cond["index"] = random.randint(1000000000000, 9999999999999)

                            for value in condition["values"]:
                                value = re.sub('/Common/', '', value)
                                value = re.sub('_', ' ', value)
                                cond["options"]["category"].append(value)
                            ruleset["conditions"].append(cond)


                        ## =================================
                        ## Category Lookup SNI
                        ## =================================
                        elif condition["condition"] == "categoryLookupSNI":
                            ## input validation: policy type requires a "values" key, and contents must be >= 1
                            if "values" not in condition:
                                raise F5ModuleError("The Category Lookup SNI condition requires a 'values' key and at least 1 category.")
                            try:
                                count = len(condition["values"])
                            except:
                                raise F5ModuleError("The Category Lookup SNI condition requires a 'values' key and at least 1 category.")

                            cond = copy.deepcopy(json_rule_category_lookup_sni)
                            cond["index"] = random.randint(1000000000000, 9999999999999)

                            for value in condition["values"]:
                                value = re.sub('/Common/', '', value)
                                value = re.sub('_', ' ', value)
                                cond["options"]["category"].append(value)
                            ruleset["conditions"].append(cond)


                        ## =================================
                        ## Client IP Geolocation
                        ## =================================
                        elif condition["condition"] == "clientIpGeolocation":
                            ## input validation: policy type requires a "values" key, and contents must be >= 1
                            if "values" not in condition:
                                raise F5ModuleError("The Client IP Geolocation condition requires a 'values' key and at least 1 geolocation.")
                            try:
                                count = len(condition["values"])
                            except:
                                raise F5ModuleError("The Client IP Geolocation condition requires a 'values' key and at least 1 geolocation.")

                            cond = copy.deepcopy(json_rule_geolocation)
                            cond["type"] = "Client IP Geolocation"
                            cond["index"] = random.randint(1000000000000, 9999999999999)

                            for value in condition["values"]:
                                ## input validation: values must contain "type" and "value" keys
                                if "type" not in value:
                                    raise F5ModuleError("Client IP Gelocation requires at least one sub-item under the 'values' key that contains a 'type' and 'value' sub-key.")
                                if "value" not in value:
                                    raise F5ModuleError("Client IP Gelocation requires at least one sub-item under the 'values' key that contains a 'type' and 'value' sub-key.")
                                
                                ## input validation: type must be 'countryCode', 'countryName', 'continent', or 'state'
                                if value["type"] not in {"countryCode", "countryName", "continent", "state"}:
                                    raise F5ModuleError("Client IP Geolocation type must be one of 'countryCode', 'countryName', 'continent', 'state', but '" + value["type"] + "' was entered.")

                                if re.match(r'^\/\w+\/[a-zA-Z0-9\-\.\_]+$', value["value"]):
                                    valType = "datagroup"
                                else:
                                    valType = "staticValue"

                                ## input validation: datagroup support introduced in SSL Orchestrator 8.2
                                if self.ssloVersion < 8.2 and valType == "datagroup":
                                    raise F5ModuleError("Data group support for Client IP Gelocation matches requires SSL Orchestrator 8.2 and higher.")                            

                                geolocation = {}
                                geolocation["matchType"] = value["type"]
                                geolocation["value"] = value["value"]
                                geolocation["valueType"] = valType
                                cond["options"]["geolocations"].append(geolocation)
                            ruleset["conditions"].append(cond)


                        ## =================================
                        ## Server IP Geolocation
                        ## =================================
                        elif condition["condition"] == "serverIpGeolocation":
                            ## input validation: policy type requires a "values" key, and contents must be >= 1
                            if "values" not in condition:
                                raise F5ModuleError("The Server IP Geolocation condition requires a 'values' key and at least 1 geolocation.")
                            try:
                                count = len(condition["values"])
                            except:
                                raise F5ModuleError("The Server IP Geolocation condition requires a 'values' key and at least 1 geolocation.")

                            cond = copy.deepcopy(json_rule_geolocation)
                            cond["type"] = "Server IP Geolocation"
                            cond["index"] = random.randint(1000000000000, 9999999999999)

                            for value in condition["values"]:
                                ## input validation: values must contain "type" and "value" keys
                                if "type" not in value:
                                    raise F5ModuleError("Server IP Gelocation requires at least one sub-item under the 'values' key that contains a 'type' and 'value' sub-key.")
                                if "value" not in value:
                                    raise F5ModuleError("Server IP Gelocation requires at least one sub-item under the 'values' key that contains a 'type' and 'value' sub-key.")
                                
                                ## input validation: type must be 'countryCode', 'countryName', 'continent', or 'state'
                                if value["type"] not in {"countryCode", "countryName", "continent", "state"}:
                                    raise F5ModuleError("Server IP Geolocation type must be one of 'countryCode', 'countryName', 'continent', 'state', but '" + value["type"] + "' was entered.")

                                if re.match(r'^\/\w+\/[a-zA-Z0-9\-\.\_]+$', value["value"]):
                                    valType = "datagroup"
                                else:
                                    valType = "staticValue"
                                
                                ## input validation: datagroup support introduced in BIG-IP 16.0
                                if self.ssloVersion < 8.2 and valType == "datagroup":
                                    raise F5ModuleError("Data group support for Server IP Geolocation matches requires SSL Orchestrator 8.2 and higher.")

                                geolocation = {}
                                geolocation["matchType"] = value["type"]
                                geolocation["value"] = value["value"]
                                geolocation["valueType"] = valType
                                cond["options"]["geolocations"].append(geolocation)
                            ruleset["conditions"].append(cond)


                        ## =================================
                        ## Client IP Reputation
                        ## =================================
                        elif condition["condition"] == "clientIpReputation":
                            ## input validation: policy type requires a "values" key, and contents must be >= 1
                            if "values" not in condition:
                                raise F5ModuleError("The Client IP Reputation condition requires a 'values' key and at least 1 reputation.")
                            try:
                                count = len(condition["values"])
                            except:
                                raise F5ModuleError("The Client IP Reputation condition requires a 'values' key and at least 1 reputation.")

                            ## input validation: type must be 'countryCode', 'countryName', 'continent', or 'state'
                            if condition["value"] not in {"good", "bad", "category"}:
                                raise F5ModuleError("Client IP Reputation value must be one of 'good', 'bad', 'category' but '" + value["value"] + "' was entered.")

                            cond = copy.deepcopy(json_rule_ip_reputation)
                            cond["type"] = "Client IP Reputation"
                            cond["index"] = random.randint(1000000000000, 9999999999999)

                            if condition["value"] == "good":
                                cond["options"]["reputation"] = "good"
                                
                            elif condition["value"] == "bad":
                                cond["options"]["reputation"] = "bad"
    
                            elif condition["value"] == "category":
                                cond["options"]["reputation"] = "category"
                                
                                ## input reputation: if value == category, must values key must exist
                                if "values" not in condition:
                                    raise F5ModuleError("Client IP Reputation category value requires a list of categories.")

                                ## input validation: reputation in category requires SSLO 7.0+
                                if self.ssloVersion < 7.0:
                                    raise F5ModuleError("Client IP reputation categories minimally requires SSL Orchestrator 7.0.")

                                for category in condition["values"]:
                                    cond["options"]["category"].append(category)

                            ruleset["conditions"].append(cond)


                        ## =================================
                        ## Server IP Reputation
                        ## =================================
                        elif condition["condition"] == "serverIpReputation":
                            ## input validation: policy type requires a "values" key, and contents must be >= 1
                            if "values" not in condition:
                                raise F5ModuleError("The Server IP Reputation condition requires a 'values' key and at least 1 reputation.")
                            try:
                                count = len(condition["values"])
                            except:
                                raise F5ModuleError("The Server IP Reputation condition requires a 'values' key and at least 1 reputation.")

                            ## input validation: type must be 'countryCode', 'countryName', 'continent', or 'state'
                            if condition["value"] not in {"good", "bad", "category"}:
                                raise F5ModuleError("Server IP Reputation value must be one of 'good', 'bad', 'category' but '" + value["value"] + "' was entered.")

                            cond = copy.deepcopy(json_rule_ip_reputation)
                            cond["type"] = "Server IP Reputation"
                            cond["index"] = random.randint(1000000000000, 9999999999999)

                            if condition["value"] == "good":
                                cond["options"]["reputation"] = "good"
                                
                            elif condition["value"] == "bad":
                                cond["options"]["reputation"] = "bad"
    
                            elif condition["value"] == "category":
                                cond["options"]["reputation"] = "category"
                                
                                ## input reputation: if value == category, must values key must exist
                                if "values" not in condition:
                                    raise F5ModuleError("Server IP Reputation category value requires a list of categories.")

                                ## input validation: reputation in category requires SSLO 7.0+
                                if self.ssloVersion < 7.0:
                                    raise F5ModuleError("IP reputation categories minimally requires SSL Orchestrator 7.0.")

                                for category in condition["values"]:
                                    cond["options"]["category"].append(category)

                            ruleset["conditions"].append(cond)


                        ## =================================
                        ## Client IP Subnet Match
                        ## =================================
                        elif condition["condition"] == "clientIpSubnet":
                            ## input validation: policy type requires a "values" key, and contents must be >= 1
                            if "values" not in condition:
                                raise F5ModuleError("The Client IP Subnet condition requires a 'values' key and at least 1 subnet.")
                            try:
                                count = len(condition["values"])
                            except:
                                raise F5ModuleError("The Client IP Subnet condition requires a 'values' key and at least 1 subnet.")

                            cond = copy.deepcopy(json_rule_subnet_match)
                            cond["type"] = "Client IP Subnet Match"
                            cond["index"] = random.randint(1000000000000, 9999999999999)

                            valType = ""
                            for value in condition["values"]:
                                if re.match(r'^\/\w+\/[a-zA-Z0-9\-\.\_]+$', value):
                                    ## input validation: client IP subnet match can only contain an IP subnet OR data group
                                    if valType == "staticValue":
                                        raise F5ModuleError("IP subnet match must only contain one type: IP subnet or data group.")
                                    valType = "datagroup"
                                
                                else:
                                    ## input validation: client IP subnet match can only contain an IP subnet OR data group
                                    if valType == "datagroup":
                                        raise F5ModuleError("IP subnet match must only contain one type: IP subnet or data group.")
                                    valType = "staticValue"
                                    try:
                                        ipaddress.ip_network(value)
                                    except:
                                        raise F5ModuleError("IP subnet match contains an invalid IP address: " + str(value))

                                ## input validation: client IP subnet datagroups require SSLO 8.2+
                                if self.ssloVersion < 8.2 and valType == "datagroup":
                                    raise F5ModuleError("Data group support for IP subnet matches requires SSL Orchestrator 8.2 and higher.")
                                
                                subnet = {}
                                subnet["subnet"] = value
                                subnet["valueType"] = valType
                                cond["options"]["subnet"].append(subnet)
                            ruleset["conditions"].append(cond)
                                

                        ## =================================
                        ## Server IP Subnet Match
                        ## =================================
                        elif condition["condition"] == "serverIpSubnet":
                            ## input validation: policy type requires a "values" key, and contents must be >= 1
                            if "values" not in condition:
                                raise F5ModuleError("The Server IP Subnet condition requires a 'values' key and at least 1 subnet.")
                            try:
                                count = len(condition["values"])
                            except:
                                raise F5ModuleError("The Server IP Subnet condition requires a 'values' key and at least 1 subnet.")

                            cond = copy.deepcopy(json_rule_subnet_match)
                            cond["type"] = "Server IP Subnet Match"
                            cond["index"] = random.randint(1000000000000, 9999999999999)

                            valType = ""
                            for value in condition["values"]:
                                if re.match(r'^\/\w+\/[a-zA-Z0-9\-\.\_]+$', value):                                
                                    ## input validation: client IP subnet match can only contain an IP subnet OR data group
                                    if valType == "staticValue":
                                        raise F5ModuleError("IP subnet match must only contain one type: IP subnet or data group.")
                                    valType = "datagroup"
                                
                                else:
                                    ## input validation: client IP subnet match can only contain an IP subnet OR data group
                                    if valType == "datagroup":
                                        raise F5ModuleError("IP subnet match must only contain one type: IP subnet or data group.")
                                    valType = "staticValue"
                                    try:
                                        ipaddress.ip_network(value)
                                    except:
                                        raise F5ModuleError("IP subnet match contains an invalid IP address: " + str(value))

                                ## input validation: client IP subnet datagroups require SSLO 8.2+
                                if self.ssloVersion < 8.2 and valType == "datagroup":
                                    raise F5ModuleError("Data group support for IP subnet matches requires SSL Orchestrator 8.2 and higher.")
                                
                                subnet = {}
                                subnet["subnet"] = value
                                subnet["valueType"] = valType
                                cond["options"]["subnet"].append(subnet)
                            ruleset["conditions"].append(cond)


                        ## =================================
                        ## Client Port Match
                        ## =================================
                        elif condition["condition"] == "clientPort":                      
                            ## input validation: rule must include type key
                            if "type" not in condition:
                                raise F5ModuleError("Port match requires a 'type' key of value 'value' or 'range'. Range is supported in SSL Orchestrator 8.2 and higher.")

                            ## input validation: type must either be 'range' or 'value'
                            if condition["type"] not in {"value", "range"}:
                                raise F5ModuleError("Port match requires a 'type' key of value 'value' or 'range'. Range is supported in SSL Orchestrator 8.2 and higher.")

                            ## input validation: type can only be "value" below SSLO 8.2
                            if self.ssloVersion < 8.2 and condition["type"] == "range":
                                raise F5ModuleError("Port match range selection minimally requires SSL Orchestrator 8.2.")

                            ## input validation: if type is 'value', then 'values' key must also exist
                            if condition["type"] == "value" and "values" not in condition:
                                raise F5ModuleError("Port match of type 'value' also requires a 'values' key.")

                            ## input validation: if type is 'range', then 'fromPort' and 'toPort' keys must also exist
                            if condition["type"] == "range" and "fromPort" not in condition:
                                raise F5ModuleError("Port match of type 'range' also requires 'fromPort' and 'toPort' keys.")
                            if condition["type"] == "range" and "toPort" not in condition:
                                raise F5ModuleError("Port match of type 'range' also requires 'fromPort' and 'toPort' keys.")

                            cond = copy.deepcopy(json_rule_port_match)
                            cond["type"] = "Client Port Match"
                            cond["index"] = random.randint(1000000000000, 9999999999999)

                            ## format changes in SSL Orchestrator 8.2 to support datagroups and port range
                            if self.ssloVersion >= 8.2:
                                cond["options"]["url"] = []
                                
                                if condition["type"] == "range":
                                    cond["valueType"] = "range"
                                    range = {}
                                    range["valueType"] = "range"
                                    range["portFrom"] = condition["fromPort"]
                                    range["portTo"] = condition["toPort"]
                                    cond["options"]["port"].append(range)
                                
                                elif condition["type"] == "value":
                                    cond["valueType"] = "valueAndDatagroup"
                                    for port in condition["values"]:
                                        this_port = {}
                                        if re.match(r'^\/\w+\/[a-zA-Z0-9\-\.\_]+$', port):
                                            this_port["port"] = port
                                            this_port["valueType"] = "datagroup"
                                        else:
                                            this_port["port"] = port
                                            this_port["valueType"] = "staticValue"
                                            if port == "80":
                                                this_port["type"] = "HTTP"
                                            elif port == "443":
                                                this_port["type"] = "HTTPS"
                                            elif port == "21":
                                                this_port["type"] = "FTP"
                                            elif port == "25":
                                                this_port["type"] = "SMTP"
                                            else:
                                                this_port["type"] = "Others"
                                        cond["options"]["port"].append(this_port)
                                
                                ruleset["conditions"].append(cond)
                                
                            else:
                                for port in condition["values"]:
                                    ## input validation: must not be a datagroup in BIG-IP below 16.0
                                    if re.match(r'^\/\w+\/[a-zA-Z0-9\-\.\_]+$', port):
                                        raise F5ModuleError("Port match datagroup selection minimally requires BIG-IP 16.0.")

                                    cond["options"]["port"].append(port)

                                ruleset["conditions"].append(cond)


                        ## =================================
                        ## Server Port Match
                        ## =================================
                        elif condition["condition"] == "serverPort":
                            ## input validation: rule must include type key
                            if "type" not in condition:
                                raise F5ModuleError("Port match requires a 'type' key of value 'value' or 'range'. Range is supported in SSL Orchestrator 8.2 and higher.")

                            ## input validation: type must either be 'range' or 'value'
                            if condition["type"] not in {"value", "range"}:
                                raise F5ModuleError("Port match requires a 'type' key of value 'value' or 'range'. Range is supported in SSL Orchestrator 8.2 and higher.")

                            ## input validation: type can only be "value" below SSLO 8.2
                            if self.ssloVersion < 8.2 and condition["type"] == "range":
                                raise F5ModuleError("Port match range selection minimally requires SSL Orchestrator 8.2.")

                            ## input validation: if type is 'value', then 'values' key must also exist
                            if condition["type"] == "value" and "values" not in condition:
                                raise F5ModuleError("Port match of type 'value' also requires a 'values' key.")

                            ## input validation: if type is 'range', then 'fromPort' and 'toPort' keys must also exist
                            if condition["type"] == "range" and "fromPort" not in condition:
                                raise F5ModuleError("Port match of type 'range' also requires 'fromPort' and 'toPort' keys.")
                            if condition["type"] == "range" and "toPort" not in condition:
                                raise F5ModuleError("Port match of type 'range' also requires 'fromPort' and 'toPort' keys.")

                            cond = copy.deepcopy(json_rule_port_match)
                            cond["type"] = "Server Port Match"
                            cond["index"] = random.randint(1000000000000, 9999999999999)

                            ## format changes in SSL Orchestrator 8.2 to support datagroups and port range
                            if self.ssloVersion >= 8.2:
                                cond["options"]["url"] = []
                                
                                if condition["type"] == "range":
                                    cond["valueType"] = "range"
                                    range = {}
                                    range["valueType"] = "range"
                                    range["portFrom"] = condition["fromPort"]
                                    range["portTo"] = condition["toPort"]
                                    cond["options"]["port"].append(range)
                                
                                elif condition["type"] == "value":
                                    cond["valueType"] = "valueAndDatagroup"
                                    for port in condition["values"]:
                                        this_port = {}
                                        if re.match(r'^\/\w+\/[a-zA-Z0-9\-\.\_]+$', port):
                                            this_port["port"] = port
                                            this_port["valueType"] = "datagroup"
                                        else:
                                            this_port["port"] = port
                                            this_port["valueType"] = "staticValue"
                                            if port == "80":
                                                this_port["type"] = "HTTP"
                                            elif port == "443":
                                                this_port["type"] = "HTTPS"
                                            elif port == "21":
                                                this_port["type"] = "FTP"
                                            elif port == "25":
                                                this_port["type"] = "SMTP"
                                            else:
                                                this_port["type"] = "Others"
                                        cond["options"]["port"].append(this_port)
                                
                                ruleset["conditions"].append(cond)
                                
                            else:
                                for port in condition["values"]:
                                    ## input validation: must not be a datagroup in BIG-IP below 16.0
                                    if re.match(r'^\/\w+\/[a-zA-Z0-9\-\.\_]+$', port):
                                        raise F5ModuleError("Port match datagroup selection minimally requires BIG-IP 16.0.")

                                    cond["options"]["port"].append(port)

                                ruleset["conditions"].append(cond)


                        ## =================================
                        ## SSL Check
                        ## =================================
                        elif condition["condition"] == "sslCheck":
                            ## input validation: value must be 'True' or 'False'
                            if condition["value"] not in {True, False}:
                                raise F5ModuleError("SSL Check condition must either be 'True' or 'False'.")

                            cond = copy.deepcopy(json_rule_ssl_check)
                            cond["index"] = random.randint(1000000000000, 9999999999999)
                            cond["options"]["ssl"] = condition["value"]
                            ruleset["conditions"].append(cond)


                        ## =================================
                        ## L7 Protocol Check TCP
                        ## =================================
                        elif condition["condition"] == "L7ProtocolCheckTcp":
                            ## input validation: policy type requires a "values" key, and contents must be >= 1
                            if "values" not in condition:
                                raise F5ModuleError("The L7 Protocol Check (TCP) condition requires a 'values' key and at least 1 protocol.")
                            try:
                                count = len(condition["values"])
                            except:
                                raise F5ModuleError("The L7 Protocol Check (TCP) condition requires a 'values' key and at least 1 protocol.")

                            cond = copy.deepcopy(json_rule_L7_protocol)
                            cond["type"] = "TCP L7 Protocol Lookup"
                            cond["index"] = random.randint(1000000000000, 9999999999999)

                            for proto in condition["values"]:
                                ## input validation: TCP protocol must be one of dns, ftp, ftps, http, httpConnect, https, imap, imaps, pop3, pop3s, smtp, smtps, telnet
                                if proto not in {"dns", "ftp", "ftps", "http", "httpConnect", "https", "imap", "imaps", "pop3", "pop3s", "smtp", "smtps", "telnet"}:
                                    raise F5ModuleError("TCP L7 protocol must be one of: 'dns', 'ftp', 'ftps', 'http', 'httpConnect', 'https', 'imap', 'imaps', 'pop3', 'pop3s', 'smtp', 'smtps', 'telnet', but '" + str(proto) + "' was entered.")

                                cond["options"]["protocol"].append(proto)

                            ruleset["conditions"].append(cond)


                        ## =================================
                        ## L7 Protocol Check UDP
                        ## =================================
                        elif condition["condition"] == "L7ProtocolCheckUdp":
                            # input validation: policy type requires a "values" key, and contents must be >= 1
                            if "values" not in condition:
                                raise F5ModuleError("The L7 Protocol Check (UDP) condition requires a 'values' key and at least 1 protocol.")
                            try:
                                count = len(condition["values"])
                            except:
                                raise F5ModuleError("The L7 Protocol Check (UDP) condition requires a 'values' key and at least 1 protocol.")

                            cond = copy.deepcopy(json_rule_L7_protocol)
                            cond["type"] = "UDP L7 Protocol Lookup"
                            cond["index"] = random.randint(1000000000000, 9999999999999)

                            for proto in condition["values"]:
                                ## input validation: UDP protocol must be one of dns, quic
                                if proto not in {"dns", "quic"}:
                                    raise F5ModuleError("UDP L7 protocol must be one of: 'dns', 'quic', but '" + str(proto) + "' was entered.")

                                cond["options"]["protocol"].append(proto)

                            ruleset["conditions"].append(cond)


                        ## =================================
                        ## URL Match
                        ## =================================
                        elif condition["condition"] == "urlMatch":
                            ## input validation: policy type requires a "values" key, and contents must be >= 1
                            if "values" not in condition:
                                raise F5ModuleError("The URL Match condition requires a 'values' key and at least 1 URL.")
                            try:
                                count = len(condition["values"])
                            except:
                                raise F5ModuleError("The URL Match condition requires a 'values' key and at least 1 URL.")

                            cond = copy.deepcopy(json_rule_url_match)
                            cond["index"] = random.randint(1000000000000, 9999999999999)

                            for value in condition["values"]:
                                ## input validation: "type" key must exist
                                if "type" not in value:
                                    raise F5ModuleError("The URL Match condition requires a 'type' key containing one of these values: 'equals', 'substring', 'prefix', 'suffix', 'glob'.")

                                ## input validation: "value" key must exist
                                if "value" not in value:
                                    raise F5ModuleError("The URL Match condition requires a 'value' key containing a string matching value.")

                                ## input validation: type field must be one of "equals", "substring", "prefix", "suffix", "glob"
                                if value["type"] not in {"equals", "substring", "prefix", "suffix", "glob"}:
                                    raise F5ModuleError("URL match type must be one of: 'equals', 'substring', 'prefix', 'suffix', 'glob', but '" + str(value["type"]) + "' was entered.")

                                url = {}
                                if value["type"] == "equals":
                                    url["matchType"] = "f5keyequalf5"
                                elif value["type"] == "substring":
                                    url["matchType"] = "f5keysubstringf5"
                                elif value["type"] == "prefix":
                                    url["matchType"] = "f5keyprefixf5"
                                elif value["type"] == "suffix":
                                    url["matchType"] = "f5keysuffixf5"
                                elif value["type"] == "glob":
                                    url["matchType"] = "f5keyglobalf5"

                                url["pattern"] = value["value"]
                                cond["options"]["url"].append(url)

                            ruleset["conditions"].append(cond)


                        ## input validation: raise error if an entered condition isn't supported
                        else:
                            raise F5ModuleError("An incorrect policy condition was entered: " + str(condition["condition"]))

                    ## add rule to JSON block
                    self.config["inputProperties"][1]["value"]["rules"].append(ruleset)


        ## process default rule
        ruleset = copy.deepcopy(json_rule_all_traffic)
        ruleset["index"] = random.randint(1000000000000, 9999999999999)
        ruleset["action"] = self.want.default_rule_allow_block
        ruleset["actionOptions"]["ssl"] = self.want.default_rule_tls_intercept
        if self.want.default_rule_service_chain == None:
            ruleset["actionOptions"]["serviceChain"] = ""
        elif self.want.default_rule_service_chain == "":
            ruleset["actionOptions"]["serviceChain"] = ""
        else:
            serviceChain = self.want.default_rule_service_chain
            if not serviceChain.startswith("ssloSC_"):
                serviceChain = "ssloSC_" + serviceChain
            ruleset["actionOptions"]["serviceChain"] = serviceChain
        self.config["inputProperties"][1]["value"]["rules"].append(ruleset)


        ## ssloGS_global - check if it exists, and if not create it first
        self.ssloGS_global_exists()


        ## create operation
        if operation == "CREATE":            
            #### TO DO: update JSON code for CREATE operation
            self.config["name"] = "sslo_obj_SECURITY_POLICY_CREATE_" + self.want.name


        ## modify/delete operations
        elif operation in ["DELETE", "MODIFY"]:
            self.config["name"] = "sslo_obj_SECURITY_POLICY_MODIFY_" + self.want.name

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
                #self.config["inputProperties"][1]["value"]["existingReference"] = id
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
            jsonstr = self.update_json("MODIFY")
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
            policyType=dict(required=True),
            serviceChains=dict(type='list'),
            trafficRules=dict(type='list'),
            defaultRule=dict(
                type='dict',
                options=dict(
                    allowBlock=dict(),
                    tlsIntercept=dict(),
                    serviceChain=dict()
                ),
            ),
            serverCertValidation=dict(
                type='bool',
                default=False
            ),
            proxyConnect=dict(
                type='dict',
                options=dict(
                    enabled=dict(type='bool', default=False),
                    pool=dict(),
                    username=dict(),
                    password=dict()
                ),
            ),
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
          **results,
          print_output=print_output
        )
        module.exit_json(**result)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()