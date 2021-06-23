#!/usr/bin/python
# -*- coding: utf-8 -*-
# 
# Copyright: (c) 2021, kevin-dot-g-dot-stewart-at-gmail-dot-com
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Version: 1.0

#### To Do:
#### Update JSON
#### Update docs
#### Test what happens when interface, tag or subnet in use

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_http_service
short_description: Manage an SSL Orchestrator http security device
description:
  - Manage an SSL Orchestrator http security device
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the HTTP security service. Configuration auto-prepends "ssloS_" to service.
        Service name should be less than 14 characters and not contain dashes "-".
    type: str
    required: True
  devicesTo:
    description:
      - Specifies the set of network settings for traffic going to the service from BIG-IP
    suboptions:
      vlan:
        description: 
            - Defines an existing VLAN to attach on the to-service side. The vlan and interface/tag options are mutually exclusive.
        type: str
      interface:
        description: 
            - Defines the interface on the to-service side. The vlan and interface/tag options are mutually exclusive.
        type: str
      tag: 
        description: 
            - Defines the VLAN tag on the to-service side (as required).
        type: int
        default: None
      selfIp:
        description: 
            - Defines the to-service self-IP.
        type: str
        required: True
      netmask:
        description: 
            - Defines the to-service self-IP netmask.
        type: str
        required: True
  devicesFrom:
    description:
      - Specifies the set of network settings for traffic going to the BIG-IP from the service
    suboptions:
      vlan:
        description: 
            - Defines an existing VLAN to attach on the from-service side. The vlan and interface/tag options are mutually exclusive.
        type: str
      interface:
        description: 
            - Defines the interface on the from-service side. The vlan and interface/tag options are mutually exclusive.
        type: str
      tag: 
        description: 
            - Defines the VLAN tag on the from-service side (as required).
        type: int
        default: None
      selfIp:
        description: 
            - Defines the from-service self-IP.
        type: str
        required: True
      netmask:
        description: 
            - Defines the from-service self-IP netmask.
        type: str
        required: True
  devices:
    description: 
        - Defines a list of service IPs and ports. Use IP only for transparent proxy, IP and port for explicit proxy.
    type: list
    elements: str
    required: True
  proxyType:
    description:
        - Specifies the HTTP service as explicit or transparent
    type: str
    choices:
        - explicit
        - transparent
    default: explicit
  authOffload:
    description:
        - Enables or disables authentication offload to the HTTP service
    type: bool
    choices:
        - True
        - False
    default: False
  ipFamily:
    description:
        - Specifies the IP family used for attached ICAP security devices. 
    type: str
    choices:
        - ipv4
        - ipv6
    default: ipv4
  monitor:
    description:
        - Specifies the monitor attached the ICAP security device pool. The monitor must already exist on the BIG-IP.
    type: str
    default: /Common/gateway_icmp
  serviceDownAction:
    description:
        - Defines how traffic is handled if all service members are down.
    type: str
    choices:
        - ignore
        - reset
        - drop
    default: ignore
  portRemap:
    description:
        - Defines the port to remap decrypted traffic to.
    type: int
    default: None
  snat:
    description:
        - Defines if and how a SNAT configuration is deployed.
        - none = no snat configuration.
        - automap = snat automap is configured.
        - snatpool = the "snatpool" key is also defined and points to an existing snatpool.
        - snatlist = the "snatlist" key is also defines and lists the SNAT IP members.
    type: str
    choices:
        - none
        - automap
        - snatpool
        - snatlist
    default: None
  snatlist:
    description:
        - Defines an existing SNAT pool, and is required if the snat key == "snatpool".
    type: str
    default: None
  snatlist:
    description:
        - Defines a list of IPs to use in a SNAT pool configuration, and is required if the snat key == "snatlist".
    type: list
    default: None
  rules:
    description:
        - Defines a list of iRules to attach to the service.
    type: list
    default: None

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
- name: Create SSLO service(s) - SSLO-created VLANs
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
    - name: SSLO HTTP service
      bigip_sslo_service_http:
        provider: "{{ provider }}"
        name: "proxy1a"
        devicesTo:
            interface: "1.3"
            tag: 40
            selfIp: "198.19.96.7"
            netmask: "255.255.255.128"
        devicesFrom:
            interface: "1.3"
            tag: 50
            selfIp: "198.19.96.245"
            netmask: "255.255.255.128"
        devices: 
          - ip: "198.19.96.96"
            port: 3128
          - ip: "198.19.96.96"
            port: 3128
        snat: snatlist
        snatlist:
          - 198.19.96.10
          - 198.19.96.11
          - 198.19.96.12
      delegate_to: localhost

- name: Create SSLO service(s) - create and reference external VLANs
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
    - name: Create a monitor
      bigip_monitor_gateway_icmp:
        provider: "{{ provider }}"
        name: gw2
        state: present
      delegate_to: localhost

    - name: create HTTP service inbound VLAN
      bigip_vlan:
        provider: "{{ provider }}"
        name: HTTPservice_vlan_in
        tagged_interface: 1.5
        tag: 600
      delegate_to: localhost

    - name: create HTTP service outbound VLAN
      bigip_vlan:
        provider: "{{ provider }}"
        name: HTTPservice_vlan_out
        tagged_interface: 1.5
        tag: 601
      delegate_to: localhost

    - name: SSLO HTTP service
      bigip_sslo_service_http:
        provider: "{{ provider }}"
        name: "proxy1a"
        devicesTo:
            vlan: "/Common/HTTPservice_vlan_in"
            selfIp: "198.19.96.7"
            netmask: "255.255.255.128"
        devicesFrom:
            vlan: "/Common/HTTPservice_vlan_out"
            selfIp: "198.19.96.245"
            netmask: "255.255.255.128"
        devices: 
          - ip: "198.19.96.30"
          - ip: "198.19.96.31"
        monitor: "/Common/gw2"
      delegate_to: localhost

- name: Create SSLO service(s) - additional options
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
    - name: SSLO HTTP service
      bigip_sslo_service_http:
        provider: "{{ provider }}"
        name: "proxy1a"
        devicesTo:
            vlan: "/Common/proxy1a-in-vlan"
            selfIp: "198.19.96.7"
            netmask: "255.255.255.128"
        devicesFrom:
            interface: "1.3"
            tag: 50
            selfIp: "198.19.96.245"
            netmask: "255.255.255.128"
        devices: 
          - ip: "198.19.96.30"
            port: 3128
          - ip: "198.19.96.31"
            port: 3128
        snat: automap
      delegate_to: localhost

- name: Create SSLO service(s) - additional options
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
    - name: Create a monitor
      bigip_monitor_gateway_icmp:
        provider: "{{ provider }}"
        name: gw2
        state: present
      delegate_to: localhost

    - name: SSLO HTTP service
      bigip_sslo_service_http:
        provider: "{{ provider }}"
        name: "proxy1a"
        devicesTo:
            vlan: "/Common/proxy1a-in-vlan"
            selfIp: "198.19.96.7"
            netmask: "255.255.255.128"
        devicesFrom:
            interface: "1.3"
            tag: 50
            selfIp: "198.19.96.245"
            netmask: "255.255.255.128"
        devices: 
          - ip: "198.19.96.30"
          - ip: "198.19.96.31"
        proxyType: "transparent"
        authOffload: true
        ipFamily: "ipv4"
        monitor: "/Common/gw2"
        serviceDownAction: "reset"
        portRemap: 8080
        snat: snatpool
        snatpool: "/Common/proxy1a-snatpool"
        rules:
          - "/Common/proxy1a-rule-1"
          - "/Common/proxy1a-rule-2"
      delegate_to: localhost
'''

RETURN = r'''
name:
  description:
    - Changed name of HTTP inline service.
  type: str
  sample: proxy1a
devicesTo:
  description: network settings for to-service configuration
  type: complex
  contains:
    vlan:
       description: defines an existing to-service VLAN
       type: str
       sample: /Common/proxy1a-to-vlan
    interface:
       description: defines a to-service interface
       type: str
       sample: 1.3
    tag:
       description: defines a to-service VLAN tag
       type: int
       sample: 40
    selfIp:
       description: defines the to-service VLAN self-IP
       type: str
       sample: 198.19.64.7
    netmask:
       description: defines the to-service VLAN self-IP netmask
       type: str
       sample: 255.255.255.128
devicesFrom:
  description: network settings for for-service configuration
  type: complex
  contains:
    vlan:
       description: defines an existing for-service VLAN
       type: str
       sample: /Common/proxy1a-from-vlan
    interface:
       description: defines a from-service interface
       type: str
       sample: 1.3
    tag:
       description: defines a from-service VLAN tag
       type: int
       sample: 50
    selfIp:
       description: defines the from-service VLAN self-IP
       type: str
       sample: 198.19.64.245
    netmask:
       description: defines the from-service VLAN self-IP netmask
       type: str
       sample: 255.255.255.128
devices:
  description:
    - Changed list of IP:port listeners for HTTP inlines services. Use IP only for transparent proxy, IP and port for explicit proxy.
  type: list
  sample: - ip: "198.19.64.30",
            port: 3128
          - ip: "198.19.64.31",
            port: 3128
state:
  description:
    - Changed state.
  type: str
  sample: present
proxyType:
  description:
    - Changed proxyType value of HTTP service, explicit or transparent.
  type: str
  sample: "transparent"
authOffload:
  description:
    - Changed authOffload value of HTTP service, to enable or disable authentication offload.
  type: bool
  sample: true
ipFamily:
  description:
    - Changed ipFamily value of HTTP services.
  type: str
  sample: ipv4
monitor:
  description:
    - Changed pool monitor.
  type: str
  sample: /Common/gateway_icmp
serviceDownAction:
  description:
    - Changed service down action.
  type: str
  sample: ignore
portRemap:
  description:
    - Changed port remap settings.
  type: int
  sample: 8080
snat:
  description:
    - Changed snat configuration.
  type: str
  sample: none
  sample: automap
  sample: snatpool
  sample: snatlist
snatpool:
  description:
    - Changed existing SNAT pool.
  type: str
  sample: /Common/test-snat-pool
snatlist:
  description:
    - Changed SNAT pool members.
  type: str
  sample: - 198.19.64.10
          - 198.19.64.11
rules:
  description:
    - Changed list of iRules attached to the service.
  type: str
  Sample: /Common/test-rule-1

mode:
  description: describes the action to take on the task.
  type: str
  sample: update
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
from netaddr import IPAddress
import json, time, re, hashlib, ipaddress

global print_output
global json_template
global obj_attempts
global min_version
global max_version

print_output = []

## define object creation timeout (in seconds)
obj_attempts = 20

## define minimum supported tmos version - min(SSLO 5.x)
min_version = 5.0

## define maximum supported tmos version - max(SSLO 8.x)
max_version = 8.9

json_template = {
    "name":"sslo_ob_SERVICE_CREATE_TEMPLATE_NAME",
    "inputProperties":[
       {
          "id":"f5-ssl-orchestrator-operation-context",
          "type":"JSON",
          "value":{
             "deploymentName":"TEMPLATE_NAME",
             "operationType":"CREATE",
             "deploymentType":"SERVICE",
             "deploymentReference":"",
             "partition":"Common",
             "version":"7.2",
             "strictness":False
          }
       },
       {
          "id":"f5-ssl-orchestrator-network",
          "type":"JSON",
          "value":[
             {
                "name":"TEMPLATE_NAME_NET_IN",
                "partition":"Common",
                "strictness":False,
                "create":True,
                "vlan":{
                   "name":"TEMPLATE_NAME_NET_IN",
                   "path":"TEMPLATE_NAME_PATH_IN",
                   "create":True,
                   "modify":False,
                   "networkError":False,
                   "interface":[
                      "TEMPLATE_INTERFACE_IN"
                   ],
                   "tag":0,
                   "networkInterface":"TEMPLATE_INTERFACE_IN",
                   "networkTag":0
                },
                "selfIpConfig":{
                   "create":True,
                   "modify":False,
                   "selfIp":"",
                   "netmask":"",
                   "floating":False,
                   "HAstaticIpMap":[]
                },
                "routeDomain":{
                   "id":0,
                   "create":False
                },
                "existingBlockId":""
             },
             {
                "name":"TEMPLATE_NAME_NET_OUT",
                "partition":"Common",
                "strictness":False,
                "create":True,
                "vlan":{
                   "name":"TEMPLATE_NAME_NET_OUT",
                   "path":"TEMPLATE_NAME_PATH_OUT",
                   "create":True,
                   "modify":False,
                   "networkError":False,
                   "interface":[
                      "TEMPLATE_INTERFACE_OUT"
                   ],
                   "tag":0,
                   "networkInterface":"TEMPLATE_INTERFACE_OUT",
                   "networkTag":0
                },
                "selfIpConfig":{
                   "create":True,
                   "modify":False,
                   "selfIp":"",
                   "netmask":"",
                   "floating":False,
                   "HAstaticIpMap":[]
                },
                "routeDomain":{
                   "id":0,
                   "create":False
                },
                "existingBlockId":""
             }
          ]
       },
       {
          "id":"f5-ssl-orchestrator-service",
          "type":"JSON",
          "value":{
             "customService":{
                "name":"TEMPLATE_NAME",
                "serviceType": "http-proxy",
                "serviceSpecific":{
                   "name":"TEMPLATE_NAME",
                   "proxyType": "Explicit",
                   "authOffload": False
                },
                "connectionInformation":{
                   "fromBigipNetwork":{
                      "name":"TEMPLATE_NAME_NET_IN",
                      "vlan":{
                         "path":"TEMPLATE_NAME_PATH_IN",
                         "create":True,
                         "modify":False,
                         "selectedValue":"",
                         "networkVlanValue":""
                      },
                      "routeDomain":{
                         "id":0,
                         "create":False
                      },
                      "selfIpConfig":{
                         "create":True,
                         "modify":False,
                         "autoValue":"198.19.96.7/25",
                         "selectedValue":"",
                         "selfIp":"TEMPLATE_SELF_IN",
                         "netmask":"TEMPLATE_MASK_IN",
                         "floating":False,
                         "HAstaticIpMap":[]
                      },
                      "networkBlockId":""
                   },
                   "toBigipNetwork":{
                      "name":"TEMPLATE_NAME_NET_OUT",
                      "vlan":{
                         "path":"TEMPLATE_NAME_PATH_OUT",
                         "create":True,
                         "modify":False,
                         "selectedValue":"",
                         "networkVlanValue":""
                      },
                      "routeDomain":{
                         "id":0,
                         "create":False
                      },
                      "selfIpConfig":{
                         "create":True,
                         "modify":False,
                         "autoValue":"198.19.96.245/25",
                         "selectedValue":"",
                         "selfIp":"TEMPLATE_SELF_OUT",
                         "netmask":"TEMPLATE_MASK_OUT",
                         "floating":False,
                         "HAstaticIpMap":[
                            
                         ]
                      },
                      "networkBlockId":""
                   }
                },
                "snatConfiguration":{
                   "clientSnat":"None",
                   "snat":{
                      "referredObj":"",
                      "ipv4SnatAddresses":[],
                      "ipv6SnatAddresses":[]
                   }
                },
                "loadBalancing":{
                   "devices":[],
                   "monitor":{
                      "fromSystem":"/Common/gateway_icmp"
                   }
                },
                "initialIpFamily":"ipv4",
                "ipFamily":"ipv4",
                "isAutoManage":True,
                "portRemap":False,
                "httpPortRemapValue":"80",
                "serviceDownAction":"ignore",
                "iRuleList":[],
                "managedNetwork":{
                   "serviceType":"http-proxy",
                   "ipFamily":"ipv4",
                   "isAutoManage":True,
                   "ipv4":{
                      "serviceType":"http-proxy",
                      "ipFamily":"ipv4",
                      "serviceSubnet":"TEMPLATE_SUBNET",
                      "serviceIndex":0,
                      "subnetMask":"255.255.255.0",
                      "toServiceNetwork":"TEMPLATE_SUBNETWORK_TO",
                      "toServiceMask":"TEMPLATE_SUBNETWORK_TO_MASK",
                      "toServiceSelfIp":"TEMPLATE_SELF_IN",
                      "fromServiceNetwork":"TEMPLATE_SUBNETWORK_FROM",
                      "fromServiceMask":"TEMPLATE_SUBNETWORK_FROM_MASK",
                      "fromServiceSelfIp":"TEMPLATE_SELF_OUT"
                   },
                   "ipv6":{
                      
                   },
                   "operation":"RESERVEANDCOMMIT"
                }
             },
             "fromVlanNetworkObj":{
                "create":True,
                "modify":False,
                "networkError":False
             },
             "fromNetworkObj":{
                "name":"TEMPLATE_NAME_NET_IN",
                "create":True,
                "partition":"Common",
                "strictness":False,
                "vlan":{
                   "create":True,
                   "modify":False,
                   "name":"TEMPLATE_NAME_NET_IN",
                   "path":"TEMPLATE_NAME_PATH_IN",
                   "networkError":False,
                   "interface":[
                      "TEMPLATE_INTERFACE_IN"
                   ],
                   "tag":0,
                   "networkInterface":"TEMPLATE_INTERFACE_IN",
                   "networkTag":0
                },
                "selfIpConfig":{
                   "create":True,
                   "modify":False,
                   "selfIp":"TEMPLATE_SELF_IN",
                   "netmask":"TEMPLATE_MASK_IN",
                   "floating":False,
                   "HAstaticIpMap":[]
                },
                "routeDomain":{
                   "id":0,
                   "create":False
                }
             },
             "toVlanNetworkObj":{
                "create":True,
                "modify":False,
                "networkError":False
             },
             "toNetworkObj":{
                "name":"TEMPLATE_NAME_NET_OUT",
                "create":True,
                "partition":"Common",
                "strictness":True,
                "vlan":{
                   "create":True,
                   "modify":False,
                   "name":"TEMPLATE_NAME_NET_OUT",
                   "path":"TEMPLATE_NAME_PATH_OUT",
                   "networkError":False,
                   "interface":[
                      "TEMPLATE_INTERFACE_OUT"
                   ],
                   "tag":0,
                   "networkInterface":"TEMPLATE_INTERFACE_OUT",
                   "networkTag":0
                },
                "selfIpConfig":{
                   "create":True,
                   "modify":False,
                   "selfIp":"TEMPLATE_SELF_OUT",
                   "netmask":"TEMPLATE_MASK_OUT",
                   "floating":False,
                   "HAstaticIpMap":[]
                },
                "routeDomain":{
                   "id":0,
                   "create":False
                }
             },
             "vendorInfo":{
                "name":"Generic Inline HTTP"
             },
             "name":"TEMPLATE_NAME",
             "partition":"Common",
             "description":"Type: HTTP",
             "strictness":False,
             "useTemplate":False,
             "serviceTemplate":"",
             "templateName":"HTTP Service",
             "previousVersion":"7.2",
             "existingBlockId":""
          }
       },
       {
          "id":"f5-ssl-orchestrator-service-chain",
          "type":"JSON",
          "value":[]
       },
       {
          "id":"f5-ssl-orchestrator-policy",
          "type":"JSON",
          "value":[]
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
        name = "ssloS_" + name
        return name

    @property
    def device_to_vlan(self):
        device_to_vlan = self._values['devicesTo']['vlan']
        if device_to_vlan is None:
            return None
        return device_to_vlan

    @property
    def device_to_interface(self):
        device_to_interface = self._values['devicesTo']['interface']
        if device_to_interface is None:
            return None
        return device_to_interface

    @property
    def device_to_tag(self):
        device_to_tag = self._values['devicesTo']['tag']
        if device_to_tag is None:
            return None
        return device_to_tag

    @property
    def device_to_self(self):
        device_to_self = self._values['devicesTo']['selfIp']
        if device_to_self is None:
            return None
        return device_to_self

    @property
    def device_to_mask(self):
        device_to_mask = self._values['devicesTo']['netmask']
        if device_to_mask is None:
            return None
        return device_to_mask

    @property
    def device_from_vlan(self):
        device_from_vlan = self._values['devicesFrom']['vlan']
        if device_from_vlan is None:
            return None
        return device_from_vlan

    @property
    def device_from_interface(self):
        device_from_interface = self._values['devicesFrom']['interface']
        if device_from_interface is None:
            return None
        return device_from_interface

    @property
    def device_from_tag(self):
        device_from_tag = self._values['devicesFrom']['tag']
        if device_from_tag is None:
            return None
        return device_from_tag

    @property
    def device_from_self(self):
        device_from_self = self._values['devicesFrom']['selfIp']
        if device_from_self is None:
            return None
        return device_from_self

    @property
    def device_from_mask(self):
        device_from_mask = self._values['devicesFrom']['netmask']
        if device_from_mask is None:
            return None
        return device_from_mask

    @property
    def devices(self):
        devices = self._values['devices']
        if devices is None:
            return None
        return devices

    @property
    def ipFamily(self):
        ipFamily = self._values['ipFamily']
        if ipFamily not in ['ipv4', 'ipv6']:
            ipFamily = 'ipv4'
        return ipFamily

    @property
    def monitor(self):
        monitor = self._values['monitor']
        if monitor is None:
            return "/Common/gateway_icmp"
        return monitor

    @property
    def serviceDownAction(self):
        serviceDownAction = self._values['serviceDownAction']
        if serviceDownAction not in ['ignore', 'reset', 'drop']:
            serviceDownAction = 'ignore'
        return serviceDownAction

    @property
    def portRemap(self):
        portRemap = self._values['portRemap']
        if portRemap is None:
            return None
        return portRemap

    @property
    def snat(self):
        snat = self._values['snat']
        if snat is None:
            return None
        return snat

    @property
    def snatpool(self):
        snatpool = self._values['snatpool']
        if snatpool is None:
            return None
        return snatpool

    @property
    def snatlist(self):
        snatlist = self._values['snatlist']
        if snatlist is None:
            return None
        return snatlist

    @property
    def rules(self):
        rules = self._values['rules']
        if rules is None:
            return None
        return rules

    @property
    def proxyType(self):
        proxyType = self._values['proxyType']
        if proxyType is None:
            return None
        elif proxyType.lower() == "explicit":
            return "Explicit"
        elif proxyType.lower() == "transparent":
            return "Transparent"

    @property
    def authOffload(self):
        authOffload = self._values['authOffload']
        if authOffload is None:
            return None
        elif authOffload == "true":
            return True
        elif authOffload == "false":
            return False

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


    def find_network_json_index(self, config, name):
        ## finds the index number of the specified name in the f5-ssl-orchestrator-network JSON block
        for i in range(0, len(config["inputProperties"][1]["value"])):
                if config["inputProperties"][1]["value"][i]["name"] == name:
                    return i
                    break


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
        ## test for empty devices
        if self.want.devices == None:
            raise F5ModuleError("You must include at least one device.")
        
        ## use this to method to create and return a modified copy of the JSON template
        self.config = json_template

        ## get base name
        self.local_name = re.sub('ssloS_', '', self.want.name)

        ## general json settings for all operations
        self.config["name"] = "sslo_ob_SERVICE_" + operation + "_" + self.want.name
        self.config["inputProperties"][0]["value"]["operationType"] = operation
        self.config["inputProperties"][0]["value"]["deploymentName"] = self.want.name
        self.config["inputProperties"][2]["value"]["customService"]["serviceSpecific"]["name"] = self.want.name
        self.config["inputProperties"][2]["value"]["customService"]["name"] = self.want.name
        self.config["inputProperties"][2]["value"]["name"] = self.want.name
        self.config["inputProperties"][2]["value"]["fromNetworkObj"]["name"] = "ssloN_" + self.local_name+ "_in"
        self.config["inputProperties"][2]["value"]["toNetworkObj"]["name"] = "ssloN_" + self.local_name+ "_out"

        ## test for create network or use existing (From BIG-IP to service)
        if self.want.device_to_vlan != None:
            ## build for an existing VLAN
            self.index = self.find_network_json_index(self.config, "TEMPLATE_NAME_NET_IN")

            del self.config["inputProperties"][1]["value"][self.index]
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["fromBigipNetwork"]["name"] = self.want.device_to_vlan
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["fromBigipNetwork"]["vlan"]["path"] = self.want.device_to_vlan
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["fromBigipNetwork"]["vlan"]["selectedValue"] = self.want.device_to_vlan
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["fromBigipNetwork"]["vlan"]["create"] = False
            self.config["inputProperties"][2]["value"]["fromNetworkObj"]["vlan"]["create"] = False
            self.config["inputProperties"][2]["value"]["fromNetworkObj"]["vlan"]["name"] = "ssloN_" + self.local_name+ "_in"
            self.config["inputProperties"][2]["value"]["fromNetworkObj"]["vlan"]["path"] = self.want.device_to_vlan
            del self.config["inputProperties"][2]["value"]["fromNetworkObj"]["vlan"]["interface"][0]
            self.config["inputProperties"][2]["value"]["fromNetworkObj"]["vlan"]["networkInterface"] = ""
        else:
            self.index = self.find_network_json_index(self.config, "TEMPLATE_NAME_NET_IN")

            self.config["inputProperties"][1]["value"][self.index]["name"] = "ssloN_" + self.local_name+ "_in"
            self.config["inputProperties"][1]["value"][self.index]["vlan"]["path"] = "/Common/ssloN_" + self.local_name + "_in.app/ssloN_" + self.local_name + "_in"
            self.config["inputProperties"][1]["value"][self.index]["vlan"]["name"] = "ssloN_" + self.local_name+ "_in"
            self.config["inputProperties"][1]["value"][self.index]["vlan"]["interface"][0] = self.want.device_to_interface
            self.config["inputProperties"][1]["value"][self.index]["vlan"]["networkInterface"] = self.want.device_to_interface
            self.config["inputProperties"][2]["value"]["fromNetworkObj"]["vlan"]["create"] = True
            self.config["inputProperties"][2]["value"]["fromNetworkObj"]["vlan"]["name"] = "ssloN_" + self.local_name+ "_in"
            self.config["inputProperties"][2]["value"]["fromNetworkObj"]["vlan"]["path"] = "/Common/ssloN_" + self.local_name + "_in.app/ssloN_" + self.local_name + "_in"
            self.config["inputProperties"][2]["value"]["fromNetworkObj"]["vlan"]["interface"][0] = str(self.want.device_to_interface)
            self.config["inputProperties"][2]["value"]["fromNetworkObj"]["vlan"]["networkInterface"] = str(self.want.device_to_interface)
            if self.want.device_to_tag != None:
                self.config["inputProperties"][1]["value"][self.index]["vlan"]["tag"] = self.want.device_to_tag
                self.config["inputProperties"][1]["value"][self.index]["vlan"]["networkTag"] = self.want.device_to_tag
                self.config["inputProperties"][2]["value"]["fromNetworkObj"]["vlan"]["tag"] = self.want.device_to_tag
                self.config["inputProperties"][2]["value"]["fromNetworkObj"]["vlan"]["networkTag"] = self.want.device_to_tag
            else:
                del self.config["inputProperties"][1]["value"][self.index]["vlan"]["tag"]
                del self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["fromBigipNetwork"]["vlan"]["tag"]
                del self.config["inputProperties"][2]["value"]["fromNetworkObj"]["vlan"]["networkTag"]
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["fromBigipNetwork"]["name"] = "ssloN_" + self.local_name+ "_in"
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["fromBigipNetwork"]["vlan"]["path"] = "/Common/ssloN_" + self.local_name + "_in.app/ssloN_" + self.local_name + "_in"

        ## test for create network or use existing (From service to BIG-IP)
        if self.want.device_from_vlan != None:
            ## build for an existing VLAN
            self.index = self.find_network_json_index(self.config, "TEMPLATE_NAME_NET_OUT")

            del self.config["inputProperties"][1]["value"][self.index]
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["toBigipNetwork"]["name"] = self.want.device_from_vlan
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["toBigipNetwork"]["vlan"]["path"] = self.want.device_from_vlan
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["toBigipNetwork"]["vlan"]["selectedValue"] = self.want.device_from_vlan
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["toBigipNetwork"]["vlan"]["create"] = False
            self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["create"] = False
            self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["name"] = "ssloN_" + self.local_name+ "_out"
            self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["path"] = self.want.device_from_vlan
            del self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["interface"][0]
            self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["networkInterface"] = ""
        else:
            self.index = self.find_network_json_index(self.config, "TEMPLATE_NAME_NET_OUT")

            self.config["inputProperties"][1]["value"][self.index]["name"] = "ssloN_" + self.local_name+ "_out"
            self.config["inputProperties"][1]["value"][self.index]["vlan"]["path"] = "/Common/ssloN_" + self.local_name + "_out.app/ssloN_" + self.local_name + "_out"
            self.config["inputProperties"][1]["value"][self.index]["vlan"]["name"] = "ssloN_" + self.local_name+ "_out"
            self.config["inputProperties"][1]["value"][self.index]["vlan"]["interface"][0] = self.want.device_from_interface
            self.config["inputProperties"][1]["value"][self.index]["vlan"]["networkInterface"] = self.want.device_from_interface
            self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["create"] = True
            self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["name"] = "ssloN_" + self.local_name+ "_out"
            self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["path"] = "/Common/ssloN_" + self.local_name + "_out.app/ssloN_" + self.local_name + "_out"
            self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["interface"] = str(self.want.device_from_interface)
            self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["networkInterface"] = str(self.want.device_from_interface)
            if self.want.device_from_tag != None:
                self.config["inputProperties"][1]["value"][self.index]["vlan"]["tag"] = self.want.device_from_tag
                self.config["inputProperties"][1]["value"][self.index]["vlan"]["networkTag"] = self.want.device_from_tag
                self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["tag"] = self.want.device_from_tag
                self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["networkTag"] = self.want.device_from_tag
            else:
                del self.config["inputProperties"][1]["value"][self.index]["vlan"]["tag"]
                del self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["toBigipNetwork"]["vlan"]["tag"]
                del self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["networkTag"]
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["toBigipNetwork"]["name"] = "ssloN_" + self.local_name+ "_out"
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["toBigipNetwork"]["vlan"]["path"] = "/Common/ssloN_" + self.local_name + "_out.app/ssloN_" + self.local_name + "_out"
            self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["create"] = True
            self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["name"] = "ssloN_" + self.local_name+ "_out"
            self.config["inputProperties"][2]["value"]["toNetworkObj"]["vlan"]["networkInterface"] = self.want.device_from_interface

        ## create self-IPs
        if self.want.ipFamily == "ipv4":
            self.to_cidr = IPAddress(self.want.device_to_mask).netmask_bits()
            self.to_ip = self.want.device_to_self + "/" + str(self.to_cidr)
            self.to_network = re.sub('/[0-9]+', '', str(ipaddress.ip_network(self.to_ip, strict=False)))

            self.from_cidr = IPAddress(self.want.device_from_mask).netmask_bits()
            self.from_ip = self.want.device_from_self + "/" + str(self.from_cidr)
            self.from_network = re.sub('/[0-9]+', '', str(ipaddress.ip_network(self.from_ip, strict=False)))

            self.config["inputProperties"][2]["value"]["customService"]["ipFamily"] = "ipv4"
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["fromBigipNetwork"]["selfIpConfig"]["autoValue"] = "198.19.64.7/25"
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["fromBigipNetwork"]["selfIpConfig"]["selfIp"] = self.want.device_to_self
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["fromBigipNetwork"]["selfIpConfig"]["netmask"] = self.want.device_to_mask
            self.config["inputProperties"][2]["value"]["fromNetworkObj"]["selfIpConfig"]["selfIp"] = self.want.device_to_self
            self.config["inputProperties"][2]["value"]["fromNetworkObj"]["selfIpConfig"]["netmask"] = self.want.device_to_mask

            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["toBigipNetwork"]["selfIpConfig"]["autoValue"] = "198.19.64.245/25"
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["toBigipNetwork"]["selfIpConfig"]["selfIp"] = self.want.device_from_self
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["toBigipNetwork"]["selfIpConfig"]["netmask"] = self.want.device_from_mask
            self.config["inputProperties"][2]["value"]["toNetworkObj"]["selfIpConfig"]["selfIp"] = self.want.device_from_self
            self.config["inputProperties"][2]["value"]["toNetworkObj"]["selfIpConfig"]["netmask"] = self.want.device_from_mask

            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipFamily"] = "ipv4"
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv4"]["serviceType"] = "http-proxy"
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv4"]["ipFamily"] = "ipv4"
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv4"]["serviceSubnet"] = self.to_network
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv4"]["serviceIndex"] = 0
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv4"]["subnetMask"] = "255.255.255.0"
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv4"]["toServiceNetwork"] = self.to_network
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv4"]["toServiceMask"] = self.want.device_to_mask
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv4"]["toServiceSelfIp"] = self.want.device_to_self
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv4"]["fromServiceNetwork"] = self.from_network
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv4"]["fromServiceMask"] = self.want.device_from_mask
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv4"]["fromServiceSelfIp"] = self.want.device_from_self

        else:
            self.to_cidr = IPAddress(self.want.device_to_mask).netmask_bits()
            self.to_ip = self.want.device_to_self + "/" + str(self.to_cidr)
            self.to_network = re.sub('/[0-9]+', '', str(ipaddress.ip_network(self.to_ip, strict=False)))

            self.from_cidr = IPAddress(self.want.device_from_mask).netmask_bits()
            self.from_ip = self.want.device_from_self + "/" + str(self.from_cidr)
            self.from_network = re.sub('/[0-9]+', '', str(ipaddress.ip_network(self.from_ip, strict=False)))

            self.config["inputProperties"][2]["value"]["customService"]["ipFamily"] = "ipv6"
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["fromBigipNetwork"]["selfIpConfig"]["autoValue"] = "2001:0200:0:0300::7/120"
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["fromBigipNetwork"]["selfIpConfig"]["selectedValue"] = "2001:0200:0:0300::7/120"
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["fromBigipNetwork"]["selfIpConfig"]["selfIp"] = self.want.device_to_self
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["fromBigipNetwork"]["selfIpConfig"]["netmask"] = self.want.device_to_mask

            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["toBigipNetwork"]["selfIpConfig"]["autoValue"] = "2001:0200:0:0300::107/120"
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["toBigipNetwork"]["selfIpConfig"]["selectedValue"] = "2001:0200:0:0300::107/120"
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["toBigipNetwork"]["selfIpConfig"]["selfIp"] = self.want.device_from_self
            self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["toBigipNetwork"]["selfIpConfig"]["netmask"] = self.want.device_from_mask

            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipFamily"] = "ipv6"
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv6"]["serviceType"] = "http-proxy"
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv6"]["ipFamily"] = "ipv6"
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv6"]["serviceSubnet"] = self.to_network
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv6"]["serviceIndex"] = 0
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv6"]["subnetMask"] = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00"
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv6"]["toServiceNetwork"] = self.to_network
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv6"]["toServiceMask"] = self.want.device_to_mask
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv6"]["toServiceSelfIp"] = self.want.device_to_self
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv6"]["fromServiceNetwork"] = self.from_network
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv6"]["fromServiceMask"] = self.want.device_from_mask
            self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv6"]["fromServiceSelfIp"] = self.want.device_from_self

        ## create devices
        if self.want.proxyType == "Transparent":
            ## ignore any supplied port value and default to port 80
            self.device_list = []
            for i in self.want.devices:
                self.device_list.append({"ip":"" + i['ip'] + "","port":80})
            self.config["inputProperties"][2]["value"]["customService"]["loadBalancing"]["devices"] = self.device_list
        elif self.want.proxyType == "Explicit":
            ## first test that port is supplied (fail otherwise), and then set devices to supplied IP:port
            try:
                for i in self.want.devices:
                    port = i['port']
            except:
                raise F5ModuleError("Explicit proxy requires an IP and port specified for devices")
            ## all good - set devices to supplied IP:port
            self.config["inputProperties"][2]["value"]["customService"]["loadBalancing"]["devices"] = self.want.devices

        ## define port remap
        if self.want.portRemap != None:
            if self.want.proxyType != "Explicit":
                self.config["inputProperties"][2]["value"]["customService"]["portRemap"] = True
                self.config["inputProperties"][2]["value"]["customService"]["httpPortRemapValue"] = self.want.portRemap

        ## define serviceDownAction
        if self.want.serviceDownAction != None:
            self.config["inputProperties"][2]["value"]["customService"]["serviceDownAction"] = self.want.serviceDownAction

        ## define monitor
        if self.want.monitor != "/Common/gateway_icmp":
            self.config["inputProperties"][2]["value"]["customService"]["loadBalancing"]["monitor"]["fromSystem"] = self.want.monitor

        ## define rules
        if self.want.rules != None:
            self.rulelist = []
            for i in self.want.rules:
                self.rulelist.append({"name":"" + i + "","value":"" + i + ""})
            self.config["inputProperties"][2]["value"]["customService"]["iRuleList"] = self.rulelist

        ## define snat
        if self.want.snat != None:
            ## send error if snatpool AND snatlist are defined
            if self.want.snatpool != None and self.want.snatlist != None:
                raise F5ModuleError("SNAT cannot define a snatpool and snatlist at the same time.")

            ## send error if snat == snatpool and no snatpool defined
            if self.want.snat == "snatpool" and self.want.snatpool == None:
                raise F5ModuleError("Snat set to snatpool but no snatpool defined.")

            ## send error if snat == snatlist and no snatlist defined
            if self.want.snat == "snatlist" and self.want.snatlist == None:
                raise F5ModuleError("Snat set to snatlist but no snatlist defined.")

            if self.want.snat == "none":
                self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['clientSnat'] = "None"
                self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['snat']['referredObj'] = ""
            elif self.want.snat == "automap":
                self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['clientSnat'] = "AutoMap"
                self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['snat']['referredObj'] = ""
            elif self.want.snat == "snatlist":
                self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['clientSnat'] = "SNAT"
                self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['snat']['referredObj'] = ""
                self.snatlist = []
                for key in self.want.snatlist:
                    self.snatlist.append({"ip":"" + key + ""})
                    if self.want.ipFamily == "ipv4":
                        self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['snat']['ipv4SnatAddresses'] = self.snatlist
                    elif self.want.ipFamily == "ipv6":
                        self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['snat']['ipv6SnatAddresses'] = self.snatlist
            elif self.want.snat == "snatpool":
                self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['clientSnat'] = "existingSNAT"
                self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['snat']['referredObj'] = self.want.snatpool

        ## define proxyType
        if self.want.proxyType != None:
            self.config["inputProperties"][2]["value"]["customService"]["serviceSpecific"]["proxyType"] = self.want.proxyType

        ## define authOffload
        if self.want.authOffload != None:
            self.config["inputProperties"][2]["value"]["customService"]["serviceSpecific"]["authOffload"] = self.want.authOffload

        if operation == "CREATE":
            ## set these to empty for CREATE
            self.config["inputProperties"][0]["value"]["deploymentReference"] = ""
            self.config["inputProperties"][2]["value"]["existingBlockId"] = ""
            self.config["name"] = "sslo_obj_SERVICE_CREATE_" + self.want.name

        elif operation in ["DELETE", "MODIFY"]:
            self.config["name"] = "sslo_obj_SERVICE_MODIFY_" + self.want.name

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
                self.config["inputProperties"][2]["value"]["existingBlockId"] = id
            except:
                raise F5ModuleError("Failure to create/modify - unable to fetch object ID")

            ## update the snat settings for a MODIFY operation, as required
            if operation in ["MODIFY"] and self.want.snat == "snatlist":
                ## update the snatpool reference if it exists
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

                if resp.status not in [200, 201, 202] or 'code' in response and response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(resp.content)

                for key in response['items'][0]['inputProperties']:
                    if str(key['id']) == "f5-ssl-orchestrator-service":
                        if self.want.name + "-svc-snatpool" in key['value']['customService']['snatConfiguration']['snat']['referredObj']:
                            ## here because this is a modify operation, user sent snatlist, and the service already has an SSLO-created snatlist (snatpool) assigned
                            ## set the same referredObj in self.config json
                            self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['snat']['referredObj'] = key['value']['customService']['snatConfiguration']['snat']['referredObj']
                            self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['clientSnat'] = "existingSNAT"
                            
                            ## create members list
                            self.snat_iplist = []
                            for member in self.want.snatlist:
                                self.snat_iplist.append({"ip":"" + member + ""})

                            ## add snatPools elements
                            self.config["inputProperties"][2]["value"]["snatPools"] = {}
                            self.config["inputProperties"][2]["value"]["snatPools"][self.want.name + "-svc-snatpool"] = {}
                            self.config["inputProperties"][2]["value"]["snatPools"][self.want.name + "-svc-snatpool"]["name"] = self.want.name + "-svc-snatpool"
                            self.config["inputProperties"][2]["value"]["snatPools"][self.want.name + "-svc-snatpool"]["members"] = self.snat_iplist
                                
                        else:
                            ## user wants to add a snatlist but one is not already defined
                            ## send error if snat == snatlist and no snatlist defined
                            if self.want.snat == "snatlist" and self.want.snatlist == None:
                                raise F5ModuleError("Snat set to snatlist but no snatlist defined.")

                            self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['clientSnat'] = "SNAT"
                            self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['snat']['referredObj'] = ""
                            self.snatlist = []
                            for key in self.want.snatlist:
                                self.snatlist.append({"ip":"" + key + ""})
                                if self.want.ipFamily == "ipv4":
                                    self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['snat']['ipv4SnatAddresses'] = self.snatlist
                                elif self.want.ipFamily == "ipv6":
                                    self.config["inputProperties"][2]["value"]['customService']['snatConfiguration']['snat']['ipv6SnatAddresses'] = self.snatlist

                        break
      
            ## update the network settings for a MODIFY operation, as required
            if operation in ["MODIFY"]:
                ## test for a self-IP change. Self-IPs are immutable, so if different must send an error
                if self.want.ipFamily == "ipv4":
                    ## query existing entry self-IPs
                    uri = "https://{0}:{1}/mgmt/tm/net/self/~Common~{2}.app~{2}-70-0-flt-S4".format(
                        self.client.provider['server'],
                        self.client.provider['server_port'],
                        self.want.name,
                    )
                    query = "?$select=address"
                    resp = self.client.api.get(uri + query).json()
                    resp_in = resp["address"]

                    ## query existing return self-IPs
                    uri = "https://{0}:{1}/mgmt/tm/net/self/~Common~{2}.app~{2}-70-0-flt-D4".format(
                        self.client.provider['server'],
                        self.client.provider['server_port'],
                        self.want.name,
                    )
                    query = "?$select=address"
                    resp = self.client.api.get(uri + query).json()
                    resp_out = resp["address"]

                    ## convert mask to cidr for comparison
                    self.in_cidr = IPAddress(self.want.device_to_mask).netmask_bits()
                    self.out_cidr = IPAddress(self.want.device_from_mask).netmask_bits()

                    ## compare yaml self/cidr to existing S4/D4 values and value if not the same
                    if resp_in != self.want.device_to_self + "/" + str(self.in_cidr):
                        raise F5ModuleError("Self-IPs are immutable. You must delete and recreate the service to change the self-IPs.")
                    elif resp_out != self.want.device_from_self + "/" + str(self.out_cidr):
                        raise F5ModuleError("Self-IPs are immutable. You must delete and recreate the service to change the self-IPs.")

                elif self.want.ipFamily == "ipv6":
                    ## query existing entry self-IPs
                    uri = "https://{0}:{1}/mgmt/tm/net/self/~Common~{2}.app~{2}-70-0-flt-S6".format(
                        self.client.provider['server'],
                        self.client.provider['server_port'],
                        self.want.name,
                    )
                    query = "?$select=address"
                    resp = self.client.api.get(uri + query).json()
                    resp_in = resp["address"]

                    ## query existing return self-IPs
                    uri = "https://{0}:{1}/mgmt/tm/net/self/~Common~{2}.app~{2}-70-0-flt-D6".format(
                        self.client.provider['server'],
                        self.client.provider['server_port'],
                        self.want.name,
                    )
                    query = "?$select=address"
                    resp = self.client.api.get(uri + query).json()
                    resp_out = resp["address"]

                    ## convert mask to cidr for comparison
                    self.in_cidr = IPAddress(self.want.device_to_mask).netmask_bits()
                    self.out_cidr = IPAddress(self.want.device_from_mask).netmask_bits()

                    ## compare yaml self/cidr to existing S6/D6 values and value if not the same
                    if resp_in != self.want.device_to_self + "/" + str(self.in_cidr):
                        raise F5ModuleError("Self-IPs are immutable. You must delete and recreate the service to change the self-IPs.")
                    elif resp_out != self.want.device_from_self + "/" + str(self.out_cidr):
                        raise F5ModuleError("Self-IPs are immutable. You must delete and recreate the service to change the self-IPs.")


                ## query for and add existingBlockId and networkBlockId for each ssloN network object
                if self.want.device_to_vlan == None:
                    self.index = self.find_network_json_index(self.config, "ssloN_" + self.local_name + "_in")

                    self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["operation"] = "RESERVEANDCOMMIT"

                    ## update from_networkBlockId - go get ssloN object block IDs
                    uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                        self.client.provider['server'],
                        self.client.provider['server_port']
                    )
                    query = "?$filter=name+eq+'ssloN_{0}_in'&$select=id".format(self.local_name)
                    resp = self.client.api.get(uri + query).json()
                    
                    if resp["items"] != []:
                        self.config["inputProperties"][1]["value"][self.index]["existingBlockId"] = resp["items"][0]["id"]
                        self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["fromBigipNetwork"]["networkBlockId"] = resp["items"][0]["id"]

                if self.want.device_from_vlan == None:
                    self.index = self.find_network_json_index(self.config, "ssloN_" + self.local_name + "_out")

                    self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["operation"] = "RESERVEANDCOMMIT"

                    ## update from_networkBlockId - go get ssloN object block IDs
                    uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                        self.client.provider['server'],
                        self.client.provider['server_port']
                    )
                    query = "?$filter=name+eq+'ssloN_{0}_out'&$select=id".format(self.local_name)
                    resp = self.client.api.get(uri + query).json()
                    
                    if resp["items"] != []:
                        self.config["inputProperties"][1]["value"][self.index]["existingBlockId"] = resp["items"][0]["id"]
                        self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["toBigipNetwork"]["networkBlockId"] = resp["items"][0]["id"]

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
                    query = "?$filter=id+eq+'{0}'&$select=id,state".format(self.operationId)
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
                    query = "?$filter=id+eq+'{0}'&$select=id,state".format(self.operationId)
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
                    query = "?$filter=id+eq+'{0}'&$select=id,state".format(self.operationId)
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
            ## object doesn't exit - just exit (changed = False)
            return False
 

    def exists(self):
        ## use this method to see if the objects already exists - queries for the respective application service object
        #uri = "https://{0}:{1}/mgmt/tm/sys/application/service/~Common~{2}.app~{2}".format(
        #    self.client.provider['server'],
        #    self.client.provider['server_port'],
        #    self.want.name,
        #)
        #resp = self.client.api.get(uri)
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

        #if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
        #    return True
        #else:
        #    return False
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
            devicesTo=dict(
                required=True,
                type='dict',
                options=dict(
                    vlan=dict(),
                    interface=dict(),
                    tag=dict(type=int),
                    selfIp=dict(required=True),
                    netmask=dict(required=True)
                ),
                mutually_exclusive=[
                  ('vlan', 'interface')
                ],
                required_one_of=[
                  ('vlan', 'interface')
                ]
            ),
            devicesFrom=dict(
                required=True,
                type='dict',
                options=dict(
                    vlan=dict(),
                    interface=dict(),
                    tag=dict(type=int),
                    selfIp=dict(required=True),
                    netmask=dict(required=True)
                ),
                mutually_exclusive=[
                  ('vlan', 'interface')
                ],
                required_one_of=[
                  ('vlan', 'interface')
                ]
            ),
            devices=dict(
                required=True,
                type='list'
            ),
            state=dict(
                default='present',
                choices=['absent','present']
            ),
            ipFamily=dict(
                default='ipv4',
                choices=['ipv4','ipv6']
            ),
            monitor=dict(
                default='/Common/gateway_icmp'
            ),
            serviceDownAction=dict(
                default='ignore',
                choices=['ignore','reset','drop']
            ),
            portRemap=dict(
                type='int'
            ),
            snat=dict(
                default='none',
                choices=['none','automap','snatlist','snatpool']
            ),
            snatlist=dict(
                type='list'
            ),
            snatpool=dict(),
            rules=dict(
                type='list'
            ),
            proxyType=dict(
                choices=['explicit','transparent'],
                default='explicit'
            ),
            authOffload=dict(
                choices=['true','false'],
                default='false'
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