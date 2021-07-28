#!/usr/bin/python
# -*- coding: utf-8 -*-
# 
# Copyright: (c) 2021, kevin-dot-g-dot-stewart-at-gmail-dot-com
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Version: 1.0.1

#### To Do:
#### Test what happens when interface, tag or subnet in use

#### Updates:
#### 1.0.1 - added 9.0 support (same as 8.3 so just changed max version)
#          - updated version and previousVersion keys to match target SSLO version


from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_layer2_service
short_description: Manage an SSL Orchestrator layer 2 security device
description:
  - Manage an SSL Orchestrator layer 2 security device
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the layer 2 security service. Configuration auto-prepends "ssloS_" to service.
        Service name should be less than 14 characters and not contain dashes "-".
    type: str
    required: True
  devices:
    description:
      - Specifies the set of network settings for traffic going to the service from BIG-IP. Multiple devices are defined as separate list items.
    type: list
    elements: dict
    suboptions:
      name:
        description:
            - Defines the name of this specific device.
        type: str
      ratio:
        description:
            - Defines a load balancing ratio setting for this device.
        type: int
        default: 1
      vlanIn:
        description: 
            - Defines an existing VLAN to attach on the to-service side. The vlan and interface/tag options are mutually exclusive.
        type: str
      interfaceIn:
        description: 
            - Defines the interface on the to-service side. The vlan and interface/tag options are mutually exclusive.
        type: str
      tagIn: 
        description: 
            - Defines the VLAN tag on the to-service side (as required).
        type: int
        default: None
      vlanOut:
        description: 
            - Defines an existing VLAN to attach on the from-service side. The vlan and interface/tag options are mutually exclusive.
        type: str
      interfaceOut:
        description: 
            - Defines the interface on the from-service side. The vlan and interface/tag options are mutually exclusive.
        type: str
      tagOut: 
        description: 
            - Defines the VLAN tag on the from-service side (as required).
        type: int
        default: None
    required: True
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
  ipOffset:
    description:
        - Defines an IP offset integer to be used in the internal IP addressing. This is typically used in a tiered architecture, where a layer 2 service is shared between multiple standalone SSL Orchestrator instances.
    type: int
    default: 0
  portRemap:
    description:
        - Defines the port to remap decrypted traffic to.
    type: int
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
    - name: SSLO LAYER 2 service
      bigip_sslo_service_layer2:
        provider: "{{ provider }}"
        name: "layer2a"
        devices:
            - name: FEYE1
              interfaceIn: 1.5
              tagIn: 100
              interfaceOut: 1.5
              tagOut: 101
            - name: FEYE2
              interfaceIn: 1.5
              tagIn: 200
              interfaceOut: 1.5
              tagOut: 201
      delegate_to: localhost

- name: Create SSLO service(s) - externally referenced VLANs
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
    - name: SSLO LAYER 2 service
      bigip_sslo_service_layer2:
        provider: "{{ provider }}"
        name: "layer2a"
        devices:
            - name: FEYE1
              interfaceIn: 1.5
              tagIn: 100
              interfaceOut: 1.5
              tagOut: 101
            - name: FEYE2
              vlanIn: "/Common/l2service1-in-vlan"
              vlanOut: "/Common/l2service1-out-vlan"
        monitor: "/Common/gw1"
        serviceDownAction: "reset"
        ipOffset: 1
        portRemap: 8080
        rules:
            - "/Common/rule1"
            - "/Common/rule1"
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

    - name: create L2 service inbound VLAN
      bigip_vlan:
        provider: "{{ provider }}"
        name: L2service_vlan_in
        tagged_interface: 1.5
        tag: 600
      delegate_to: localhost

    - name: create L2 service outbound VLAN
      bigip_vlan:
        provider: "{{ provider }}"
        name: L2service_vlan_out
        tagged_interface: 1.5
        tag: 601
      delegate_to: localhost

    - name: SSLO LAYER2 service
      bigip_sslo_service_layer2:
        provider: "{{ provider }}"
        name: "layer2a"
        devices:
          - name: "FEYE1"
            vlanIn: "/Common/L2service_vlan_in"
            vlanOut: "/Common/L2service_vlan_out"
        monitor: "/Common/gw2"
        #serviceDownAction: "reset"
        #ipOffset: 1
        #portRemap: 8283
        #rules:
        #  - "/Common/test1"
        #  - "/Common/test2"
      delegate_to: localhost
'''

RETURN = r'''
name:
  description:
    - Changed name of layer 2 inline service.
  type: str
  sample: layer2a
devices:
  description: network settings for layer 2 device configurations
  type: complex
  contains:
    name:
       description: defines the name of this device
       type: str
       sample: FEYE1
    ratio:
       description: defines a load balancing ratio for this device
       type: int
       sample: 2
    vlanIn:
       description: defines a to-service vlan
       type: str
       sample: /Common/vlan-in
    interfaceIn:
       description: defines a to-service interface
       type: str
       sample: 1.3
    tagIn:
       description: defines a to-service tag
       type: str
       sample: 100
    vlanOut:
       description: defines a from-service vlan
       type: str
       sample: /Common/vlan-out
    interfaceOut:
       description: defines a from-service interface
       type: str
       sample: 1.3
    tagOut:
       description: defines a from-service tag
       type: str
       sample: 101
state:
  description:
    - Changed state.
  type: str
  sample: present
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
ipOffset:
  description:
    - Changed IP offset for all internal IP addressing.
  type: int
  Sample: 1
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
import json, time, re, hashlib, ipaddress, copy

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
    "name":"proxy-f5-ssl-orchestrator-service-CREATE",
    "inputProperties":[
         {
             "id": "f5-ssl-orchestrator-operation-context",
             "type": "JSON",
             "value": {
                 "deploymentName": "TEMPLATE_NAME",
                 "operationType": "CREATE",
                 "deploymentType": "SERVICE",                
                 "deploymentReference": "",
                 "partition": "Common",
                 "version": "7.2",
                 "strictness": False
             }
         },
         {
             "id":"f5-ssl-orchestrator-network",
             "type":"JSON",
             "value":[]
         },
         {
             "id":"f5-ssl-orchestrator-service",
             "type":"JSON",
             "value":{
                 "strictness":False,
                 "customService":{
                     "name":"TEMPLATE_NAME",
                     "serviceType":"L2",
                     "serviceSpecific":{
                         "unitIdMap":[],
                         "name":"TEMPLATE_NAME"
                     },
                     "connectionInformation":{
                         "interfaces":[]
                     },
                     "loadBalancing":{
                         "devices":[],
                         "monitor":{
                             "fromSystem":"/Common/gateway_icmp"
                         }
                     },
                     "portRemap":False,
                     "httpPortRemapValue":"80",
                     "serviceDownAction":"ignore",
                     "iRuleReference":"",
                     "iRuleList":[],                    
                     "managedNetwork":{
                         "serviceType":"L2",
                         "ipFamily":"both",
                         "ipv4":{
                             "serviceType":"L2",
                             "ipFamily":"ipv4",
                             "serviceSubnet":"198.19.32.0",
                             "serviceIndex":0,
                             "subnetMask":"255.255.255.0"
                         },
                         "ipv6":{
                             "serviceType":"L2",
                             "ipFamily":"ipv6",
                             "serviceSubnet":"2001:0200:0:0200::",
                             "serviceIndex":0,
                             "subnetMask":"ffff:ffff:ffff:ffff::"
                         },
                         "operation":"RESERVEANDCOMMIT"
                     }
                 },
                 "vendorInfo":{
                     "name":"Generic Inline Layer 2"
                 },
                 "modifiedNetworkObjects":[],
                 "removedNetworks":[],
                 "networkObjects":[],
                 "name":"TEMPLATE_NAME",
                 "description":"Type: L2",
                 "useTemplate":False,
                 "serviceTemplate":"",
                 "partition":"Common",
                 "advancedMode":"off",
                 "iRulesSelected":[],
                 "existingBlockId": ""
             }
         },
         {
             "id": "f5-ssl-orchestrator-service-chain",
             "type": "JSON",
             "value": []
         },
         {
             "id": "f5-ssl-orchestrator-policy",
             "type": "JSON",
             "value": []
         }
     ],
     "dataProperties":[],
     "configurationProcessorReference": {
         "link": "https://localhost/mgmt/shared/iapp/processors/f5-iappslx-ssl-orchestrator-gc"
     },
     "configProcessorTimeoutSeconds": 120,
     "statsProcessorTimeoutSeconds": 60,
     "configProcessorAffinity": {
         "processorPolicy": "LOCAL",
         "affinityProcessorReference": {
            "link": "https://localhost/mgmt/shared/iapp/affinity/local"
         }
     },
     "state": "BINDING",
     "presentationHtmlReference": {
         "link": "https://localhost/iapps/f5-iappslx-ssl-orchestrator/sgc/sgcIndex.html"
     }
}

json_template_f5_ssl_orchestrator_network = {
    "partition":"Common",
    "strictness":False,
    "name":"TEMPLATE_NETWORK_NAME",
    "previousVersion":"7.2",
    "version":"7.2",
    "vlan":{
        "create":True,
        "path":"TEMPLATE_NETWORK_PATH",
        "interface":[
           "TEMPLATE_NETWORK_INTERFACE"
        ],
        "tag":0,
        "name":"TEMPLATE_NETWORK_NAME"
    },
    "selfIpConfig":{
        "selfIp":"",
        "netmask":"",
        "floating":False,
        "HAstaticIpMap":[
            {
                "deviceMgmtIp":"",
                "selfIp":""
            }
        ]
    },
    "routeDomain":{
        "create":False,
        "id":0,
        "path":""
    },
    "existingBlockId":""
}

json_template_f5_ssl_orchestrator_service_customService_connectionInformation_interfaces = {
    "fromBigipVlan":{
        "path":"TEMPLATE_NETWORK_PATH_IN",
        "interface":[
              "TEMPLATE_NETWORK_INTERFACE_IN"
        ],
        "tag":0,
        "name":"TEMPLATE_NETWORK_NAME_IN",
        "networkBlockId":""
    },
    "toBigipVlan":{
        "path":"TEMPLATE_NETWORK_PATH_OUT",
        "interface":[
              "TEMPLATE_NETWORK_INTERFACE_OUT"
        ],
        "tag":0,
        "name":"TEMPLATE_NETWORK_NAME_OUT",
        "networkBlockId":""
    }
}

json_template_f5_ssl_orchestrator_service_customService_loadBalancing_devices = {
    "ratio":"1",
    "port":"0",
    "ip":[]
}

json_template_f5_ssl_orchestrator_service_networkObjects = {
    "partition":"Common",
    "strictness":False,
    "name":"TEMPLATE_NETWORK_NAME",
    "previousVersion":"7.2",
    "version":"7.2",
    "vlan":{
        "create":True,
        "path":"TEMPLATE_NETWORK_PATH",
        "interface":[
            "TEMPLATE_NETWORK_INTERFACE"
        ],
        "tag":0,
        "name":"TEMPLATE_NETWORK_NAME"
    },
    "selfIpConfig":{
        "selfIp":"",
        "netmask":"",
        "floating":False,
        "HAstaticIpMap":[
            {
                "deviceMgmtIp":"",
                "selfIp":""
            }
        ]
    },
    "routeDomain":{
        "create":False,
        "id":0,
        "path":""
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
        name = "ssloS_" + name
        return name

    @property
    def devices(self):
        devices = self._values['devices']
        if devices is None:
            return None
        return devices

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
    def ipOffset(self):
        ipOffset = self._values['ipOffset']
        if ipOffset is None:
            return None
        return ipOffset

    @property
    def rules(self):
        rules = self._values['rules']
        if rules is None:
            return None
        return rules

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


    def find_existing_network_object(self, name):
        ## use this method to find any existing network object
        uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
        )
        query = "?$filter=name+eq+'{0}'".format(name)
        resp = self.client.api.get(uri + query).json()    
        if resp["totalItems"] > 0:
            return True
        else:
            return False


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

        ## test for incorrect device settings
        ## - Cannot exceed 8 devices
        if len(self.want.devices) > 8:
            raise F5ModuleError("SSL Orchestrator supports up to eight (8) devices per inline layer 2 service.")

        ## test for incorrect device settings
        ## - Name must be supplied
        ## - VLAN and interface/tag cannot be supplied together
        ## - In and Out networks must defined
        device_test = {}
        device_cnt = 0

        for device in self.want.devices:
            ## find duplicate names (part 1)
            device_test[device_cnt] = device["name"]
            device_cnt += 1

            ## test for existence of name key
            if "name" not in device.keys():
                raise F5ModuleError("Devices must include a name.")

            ## test if VLAN and interface are supplied
            if "vlanIn" in device.keys() and "interfaceIn" in device.keys():
                raise F5ModuleError("Devices can only specify a VLAN or Interface/tag.")
            if "vlanOut" in device.keys() and "interfaceOut" in device.keys():
                raise F5ModuleError("Devices can only specify a VLAN or Interface/tag.")

            ## test if In and Out networks are defined
            if ( ( "vlanIn" in device.keys() or "interfaceIn" in device.keys() ) and ( "vlanOut" in device.keys() or "interfaceOut" in device.keys() ) ):
                pass
            else:
                raise F5ModuleError("Devices must specify IN and OUT network settings.")

        ## find duplicate names (part 2)
        devices_dup_check = {}
        for key, value in device_test.items():
            devices_dup_check.setdefault(value, set()).add(key)
        res = filter(lambda x: len(x) >1, devices_dup_check.values())
        if len(list(res)) > 0:
            raise F5ModuleError("Device names must be unique.")


        ## use this to method to create and return a modified copy of the JSON template
        self.config = json_template

        ## get base name
        self.local_name = re.sub('ssloS_', '', self.want.name)

        ## general json settings for all operations
        self.config["name"] = "sslo_ob_SERVICE_" + operation + "_" + self.want.name
        self.config["inputProperties"][0]["value"]["operationType"] = operation
        self.config["inputProperties"][0]["value"]["deploymentName"] = self.want.name
        self.config["inputProperties"][2]["value"]["name"] = self.want.name
        self.config["inputProperties"][2]["value"]["customService"]["name"] = self.want.name
        self.config["inputProperties"][2]["value"]["customService"]["serviceSpecific"]["name"] = self.want.name


        ## =================================
        ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
        ## =================================
        self.config["inputProperties"][0]["value"]["version"] = self.ssloVersion
        self.config["inputProperties"][2]["value"]["version"] = self.ssloVersion
        self.config["inputProperties"][2]["value"]["previousVersion"] = self.ssloVersion


        ## define port remap
        if self.want.portRemap != None:
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


        ## create operation
        if operation == "CREATE":
            ## set these to empty for CREATE
            self.config["inputProperties"][0]["value"]["deploymentReference"] = ""
            self.config["inputProperties"][2]["value"]["existingBlockId"] = ""
            self.config["name"] = "sslo_obj_SERVICE_CREATE_" + self.want.name

            ## for a service CREATE operation, assume all network objects are also new
            ## loop through the list of devices and update JSON accordingly
            
            ## define a dictionary to hold service count:last IP octet information
            services_ip4_list = {1:30,2:62,3:95,4:126,5:158,6:190,7:222,8:255}
            services_ip6_list = {1:"1e",2:"3e",3:"5e",4:"7e",5:"9e",6:"ae",7:"ce",8:"ee"}
            service_cnt = 1

            ## loop through each service dictionary
            for device in self.want.devices:

                ## add f5-ssl-orchestrator-network objects
                ## process to-service network
                if "interfaceIn" in device.keys():
                    ## make deep copy vs. reference, modify as required
                    net_config_in = copy.deepcopy(json_template_f5_ssl_orchestrator_network)
                    net_config_in["name"] = "ssloN_" + device["name"] + "_in"
                    net_config_in["vlan"]["name"] = "ssloN_" + device["name"] + "_in"
                    net_config_in["vlan"]["path"] = "/Common/ssloN_" + device["name"] + "_in.app/ssloN_" + device["name"] + "_in"
                    net_config_in["vlan"]["interface"][0] = device["interfaceIn"]
                    if "tagIn" in device.keys():
                        net_config_in["vlan"]["tag"] = device["tagIn"]
                    else:
                        del net_config_in["vlan"]["tag"]

                    ## =================================
                    ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
                    ## =================================
                    net_config_in["version"] = self.ssloVersion
                    net_config_in["previousVersion"] = self.ssloVersion

                    self.config["inputProperties"][1]["value"].append(net_config_in)

                ## process from-service network
                if "interfaceOut" in device.keys():
                    ## make deep copy vs. reference, modify as required
                    net_config_out = copy.deepcopy(json_template_f5_ssl_orchestrator_network)
                    net_config_out["name"] = "ssloN_" + device["name"] + "_out"
                    net_config_out["vlan"]["name"] = "ssloN_" + device["name"] + "_out"
                    net_config_out["vlan"]["path"] = "/Common/ssloN_" + device["name"] + "_out.app/ssloN_" + device["name"] + "_out"
                    net_config_out["vlan"]["interface"][0] = device["interfaceOut"]
                    if "tagOut" in device.keys():
                        net_config_out["vlan"]["tag"] = device["tagOut"]
                    else:
                        del net_config_out["vlan"]["tag"]

                    ## =================================
                    ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
                    ## =================================
                    net_config_out["version"] = self.ssloVersion
                    net_config_out["previousVersion"] = self.ssloVersion

                    self.config["inputProperties"][1]["value"].append(net_config_out)

                ## add f5-ssl-orchestrator-service-customService-connectionInformation-interfaces objects
                ## process to-service and from-service networks
                ## make a deep copy vs. reference, modify as required
                net_config = copy.deepcopy(json_template_f5_ssl_orchestrator_service_customService_connectionInformation_interfaces)

                if "interfaceIn" in device.keys():
                    net_config["fromBigipVlan"]["name"] = "ssloN_" + device["name"] + "_in"
                    net_config["fromBigipVlan"]["create"] = True
                    net_config["fromBigipVlan"]["path"] = "/Common/ssloN_" + device["name"] + "_in.app/ssloN_" + device["name"] + "_in"
                    net_config["fromBigipVlan"]["interface"][0] = device["interfaceIn"]
                    if "tagIn" in device.keys():
                        net_config["fromBigipVlan"]["tag"] = device["tagIn"]
                    else:
                        del net_config["fromBigipVlan"]["tag"]
                    
                elif "vlanIn" in device.keys():
                    net_config["fromBigipVlan"]["name"] = "ssloN_" + device["name"] + "_in"
                    net_config["fromBigipVlan"]["create"] = False
                    net_config["fromBigipVlan"]["path"] = device["vlanIn"]
                    del net_config["fromBigipVlan"]["interface"]
                    del net_config["fromBigipVlan"]["tag"]

                if "interfaceOut" in device.keys():
                    net_config["toBigipVlan"]["name"] = "ssloN_" + device["name"] + "_out"
                    net_config["toBigipVlan"]["create"] = True
                    net_config["toBigipVlan"]["path"] = "/Common/ssloN_" + device["name"] + "_out.app/ssloN_" + device["name"] + "_out"
                    net_config["toBigipVlan"]["interface"][0] = device["interfaceOut"]
                    if "tagOut" in device.keys():
                        net_config["toBigipVlan"]["tag"] = device["tagOut"]
                    else:
                        del net_config["toBigipVlan"]["tag"]

                elif "vlanOut" in device.keys():
                    net_config["toBigipVlan"]["name"] = "ssloN_" + device["name"] + "_out"
                    net_config["toBigipVlan"]["create"] = False
                    net_config["toBigipVlan"]["path"] = device["vlanOut"]
                    del net_config["toBigipVlan"]["interface"]
                    del net_config["toBigipVlan"]["tag"]

                self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["interfaces"].append(net_config)

                ## add f5-ssl-orchestrator-service-customService-loadbalancing-devices objects
                ## make a deep copy vs. reference, modify as required
                net_config = copy.deepcopy(json_template_f5_ssl_orchestrator_service_customService_loadBalancing_devices)
                if "ratio" in device.keys():
                    net_config["ratio"] = device["ratio"]
                
                if self.want.ipOffset != None:
                    ip4_offset_octet = 32 + self.want.ipOffset
                    ip6_offset_octet = 200 + self.want.ipOffset
                else:
                    ip4_offset_octet = 32
                    ip6_offset_octet = 200
                
                net_config["ip"].append("198.19." + str(ip4_offset_octet) + "." + str(services_ip4_list[service_cnt]))
                net_config["ip"].append("2001:0200:0:" + str(ip6_offset_octet) + "::" + str(services_ip6_list[service_cnt]))
                self.config["inputProperties"][2]["value"]["customService"]["loadBalancing"]["devices"].append(net_config)
                service_cnt += service_cnt

                ## add f5-ssl-orchestrator-service-networkObjects objects
                ## process to-service network
                if "interfaceIn" in device.keys():
                    ## make deep copy vs. reference, modify as required
                    net_config_in = copy.deepcopy(json_template_f5_ssl_orchestrator_service_networkObjects)
                    net_config_in["name"] = "ssloN_" + device["name"] + "_in"
                    net_config_in["vlan"]["name"] = "ssloN_" + device["name"] + "_in"
                    net_config_in["vlan"]["path"] = "/Common/ssloN_" + device["name"] + "_in.app/ssloN_" + device["name"] + "_in"
                    net_config_in["vlan"]["interface"][0] = device["interfaceIn"]
                    if "tagIn" in device.keys():
                        net_config_in["vlan"]["tag"] = device["tagIn"]
                    else:
                        del net_config_in["vlan"]["tag"]

                    ## =================================
                    ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
                    ## =================================
                    net_config_in["version"] = self.ssloVersion
                    net_config_in["previousVersion"] = self.ssloVersion

                    self.config["inputProperties"][2]["value"]["networkObjects"].append(net_config_in)

                ## process from-service network
                if "interfaceOut" in device.keys():
                    ## make deep copy vs. reference, modify as required
                    net_config_out = copy.deepcopy(json_template_f5_ssl_orchestrator_service_networkObjects)
                    net_config_out["name"] = "ssloN_" + device["name"] + "_out"
                    net_config_out["vlan"]["name"] = "ssloN_" + device["name"] + "_out"
                    net_config_out["vlan"]["path"] = "/Common/ssloN_" + device["name"] + "_out.app/ssloN_" + device["name"] + "_out"
                    net_config_out["vlan"]["interface"][0] = device["interfaceOut"]
                    if "tagOut" in device.keys():
                        net_config_out["vlan"]["tag"] = device["tagOut"]
                    else:
                        del net_config_out["vlan"]["tag"]

                    ## =================================
                    ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
                    ## =================================
                    net_config_out["version"] = self.ssloVersion
                    net_config_out["previousVersion"] = self.ssloVersion

                    self.config["inputProperties"][2]["value"]["networkObjects"].append(net_config_out)

            
            ## modify subnet values if ipOffset is not None
            if self.want.ipOffset != None:
                ip4_offset_octet = 32 + self.want.ipOffset
                ip6_offset_octet = 200 + self.want.ipOffset
                self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv4"]["serviceSubnet"] = "198.19." + str(ip4_offset_octet) + ".0"
                self.config["inputProperties"][2]["value"]["customService"]["managedNetwork"]["ipv6"]["serviceSubnet"] = "2001:0200:0:" + str(ip6_offset_octet) + "::"


        ## modify/delete operations
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

            
            if operation in ["MODIFY"]:

                ## a service MODIFY operation could add/remove/change services
                ## must first loop through the supplied list of devices and determine if anything is different, update JSON accordingly
                ## YAML-input devices are in the 'self.want.devices' list
                ## Existing service devices are generated in the servicesList list below

                ## this gets objects from inputProperties/value/customService/connectionInformation/interfaces into a serviceJson variable
                serviceJson = ""
                for i in range(0, len(self.existing_config["inputProperties"])):
                    if self.existing_config["inputProperties"][i]["id"] == "f5-ssl-orchestrator-service":
                        serviceJson = self.existing_config["inputProperties"][i]["value"]["customService"]["connectionInformation"]["interfaces"]
                        break
                
                ## this parses the dictionaries inside the serviceJson variable and creates a new filtered list with only name, interface, tag and vlan
                ## for comparison with yaml-device list. This also creates a list of existing networkBlockIds.
                servicesList = []
                networkIdList = {}
                if serviceJson != "":
                    for i in range(0, len(serviceJson)):
                        tempList = {}
                        name = re.sub('_out$', '', re.sub('_in$', '', re.sub('^ssloN_', '', serviceJson[i]["fromBigipVlan"]["name"])))
                        tempList["name"] = name

                        if "/Common/ssloN" in serviceJson[i]["fromBigipVlan"]["path"]:
                            tempList["interfaceIn"] = serviceJson[i]["fromBigipVlan"]["interface"][0]
                            if "tag" in serviceJson[i]["fromBigipVlan"].keys():
                                tempList["tagIn"] = int(serviceJson[i]["fromBigipVlan"]["tag"])
                            if "networkBlockId" in serviceJson[i]["fromBigipVlan"]:
                                networkIdList[serviceJson[i]["fromBigipVlan"]["name"]] = serviceJson[i]["fromBigipVlan"]["networkBlockId"]
                        else:
                            tempList["vlanIn"] = serviceJson[i]["fromBigipVlan"]["path"]

                        if "/Common/ssloN" in serviceJson[i]["toBigipVlan"]["path"]:
                            tempList["interfaceOut"] = serviceJson[i]["toBigipVlan"]["interface"][0]
                            if "tag" in serviceJson[i]["toBigipVlan"].keys():
                                tempList["tagOut"] = int(serviceJson[i]["toBigipVlan"]["tag"])
                            if "networkBlockId" in serviceJson[i]["toBigipVlan"]:
                                networkIdList[serviceJson[i]["toBigipVlan"]["name"]] = serviceJson[i]["toBigipVlan"]["networkBlockId"]
                        else:
                            tempList["vlanOut"] = serviceJson[i]["toBigipVlan"]["path"]

                        servicesList.append(tempList)


                ## this loops through the two lists (self.want.devices and servicesList) and looks for differences. Any services that are not
                ## the same are added to a changedServices list. Also track any (new) devices in the (yaml) device list not in the existing services list
                changedServices = []
                newDeviceList = copy.deepcopy(self.want.devices)
                for device in self.want.devices:
                    ## loop through servicesList to find dictionary with the same service name
                    sameIn = 1
                    sameOut = 1
                    for service in servicesList:
                        if device["name"] == service["name"]:
                            ## found the same service, now compare the values
                            if "vlanIn" in device.keys() and "vlanIn" not in service.keys():
                                sameIn = 0
                            if "vlanIn" not in device.keys() and "vlanIn" in service.keys():
                                sameIn = 0
                            if "vlanIn" in device.keys() and "vlanIn" in service.keys() and device["vlanIn"] != service["vlanIn"]:
                                sameIn = 0
                            if "interfaceIn" in device.keys() and "interfaceIn" not in service.keys():
                                sameIn = 0
                            if "interfaceIn" not in device.keys() and "interfaceIn" in service.keys():
                                sameIn = 0
                            if "interfaceIn" in device.keys() and "interfaceIn" in service.keys() and device["interfaceIn"] != service["interfaceIn"]:
                                sameIn = 0
                            if "tagIn" in device.keys() and "tagIn" not in service.keys():
                                sameIn = 0
                            if "tagIn" not in device.keys() and "tagIn" in service.keys():
                                sameIn = 0
                            if "tagIn" in device.keys() and "tagIn" in service.keys() and device["tagIn"] != service["tagIn"]:
                                sameIn = 0
                            if sameIn == 0:
                                tmpList = {}
                                tmpList["name"] = "ssloN_" + device["name"] + "_in"
                                if "vlanIn" in device.keys():
                                    tmpList["vlan"] = device["vlanIn"]
                                elif "interfaceIn" in device.keys():
                                    tmpList["interface"] = device["interfaceIn"]
                                    if "tagIn" in device.keys():
                                        tmpList["tag"] = device["tagIn"]
                                changedServices.append(tmpList)

                            if "vlanOut" in device.keys() and "vlanOut" not in service.keys():
                                sameOut = 0
                            if "vlanOut" not in device.keys() and "vlanOut" in service.keys():
                                sameOut = 0
                            if "vlanOut" in device.keys() and "vlanOut" in service.keys() and device["vlanOut"] != service["vlanOut"]:
                                sameOut = 0
                            if "interfaceOut" in device.keys() and "interfaceOut" not in service.keys():
                                sameOut = 0
                            if "interfaceOut" not in device.keys() and "interfaceOut" in service.keys():
                                sameOut = 0
                            if "interfaceOut" in device.keys() and "interfaceOut" in service.keys() and device["interfaceOut"] != service["interfaceOut"]:
                                sameOut = 0
                            if "tagOut" in device.keys() and "tagOut" not in service.keys():
                                sameOut = 0
                            if "tagOut" not in device.keys() and "tagOut" in service.keys():
                                sameOut = 0
                            if "tagOut" in device.keys() and "tagOut" in service.keys() and device["tagOut"] != service["tagOut"]:
                                sameOut = 0
                            if sameOut == 0:
                                tmpList = {}
                                tmpList["name"] = "ssloN_" + device["name"] + "_out"
                                if "vlanOut" in device.keys():
                                    tmpList["vlan"] = device["vlanOut"]
                                elif "interfaceOut" in device.keys():
                                    tmpList["interface"] = device["interfaceOut"]
                                    if "tagOut" in device.keys():
                                        tmpList["tag"] = device["tagOut"]
                                changedServices.append(tmpList)
                            
                            ## also delete this device from localDeviceList
                            for i in range(0, len(newDeviceList)):
                                if newDeviceList[i]["name"] == device["name"]:
                                    del newDeviceList[i]
                                    break

                            break


                ## we now have the changedServices and networkIdList lists. 
                ## the (yaml) device list will aid in building (service)interfaces objects.
                ## the changedServices list will aid in building (service)modifiedNetworkObjects and f5-ssl-orchestrator-network objects.
                ## the networkIdList list will aid in inserting networkBlockId and existingBlockId values where needed
                ## the newDeviceList list will add any new devices to service(networkObjects) and f5-ssl-orchestrator-network objects

                ## update (service)interfaces from (yaml) device list
                for device in self.want.devices:
                    net_config = copy.deepcopy(json_template_f5_ssl_orchestrator_service_customService_connectionInformation_interfaces)

                    ## populate interface properties appropriately
                    if "interfaceIn" in device.keys():
                        net_config["fromBigipVlan"]["name"] = "ssloN_" + device["name"] + "_in"
                        #net_config["fromBigipVlan"]["create"] = True
                        net_config["fromBigipVlan"]["path"] = "/Common/ssloN_" + device["name"] + "_in.app/ssloN_" + device["name"] + "_in"
                        net_config["fromBigipVlan"]["interface"][0] = device["interfaceIn"]
                        if "tagIn" in device.keys():
                            net_config["fromBigipVlan"]["tag"] = device["tagIn"]
                        else:
                            del net_config["fromBigipVlan"]["tag"]
                        if not self.find_existing_network_object("ssloN_" + device["name"] + "_in"):
                            net_config["fromBigipVlan"]["create"] = True
                        
                    elif "vlanIn" in device.keys():
                        net_config["fromBigipVlan"]["name"] = "ssloN_" + device["name"] + "_in"
                        net_config["fromBigipVlan"]["create"] = False
                        net_config["fromBigipVlan"]["path"] = device["vlanIn"]
                        del net_config["fromBigipVlan"]["interface"]
                        del net_config["fromBigipVlan"]["tag"]

                    if "interfaceOut" in device.keys():
                        net_config["toBigipVlan"]["name"] = "ssloN_" + device["name"] + "_out"
                        #net_config["toBigipVlan"]["create"] = True
                        net_config["toBigipVlan"]["path"] = "/Common/ssloN_" + device["name"] + "_out.app/ssloN_" + device["name"] + "_out"
                        net_config["toBigipVlan"]["interface"][0] = device["interfaceOut"]
                        if "tagOut" in device.keys():
                            net_config["toBigipVlan"]["tag"] = device["tagOut"]
                        else:
                            del net_config["toBigipVlan"]["tag"]
                        if not self.find_existing_network_object("ssloN_" + device["name"] + "_out"):
                            net_config["toBigipVlan"]["create"] = True

                    elif "vlanOut" in device.keys():
                        net_config["toBigipVlan"]["name"] = "ssloN_" + device["name"] + "_out"
                        net_config["toBigipVlan"]["create"] = False
                        net_config["toBigipVlan"]["path"] = device["vlanOut"]
                        del net_config["toBigipVlan"]["interface"]
                        del net_config["toBigipVlan"]["tag"]

                    ## if the object is unchanged (does not have an entry in the changedServices list), add its block ID if it exists
                    foundit = 0
                    for service in changedServices:
                        if service["name"] == "ssloN_" + device["name"] + "_in":
                            foundit = 1
                            break
                    if foundit == 0:
                        if "ssloN_" + device["name"] + "_in" in networkIdList.keys():
                            net_config["fromBigipVlan"]["networkBlockId"] = networkIdList["ssloN_" + device["name"] + "_in"]
                            net_config["fromBigipVlan"]["create"] = False

                    foundit = 0
                    for service in changedServices:
                        if service["name"] == "ssloN_" + device["name"] + "_out":
                            foundit = 1
                            break
                    if foundit == 0:
                        if "ssloN_" + device["name"] + "_out" in networkIdList.keys():
                            net_config["toBigipVlan"]["networkBlockId"] = networkIdList["ssloN_" + device["name"] + "_out"]
                            net_config["toBigipVlan"]["create"] = False

                    self.config["inputProperties"][2]["value"]["customService"]["connectionInformation"]["interfaces"].append(net_config)


                ## update (service)modifiedNetworkObjects from changedServices list - only do this for SSLO-created network objects
                for service in changedServices:
                    if "interface" in service.keys():
                        ## only do this if the network object doesn't already exist in JSON block storage
                        if not self.find_existing_network_object(service["name"]):
                            net_config = copy.deepcopy(json_template_f5_ssl_orchestrator_service_networkObjects)
                            net_config["name"] = service["name"]
                            net_config["vlan"]["create"] = True
                            net_config["vlan"]["name"] = service["name"]
                            net_config["vlan"]["path"] = "/Common/" + service["name"] + ".app/" + service["name"]
                            net_config["vlan"]["interface"][0] = service["interface"]
                            if "tag" in service.keys():
                                net_config["vlan"]["tag"] = service["tag"]

                            ## =================================
                            ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
                            ## =================================
                            net_config["version"] = self.ssloVersion
                            net_config["previousVersion"] = self.ssloVersion

                            self.config["inputProperties"][2]["value"]["modifiedNetworkObjects"].append(net_config)
                    

                ## update f5-ssl-orchestrator-network from changedServices list
                for service in changedServices:
                    if "interface" in service.keys():
                        ## only do this if the network object doesn't already exist in JSON block storage
                        if not self.find_existing_network_object(service["name"]):
                            net_config = copy.deepcopy(json_template_f5_ssl_orchestrator_network)
                            net_config["name"] = service["name"]
                            net_config["vlan"]["name"] = service["name"]
                            net_config["vlan"]["create"] = False
                            net_config["vlan"]["modify"] = True
                            net_config["vlan"]["path"] = "/Common/" + service["name"] + ".app/" + service["name"]
                            net_config["vlan"]["interface"][0] = service["interface"]
                            if "tag" in service.keys():
                                net_config["vlan"]["tag"] = service["tag"]
                            else:
                                del net_config["vlan"]["tag"]
                            if service["name"] in networkIdList.keys():
                                net_config["existingBlockId"] = networkIdList[service["name"]]

                            ## =================================
                            ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
                            ## =================================
                            net_config["version"] = self.ssloVersion
                            net_config["previousVersion"] = self.ssloVersion

                            self.config["inputProperties"][1]["value"].append(net_config)


                ## update (service)loadBalancing from (yaml) device list
                ## define a dictionary to hold service count:last IP octet information
                services_ip4_list = {1:30,2:62,3:95,4:126,5:158,6:190,7:222,8:255}
                services_ip6_list = {1:"1e",2:"3e",3:"5e",4:"7e",5:"9e",6:"ae",7:"ce",8:"ee"}
                service_cnt = 1
                for device in self.want.devices:
                    net_config = copy.deepcopy(json_template_f5_ssl_orchestrator_service_customService_loadBalancing_devices)
                    if "ratio" in device.keys():
                        net_config["ratio"] = device["ratio"]
                    
                    if self.want.ipOffset != None:
                        ip4_offset_octet = 32 + self.want.ipOffset
                        ip6_offset_octet = 200 + self.want.ipOffset
                    else:
                        ip4_offset_octet = 32
                        ip6_offset_octet = 200
                    
                    net_config["ip"].append("198.19." + str(ip4_offset_octet) + "." + str(services_ip4_list[service_cnt]))
                    net_config["ip"].append("2001:0200:0:" + str(ip6_offset_octet) + "::" + str(services_ip6_list[service_cnt]))
                    self.config["inputProperties"][2]["value"]["customService"]["loadBalancing"]["devices"].append(net_config)
                    service_cnt += service_cnt


                ## update service(networkObjects) and f5-ssl-orchestrator-network objects if newDeviceList is not empty
                if len(newDeviceList) > 0:
                    ## update service(networkObjects)
                    for device in newDeviceList:
                        if "interfaceIn" in device.keys():
                            ## make deep copy vs. reference, modify as required
                            net_config_in = copy.deepcopy(json_template_f5_ssl_orchestrator_service_networkObjects)
                            net_config_in["name"] = "ssloN_" + device["name"] + "_in"
                            net_config_in["vlan"]["name"] = "ssloN_" + device["name"] + "_in"
                            net_config_in["vlan"]["path"] = "/Common/ssloN_" + device["name"] + "_in.app/ssloN_" + device["name"] + "_in"
                            net_config_in["vlan"]["interface"][0] = device["interfaceIn"]
                            if "tagIn" in device.keys():
                                net_config_in["vlan"]["tag"] = device["tagIn"]
                            else:
                                del net_config_in["vlan"]["tag"]

                            ## =================================
                            ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
                            ## =================================
                            net_config_in["version"] = self.ssloVersion
                            net_config_in["previousVersion"] = self.ssloVersion

                            self.config["inputProperties"][2]["value"]["networkObjects"].append(net_config_in)

                        ## process from-service network
                        if "interfaceOut" in device.keys():
                            ## make deep copy vs. reference, modify as required
                            net_config_out = copy.deepcopy(json_template_f5_ssl_orchestrator_service_networkObjects)
                            net_config_out["name"] = "ssloN_" + device["name"] + "_out"
                            net_config_out["vlan"]["name"] = "ssloN_" + device["name"] + "_out"
                            net_config_out["vlan"]["path"] = "/Common/ssloN_" + device["name"] + "_out.app/ssloN_" + device["name"] + "_out"
                            net_config_out["vlan"]["interface"][0] = device["interfaceOut"]
                            if "tagOut" in device.keys():
                                net_config_out["vlan"]["tag"] = device["tagOut"]
                            else:
                                del net_config_out["vlan"]["tag"]

                            ## =================================
                            ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
                            ## =================================
                            net_config_out["version"] = self.ssloVersion
                            net_config_out["previousVersion"] = self.ssloVersion

                            self.config["inputProperties"][2]["value"]["networkObjects"].append(net_config_out)

                    ## update f5-ssl-orchestrator-network objects
                    for device in newDeviceList:
                        if "interfaceIn" in device.keys():
                            ## make deep copy vs. reference, modify as required
                            net_config_in = copy.deepcopy(json_template_f5_ssl_orchestrator_network)
                            net_config_in["name"] = "ssloN_" + device["name"] + "_in"
                            net_config_in["vlan"]["name"] = "ssloN_" + device["name"] + "_in"
                            net_config_in["vlan"]["path"] = "/Common/ssloN_" + device["name"] + "_in.app/ssloN_" + device["name"] + "_in"
                            net_config_in["vlan"]["interface"][0] = device["interfaceIn"]
                            if "tagIn" in device.keys():
                                net_config_in["vlan"]["tag"] = device["tagIn"]
                            else:
                                del net_config_in["vlan"]["tag"]

                            ## =================================
                            ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
                            ## =================================
                            net_config_in["version"] = self.ssloVersion
                            net_config_in["previousVersion"] = self.ssloVersion

                            self.config["inputProperties"][1]["value"].append(net_config_in)

                        ## process from-service network
                        if "interfaceOut" in device.keys():
                            ## make deep copy vs. reference, modify as required
                            net_config_out = copy.deepcopy(json_template_f5_ssl_orchestrator_network)
                            net_config_out["name"] = "ssloN_" + device["name"] + "_out"
                            net_config_out["vlan"]["name"] = "ssloN_" + device["name"] + "_out"
                            net_config_out["vlan"]["path"] = "/Common/ssloN_" + device["name"] + "_out.app/ssloN_" + device["name"] + "_out"
                            net_config_out["vlan"]["interface"][0] = device["interfaceOut"]
                            if "tagOut" in device.keys():
                                net_config_out["vlan"]["tag"] = device["tagOut"]
                            else:
                                del net_config_out["vlan"]["tag"]

                            ## =================================
                            ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
                            ## =================================
                            net_config_out["version"] = self.ssloVersion
                            net_config_out["previousVersion"] = self.ssloVersion

                            self.config["inputProperties"][1]["value"].append(net_config_out)


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
            devices=dict(
                required=True,
                type='list'
            ),
            state=dict(
                default='present',
                choices=['absent','present']
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
            ipOffset=dict(
                type='int',
                default=0
            ),
            rules=dict(
                type='list'
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