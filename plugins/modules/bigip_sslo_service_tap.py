#!/usr/bin/python
# -*- coding: utf-8 -*-
# 
# Copyright: (c) 2021, kevin-dot-g-dot-stewart-at-gmail-dot-com
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Version: 1.0

#### To Do:
#### Test what happens when interface, tag or subnet in use

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_tap_service
short_description: Manage an SSL Orchestrator TAP security device
description:
  - Manage an SSL Orchestrator TAP security device
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the TAP security service. Configuration auto-prepends "ssloS_" to service.
        Service name should be less than 14 characters and not contain dashes "-".
    type: str
    required: True
  devices:
    description:
      - Specifies the network attachment for the TAP security device
    suboptions:
      vlan:
        description: used to indicate an existing VLAN to attach the TAP service to. The vlan and interface keys are mutually exclusive.
        type: string
      interface:
        description: used to indicate the interface to attach to when SSLO creates the VLAN. The vlan and interface keys are mutually exclusive.
        type: string
      tag:
        description: used to indicate the VLAN tag, if SSLO creates the VLAN, and the service requires 802.1Q.
        type: int
        default: None
    required: True
  macAddress:
    description:
      - Specifies the MAC address to use for the TAP service clone pool (static ARP). 
    type: str
    default: F5:F5:F5:F5:XX:YY (where XX:YY are generated from a hash of the service name)
  portRemap:
    description:
      - Specifies the port number to remap to for traffic to this TAP service.
    type: int
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
- name: Create SSLO service(s)
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
    - name: create TAP service VLAN
      bigip_vlan:
        provider: "{{ provider }}"
        name: TAPservice_vlan
        tagged_interface: 1.7
      delegate_to: localhost

    - name: SSLO TAP service
      bigip_sslo_service_tap:
        provider: "{{ provider }}"
        name: "tap1"
        devices: 
          vlan: "/Common/TAPservice_vlan"
      delegate_to: localhost

- name: Create SSLO service(s)
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
    - name: SSLO TAP service
      bigip_sslo_service_tap:
        provider: "{{ provider }}"
        name: "tap1"
        state: "present"
        devices: 
          interface: "1.7"
          port: 1000
        macAddress: "12:12:12:12:12:12"
        portRemap: 8080
      delegate_to: localhost
'''

RETURN = r'''
name:
  description:
    - Changed name of TAP service.
  type: str
  sample: tap1
devices:
  description:
    - Changed value of (existing) vlan or interface (and optional 802.1Q tag) for TAP services.
  type: list
  sample (vlan): "/Common/existing-tap-vlan"
  sample (interface): "1.7"
state:
  description:
    - Changed state.
  type: str
  sample: present
macAddress:
  description:
    - Changed MAC address value of TAP services.
  type: str
  sample: "12:12:12:12:12:12"
portRemap:
  description:
    - Changed port remap value.
  type: int
  sample: 8080

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
import json, time, re, hashlib

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
    "name": "sslo_ob_SERVICE_TEMPLATE_OPERATION_TEMPLATE_NAME",
    "inputProperties": [
        {
            "id": "f5-ssl-orchestrator-operation-context",
            "type": "JSON",
            "value": {
                "operationType": "TEMPLATE_OPERATION",
                "deploymentType": "SERVICE",
                "deploymentName": "TEMPLATE_NAME",
                "deploymentReference": "TEMPLATE_DEPLOYMENT_REFERENCE",
                "partition": "Common",
                "version": "7.2",
                "strictness": False
            }
        },
        {
            "id": "f5-ssl-orchestrator-network",
            "type": "JSON",
            "value": [
                {
                    "name": "TEMPLATE_NET_NAME",
                    "partition": "Common",
                    "strictness": False,
                    "vlan": {
                        "create": True,
                        "path": "TEMPLATE_NET_NAME_APP_PATH",
                        "tag": "1322",
                        "name": "TEMPLATE_NET_NAME",
                        "interface": [
                            "TEMPLATE_INTERFACE"
                        ]
                    },
                    "selfIpConfig": {
                        "create": False,
                        "netmask": "",
                        "selfIp": "",
                        "floating": False,
                        "HAstaticIpMap": [
                            {
                                "deviceMgmtIp": "",
                                "selfIp": ""
                            }
                        ]
                    },
                    "routeDomain": {
                        "create": False,
                        "path": "",
                        "id": 0.0
                    }
                }
            ]
        },
        {
            "id": "f5-ssl-orchestrator-service",
            "type": "JSON",
            "value": [
                {
                    "description": "Type: tap",
                    "createNewNetworkObj": {
                        "name": "TEMPLATE_NET_NAME",
                        "networkTag": 1000,
                        "networkInterface": "TEMPLATE_INTERFACE"
                    },
                    "useExistingNetworkObj": {
                        "path": "",
                        "interface": ""
                    },
                    "customService": {
                        "name": "TEMPLATE_NAME",
                        "serviceType": "tap",
                        "connectionInformation": [{}],
                        "loadBalancing": {"devices": [],"monitor": {}},
                        "portRemap": False,
                        "serviceDownAction": "ignore",
                        "iRuleReference": "",
                        "httpPortRemapValue": 80,
                        "serviceSpecific": {
                            "description": "",
                            "macAddress": "TEMPLATE_MAC",
                            "name": "TEMPLATE_NAME",
                            "vlan": {
                                "create": True,
                                "path": "/Common/ssloN_TAP_VLAN.app/ssloN_TAP_VLAN",
                                "interfacesList": [],
                                "interface": "",
                                "name": "TEMPLATE_NET_NAME",
                                "networkTag": 'null',
                                "tag": 'null'
                            },
                            "vendorConfig": {
                                "name": "TAP Service",
                                "model": "",
                                "product": "",
                                "version": ""
                            }
                        },
                        "managedNetwork": {
                            "ipFamily": "both",
                            "serviceType": "tap",
                            "ipv4": {
                                "serviceType": "tap",
                                "ipFamily": "ipv4",
                                "serviceSubnet": "TEMPLATE_IPV4_SUBNET",
                                "serviceIndex": 2,
                                "subnetMask": "255.255.255.252",
                                "serviceSelfIp": "TEMPLATE_IPV4_SELF_IP",
                                "serviceHASelfIp": "TEMPLATE_IPV4_HA_SELF_IP",
                                "deviceIp": "TEMPLATE_IPV4_DEVICE_IP"
                            },
                            "ipv6": {
                                "serviceType": "tap",
                                "ipFamily": "ipv6",
                                "serviceSubnet": "TEMPLATE_IPV6_SUBNET",
                                "serviceIndex": 2,
                                "subnetMask": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0",
                                "serviceSelfIp": "TEMPLATE_IPV6_SELF_IP",
                                "serviceHASelfIp": "TEMPLATE_IPV6_HA_SELF_IP",
                                "deviceIp": "TEMPLATE_IPV6_DEVICE_IP"
                            }
                        }
                    },
                    "vendorInfo": {
                        "name": "TAP Service",
                        "model": "",
                        "product": "",
                        "version": ""
                    },
                    "name": "TEMPLATE_NAME",
                    "useTemplate": False,
                    "serviceTemplate": "",
                    "templateName": "TAP Service",
                    "partition": "Common",
                    "version": "7.2",
                    "strictness": False,
                    "previousVersion": "7.2"
                }
            ]
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
    def device_vlan(self):
        device_vlan = self._values['devices']['vlan']
        if device_vlan is None:
            return None
        return device_vlan

    @property
    def device_interface(self):
        device_interface = self._values['devices']['interface']
        if device_interface is None:
            return None
        return device_interface

    @property
    def device_tag(self):
        device_tag = self._values['devices']['tag']
        if device_tag is None:
            return None
        return device_tag

    @property
    def macAddress(self):
        macAddress = self._values['macAddress']
        if macAddress is None:
            macAddress = 'F5:F5:F5:F5:XX:YY'
        return macAddress

    @property
    def portRemap(self):
        portRemap = self._values['portRemap']
        return portRemap

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
        self.mode_output = ""


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
        self.local_name = re.sub('ssloS_', '', self.want.name)

        ## general json settings for all operations
        self.config["name"] = "sslo_ob_SERVICE_" + operation + "_" + self.want.name
        self.config["inputProperties"][0]["value"]["operationType"] = operation
        self.config["inputProperties"][0]["value"]["deploymentName"] = self.want.name
        self.config["inputProperties"][2]["value"][0]["name"] = self.want.name
        self.config["inputProperties"][2]["value"][0]["customService"]["name"] = self.want.name
        self.config["inputProperties"][2]["value"][0]["customService"]["serviceSpecific"]["name"] = self.want.name


        ## set macAddress
        if self.want.macAddress == "F5:F5:F5:F5:XX:YY":
            mac_random_octet = re.sub("0x", '', hex((int(hashlib.md5(self.local_name.encode()).hexdigest(), 16) % 65535) + 1))
            mac_pieces = list(map(''.join, zip(*[iter(mac_random_octet)]*2)))
            self.macAddress = re.sub("XX", mac_pieces[0], self.want.macAddress)
            self.macAddress = re.sub("YY", mac_pieces[1], self.macAddress)
            self.config["inputProperties"][2]["value"][0]["customService"]["serviceSpecific"]["macAddress"] = self.macAddress
        else:
            self.config["inputProperties"][2]["value"][0]["customService"]["serviceSpecific"]["macAddress"] = self.want.macAddress


        ## test for create network or use existing
        if self.want.device_vlan != None:
            ## build for an existing VLAN
            del self.config["inputProperties"][1]["value"][0]
            self.config["inputProperties"][2]["value"][0]["createNewNetworkObj"]["name"] = ""
            self.config["inputProperties"][2]["value"][0]["createNewNetworkObj"]["networkTag"] = ""
            self.config["inputProperties"][2]["value"][0]["createNewNetworkObj"]["networkInterface"] = ""
            self.config["inputProperties"][2]["value"][0]["useExistingNetworkObj"]["path"] = self.want.device_vlan
            self.config["inputProperties"][2]["value"][0]["customService"]["serviceSpecific"]["vlan"]["create"] = False
            self.config["inputProperties"][2]["value"][0]["customService"]["serviceSpecific"]["vlan"]["path"] = self.want.device_vlan
            self.config["inputProperties"][2]["value"][0]["customService"]["serviceSpecific"]["vlan"]["name"] = ""
        
        elif self.want.device_interface != None:
            ## build for an SSLO-created network
            self.config["inputProperties"][1]["value"][0]["name"] = "ssloN_" + self.local_name
            self.config["inputProperties"][1]["value"][0]["vlan"]["path"] = "/Common/ssloN_" + self.local_name + ".app/ssloN_" + self.local_name
            self.config["inputProperties"][1]["value"][0]["vlan"]["name"] = "ssloN_" + self.local_name
            self.config["inputProperties"][1]["value"][0]["vlan"]["interface"][0] = self.want.device_interface

            self.config["inputProperties"][2]["value"][0]["createNewNetworkObj"]["name"] = "ssloN_" + self.local_name            
            self.config["inputProperties"][2]["value"][0]["createNewNetworkObj"]["networkInterface"] = self.want.device_interface
            self.config["inputProperties"][2]["value"][0]["useExistingNetworkObj"]["path"] = ""
            self.config["inputProperties"][2]["value"][0]["customService"]["serviceSpecific"]["vlan"]["create"] = True
            self.config["inputProperties"][2]["value"][0]["customService"]["serviceSpecific"]["vlan"]["path"] = "/Common/ssloN_" + self.local_name + ".app/ssloN_" + self.local_name
            self.config["inputProperties"][2]["value"][0]["customService"]["serviceSpecific"]["vlan"]["interface"] = self.want.device_interface
            self.config["inputProperties"][2]["value"][0]["customService"]["serviceSpecific"]["vlan"]["name"] = "ssloN_" + self.local_name
        
            if self.want.device_tag != None:
                ## build for tag if SSLO-created network
                self.config["inputProperties"][1]["value"][0]["vlan"]["tag"] = self.want.device_tag

                self.config["inputProperties"][2]["value"][0]["createNewNetworkObj"]["networkTag"] = self.want.device_tag
                self.config["inputProperties"][2]["value"][0]["customService"]["serviceSpecific"]["vlan"]["networkTag"] = self.want.device_tag
                self.config["inputProperties"][2]["value"][0]["customService"]["serviceSpecific"]["vlan"]["tag"] = self.want.device_tag
        
        ## configure portremap
        if self.want.portRemap is None:
            self.config["inputProperties"][2]["value"][0]["customService"]["portRemap"] = False
        else:
            self.config["inputProperties"][2]["value"][0]["customService"]["portRemap"] = True
            self.config["inputProperties"][2]["value"][0]["customService"]["httpPortRemapValue"] = self.want.portRemap


        ## configure managedNetwork
        ipv4_random_octet = (int(hashlib.md5(self.local_name.encode()).hexdigest(), 16) % 252) + 1
        ipv6_random_octet = re.sub("0x", '', hex((int(hashlib.md5(self.local_name.encode()).hexdigest(), 16) % 65535) + 1))
        self.config["inputProperties"][2]["value"][0]["customService"]["managedNetwork"]["ipv4"]["serviceSubnet"] = "198.19." + str(ipv4_random_octet) + ".0"
        self.config["inputProperties"][2]["value"][0]["customService"]["managedNetwork"]["ipv4"]["serviceSelfIp"] = "198.19." + str(ipv4_random_octet) + ".8"
        self.config["inputProperties"][2]["value"][0]["customService"]["managedNetwork"]["ipv4"]["serviceHASelfIp"] = "198.19." + str(ipv4_random_octet) + ".9"
        self.config["inputProperties"][2]["value"][0]["customService"]["managedNetwork"]["ipv4"]["deviceIp"] = "198.19." + str(ipv4_random_octet) + ".10"
        
        self.config["inputProperties"][2]["value"][0]["customService"]["managedNetwork"]["ipv6"]["serviceSubnet"] = "2001:200:0:" + str(ipv6_random_octet) + "::"
        self.config["inputProperties"][2]["value"][0]["customService"]["managedNetwork"]["ipv6"]["serviceSelfIp"] = "2001:200:0:" + str(ipv6_random_octet) + "::9"
        self.config["inputProperties"][2]["value"][0]["customService"]["managedNetwork"]["ipv6"]["serviceHASelfIp"] = "2001:200:0:" + str(ipv6_random_octet) + "::9"
        self.config["inputProperties"][2]["value"][0]["customService"]["managedNetwork"]["ipv6"]["deviceIp"] = "2001:200:0:" + str(ipv6_random_octet) + "::a"
      

        if operation == "CREATE":
            ## set these to empty for CREATE
            self.config["inputProperties"][0]["value"]["deploymentReference"] = ""
            self.config["inputProperties"][2]["value"][0]["existingBlockId"] = ""
            self.config["name"] = "sslo_obj_SERVICE_CREATE_" + self.want.name

            
        elif operation in ["DELETE", "MODIFY"]:
            self.config["name"] = "sslo_obj_SERVICE_MODIFY_" + self.want.name

            ## clear the network block for DELETE operation
            if operation in ["DELETE"]:
                del self.config["inputProperties"][1]["value"][0]

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
                self.config["inputProperties"][2]["value"][0]["existingBlockId"] = id
            except:
                raise F5ModuleError("Failure to create/modify - unable to fetch object ID")

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
            ## object doesn't exit - just exit (changed = false)
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
        resp = self.client.api.get(uri)

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
            devices=dict(
                required=True,
                type='dict',
                options=dict(
                    vlan=dict(),
                    interface=dict(),
                    tag=dict(type=int),
                ),
                mutually_exclusive=[
                  ('vlan', 'interface')
                ],
                required_one_of=[
                  ('vlan', 'interface')
                ]
            ),
            state=dict(
                default='present',
                choices=['absent','present']
            ),
            macAddress=dict(
                default='F5:F5:F5:F5:XX:YY'
            ),
            portRemap=dict(
                type='int'
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