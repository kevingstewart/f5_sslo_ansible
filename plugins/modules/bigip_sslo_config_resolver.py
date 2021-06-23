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
module: bigip_sslo_config_resolver
short_description: Manage the SSL Orchestrator DNS resolver config
description:
  - Manage the SSL Orchestrator DNS resolver config
version_added: "1.0.0"
options:
  forwardingNameservers:
    description:
      - Specifies the list of IP addresses for forwarding nameservers. Declaration can contain a forwardingNameservers key, or forwardingZones key, but not both.
    type: list
    elements: str
  forwardingZones:
    description:
      - Specifies the list of zone:nameservers key pairs.
    type: list
    elements: dict
    suboptions:
      zone:
        description: 
            - Defines the zone pattern.
        type: str
      nameservers:
        description: 
            - Defines the list of nameservers for this zone.
        type: list
        elements: str
  enableDNSsec: 
    description: 
        - Enables or disables DNS security.
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
- name: Create SSLO DNS resolver (forwarding nameservers)
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
    - name: SSLO dns resolver
      bigip_sslo_config_resolver:
        provider: "{{ provider }}"

        forwardingNameservers:
          - "10.1.20.1"
          - "10.1.20.2"
          - "fd66:2735:1533:46c1:68c8:0:0:7110"
          - "fd66:2735:1533:46c1:68c8:0:0:7111"
      delegate_to: localhost

- name: Create SSLO DNS resolver (forwarding zones)
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
    - name: SSLO dns resolver
      bigip_sslo_config_resolver:
        provider: "{{ provider }}"

        forwardingZones:
          - zone: "."
            nameservers:
              - "10.1.20.1"
              - "10.1.20.5"
          - zone: "foo."
            nameservers:
              - "8.8.8.8"
              - "8.8.4.4"
              - "fd66:2735:1533:46c1:68c8:0:0:7113"

        enableDNSsec: True
      delegate_to: localhost
'''

RETURN = r'''
forwardingNameservers:
  description:
    - Changed list of nameserver IP addresses.
  type: str
  sample: 8.8.8.8
forwardingZones:
  description: 
    - Changed list of zone:nameserver key pairs.
  type: complex
  contains:
    zone:
       description: defines the zone name.
       type: str
       sample: "."
    nameservers:
       description: defines the list of nameserver IP addresses for this zone.
       type: str
       sample: 8.8.8.8
enableDNSsec:
    description: 
        - Changed the DNS security option.
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
from ansible_collections.f5networks.f5_modules.plugins.module_utils.bigip import F5RestClient
from ansible_collections.f5networks.f5_modules.plugins.module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec
)
from ansible_collections.f5networks.f5_modules.plugins.module_utils.icontrol import tmos_version
import json, time, re, hashlib, ipaddress

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
                "strictness":False,
                "existingBlockId":""
           }
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

json_logging_config = {
    "logLevel":0,
    "logPublisher":"none",
    "statsToRecord":0
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
    def forwarding_nameservers(self):
        forwarding_nameservers = self._values['forwardingNameservers']
        if forwarding_nameservers == None:
            return None
        return forwarding_nameservers

    @property
    def forwarding_zones(self):
        forwarding_zones = self._values['forwardingZones']
        if forwarding_zones == None:
            return None
        return forwarding_zones

    @property
    def enable_dnssec(self):
        try: 
            enable_dnssec = self._values['enableDNSsec']
            if enable_dnssec == None:
                return False
            return enable_dnssec
        except:
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


    def validIPAddress(self, IP):    
        def isIPv4(s):
            try: return str(int(s)) == s and 0 <= int(s) <= 255
            except: return False
        def isIPv6(s):
            if len(s) > 4:
                return False
            try : return int(s, 16) >= 0 and s[0] != '-'
            except:
                return False
        if IP.count(".") == 3 and all(isIPv4(i) for i in IP.split(".")):
            return "ipv4"
        if IP.count(":") == 7 and all(isIPv6(i) for i in IP.split(":")):
            return "ipv6"
        return "None"


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


        ## perform some input validation
        ## input validation: forwardingNameservers and forwardingZones cannot both be None
        if self.want.forwarding_nameservers == None and self.want.forwarding_zones == None:
            raise F5ModuleError("one of the following is required: forwardingNameservers, forwardingZones.")


        ## process general json settings for all operations
        self.config["inputProperties"][0]["value"]["operationType"] = operation


        ## version difference: for SSLO 5.x, JSON also requires a loggingConfig block        
        if self.ssloVersion < 6.0:
            self.config["inputProperties"][1]["value"]["loggingConfig"] = json_logging_config


        if self.want.forwarding_nameservers != None:
            ## process JSON for forwarding nameservers
            self.config["inputProperties"][1]["value"]["dns"]["enableLocalDnsQueryResolution"] = True
            
            ## loop through list of IP addresses, add to JSON block and determine IP family
            ipFamily = ""
            for ipaddr in self.want.forwarding_nameservers:
                try:
                    ip = ipaddress.ip_address(ipaddr)
                    if ipFamily != "" and ip.version != ipFamily:
                        ipFamily = "both"
                    else:
                        ipFamily = ip.version
                except ValueError:
                    raise F5ModuleError("A submitted IP address does not conform to standard notation: " + str(ipaddr) + ".")
                except:
                    raise F5ModuleError("A submitted IP address does not conform to standard notation: " + str(ipaddr) + ".")

                self.config["inputProperties"][1]["value"]["dns"]["localDnsNameservers"].append(ipaddr)

            if ipFamily == 4:
                ipf = "ipv4"                
            elif ipFamily == 6:
                ipf = "ipv6"
            elif ipFamily == "both":
                ipf = "both"
            
            self.config["inputProperties"][1]["value"]["ipFamily"] = ipf
                

        elif self.want.forwarding_zones != None:
            ## process JSON for forwarding zones
            self.config["inputProperties"][1]["value"]["dns"]["enableLocalDnsZones"] = True

            ## loop through list of IP addresses, add to JSON block and determine IP family
            ipFamily = ""
            for zone in self.want.forwarding_zones:
                ## input validation: forwardingZones key must have a 'zone' and 'nameservers' subkey
                if "zone" not in zone:
                    raise F5ModuleError("A forwarding zone requires a list of at least one 'zone' and 'nameservers' key pair.")
                if "nameservers" not in zone:
                    raise F5ModuleError("A forwarding zone requires a list of at least one 'zone' and 'nameservers' key pair.")

                ## input validation: the 'nameservers' subkey must contain at least one entry
                if zone["nameservers"] == None:
                    raise F5ModuleError("A forwarding zone 'nameservers' key must contain at least one IP address entry.")

                this_zone = {}
                this_zone["zone"] = zone["zone"]
                this_zone["nameServerIps"] = []
                for ipaddr in zone["nameservers"]:                    
                    try:
                        ip = ipaddress.ip_address(ipaddr)
                        if ipFamily != "" and ip.version != ipFamily:
                            ipFamily = "both"
                        else:
                            ipFamily = ip.version
                    except ValueError:
                        raise F5ModuleError("A submitted IP address does not conform to standard notation: " + str(ipaddr) + ".")
                    except:
                        raise F5ModuleError("A submitted IP address does not conform to standard notation: " + str(ipaddr) + ".")

                    this_zone["nameServerIps"].append(ipaddr)
                
                self.config["inputProperties"][1]["value"]["dns"]["localDnsZones"].append(this_zone)

            if ipFamily == 4:
                    ipf = "ipv4"                
            elif ipFamily == 6:
                ipf = "ipv6"
            elif ipFamily == "both":
                ipf = "both"
            
            self.config["inputProperties"][1]["value"]["ipFamily"] = ipf
                
        ## dnssec
        self.config["inputProperties"][1]["value"]["dns"]["enableDnsSecurity"] = self.want.enable_dnssec


        ## create operation
        if operation == "CREATE":            
            #### TO DO: update JSON code for CREATE operation
            self.config["name"] = "sslo_obj_GENERAL_SETTINGS_CREATE_ssloGS_global"


        ## modify/delete operations
        elif operation in ["DELETE", "MODIFY"]:
            self.config["name"] = "sslo_obj_GENERAL_SETTINGS_MODIFY_ssloGS_global"

            ## get object ID and add to deploymentReference and existingBlockId values
            uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                self.client.provider['server'],
                self.client.provider['server_port']
            )
            query = "?$filter=name+eq+'{0}'&$select=id".format(self.name)
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
        self.name = "ssloGS_global"

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
                    raise F5ModuleError("Object " + self.name + " create/modify operation timeout")

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
                    raise F5ModuleError("Object " + self.name + " create/modify operation timeout")


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
                    raise F5ModuleError("Object " + self.name + " create/modify operation timeout")

        else:
            ## object doesn't exit - just exit (changed = False)
            return False


    def exists(self):
        ## use this method to see if the objects already exists - queries for the respective application service object
        uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        query = "?$filter=name+eq+'{0}'".format(self.name)
        resp = self.client.api.get(uri + query)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            
            foundit = 0
            for i in range(0, len(response["items"])):
                try:
                    if str(response["items"][i]["name"]) == self.name:
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
            forwardingNameservers=dict(type='list'),
            forwardingZones=dict(type='list'),
            enableDNSsec=dict(
                type='bool',
                default=False
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
        self.mutually_exclusive=[
            ['forwardingNameservers', 'forwardingZones']
        ]
        self.required_one_of=[
            ['forwardingNameservers', 'forwardingZones']
        ]

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
        mutually_exclusive=spec.mutually_exclusive,
        required_one_of=spec.required_one_of
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