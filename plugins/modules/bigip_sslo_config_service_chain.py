#!/usr/bin/python
# -*- coding: utf-8 -*-
# 
# Copyright: (c) 2021, kevin-dot-g-dot-stewart-at-gmail-dot-com
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Version: 1.0.1

#### Updates:
#### 1.0.1 - added 9.0 support (same as 8.3 so just changed max version)
#          - updated version and previousVersion keys to match target SSLO version


from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_config_service_chain
short_description: Manage an SSL Orchestrator service chain
description:
  - Manage an SSL Orchestrator service chain
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the service chain. Configuration auto-prepends "ssloSC_" to service. Service name should be less than 14 characters and not contain dashes "-". Note that service chain creation/management does not verify that the defined services exist.
    type: str
    required: True
  services:
    description:
      - Specifies the client-side SSL settings
    required: True
    type: list
    elements: dict
    suboptions:
      name:
        description: 
            - Defines the name of the service.
        type: str
        required: True
      serviceType:
        description: 
            - Defines the type of service.
        type: str
        choices:
            - L2
            - L3
            - http-proxy
            - icap
            - tap
        required: True
      ipFamily: 
        description: 
            - Defines the IP family for this service.
        type: str
        choices:
            - ipv4
            - ipv6
        default: ipv4
  
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
- name: Create SSLO Service Chain
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
    - name: SSLO service chain
      bigip_sslo_config_service_chain:
        provider: "{{ provider }}"
        name: "demo_chain_1"
        
        services:
          - name: "icap3"
            serviceType: "icap"
            ipFamily: "ipv4"

          - name: "layer3a"
            serviceType: "L3"
            ipFamily: "ipv4"
      delegate_to: localhost
'''

RETURN = r'''
name:
  description:
    - Changed name of service chain.
  type: str
  sample: demo_chain_1
services:
  description: list of services to include in the service chain
  type: complex
  contains:
    name:
       description: defines the name of the service.
       type: str
       sample: icap3
    ipFamily:
       description: defines the IP family for the specified service. Options are 'ipv4', or 'ipv6'.
       type: str
       sample: ipv4
    serviceType:
       description: defines the service type for the specified service. Options are 'L2', 'L3', 'http-proxy', 'icap', or 'tap'.
       type: str
       sample: icap

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
import json, time, re, hashlib

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
            "operationType":"TEMPLATE_OPERATION",
            "deploymentType":"SERVICE_CHAIN",
            "deploymentName":"TEMPLATE_NAME",
            "deploymentReference":"",
            "partition":"Common",
            "strictness":False
         }
      },
      {
         "id":"f5-ssl-orchestrator-service-chain",
         "type":"JSON",
         "value": {
               "name": "TEMPLATE_NAME",
               "description": "",
               "orderedServiceList": [],
               "partition": "Common",
               "version": "7.2",
               "strictness": False,
               "previousVersion": "7.2"
           }
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
        name = "ssloSC_" + name
        return name

    @property
    def services(self):
        try:
            services = self._values['services']
            if services == None:
                return None
            return services
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
        self.local_name = re.sub('ssloSC_', '', self.want.name)

        ## perform some input validation
        ## input validation: there must be at least one service devices under services key
        #if self.want.services == None:
        #    raise F5ModuleError("The 'services' key must contain at least one service definition.")


        ## process general json settings for all operations
        self.config["inputProperties"][0]["value"]["deploymentName"] = self.want.name
        self.config["inputProperties"][0]["value"]["operationType"] = operation
        self.config["inputProperties"][1]["value"]["name"] = self.want.name


        ## =================================
        ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
        ## =================================
        self.config["inputProperties"][0]["value"]["version"] = self.ssloVersion
        self.config["inputProperties"][1]["value"]["version"] = self.ssloVersion
        self.config["inputProperties"][1]["value"]["previousVersion"] = self.ssloVersion


        ## process service chains
        if self.want.services != None:
            for service in self.want.services:
                ## input validation: service must contain 'name', 'ipFamily', and 'serviceType' keys
                if "name" not in service:
                    raise F5ModuleError("Each service must contain a 'name' key.")
                
                ## input validation: ipFamily key must either be 'ipv4' or 'ipv6'. If key doesn't exist, assume 'ipv4'
                if "ipFamily" not in service:
                    ipfamily = 'ipv4'
                else:
                    ipfamily = service["ipFamily"]
                
                ## input validation: serviceType key must either be 'L2', 'L3', 'http-proxy', 'icap', or 'tap'
                if "serviceType" not in service:
                    raise F5ModuleError("Each service must contain an 'serviceType' key, of either 'L2', 'L3', 'http-proxy', 'icap', or 'tap'.")

                service_chain = {}
                svc_name = service["name"]
                if not svc_name.startswith("ssloS_"):
                    svc_name = "ssloS_" + svc_name
                service_chain["name"] = svc_name
                service_chain["ipFamily"] = ipfamily
                service_chain["serviceType"] = service["serviceType"]
                self.config["inputProperties"][1]["value"]["orderedServiceList"].append(service_chain)


        ## create operation
        if operation == "CREATE":            
            #### TO DO: update JSON code for CREATE operation
            self.config["name"] = "sslo_obj_SERVICE_CHAIN_CREATE_" + self.want.name


        ## modify/delete operations
        elif operation in ["DELETE", "MODIFY"]:
            self.config["name"] = "sslo_obj_SERVICE_CHAIN_MODIFY_" + self.want.name

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
            services=dict(type='list', required=True),
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