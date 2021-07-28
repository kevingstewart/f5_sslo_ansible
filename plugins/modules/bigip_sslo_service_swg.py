#!/usr/bin/python
# -*- coding: utf-8 -*-
# 
# Copyright: (c) 2021, kevin-dot-g-dot-stewart-at-gmail-dot-com
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Version: 1.0.1

#### Updates:
#### 1.0.1 - swg module added in 9.0
#          - updated version and previousVersion keys to match target SSLO version


from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_service_swg
short_description: Manage an SSL Orchestrator SWG service
description:
  - Manage an SSL Orchestrator SWG service
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the service. Configuration auto-prepends "ssloS_" to the object. Names should be less than 14 characters and not contain dashes "-".
    type: str
    required: True
  swgPolicy:
    description:
      - Specifies the name of the SWG per-request policy to attach to the service configuration.
    type: str
    required: True
  profileScope:
    description:
      - Blah.
    type: Specifies the level of information sharing (scope). When using named scope, an authentication access profile attached to the topology can share its user identity information with the SWG policy.
    choices:
      - profile
      - named
    default: profile
  namedScope:
    description:
      - Used when profileScope is 'named' and specifies a name string that the authentication and SWG policies share to allow access to identity information.
    type: str
  accessProfile:
    description:
      - Specifies a custom SWG-Transparent access profile to apply to the SWG service. In the absence of a value here, the configuration auto-generates the access profile.
    type: str
  serviceDownAction:
    description:
      - Blah.
    type: Specifies the action taken if the SWG service fails.
    choices:
      - ignore
      - reset
      - drop
    default: reset
  logSettings:
    description:
      - Specifies a custom log setting for the SWG service.
    type: str
    default: /Common/default-log-setting
  rules:
    description:
      - Specifies custom iRules to apply to the SWG service.
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
- name: SSLO SWG service
  hosts: localhost
  gather_facts: False
  connection: local

  collections:
    - kevingstewart.f5_sslo_ansible
  
  vars: 
    provider:
      server: 10.1.1.4
      user: admin
      password: admin
      validate_certs: no
      server_port: 443

  tasks:
    - name: SSLO SWG service
      bigip_sslo_service_swg:
        provider: "{{ provider }}"
        name: "swg2"
        swgPolicy: "/Common/test-swg"
      delegate_to: localhost

- name: SSLO SWG service
  hosts: localhost
  gather_facts: False
  connection: local

  collections:
    - kevingstewart.f5_sslo_ansible
  
  vars: 
    provider:
      server: 10.1.1.4
      user: admin
      password: admin
      validate_certs: no
      server_port: 443

  tasks:
    - name: SSLO SWG service
      bigip_sslo_service_swg:
        provider: "{{ provider }}"
        name: "swg2"
        swgPolicy: "/Common/test-swg"
        profileScope: "named"
        namedScope: "SSLO"
        accessProfile: "/Common/test-access"
        logSettings:
          - "/Common/default-log-setting1"
          - "/Common/default-log-setting2"
        rules:
          - "/Common/test-rule"
      delegate_to: localhost
'''

RETURN = r'''
name:
  description:
    - Changed name of service chain.
  type: str
  sample: swg1
swgPolicy:
  description:
    - Changed the name of the SWG per-request policy.
  type: str
  sample: /Common/my-swg-policy
profileScope:
  description:
    - Changed the profile scope.
  type: str
  sample: named
namedScope:
  description:
    - Changes the named scope value.
  type: str
  sample: SSLO
accessProfile:
  description:
    - Changed to a custom SWG-Transparent access profile.
  type: str
  sample: /Common/my-access-profile
serviceDownAction:
  description:
    - Changed the service down action.
  type: str
  sample: reset
logSettings:
  description:
    - Changed to a custom log settings configuration.
  type: str
  sample: /Common/my-log-settings
rules:
  description:
    - Added custom iRules to the SWG service configuration.
  type: str
  sample: /Common/my-swg-rule1

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

## define minimum supported tmos version - min(SSLO 9.0)
min_version = 9.0

## define maximum supported tmos version - max(SSLO 9.9)
max_version = 9.9

json_template = {
    "name": "sslo_ob_SERVICE_CREATE_",
    "inputProperties": [
        {
            "id": "f5-ssl-orchestrator-operation-context",
            "type": "JSON",
            "value": {
                "version": "9.0",
                "partition": "Common",
                "strictness": False,
                "operationType": "CREATE",
                "deploymentName": "TEMPLATE_NAME",
                "deploymentReference": "",
                "deploymentType": "SERVICE"
            }
        },
        {
            "id":"f5-ssl-orchestrator-service",
            "type":"JSON",
            "value":{
                "name":"TEMPLATE_NAME",
                "strictness":False,
                "customService":{
                   "name":"TEMPLATE_NAME",
                   "serviceDownAction":"reset",
                   "serviceType":"swg",
                   "serviceSpecific":{
                      "name":"TEMPLATE_NAME",
                      "description":"",
                      "accessProfile":"TEMPLATE_ACCESS_PROFILE",
                      "accessProfileScope":"TEMPLATE_NAMED_SCOPE",
                      "logSettings":[],
                      "accessProfileNameScopeValue":"TEMPLATE_SCOPE_VALUE",
                      "accessProfileScopeCustSource":"/Common/modern",
                      "perReqPolicy":"TEMPLATE_SWG_POLICY",
                      "iRuleList":[]
                    }
                },
                "vendorInfo":{
                   "name":"F5 Secure Web Gateway"
                },
                "description":"Type: swg",
                "useTemplate":False,
                "serviceTemplate":"",
                "partition":"Common",
                "previousVersion":"9.0",
                "version":"9.0"
            }
        },
        {
            "id":"f5-ssl-orchestrator-network",
            "type":"JSON",
            "value":[]
        }
    ],
    "configurationProcessorReference": {
        "link": "https://localhost/mgmt/shared/iapp/processors/f5-iappslx-ssl-orchestrator-gc"
    },
    "state": "BINDING",
    "presentationHtmlReference": {
        "link": "https://localhost/iapps/f5-iappslx-ssl-orchestrator/sgc/sgcIndex.html"
    },
    "operation": "CREATE"
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
    def swg_policy(self):
        try:
            swg_policy = self._values["swgPolicy"]
            if swg_policy == None:
                return None
            return swg_policy
        except:
            return None
    
    @property
    def profile_scope(self):
        try:
            profile_scope = self._values["profileScope"]
            if profile_scope == None:
                return "profile"
            return profile_scope
        except:
            return "profile"
    
    @property
    def named_scope(self):
        try:
            named_scope = self._values["namedScope"]
            if named_scope == None:
                return None
            return named_scope
        except:
            return None
            
    @property
    def access_profile(self):
        try:
            access_profile = self._values["accessProfile"]
            if access_profile == None:
                return None
            return access_profile
        except:
            return None

    @property
    def service_down_action(self):
        try:
            service_down_action = self._values["serviceDownAction"]
            if service_down_action == None:
                return "reset"
            return service_down_action
        except:
            return "reset"

    @property
    def log_settings(self):
        try:
            log_settings = self._values["logSettings"]
            if log_settings == None:
                return None
            return log_settings
        except:
            return None
    
    @property
    def rules(self):
        try:
            rules = self._values["rules"]
            if rules == None:
                return None
            return rules
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
        self.local_name = re.sub('ssloS_', '', self.want.name)

        ## perform some input validation


        ## process general json settings for all operations
        self.config["inputProperties"][0]["value"]["deploymentName"] = self.want.name
        self.config["inputProperties"][0]["value"]["operationType"] = operation
        self.config["inputProperties"][1]["value"]["name"] = self.want.name
        self.config["inputProperties"][1]["value"]["customService"]["name"] = self.want.name
        self.config["inputProperties"][1]["value"]["customService"]["serviceSpecific"]["name"] = self.want.name


        ## process swgPolicy
        if self.want.swg_policy == "":
            raise F5ModuleError("swgProfile is defined but empty. The SWG service minimally requires the 'swgProfile' key set and referencing an existing SWG per-request policy.")
        else:
            self.config["inputProperties"][1]["value"]["customService"]["serviceSpecific"]["perReqPolicy"] = self.want.swg_policy


        ## process profileScope
        self.config["inputProperties"][1]["value"]["customService"]["serviceSpecific"]["accessProfileScope"] = self.want.profile_scope


        ## process namedScope (must exist if profileScope == named)
        if self.want.profile_scope == "named" and (self.want.named_scope == None or self.want.named_scope == ""):
            raise F5ModuleError("A profileScope of 'named' requires a namedScope string value.")
        if self.want.profile_scope == "named":
            self.config["inputProperties"][1]["value"]["customService"]["serviceSpecific"]["accessProfileNameScopeValue"] = self.want.named_scope
        else:
            self.config["inputProperties"][1]["value"]["customService"]["serviceSpecific"]["accessProfileNameScopeValue"] = ""


        ## process accessProfile (auto-generate value if not specified)
        if self.want.access_profile == None or self.want.access_profile == "":
            ## set auto-generated access profile name value
            self.config["inputProperties"][1]["value"]["customService"]["serviceSpecific"]["accessProfile"] = "/Common/" + self.want.name + ".app/" + self.want.name + "_M_accessProfile"
        else:
            self.config["inputProperties"][1]["value"]["customService"]["serviceSpecific"]["accessProfile"] = self.want.access_profile


        ## process serviceDownAction
        self.config["inputProperties"][1]["value"]["customService"]["serviceDownAction"] = self.want.service_down_action


        ## process logSettings
        if self.want.log_settings == None:
            logs = {}
            logs["name"] = "/Common/default-log-setting"
            logs["value"] = "/Common/default-log-setting"
            self.config["inputProperties"][1]["value"]["customService"]["serviceSpecific"]["logSettings"].append(logs)
        else:
            for log in self.want.log_settings:
                logs = {}
                logs["name"] = log
                logs["value"] = log
                self.config["inputProperties"][1]["value"]["customService"]["serviceSpecific"]["logSettings"].append(logs)


        ## process rules (auto-generate the SWG iRule)
        if self.want.rules == None:
            rules = {}
            rules["name"] = "/Common/" + self.want.name + ".app/" + self.want.name + "-swg"
            rules["value"] = "/Common/" + self.want.name + ".app/" + self.want.name + "-swg"
            self.config["inputProperties"][1]["value"]["customService"]["serviceSpecific"]["iRuleList"].append(rules)
        else:
            rules = {}
            rules["name"] = "/Common/" + self.want.name + ".app/" + self.want.name + "-swg"
            rules["value"] = "/Common/" + self.want.name + ".app/" + self.want.name + "-swg"
            self.config["inputProperties"][1]["value"]["customService"]["serviceSpecific"]["iRuleList"].append(rules)

            for rule in self.want.rules:
                rules = {}
                rules["name"] = rule
                rules["value"] = rule
                self.config["inputProperties"][1]["value"]["customService"]["serviceSpecific"]["iRuleList"].append(rules)


        ## =================================
        ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
        ## =================================
        self.config["inputProperties"][0]["value"]["version"] = self.ssloVersion
        self.config["inputProperties"][1]["value"]["version"] = self.ssloVersion
        self.config["inputProperties"][1]["value"]["previousVersion"] = self.ssloVersion


        ## create operation
        if operation == "CREATE":
            #### TO DO: update JSON code for CREATE operation
            self.config["name"] = "sslo_obj_SERVICE_CREATE_" + self.want.name


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
                self.config["inputProperties"][1]["value"]["existingBlockId"] = id
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
            state=dict(
                default='present',
                choices=['absent','present']
            ),
            swgPolicy=dict(required=True),
            profileScope=dict(
                choices=["profile","named"],
                default="profile"
            ),
            namedScope=dict(),
            accessProfile=dict(),
            serviceDownAction=dict(
                choices=["ignore","reset","drop"],
                default="reset"
            ),
            logSettings=dict(type='list'),
            rules=dict(type='list'),
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