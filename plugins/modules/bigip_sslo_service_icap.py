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
module: bigip_sslo_icap_service
short_description: Manage an SSL Orchestrator ICAP security device
description:
  - Manage an SSL Orchestrator ICAP security device
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the ICAP security service. Configuration auto-prepends "ssloS_" to service.
        Service name should be less than 14 characters and not contain dashes "-".
    type: str
    required: True
  devices:
    description:
      - Specifies a list of listening IP:ports for each ICAP security device
    type: list
    elements: dict
    required: True
  ipFamily:
    description:
      - Specifies the IP family used for attached ICAP security devices. 
    type: str
    choices:
      - ipv4
      - ipv6
      - both
    default: ipv4
  monitor:
    description:
      - Specifies the monitor attached the ICAP security device pool. The monitor must already exist on the BIG-IP.
    type: str
    default: /Common/tcp
  headers:
    description:
      - Enables or disables custom headers to be inserted to the ICAP server. When enabled, the values in th additional
        "header_" parameters will be applied.
    type: bool
    default: False
  header_referrer:
    description:
      - Specifies a Referrer header to pass to the ICAP service.
    type: str
  header_host:
    description:
      - Specifies a Host header to pass to the ICAP service.
    type: str
  header_user_agent:
    description:
      - Specifies a User-Agent header to pass to the ICAP service.
    type: str
  header_from:
    description:
      - Specifies a From header to pass to the ICAP service.
    type: str
  enableOneConnect:
    description:
      - Enables or disables OneConnect optimization to the ICAP server.
    type: bool
    default: True
  requestURI:
    description:
      - Specifies the ICAP request URI. This URI must always start with a forward slash "/" (ex. "/avscan")
    type: str
    default: /
  responseURI:
    description:
      - Specifies the ICAP response URI. This URI must always start with a forward slash "/" (ex. "/avscan")
    type: str
    default: /
  previewLength:
    description:
      - Specifies the ICAP preview length value, in KB.
    type: int
    default: 1024
  serviceDownAction:
    description:
      - Specifies the action to take on monitor failure. Setting to 'ignore' bypass the security device in the service
        chain. Setting to 'reset' or 'drop' resets or drops the connection, respectively if the service monirtor fails.
    type: str
    choices:
      - ignore
      - reset
      - drop
    default: ignore
  allowHttp10:
    description:
      - Enables or disables HTTP/1.0 support to ICAP.
    type: bool
    default: True
  cpmPolicies:
    description:
      - Specifies an LTM CPM ICAP policy to apply to this ICAP security service. The LTM CPM must already exist on the BIG-IP.
    type: str
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
    - name: SSLO ICAP service
      bigip_sslo_service_icap:
        provider: "{{ provider }}"
        name: "icap1"
        devices: 
          - ip: "1.1.1.1"
            port: 1344
          - ip: "2.2.2.2"
            port: 1348
        requestURI: "/avscan"
        responseURI: "/avscan"
        previewLength: 1024
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
    - name: SSLO ICAP service
      bigip_sslo_service_icap:
        provider: "{{ provider }}"
        name: "icap1"
        state: "present"
        ipFamily: "ipv4"
        devices: 
          - ip: "1.1.1.1"
            port: 1344
          - ip: "2.2.2.2"
            port: 1348
        headers: true
        header_from: "foo_from"
        header_host: "foo_host"
        header_user_agent: "foo_ua"
        header_referrer: "foo_referrer"
        enableOneConnect: True
        requestURI: "/avscan"
        responseURI: "/avscan"
        previewLength: 1024
        serviceDownAction: "ignore"
        allowHttp10: True
        cpmPolicies: "/Common/icap_policy"
      delegate_to: localhost
'''

RETURN = r'''
name:
  description:
    - Changed name of ICAP service.
  type: str
  sample: icap1
devices:
  description:
    - Changed list of IP:port listeners for ICAP services.
  type: list
  sample: [{'ip':'1.2.3.4','port':1344}]
state:
  description:
    - Changed state.
  type: str
  sample: present
ipFamily:
  description:
    - Changed ipFamily value of ICAP services.
  type: str
  sample: ipv4
monitor:
  description:
    - Changed pool monitor.
  type: str
  sample: /Common/tcp
headers:
  description:
    - Changed true:false value for enabling/disabling custom ICAP headers.
  type: bool
  sample: False
header_referrer:
  description:
    - Changed ICAP Referrer header.
  type: str
  sample: my_referrer
header_host:
  description:
    - Changed ICAP Host header.
  type: str
  sample: my_host
header_user_agent:
  description:
    - Changed ICAP User-Agent header.
  type: str
  sample: my_user_agent
header_from:
  description:
    - Changed ICAP From header.
  type: str
  sample: my_from
enableOneConnect:
  description:
    - Changed true:false value for enabling/disabling OneConnect optimization.
  type: bool
  Sample: True
requestURI:
  description:
    - Changed ICAP request URI.
  type: str
  sample: /avscan
responseURI:
  description:
    - Changed ICAP response URI.
  type: str
  sample: /avscan
previewLength:
  description:
    - Changed ICAP preview length value.
  type: int
  sample: 1024
serviceDownAction:
  description:
    - Changed service down action.
  type: str
  sample: ignore
allowHttp10:
  description:
    - Changed true:false value for enabling/disabling HTTP/1.0 ICAP support.
  type: bool
  default: True
cpmPolicies:
  description:
    - Changed LTM CPM ICAP policy assignment.
  type: str
  sample: /Common/icap_policy

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
import json, time

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
max_version = 9.0

json_template = {
    "name": "sslo_ob_SERVICE_TEMPLATE_OPERATION_TEMPLATE_NAME",
    "inputProperties": [
        {
            "id": "f5-ssl-orchestrator-operation-context",
            "type": "JSON",
            "value": {
                "version": "7.2",
                "partition": "Common",
                "strictness": False,
                "operationType": "TEMPLATE_OPERATION",
                "deploymentName": "TEMPLATE_NAME",
                "deploymentType": "SERVICE",
                "deploymentReference": "TEMPLATE_DEPLOYMENT_REFERENCE"
            }
        },
        {
            "id": "f5-ssl-orchestrator-service",
            "type": "JSON",
            "value": [
                {
                    "name": "TEMPLATE_NAME",
                    "version": "7.2",
                    "partition": "Common",
                    "strictness": False,
                    "vendorInfo": {
                        "name": "Generic ICAP Service"
                    },
                    "customService": {
                        "name": "TEMPLATE_NAME",
                        "ipFamily": "TEMPLATE_IP_FAMILY",
                        "serviceType": "icap",
                        "loadBalancing": {
                            "devices": "TEMPLATE_DEVICES",
                            "monitor": {
                                "fromSystem": "TEMPLATE_MONITOR"
                            }
                        },
                        "serviceSpecific": {
                            "name": "TEMPLATE_NAME",
                            "headers": {
                              "mode": "TEMPLATE_HEADER_MODE",
                              "headerConfig": {}
                            },
                            "requestUri": "icap://${SERVER_IP}:${SERVER_PORT}TEMPLATE_REQUEST_URI",
                            "allowHttp10": "TEMPLATE_ALLOW_HTTP10",
                            "responseUri": "icap://${SERVER_IP}:${SERVER_PORT}TEMPLATE_RESPONSE_URI",
                            "previewLength": "TEMPLATE_PREVIEW_LENGTH",
                            "enableOneConnect": "TEMPLATE_ONECONNECT"
                        },
                        "serviceDownAction": "TEMPLATE_SERVICE_ACTION_DOWN"
                    },
                    "previousVersion": "7.2",
                    "existingBlockId": "TEMPLATE_BLOCK_ID"
                }
            ]
        },{
            "id": "f5-ssl-orchestrator-service-chain",
            "type": "JSON",
            "value": []
        },{
            "id": "f5-ssl-orchestrator-network",
            "type": "JSON",
            "value": []
        },{
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
    def devices(self):
        devices = self._values['devices']
        return devices

    @property
    def ipFamily(self):
        ipFamily = self._values['ipFamily']
        if ipFamily not in ['ipv4', 'ipv6', 'both']:
            ipFamily = 'ipv4'
        return ipFamily

    @property
    def monitor(self):
        monitor = self._values['monitor']
        if monitor is None:
            return "/Common/tcp"
        return monitor

    @property
    def headers(self):
        headers = self._values['headers']
        if headers not in [True, False]:
            headers = False
        return headers

    @property
    def header_referrer(self):
        header_referrer = self._values['header_referrer']
        if header_referrer is None:
            return None
        return header_referrer

    @property
    def header_host(self):
        header_host = self._values['header_host']
        if header_host is None:
            return None
        return header_host

    @property
    def header_user_agent(self):
        header_user_agent = self._values['header_user_agent']
        if header_user_agent is None:
            return None
        return header_user_agent

    @property
    def header_from(self):
        header_from = self._values['header_from']
        if header_from is None:
            return None
        return header_from

    @property
    def enableOneConnect(self):
        enableOneConnect = self._values['enableOneConnect']
        if enableOneConnect not in [True, False]:
            enableOneConnect = True
        return enableOneConnect

    @property
    def requestURI(self):
        requestURI = self._values['requestURI']
        if requestURI is None:
            return "/"
        return requestURI

    @property
    def responseURI(self):
        responseURI = self._values['responseURI']
        if responseURI is None:
            return "/"
        return responseURI

    @property
    def previewLength(self):
        previewLength = self._values['previewLength']
        return previewLength

    @property
    def serviceDownAction(self):
        serviceDownAction = self._values['serviceDownAction']
        if serviceDownAction not in ['ignore', 'reset', 'drop']:
            serviceDownAction = 'ignore'
        return serviceDownAction

    @property
    def allowHttp10(self):
        allowHttp10 = self._values['allowHttp10']
        if allowHttp10 not in [True, False]:
            allowHttp10 = True
        return allowHttp10

    @property
    def cpmPolicies(self):
        cpmPolicies = self._values['cpmPolicies']
        if cpmPolicies is None:
            return None
        return cpmPolicies

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

        ## general json settings for all operations
        self.config["name"] = "sslo_ob_SERVICE_" + operation + "_" + self.want.name
        self.config["inputProperties"][0]["value"]["operationType"] = operation
        self.config["inputProperties"][0]["value"]["deploymentName"] = self.want.name
        self.config["inputProperties"][1]["value"][0]["name"] = self.want.name
        self.config["inputProperties"][1]["value"][0]["customService"]["name"] = self.want.name
        self.config["inputProperties"][1]["value"][0]["customService"]["ipFamily"] = self.want.ipFamily
        self.config["inputProperties"][1]["value"][0]["customService"]["loadBalancing"]["devices"] = self.want.devices
        self.config["inputProperties"][1]["value"][0]["customService"]["loadBalancing"]["monitor"]["fromSystem"] = self.want.monitor
        self.config["inputProperties"][1]["value"][0]["customService"]["serviceSpecific"]["name"] = self.want.name
        self.config["inputProperties"][1]["value"][0]["customService"]["serviceSpecific"]["headers"]["mode"] = self.want.headers
        self.config["inputProperties"][1]["value"][0]["customService"]["serviceSpecific"]["requestUri"] = "icap://${SERVER_IP}:${SERVER_PORT}" + self.want.requestURI
        self.config["inputProperties"][1]["value"][0]["customService"]["serviceSpecific"]["responseUri"] = "icap://${SERVER_IP}:${SERVER_PORT}" + self.want.responseURI
        self.config["inputProperties"][1]["value"][0]["customService"]["serviceSpecific"]["allowHttp10"] = self.want.allowHttp10
        self.config["inputProperties"][1]["value"][0]["customService"]["serviceSpecific"]["previewLength"] = self.want.previewLength
        self.config["inputProperties"][1]["value"][0]["customService"]["serviceSpecific"]["enableOneConnect"] = self.want.enableOneConnect
        self.config["inputProperties"][1]["value"][0]["customService"]["serviceDownAction"] = self.want.serviceDownAction

        tmp_headers = {}
        if self.want.header_from is not None:
            tmp_headers["from"] = self.want.header_from
        if self.want.header_host is not None:
            tmp_headers["host"] = self.want.header_host
        if self.want.header_referrer is not None:
            tmp_headers["referrer"] = self.want.header_referrer
        if self.want.header_user_agent is not None:
            tmp_headers["userAgent"] = self.want.header_user_agent      
        self.config["inputProperties"][1]["value"][0]["customService"]["serviceSpecific"]["headers"]["headerConfig"] = tmp_headers


        ## =================================
        ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
        ## =================================
        self.config["inputProperties"][0]["value"]["version"] = self.ssloVersion
        self.config["inputProperties"][1]["value"][0]["version"] = self.ssloVersion
        self.config["inputProperties"][1]["value"][0]["previousVersion"] = self.ssloVersion


        if operation == "CREATE":
            ## set these to empty for CREATE
            self.config["inputProperties"][0]["value"]["deploymentReference"] = ""
            self.config["inputProperties"][1]["value"][0]["existingBlockId"] = ""
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
                self.config["inputProperties"][1]["value"][0]["existingBlockId"] = id
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
            ## object doesn't exit - just exit (changed = false)
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
                type='list'
            ),
            state=dict(
                default='present',
                choices=['absent','present']
            ),
            ipFamily=dict(
                default='ipv4',
                choices=['ipv4','ipv6','both']
            ),
            monitor=dict(
                default='/Common/tcp'
            ),
            headers=dict(
                default=False,
                type='bool'
            ),
            header_referrer=dict(),
            header_host=dict(),
            header_user_agent=dict(),
            header_from=dict(),
            enableOneConnect=dict(
                default=True,
                type='bool'
            ),
            requestURI=dict(
                default='/'
            ),
            responseURI=dict(
                default='/'
            ),
            previewLength=dict(
                type='int',
                default=1024
            ),
            serviceDownAction=dict(
                default='ignore',
                choices=['ignore','reset','drop']
            ),
            allowHttp10=dict(
                default=True,
                type='bool'
            ),
            cpmPolicies=dict(),
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