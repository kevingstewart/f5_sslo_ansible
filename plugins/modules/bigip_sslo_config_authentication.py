#!/usr/bin/python
# -*- coding: utf-8 -*-
# 
# Copyright: (c) 2021, kevin-dot-g-dot-stewart-at-gmail-dot-com
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Version: 1.0.1

#### Updates:
#### 1.0.1 - authentication module added in 9.0 (supports ocsp)
#          - updated version and previousVersion keys to match target SSLO version


from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_config_authentication
short_description: Manage an SSL Orchestrator authentication object
description:
  - Manage an SSL Orchestrator authentication object
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name of the authentication object. Configuration auto-prepends "ssloA_" to the object. Names should be less than 14 characters and not contain dashes "-".
    type: str
    required: True
  ocsp:
    description:
      - Specifies an OCSP type authentication object
    required: True
    type: dict
    elements: dict
    suboptions:
      fqdn:
        description: 
            - Defines the fully qualified name of the OCSP authentication service.
        type: str
        required: True
      dest:
        description: 
            - Defines the OCSP authentication service destination IP address.
        type: str
        required: True
      sslProfile: 
        description: 
            - Defines the existing SSL settings object to reference in the ocsp authentication.
        type: str
        required: True
      vlans: 
        description: 
            - Defines the list of client-facing VLANs for the ocsp authentication service.
        type: list
        required: True
      source: 
        description: 
            - Defines a source IP address filter.
        type: str
        default: 0.0.0.0%0/0
      httpProfile: 
        description: 
            - Defines a custom http profile to apply to the ocsp authentication service virtual server.
        type: str
        default: /Common/http
      tcpSettingsClient: 
        description: 
            - Defines a custom client TCP profile.
        type: str
        default: /Common/f5-tcp-wan
      tcpSettingsServer: 
        description: 
            - Defines a custom server TCP profile.
        type: str
        default: /Common/f5-tcp-lan
      existingOcsp: 
        description: 
            - Defines an existing OCSP profile to use. Otherwise the OCSP profile is created automatically.
        type: str
        default: None
      ocspMaxAge: 
        description: 
            - Defines a max age value for the OCSP profile (if not using an existing OCSP profile).
        type: int
        default: 604800
      ocspNonce: 
        description: 
            - Enables or disables OCSP nonce (if not using an existing OCSP profile).
        type: bool
        default: True
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
- name: Create SSLO Authentication (simple)
  hosts: localhost
  gather_facts: False
  connection: local

  collections:
    - kevingstewart.f5_sslo_ansible

  vars: 
    provider:
      server: 172.16.1.83
      user: admin
      password: admin
      validate_certs: no
      server_port: 443

  tasks:
    - name: SSLO authentication
      bigip_sslo_config_authentication:
        provider: "{{ provider }}"
        name: "ocsp2"

        ocsp:
          fqdn: "ocsp2.f5labs.com"
          dest: "10.1.10.133/32"
          sslProfile: "demo"
          vlans: 
            - "/Common/client-vlan"
            - "/Common/dlp-vlan"

      delegate_to: localhost

- name: Create SSLO Authentication (full)
  hosts: localhost
  gather_facts: False
  connection: local

  collections:
    - kevingstewart.f5_sslo_ansible

  vars: 
    provider:
      server: 172.16.1.83
      user: admin
      password: admin
      validate_certs: no
      server_port: 443

  tasks:
    - name: SSLO authentication
      bigip_sslo_config_authentication:
        provider: "{{ provider }}"
        name: "ocsp2"

        ocsp:
          fqdn: "ocsp2.f5labs.com"
          dest: "10.1.10.133/32"
          sslProfile: "demo"
          vlans: 
            - "/Common/client-vlan"
            - "/Common/dlp-vlan"
          source: "0.0.0.0%0/0"
          port: 80
          httpProfile: "/Common/http"
          tcpSettingsClient: "/Common/f5-tcp-wan"
          tcpSettingsServer: "/Common/f5-tcp-lan"
          #existingOcsp: ""
          ocspMaxAge: 604800
          ocspNonce: True

      delegate_to: localhost
'''

RETURN = r'''
name:
  description:
    - Changed name of service chain.
  type: str
  sample: ocsp2
ocsp:
  description: settings used to define an OCP authentication object
  type: complex
  contains:
    fqdn:
       description: defines the fully qualified name that clients will use to access the OCSP authentication service.
       type: str
       sample: ocsp.f5labs.com
    dest:
       description: defines the destination IP address.
       type: str
       sample: 10.1.10.150/32
    sslProfile:
       description: defines the SSL settings object that the OCSP authentication service will monitor for revocation states.
       type: str
       sample: ssl_settings_1
    vlans:
       description: defines the list of client-facing VLANs to listen on.
       type: str
       sample: /Common/client-vlan
    source:
       description: defines a source IP address filter.
       type: str
       sample: 0.0.0.0%0/0
    port:
       description: defines a custom port for the authentication service.
       type: int
       sample: 80
    httpProfile:
       description: defines a custom http profile to use for the authentication service.
       type: str
       sample: /Common/http
    tcpSettingsClient:
       description: defines a custom client TCP profile to use for the authentication service.
       type: str
       sample: /Common/f5-tcp-wan
    tcpSettingsServer:
       description: defines a custom server TCP profile to use for the authentication service.
       type: str
       sample: /Common/f5-tcp-lan
    existingOcsp:
       description: defines an existing OCSP profile to use for the authentication service.
       type: str
       sample: /Common/my-ocsp
    ocspMaxAge:
       description: defines a max age value for the OCSP profile (if not using an existing OCSP profile).
       type: int
       sample: 604800
    ocspNonce:
       description: enables or disables nonce in the OCSP profile (if not using an existing OCSP profile).
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
import json, time, re, hashlib

global print_output
global json_template_auth_ocsp
global json_template_ocsp_auth_delete
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

json_template_auth_ocsp = {
    "name": "sslo_ob_AUTHENTICATION_CREATE_",
    "inputProperties": [
        {
            "id": "f5-ssl-orchestrator-operation-context",
            "type": "JSON",
            "value": {
                "version": "9.0",
                "partition": "Common",
                "strictness": False,
                "operationType": "TEMPLATE_OPERATION",
                "deploymentName": "TEMPLATE_NAME",
                "deploymentType": "AUTHENTICATION"
            }
        },
        {
            "id":"f5-ssl-orchestrator-authentication",
            "type":"JSON",
            "value":{
               "name":"TEMPLATE_NAME",
               "description":"OCSP Responder",
               "authType":"ocsp",
               "serverDef":{
                  "source":"0.0.0.0%0/0",
                  "destination":{
                     "address":"TEMPLATE_NAME_DEST",
                     "port":"80",
                     "mask":""
                  },
                  "vlans":[],
                  "serverTcpProfile":"/Common/f5-tcp-wan",
                  "clientTcpProfile":"/Common/f5-tcp-lan",
                  "httpProfile":"/Common/http",
                  "sslSettingReference":"TEMPLATE_SSL"
               },
               "vendorInfo":{
                  "name":"OCSP Responder",
                  "product":"",
                  "model":"",
                  "version":""
               },
               "ocsp":{
                  "useExisting":False,
                  "ocspProfile":"",
                  "maxAge":604800,
                  "nonce":"enabled",
                  "fqdn":"TEMPLATE_FQDN"
               },
               "useTemplate":False,
               "authTemplate":"",
               "partition":"Common",
               "previousVersion":"9.0",
               "version":"9.0",
               "strictness":False
            }
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

json_template_ocsp_auth_delete = {
    "name": "sslo_obj_AUTHENTICATION_DELETE_",
    "inputProperties": [
        {
            "id": "f5-ssl-orchestrator-operation-context",
            "type": "JSON",
            "value": {
                "deploymentName": "TEMPLATE_NAME",
                "deploymentReference": "",
                "deploymentType": "AUTHENTICATION",
                "operationType": "DELETE",
                "partition": "Common"
            }
        },
        {
            "id": "f5-ssl-orchestrator-authentication",
            "type": "JSON",
            "value": {
                "existingBlockId": "",
                "name": "TEMPLATE_NAME",
                "partition": "Common"
            }
        }
    ],
    "dataProperties":[],
    "configurationProcessorReference": {
        "link": "https://localhost/mgmt/shared/iapp/processors/f5-iappslx-ssl-orchestrator-gc"
    },
    "state": "BINDING"
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
        name = "ssloA_" + name
        return name

    @property
    def ocsp_fqdn(self):
        try:
            ocsp_fqdn = self._values["ocsp"]['fqdn']
            if ocsp_fqdn == None:
                return None
            return ocsp_fqdn
        except:
            return None
    
    @property
    def ocsp_ssl_profile(self):
        try:
            ocsp_ssl_profile = self._values["ocsp"]['sslProfile']
            if ocsp_ssl_profile == None:
                return None
            return ocsp_ssl_profile
        except:
            return None
    
    @property
    def ocsp_vlans(self):
        try:
            ocsp_vlans = self._values["ocsp"]['vlans']
            if ocsp_vlans == None:
                return None
            return ocsp_vlans
        except:
            return None
            
    @property
    def ocsp_source(self):
        try:
            ocsp_source = self._values["ocsp"]['source']
            if ocsp_source == None:
                return None
            return ocsp_source
        except:
            return None

    @property
    def ocsp_dest(self):
        try:
            ocsp_dest = self._values["ocsp"]['dest']
            if ocsp_dest == None:
                return None
            return ocsp_dest
        except:
            return None

    @property
    def ocsp_port(self):
        try:
            ocsp_port = self._values["ocsp"]['port']
            if ocsp_port == None:
                return None
            return ocsp_port
        except:
            return None
    
    @property
    def ocsp_http_profile(self):
        try:
            ocsp_http_profile = self._values["ocsp"]['httpProfile']
            if ocsp_http_profile == None:
                return None
            return ocsp_http_profile
        except:
            return None

    @property
    def ocsp_tcp_settings_client(self):
        try:
            ocsp_tcp_settings_client = self._values["ocsp"]['tcpSettingsClient']
            if ocsp_tcp_settings_client == None:
                return None
            return ocsp_tcp_settings_client
        except:
            return None

    @property
    def ocsp_tcp_settings_server(self):
        try:
            ocsp_tcp_settings_server = self._values["ocsp"]['tcpSettingsServer']
            if ocsp_tcp_settings_server == None:
                return None
            return ocsp_tcp_settings_server
        except:
            return None

    @property
    def ocsp_existing_ocsp(self):
        try:
            ocsp_existing_ocsp = self._values["ocsp"]['existingOcsp']
            if ocsp_existing_ocsp == None:
                return None
            return ocsp_existing_ocsp
        except:
            return None
    
    @property
    def ocsp_max_age(self):
        try:
            ocsp_max_age = self._values["ocsp"]['ocspMaxAge']
            if ocsp_max_age == None:
                return None
            return ocsp_max_age
        except:
            return None
    
    @property
    def ocsp_nonce(self):
        try:
            ocsp_nonce = self._values["ocsp"]['ocspNonce']
            if ocsp_nonce == None:
                return True
            return ocsp_nonce
        except:
            return True
    
    @property
    def mode(self):
        mode = self._values['mode']
        return mode


class ModuleManager(object):
    global print_output
    global json_template_auth_ocsp
    global json_template_ocsp_auth_delete
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
        self.config = json_template_auth_ocsp

        ## get base name
        self.local_name = re.sub('ssloA_', '', self.want.name)

        ## perform some input validation


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



        ## process fqdn (required)
        if self.want.ocsp_fqdn == None:
            raise F5ModuleError("FQDN not defined. OCSP Authentication minimally requires the 'fqdn', 'dest', 'sslProfile' and 'vlans' keys to be defined.")
        else:
            self.config["inputProperties"][1]["value"]["ocsp"]["fqdn"] = self.want.ocsp_fqdn
        

        ## process dest (required)
        if self.want.ocsp_dest == None:
            raise F5ModuleError("Destination IP address not defined. OCSP Authentication minimally requires the 'fqdn', 'dest', 'sslProfile' and 'vlans' keys to be defined.")
        else: 
            ## input validation: destination must include subnet
            try:
                m = re.search('^.*/(\d+)$', self.want.ocsp_dest)
                if int(m.group(1)) > 32:
                    raise F5ModuleError("Destination address must contain a subnet (CIDR) value <= 32.")
            except AttributeError:
                raise F5ModuleError("Destination address must contain a subnet (CIDR) value <= 32.")

            ## input validation: destination address must contain a route domain - if it doesn't, auto-add %0
            m = re.search('^.*%(\d+).*$', self.want.ocsp_dest)            
            try:
                tmp = m.group(1)
                self.dest = self.want.ocsp_dest
            except:
                iplist = self.want.ocsp_dest.split("/")
                iplist[0] = re.sub('%.*', '', iplist[0])
                self.dest = iplist[0] + "%0/" + iplist[1]

            self.config["inputProperties"][1]["value"]["serverDef"]["destination"]["address"] = self.dest


        ## process sslProfile (required)
        if self.want.ocsp_ssl_profile == None:
            raise F5ModuleError("SSL Profile not defined. OCSP Authentication minimally requires the 'fqdn', 'dest', 'sslProfile' and 'vlans' keys to be defined.")
        else:
            if not self.want.ocsp_ssl_profile.startswith("ssloT_"):
                self.ssl = "ssloT_" + self.want.ocsp_ssl_profile
            else:
                self.ssl = self.want.ocsp_ssl_profile
            
            self.config["inputProperties"][1]["value"]["serverDef"]["sslSettingReference"] = self.ssl


        ## process vlans (required)
        if self.want.ocsp_vlans == None:
            raise F5ModuleError("VLANs are not defined. OCSP Authentication minimally requires the 'fqdn', 'dest', 'sslProfile' and 'vlans' keys to be defined.")
        else:
            for vlan in self.want.ocsp_vlans:
                vlan_elem = {}
                vlan_elem["name"] = vlan
                vlan_elem["value"] = vlan
                self.config["inputProperties"][1]["value"]["serverDef"]["vlans"].append(vlan_elem)


        ## process source
        if self.want.ocsp_source == "":
            raise F5ModuleError("Source IP address is defined but empty.")
        else: 
            ## input validation: source must include subnet
            try:
                m = re.search('^.*/(\d+)$', self.want.ocsp_source)
                if int(m.group(1)) > 32:
                    raise F5ModuleError("Source address must contain a subnet (CIDR) value <= 32.")
            except AttributeError:
                raise F5ModuleError("Source address must contain a subnet (CIDR) value <= 32.")

            ## input validation: source address must contain a route domain - if it doesn't, auto-add %0
            m = re.search('^.*%(\d+).*$', self.want.ocsp_source)            
            try:
                tmp = m.group(1)
                self.source = self.want.ocsp_source
            except:
                iplist = self.want.ocsp_source.split("/")
                iplist[0] = re.sub('%.*', '', iplist[0])
                self.source = iplist[0] + "%0/" + iplist[1]

            self.config["inputProperties"][1]["value"]["serverDef"]["source"] = self.source


        ## process port
        ## input validation: source port must be an integer between 0 and 65535
        if self.want.ocsp_port >= 0 and self.want.ocsp_port <= 65535:
            self.port = self.want.ocsp_port
        else:
            raise F5ModuleError("A defined port must be an integer between 0 and 65535.")
        
        self.config["inputProperties"][1]["value"]["serverDef"]["destination"]["port"] = self.port


        ## process httpProfile
        if self.want.ocsp_http_profile == "":
            raise F5ModuleError("httpProfile is defined but empty.")
        else:
            self.config["inputProperties"][1]["value"]["serverDef"]["httpProfile"] = self.want.ocsp_http_profile


        ## process tcpSettingsClient
        if self.want.ocsp_tcp_settings_client == "":
            raise F5ModuleError("tcpSettingsClient is defined but empty.")
        else:
            self.config["inputProperties"][1]["value"]["serverDef"]["clientTcpProfile"] = self.want.ocsp_tcp_settings_client


        ## process tcpSettingsServer
        if self.want.ocsp_tcp_settings_server == "":
            raise F5ModuleError("tcpSettingsServer is defined but empty.")
        else:
            self.config["inputProperties"][1]["value"]["serverDef"]["serverTcpProfile"] = self.want.ocsp_tcp_settings_server


        ## process existingOcsp (this and ocspMaxAge/ocspNonce are mutually exclusive)
        if self.want.ocsp_existing_ocsp != None and self.want.ocsp_existing_ocsp != "":
            self.config["inputProperties"][1]["value"]["ocsp"]["useExisting"] = True
            self.config["inputProperties"][1]["value"]["ocsp"]["ocspProfile"] = self.want.ocsp_existing_ocsp


        ## process ocspMaxAge (this/ocspNonce and existingOcsp are mutually exclusive)
        if self.want.ocsp_max_age == "":
            raise F5ModuleError("ocspMaxAge is defined but empty.")
        else:
            self.config["inputProperties"][1]["value"]["ocsp"]["maxAge"] = self.want.ocsp_max_age


        ## process ocspNonce (this/ocspMaxAge and existingOcsp are mutually exclusive)
        if self.want.ocsp_nonce == "":
            raise F5ModuleError("ocspNonce is defined but empty.")
        else:
            if self.want.ocsp_nonce == True:
                self.config["inputProperties"][1]["value"]["ocsp"]["nonce"] = "enabled"
            elif self.want.ocsp_nonce == False:
                self.config["inputProperties"][1]["value"]["ocsp"]["nonce"] = "disabled"
            else:
                raise F5ModuleError("ocspNonce must be a True|False value.")



        ## create operation
        if operation == "CREATE": 
            #### TO DO: update JSON code for CREATE operation
            self.config["name"] = "sslo_obj_AUTHENTICATION_CREATE_" + self.want.name


        ## modify/delete operations
        elif operation == "MODIFY":
            self.config["name"] = "sslo_obj_AUTHENTICATION_MODIFY_" + self.want.name

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


        elif operation == "DELETE":
            ## use the json delete template
            self.config = json_template_ocsp_auth_delete

            self.config["name"] = "sslo_obj_AUTHENTICATION_DELETE_" + self.want.name
            self.config["inputProperties"][0]["value"]["deploymentName"] = self.want.name
            self.config["inputProperties"][1]["value"]["name"] = self.want.name

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
            ocsp=dict(
                type='dict',
                options=dict(
                    fqdn=dict(),
                    dest=dict(),
                    sslProfile=dict(),
                    vlans=dict(type='list'),
                    source=dict(default="0.0.0.0%0/0"),
                    port=dict(type='int',default=80),
                    httpProfile=dict(default="/Common/http"),
                    tcpSettingsClient=dict(default="/Common/f5-tcp-wan"),
                    tcpSettingsServer=dict(default="/Common/f5-tcp-lan"),
                    existingOcsp=dict(),
                    ocspMaxAge=dict(type='int',default=604800),
                    ocspNonce=dict(type='bool',default=True)
                ),
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