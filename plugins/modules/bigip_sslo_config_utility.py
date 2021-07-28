#!/usr/bin/python
# -*- coding: utf-8 -*-
# 
# Copyright: (c) 2021, kevin-dot-g-dot-stewart-at-gmail-dot-com
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Version: 1.0

#### Updates:
#### 1.0.1 - added 9.0 support (same as 8.3 so just changed max version)


from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_config_utility
short_description: Manage the set of SSL Orchestrator utility functions
description:
  - Manage the set of SSL Orchestrator utility functions
version_added: "1.0.0"
options:
  utility:
    description:
        - Specifies the utility function to perform.
    type: str
    choices:
        - delete-all
  
extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Kevin Stewart (kevin-dot-g-dot-stewart-at-gmail-dot-com)
'''

EXAMPLES = r'''
- name: SSLO utility functions
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
    - name: SSLO Utility Functions
      bigip_sslo_config_utility:
        provider: "{{ provider }}"
        
        utility: delete-all

      delegate_to: localhost
'''

RETURN = r'''
utility:
  description:
    - Defines the utility function to perform.
  type: str
  sample: delete-all
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
max_version = 9.0

json_template = {}



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
    def utility(self):
        utility = self._values['utility']
        if utility == None:
            return None
        return utility


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


    def exec_module(self):
        start = datetime.now().isoformat()
        self.ssloVersion = self.getSsloVersion()
        changed = False
        result = dict()
        state = self.want.state


        ## test for correct TMOS version
        if self.ssloVersion < min_version or self.ssloVersion > max_version:
            raise F5ModuleError("Unsupported SSL Orchestrator version, requires a version between min(" + str(min_version) + ") and max(" + str(max_version) + ")")

        
        ## use this to initiate the different utility functions
        if self.want.utility == "delete-all":
            changed = self.deleteAll()


        result.update(dict(changed=changed))
        print_output.append('changed=' + str(changed))
        return result


    def deleteAll(self):
        if self.module.check_mode:
            return True

        ## use this to perform the SSLO delete-all function
        uri = "https://{0}:{1}/mgmt/shared/iapp/f5-iappslx-ssl-orchestrator/appsCleanup".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        jsonstr = {"operationType": "CLEAN_ALL_GC_APP"}
        resp = self.client.api.post(uri, json=jsonstr)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status not in [200, 201, 202] or 'code' in response and response['code'] not in [200, 201, 202]:
            raise F5ModuleError(resp.content)

        ## poll the request to see if any errors are generated
        attempts = 1
        while attempts <= obj_attempts:
            uri = "https://{0}:{1}/mgmt/shared/iapp/f5-iappslx-ssl-orchestrator/appsCleanup".format(
                self.client.provider['server'],
                self.client.provider['server_port']
            )
            resp = self.client.api.get(uri).json()
            time.sleep(1)
            try:
                if resp["running"] == False and resp["message"] == "Cleanup process completed. Press ok to continue.":
                    break
                elif resp["running"] == False and len(resp["successMessage"]) > 0 and resp["successMessage"][0]["type"] == "error":
                    raise F5ModuleError(str(resp["successMessage"][0]["message"]))
                    break
                else:
                    attempts += 1
            except Exception as err:
                raise F5ModuleError("Utility(delete-all) failed with the following message: " + str(err))


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            utility=dict(
                choices=["delete-all"],
                required=True
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
        supports_check_mode=spec.supports_check_mode
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