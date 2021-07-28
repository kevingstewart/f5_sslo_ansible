F5 SSL Orchestrator Ansible Automation Collection
+++++++++++++++++++++++++++++++++++++++++++++++++

Documentation - Secure Web Gateway (SWG) Service 
================================================

Module: bigip_sslo_service_swg
------------------------------

Description
-----------
The SWG service is F5 Secure Web Gateway running as a security service in the SSL Orchestrator decrypted service chain.

Sample with all options defined
-------------------------------
.. code-block:: yaml

    - name: SSLO SWG service
      bigip_sslo_service_swg:
        provider: "{{ provider }}"
        name: "swg2"
        swgPolicy: "/Common/test-swg"
        profileScope: "named"
        namedScope: "SSLO"
        accessProfile: "/Common/test-access"
        serviceDownAction: "reset"
        logSettings:
          - "/Common/default-log-setting1"
        rules:
          - "/Common/test-rule"
      delegate_to: localhost


Parameters
----------

.. raw:: html

  <table border="1" cellpadding="1" cellspacing="1" style="width:50%;background-color:#ffffcc;border-collapse:collapse;border:1px solid #ffcc00">
    <tbody>
        <tr>
          <td colspan="2" rowspan="1" style="text-align: center;">Key</td>
          <td style="text-align: center;">Required</td>
          <td style="text-align: center;">Default</td>
          <td style="text-align: center;">Options</td>
          <td style="text-align: center;">Support</td>
          <td style="text-align: center;">Description</td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">provider</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td>The BIG-IP connection provider information</td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">name</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>The name of the security service (ex. swg1)</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">state</td>
          <td>no</td>
          <td>present</td>
          <td>present<br />absent</p></td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>Value to determine create/modify (present) or delete (absent) action</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">swgProfile</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>Name of the SWG per-request policy to attach to the service configuration</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">profileScope</td>
          <td>no</td>
          <td>profile</td>
          <td>profile<br />named</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>Determines the level of information sharing between policies. With 'named' set, an authentication access policy can share its user identity information with the SWG policy</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">namedScope</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>Required when profileScope is set to 'named'. Specifies a string value shared between an authentication access policy and the SWG policy to share user identity information</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">accessProfile</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>Specifies a custom SWG-Transparent access profile to assign to the SWG service. Otherwise the SWG access policy is auto-generated</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">serviceDownAction</td>
          <td>no</td>
          <td>reset</td>
          <td>ignore<br />reset<br />drop</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>Specifies the action to take on traffic flow if the SWG service fails</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">logSettings</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>Specifies a list of custom log settings to apply to the SWG service</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">rules</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>Specified a list of custom iRules to apply to the SWG service</p>
          </td>
        </tr>
      </tbody>
    </table>

Examples
--------

.. code-block:: yaml

    - name: SSLO SWG service (simple)
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

.. code-block:: yaml

    - name: SSLO SWG service (full)
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
            serviceDownAction: "reset"
            logSettings:
              - "/Common/default-log-setting1"
            rules:
              - "/Common/test-rule"
          delegate_to: localhost