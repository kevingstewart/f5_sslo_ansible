F5 SSL Orchestrator Ansible Automation Collection
+++++++++++++++++++++++++++++++++++++++++++++++++

Documentation - Security Service Chain
======================================

Module: bigip_sslo_config_service_chain
---------------------------------------

Description
-----------
A security service chain is a container object for an ordered set of security services. Service chains are then applied to SSL Orchestrator security policies. From a configuration and automation perspective, a service chain minimally contains a list of services (by service name), and the respective service type.

Sample with all options defined
-------------------------------
.. code-block:: yaml

    - name: SSLO service chain
      bigip_sslo_config_service_chain:
        provider: "{{ provider }}"
        name: service_chain_1
        state: present
        services:
          - name: "layer2_1"
            serviceType: "L2"
            ipFamily: "ipv4"
          
          - name: "layer3_1"
            serviceType: "L3"
            ipFamily: "ipv4"
          
          - name: "http_1"
            serviceType: "http-proxy"
            ipFamily: "ipv4"
          
          - name: "icap_1"
            serviceType: "icap"
            ipFamily: "ipv4"
          
          - name: "tap_1"
            serviceType: "tap"
            ipFamily: "ipv4"
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
          <td>all</td>
          <td>The BIG-IP connection provider information</td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">name</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of the security service (ex. service_chain_1)</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">state</td>
          <td>no</td>
          <td>present</td>
          <td>present<br />absent</p></td>
          <td>all</td>
          <td><p>[string]</p>
          <p>Value to determine create/modify (present) or delete (absent) action</p>
          </td>
        </tr>


        <tr>
          <td colspan="2" rowspan="1">services</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of services to add to this service chain</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>name</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of specific service (ex. layer2_1)</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>serviceType</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>L2<br />L3<br /><nobr>http-proxy</nobr><br />icap<br />tap</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The service type</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>ipFamily</td>
          <td>no</td>
          <td>ipv4</td>
          <td>ipv4<br />ipv6</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The ipFamily supported</p>
          </td>
        </tr>

      </tbody>
    </table>
 

Examples
--------

.. code-block:: yaml

    - name: Create SSLO Service Chain
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
        - name: SSLO service chain
          bigip_sslo_config_service_chain:
            provider: "{{ provider }}"
            name: "service_chain_1"
            
            services:
              - name: "icap_1"
                serviceType: "icap"
                ipFamily: "ipv4"

              - name: "layer3_1"
                serviceType: "L3"
                ipFamily: "ipv4"

              - name: "layer2_1"
                serviceType: "L2"
                ipFamily: "ipv4"

              - name: "http_1"
                serviceType: "http-proxy"
                ipFamily: "ipv4"

              - name: "tap_1"
                serviceType: "tap"
                ipFamily: "ipv4"

          delegate_to: localhost
