F5 SSL Orchestrator Ansible Automation Collection
+++++++++++++++++++++++++++++++++++++++++++++++++

Documentation - DNS Resolver Configuration
==========================================

Module: bigip_sslo_config_resolver
----------------------------------

Description
-----------
The resolver configuration is the set of system-wide DNS resolution settings. From a configuration and automation perspective, a resolver minimally requires a list of forwardingNameserver IP addresses, or a list of forwardingZones zone:nameservers properties.

Sample with all options defined
-------------------------------
.. code-block:: yaml

    - name: SSLO resolver
      bigip_sslo_config_resolver:
        provider: "{{ provider }}"
        state: present

        forwardingNameservers:
          - 10.1.20.1
          - 10.1.20.2

        forwardingZones:
          - zone: "."
            nameservers:
              - 10.1.20.1
              - 10.1.20.2
          - zone: "foo.com"
            nameservers:
              - 8.8.8.8
              - 8.8.4.4

        enableDNSsec: False
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
          <td colspan="2" rowspan="1">forwardingNameServers</td>
          <td>no *</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>List of name server IP addresses</p>
          </td>
        </tr>


        <tr>
          <td colspan="2" rowspan="1">forwardingZones</td>
          <td>no *</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>List of zone:nameserver properties</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>zone</td>
          <td>no **</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>A domain match pattern (ex. ".")</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>nameservers</td>
          <td>no **</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>The corresponding list of name servers for this zone</p>
          </td>
        </tr>


        <tr>
          <td colspan="2" rowspan="1">enableDNSsec</td>
          <td>no</td>
          <td>False</td>
          <td>True<br />False</td>
          <td>all</td>
          <td><p>[bool]</p>
          <p>Switch to enable or disable DNSsec support</p>
          </td>
        </tr>

      </tbody>
    </table>

Footnotes
---------
- \* The forwardingNameServers and forwardingZones options mutually exclusive, but at least one must be defined
- \*\* If forwardingZones is defined, at least one zone:nameserver property pair must also be defined
    

Examples
--------

.. code-block:: yaml

    - name: Create SSLO DNS resolver (forwarding nameservers)
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
        - name: SSLO dns resolver
          bigip_sslo_config_resolver:
            provider: "{{ provider }}"

            forwardingNameservers:
              - "10.1.20.1"
              - "10.1.20.2"
              - "fd66:2735:1533:46c1:68c8:0:0:7110"
              - "fd66:2735:1533:46c1:68c8:0:0:7111"
          delegate_to: localhost

.. code-block:: yaml

    - name: Create SSLO DNS resolver (forwarding zones)
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
