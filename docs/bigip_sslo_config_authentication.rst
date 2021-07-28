F5 SSL Orchestrator Ansible Automation Collection
+++++++++++++++++++++++++++++++++++++++++++++++++

Documentation - Authentication
==============================

Module: bigip_sslo_config_authentication
----------------------------------------

Description
-----------
Authentication services are introduced in SSL Orchestrator 9.0 and represent a client-facing authentication function. In this intial release it supports a local OCSP responder service. This service monitors the server side certificate revocation state and mirrors that to internal clients that direct an OCSP revocation request at the BIG-IP.

Sample with all options defined
-------------------------------
.. code-block:: yaml

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
          source: "0.0.0.0%0/0"
          port: 80
          httpProfile: "/Common/http"
          tcpSettingsClient: "/Common/f5-tcp-wan"
          tcpSettingsServer: "/Common/f5-tcp-lan"
          existingOcsp: "/Common/my-ocsp"
          ocspMaxAge: 604800
          ocspNonce: True
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
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>The name of the security service (ex. tap_1)</p>
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
          <td colspan="2" rowspan="1">ocsp</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[dict]</p>
          <p>The corresponding settings for OCSP authentication</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>fqdn</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>The fully qualified domain name of the ocsp authentication service</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>dest</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>The destination IP address of the OCSP authentication service</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>sslProfile</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>The SSL settings object that the OCSP authentication service will monitor for server side revocation state</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>vlans</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>The list of client-facing VLANs the authentication service will listen on</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>source</td>
          <td>no</td>
          <td>0.0.0.0%0/0</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>An option source IP address filter</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>port</td>
          <td>no</td>
          <td>80</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[int]</p>
          <p>A custom listening port for the authentication service</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>httpProfile</td>
          <td>no</td>
          <td>/Common/http</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>A custom http profile for the authentication service</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>tcpSettingsClient</td>
          <td>no</td>
          <td><nobr>/Common/f5-tcp-wan</nobr></td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>A custom client TCP profile</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>tcpSettingsServer</td>
          <td>no</td>
          <td><nobr>/Common/f5-tcp-lan</nobr></td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>A custom server TCP profile</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>existingOcsp</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[string]</p>
          <p>The name of an existing OCSP profile to use</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>ocspMaxAge</td>
          <td>no</td>
          <td>604800</td>
          <td>&nbsp;</td>
          <td>9.0+</td>
          <td><p>[int]</p>
          <p>A custom OCSP max age value (if not using an existing OCSP profile)</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>ocspNonce</td>
          <td>no</td>
          <td>True</td>
          <td>True<br />False</td>
          <td>9.0+</td>
          <td><p>[bool]</p>
          <p>Enables or disables OCSP nonce (if not using an existing OCSP profile)</p>
          </td>
        </tr>
      </tbody>
    </table>

Footnotes
---------

* \* The vlan and interface options are mutually exclusive
    
Examples
--------

.. code-block:: yaml

    - name: Create SSLO Authentication
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

.. code-block:: yaml

    - name: Create SSLO Authentication
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
            state: absent

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

