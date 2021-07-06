F5 SSL Orchestrator Ansible Automation Collection
+++++++++++++++++++++++++++++++++++++++++++++++++

Documentation - ICAP Service
============================

Module: bigip_sslo_service_icap
-------------------------------

Description
-----------
An ICAP service is generally defined as any service that is controlled using the Internet Content Adaptation Protocol (ICAP) process. ICAP is essentially an encapsulation protocol for multiple types of services, but is often used in anti-virus, anti-malware, and data loss prevention (DLP) solutions.

From a configuration and automation persepective, an SSL Orchestrator ICAP security service an ICAP client that targets an external ICAP service (AV, DLP). This minimally requires knowledge of the service's listening IP address and port, and request/response URLs. You may also activate additional headers, a custom preview length, and apply a policy to control when and how the ICAP client engages the ICAP server.

Sample with all options defined
-------------------------------
.. code-block:: yaml

    - name: SSLO ICAP service
      bigip_sslo_service_icap:
        provider: "{{ provider }}"
        name: icap_1
        state: present
        
        devices:
          - ip: "10.1.30.50"
            port: 1344
        
        ipFamily: "ipv4"
        monitor: "/Common/tcp"
        headers: True
        header_referrer: "foo"
        header_host: "bar"
        header_user_agent: "this"
        header_from: "that"
        enableOneConnect: True
        requestURI: "/avscan"
        responseURI: "/avscan"
        previewLength: 4096
        serviceDownAction: "ignore"
        allowHttp10: True
        cpmPolicies: /Common/my-icap-policy
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
          <p>The name of the security service (ex. icap_1)</p>
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
          <td colspan="2" rowspan="1">devices</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of device IP addresses and ports</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>ip</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>ICAP service listening IP address</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>port</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>ICAP service listening port (usually 1344)</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">ipFamily</td>
          <td>no</td>
          <td>ipv4</td>
          <td>ipv4<br />ipv6</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The IP family expected for this security device</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">monitor</td>
          <td>no</td>
          <td>/Common/tcp</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The load balancing health monitor to assign to this security service</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">headers</td>
          <td>no</td>
          <td>False</td>
          <td>True<br />False</td>
          <td>all</td>
          <td><p>[bool]</p>
          <p>Switch to enable or disable custom headers. When enabled (True), the below header values can be set</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">header_referrer</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>A custom Referrer header</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">header_host</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>A custom Host header</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">header_user_agent</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>A custom User-Agent header</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">header_from</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>A custom From header</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">enableOneConnect</td>
          <td>no</td>
          <td>True</td>
          <td>True<br />False</td>
          <td>all</td>
          <td><p>[bool]</p>
          <p>Switch to enable or disable OneConnect optimization. When enabled (True), the server side is kept open between ICAP requests to optimize traffic flow</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">requestURI</td>
          <td>no</td>
          <td>/</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The ICAP service request URI</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">responseURI</td>
          <td>no</td>
          <td>/</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The ICAP service response URI</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">previewLength</td>
          <td>no</td>
          <td>1024</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[int]</p>
          <p>The ICAP service's required preview length</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">serviceDownAction</td>
          <td>no</td>
          <td>ignore</td>
          <td>ignore<br />reset<br />drop</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The action to take if all service pool members are marked down. The reset and drop options reset and drop the connection, respectively, while the ignore option causes traffic to bypass this service</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">allowHttp10</td>
          <td>no</td>
          <td>True</td>
          <td>True<br />False</td>
          <td>all</td>
          <td><p>[bool]</p>
          <p>Switch to enable or disable HTTP/1.0 processing. When enabled (True), the ICAP client accepts HTTP/1.1 and HTTP/1.0 responses</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">cpmPolicies</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of an LTM CPM policy used to control ICAP processing</p>
          </td>
        </tr>
      </tbody>
    </table>

    
Examples
--------

.. code-block:: yaml

    - name: Create SSLO service(s) - simple
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
        - name: SSLO ICAP service
          bigip_sslo_service_icap:
            provider: "{{ provider }}"
            name: "icap_1"
            devices: 
              - ip: "10.1.30.50"
                port: 1344
              - ip: "10.1.30.51"
                port: 1344
            requestURI: "/avscan"
            responseURI: "/avscan"
            previewLength: 1024
          delegate_to: localhost

.. code-block:: yaml

    - name: Create SSLO service(s) - complex
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
        - name: SSLO ICAP service
          bigip_sslo_service_icap:
            provider: "{{ provider }}"
            name: "icap_1"
            state: "present"
            ipFamily: "ipv4"
            devices: 
              - ip: "10.1.30.50"
                port: 1344
              - ip: "10.1.30.51"
                port: 1344
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

