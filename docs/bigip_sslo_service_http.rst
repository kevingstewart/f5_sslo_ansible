F5 SSL Orchestrator Ansible Automation Collection
+++++++++++++++++++++++++++++++++++++++++++++++++

Documentation - Inline HTTP Service
===================================

Module: bigip_sslo_service_http
-------------------------------

Description
-----------
An inline HTTP device is generally defined as any proxy-type security device that possesses separate inbound and outbound interfaces. An HTTP device will have separate to-service "in" and from-service "out" interfaces on different IP subnets. These could also be logically separated using 802.1Q VLAN tags attached to a single interface.

From a configuration and automation perspective, SSL Orchestrator requires that you define the to-service and from-service networking attributes.

Sample with all options defined
-------------------------------
.. code-block:: yaml

    - name: SSLO HTTP service
      bigip_sslo_service_http:
        provider: "{{ provider }}"
        name: http_1
        state: present
        
        devicesTo:
            vlan: "/Common/HTTPservice1_in"
            interface: "1.3"
            tag: 50
            selfIp:	"198.19.96.7"
            netmask: "255.255.255.128"
        
        devicesFrom:
            vlan: "/Common/HTTPservice1_out"
            interface: "1.3"
            tag: 60
            selfIp:	"198.19.96.245"
            netmask: "255.255.255.128"
        
        devices:
            - ip: "198.19.96.30"
              port: 3128
            - ip: "198.19.96.31"
              port: 3128
        
        proxyType: "explicit"
        authOffload: True
        ipFamily: "ipv4"
        monitor: "/Common/gateway_icmp"
        serviceDownAction: "ignore"
        portRemap: 8080

        snat: "automap"
        snatlist: 
            - "198.19.64.140"
            - "198.19.64.141"
        snatpool: "/Common/my-L3service-snatpool"
        
        rules: 
            - "/Common/rule1"
            - "/Common/rule2"
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

          <p>The name of the security service (ex. http_1)</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">state</td>
          <td>no</td>
          <td>present</td>
          <td>present<br />absent</p></td>
          </td>
          <td>all</td>
          <td><p>[string]</p>
          <p>Value to determine create/modify (present) or delete (absent) action</p>
          </td>
        </tr>


        <tr>
          <td colspan="2" rowspan="1">devicesTo</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[dict]</p>
          <p>The set of networking propertied associated with trafic flowing to the security service from the F5</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>vlan</td>
          <td>yes *</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of an existing VLAN connected to the to-service side of the security device - the VLAN and interface options are mutually exclusive</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>interface</td>
          <td>yes *</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The interface connected to the to-service side of the security device - the vlan and interface options are mutually exclusive</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>tag</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The VLAN tag associated with the to-service side of the security service, and only if requried, and using the interface option</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>selfIp</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The BIG-IP self-IP address on the to-service side of the security service</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>netmask</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The respective netmask for the to-service self-IP</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">devicesFrom</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[dict]</p>
          <p>The set of networking propertied associated with trafic flowing from the security service back to the F5</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>vlan</td>
          <td>yes **</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of an existing VLAN connected to the from-service side of the security device - the VLAN and interface options are mutually exclusive</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>interface</td>
          <td>yes **</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The interface connected to the from-service side of the security device - the vlan and interface options are mutually exclusive</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>tag</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The VLAN tag associated with the from-service side of the security service, and only if requried, and using the interface option</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>selfIp</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The BIG-IP self-IP address on the from-service side of the security service</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp;</td>
          <td>netmask</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The respective netmask for the from-service self-IP</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">devices</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of device IP addresses. These will be addresses in the to-service IP subnet</p>
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
          <p>The to-service IP address of a specific security device</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>port</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[int]</p>
          <p>The to-service explicit proxy listening port (ex. 3128)</p>
          </td>
        </tr>


        <tr>
          <td colspan="2" rowspan="1">proxyType</td>
          <td>no</td>
          <td>explicit</td>
          <td>explicit<br />transparent</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The type of HTTP proxy device, explicit or transparent</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">authOffload</td>
          <td>no</td>
          <td>False</td>
          <td>True<br />False</td>
          <td>all</td>
          <td><p>[bool]</p>
          <p>This option defines a mechanism that sends authenticated user information to the proxy device in a X-Authenticated-User HTTP header. This option requires APM authentication</p>
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
          <td>/Common/gateway_icmp</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The load balancing health monitor to assign to this security service</p>
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
          <td colspan="2" rowspan="1">portRemp</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[int]</p>
          <p>The port to remap decrypted http traffic to (if required)</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">snat</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>automap<br />snatpool<br />snatlist</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The option to use if source NAT is required to the security device</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">snatlist</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of source NAT addresses to use if the snat option is 'snatlist'</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">snatpool</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of an existing SNAT pool if the snat option is 'snatpool'</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">rules</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>A list of iRules to attach to this security service</p>
          </td>
        </tr>

      </tbody>
    </table>

Footnotes
---------

* \* The devicesTo vlan and devicesTo interface options are mutually exclusive
* \*\* The devicesFrom vlan and devicesFrom interface options are mutually exclusive
    
Examples
--------

.. code-block:: yaml

      - name: Create SSLO service(s) - SSLO-created VLANs
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
          - name: SSLO HTTP service
            bigip_sslo_service_http:
              provider: "{{ provider }}"
              name: "http_1"
              devicesTo:
                  interface: "1.3"
                  tag: 40
                  selfIp: "198.19.96.7"
                  netmask: "255.255.255.128"
              devicesFrom:
                  interface: "1.3"
                  tag: 50
                  selfIp: "198.19.96.245"
                  netmask: "255.255.255.128"
              devices: 
                - ip: "198.19.96.96"
                  port: 3128
                - ip: "198.19.96.96"
                  port: 3128
              snat: snatlist
              snatlist:
                - 198.19.96.10
                - 198.19.96.11
                - 198.19.96.12
            delegate_to: localhost

.. code-block:: yaml

    - name: Create SSLO service(s) - create and reference external VLANs
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
        - name: Create a monitor
          bigip_monitor_gateway_icmp:
            provider: "{{ provider }}"
            name: gw2
            state: present
          delegate_to: localhost

        - name: create HTTP service inbound VLAN
          bigip_vlan:
            provider: "{{ provider }}"
            name: HTTPservice_vlan_in
            tagged_interface: 1.5
            tag: 600
          delegate_to: localhost

        - name: create HTTP service outbound VLAN
          bigip_vlan:
            provider: "{{ provider }}"
            name: HTTPservice_vlan_out
            tagged_interface: 1.5
            tag: 601
          delegate_to: localhost

        - name: SSLO HTTP service
          bigip_sslo_service_http:
            provider: "{{ provider }}"
            name: "http_1"
            devicesTo:
                vlan: "/Common/HTTPservice_vlan_in"
                selfIp: "198.19.96.7"
                netmask: "255.255.255.128"
            devicesFrom:
                vlan: "/Common/HTTPservice_vlan_out"
                selfIp: "198.19.96.245"
                netmask: "255.255.255.128"
            proxyType: "transparent"
            devices: 
              - ip: "198.19.96.30"
              - ip: "198.19.96.31"
            monitor: "/Common/gw2"
          delegate_to: localhost

.. code-block:: yaml

    - name: Create SSLO service(s) - additional options
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
        - name: SSLO HTTP service
          bigip_sslo_service_http:
            provider: "{{ provider }}"
            name: "http_1"
            devicesTo:
                vlan: "/Common/proxy1a-in-vlan"
                selfIp: "198.19.96.7"
                netmask: "255.255.255.128"
            devicesFrom:
                interface: "1.3"
                tag: 50
                selfIp: "198.19.96.245"
                netmask: "255.255.255.128"
            devices: 
              - ip: "198.19.96.30"
                port: 3128
              - ip: "198.19.96.31"
                port: 3128
            snat: automap
          delegate_to: localhost

.. code-block:: yaml

    - name: Create SSLO service(s) - additional options
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
        - name: Create a monitor
          bigip_monitor_gateway_icmp:
            provider: "{{ provider }}"
            name: gw2
            state: present
          delegate_to: localhost

        - name: SSLO HTTP service
          bigip_sslo_service_http:
            provider: "{{ provider }}"
            name: "proxy1a"
            devicesTo:
                vlan: "/Common/proxy1a-in-vlan"
                selfIp: "198.19.96.7"
                netmask: "255.255.255.128"
            devicesFrom:
                interface: "1.3"
                tag: 50
                selfIp: "198.19.96.245"
                netmask: "255.255.255.128"
            devices: 
              - ip: "198.19.96.30"
              - ip: "198.19.96.31"
            proxyType: "transparent"
            authOffload: true
            ipFamily: "ipv4"
            monitor: "/Common/gw2"
            serviceDownAction: "reset"
            portRemap: 8080
            snat: snatpool
            snatpool: "/Common/proxy1a-snatpool"
            rules:
              - "/Common/proxy1a-rule-1"
              - "/Common/proxy1a-rule-2"
          delegate_to: localhost

Best Practices and Considerations
---------------------------------
- It is generally better to create the VLANs outside of the service definition and reference within (third example).

- iRules applied in the service definition are applied at the incoming (to-service) side of the service. If the specific use case for adding an iRule is to inject an HTTP header, where that header should be stripped on the other side, it would be better to customize the service after its created using the native F5 BIG-IP iRule module. For an inline layer 3 service, and TCP traffic, SSL Orchestrator creates:
    - A sending to-service virtual server (/Common/ssloS_[name].app/ssloS_[name]-t-4)
    - A receiving from-server virtual server (/Common/ssloS_[name].app/ssloS_[name]-D-0-t-4).