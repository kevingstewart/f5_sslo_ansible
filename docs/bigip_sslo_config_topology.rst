F5 SSL Orchestrator Ansible Automation Collection
+++++++++++++++++++++++++++++++++++++++++++++++++

Documentation - Topology
========================

Module: bigip_sslo_config_topology
----------------------------------

Description
-----------
An SSL Orchestrator topology is generally defined as the set of the properties that constitute a complete security inspection environment. Topologies are classified by a type that identifies how they attach to a network and consume traffic (i.e. transparent forward proxy, explicit forward proxy, reverse proxy), and include the setting that control decryption and re-encryption, and dynamic service chain management.

From a configuration and automation perspective, topologies can be further categorized by two deployment methods:

Deployment Methods
------------------
There are generally two options for automated SSL Orchestrator topology deployment:

- **Atomic**: where the topology configuration minimally defines itelf, and references to SSL and security policy settings. In this mode, the other dependent objects (i.e. security services, service chains, security policy, and SSL settings) must all be created first. In an Ansible playbook these could simply be separate tasks that are created in parent-child dependent order, or they could be created in separate playbooks at different times. Creating all of the SSL Orchestrator objects as atomic tasks in a playbook will take a while to complete, as each object creation task must finish before the next is started.

  .. image:: ../images/f5_sslo_ansible_deployment_atomic.png
    :width: 500px

- **Aggregate**: where dependent object creation is deferred and its configuration block referenced inside a single topology creation task. This method uses a special "mode" option in the dependent objects to defer sending the configuration to the target host. When the mode is set to "output", the object task bypasses creation, and simply returns the JSON configuration block in a registered variable. The topology declaration can then reference this JSON block as a Jinja2 variable, and combine all of the JSON blocks into a single all-encompassing creation task. The advantage of this approach is a much faster creation time.

  .. image:: ../images/f5_sslo_ansible_deployment_aggregate.png
    :width: 250px

A topology declaration must minimally contain SSL and security policy settings, and one (and only one) topology definition.


Sample with all options defined
-------------------------------
.. code-block:: yaml

    - name: SSLO topology
      bigip_sslo_config_topology:
        provider: "{{ provider }}"
        name: topology_1
        state: present

        configReferences:
          sslSettings: "sslsettings_1"
          securityPolicy: "securitypolicy_1"
          services:
            - "{{ layer2_1 }}"
            - "{{ layer3_1 }}"
          serviceChains:
            - "{{ servicechain_1 }}"
            - "{{ servicechain_1 }}"
          resolver: "{{ resolversettings }}"


        topologyOutboundL3:
          ipFamily: "ipv4"
          protocol: "tcp"
          source: "0.0.0.0%0/0"
          dest: "0.0.0.0%0/0"
          port: 0
          vlans: "/Common/client-vlan"
          snat: "Automap"
          snatlist: 
            - 10.1.20.110
            - 10.1.20.111
          snatpool: "/Common/my-snat-pool"
          gateway: "system"
          gatewaylist:
            - 10.1.20.1
            - 10.1.20.2
          gatewaypool: "/Common/my-gateway-pool"
          tcpSettingsClient: "/Common/f5-tcp-lan"
          tcpSettingsServer: "/Common/f5-tcp-wan"
          L7ProfileType: "http"
          L7Profile: "/Common/http"
          additionalProtocols:
            - ftp
            - imap
            - pop3
            - smtps
          accessProfile: "/Common/ssloDefault_accessProfile"
          profileScope: "named"
          profileScopeValue: "SSLO"
          primaryAuthUri: "https://auth.f5labs.com"


        topologyOutboundExplicit:
          ipFamily: "ipv4"
          source: "0.0.0.0%0/0"
          proxyIp: "10.1.10.150"
          proxyPort: 3128
          vlans: "/Common/client-vlan"
          snat: "snatpool"
          snatlist:
            - 10.1.20.110
            - 10.1.20.110
          snatpool: "/Common/my-snat-pool"
          gateway: "iplist"
          gatewaylist:
            - 10.1.20.1
            - 10.1.20.2
          gatewaypool: "/Common/my-gateway-pool"
          authProfile: "/Common/my-swgexplicit-auth"


        topologyInboundL3:
          ipFamily: "ipv4"
          protocol: "tcp"
          source: "0.0.0.0%0/0"
          dest: "0.0.0.0%0/0"
          port: 0
          vlans: "/Common/inbound-vlan"
          snat: "snatlist"
          snatlist:
            - 10.1.10.110
            - 10.1.10.111
          snatpool: "/Common/my-snatpool"
          gateway: "pool"
          gatewaylist:
            - 10.1.10.1
            - 10.1.10.2
          gatewaypool: "/Common/my-gateway-pool"
          pool: "/Common/my-app-pool"
          tcpSettingsClient: "/Common/f5-tcp-wan"
          tcpSettingsServer: "/Common/f5-tcp-lan"
          L7ProfileType: "http"
          L7Profile: "/Common/http"


        logging: 
          sslo: error
          perRequestPolicy: error
          ftp: error
          imap: error
          pop3: error
          smtps: error

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
          <p>The name of the security service (ex. topology_1)</p>
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

      </tbody>
    </table>

|

Parameters: configReferences
----------------------------
Description: defines a set of external configuration references

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
          <td colspan="2" rowspan="1">sslSettings</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of an SSL configuration, or Jinja2 reference to a local SSL configuration task</p>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">securityPolicy</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of a security policy, or Jinja2 reference to a local security policy task</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">services</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of Jinja2 references for local service creation tasks</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">serviceChains</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of Jinja2 references for local service chain creation tasks</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">resolver</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>A Jinja2 reference to a local resolver configuration task</p>
          </td>
        </tr>

      </tbody>
    </table>


|

Parameters: topologyOutboundL3
------------------------------
Description: defines the properties of an outbound layer 3 (transparent forward proxy) topology

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
          <td colspan="2" rowspan="1">ipFamily</td>
          <td>no</td>
          <td>ipv4</td>
          <td>ipv4<br />ipv6</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The IP family expected for this security device</p>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">protocol</td>
          <td>no</td>
          <td>tcp</td>
          <td>tcp<br />udp<br />other</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The matching layer 4 protocol</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">source</td>
          <td>no</td>
          <td>0.0.0.0%0/0</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>A source IP address filter</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">dest</td>
          <td>no</td>
          <td>0.0.0.0%0/0</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>A destination IP address filter</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">port</td>
          <td>no</td>
          <td>0</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[int]</p>
          <p>A destination port filter</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">vlans</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of client-facing VLANs</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">snat</td>
          <td>no</td>
          <td>none</td>
          <td>none<br />automap<br />snatpool<br />snatlist</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>An egress source NAT option</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">snatlist</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>If snat is snatpool, this is a list of SNAT IP addresses</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">snatpool</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>If snat is snatpool, this is the name of an existing SNAT pool</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">gateway</td>
          <td>no</td>
          <td>system</td>
          <td>system<br />pool<br />iplist</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>An egress gateway option</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">gatewaylist</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>If gateway is gatewaylist, this is the list of gateway IP addresses</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">gatewaypool</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>If gateway is gatewaypool, this is the name of an existing gateway pool</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">tcpSettingsClient</td>
          <td>no</td>
          <td><nobr>/Common/f5-tcp-lan</nobr></td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of a custom client side TCP profile</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">tcpSettingsServer</td>
          <td>no</td>
          <td><nobr>/Common/f5-tcp-wan</nobr></td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of a custom server side TCP profile</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">L7ProfileType</td>
          <td>no</td>
          <td>none</td>
          <td>none<br />http</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>If required, this selects a specific L7 profile type</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">L7Profile</td>
          <td>no</td>
          <td>none</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>If L7ProfileType is http, this is the name of a specific HTTP profile</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">additionalProtocols</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>ftp<br />imap<br />pop3<br />smtps</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of additional protocols to create listeners for</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">accessProfile</td>
          <td>no</td>
          <td>(generated profile)</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of a custom SSL Orchestrator access profile</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">profileScope</td>
          <td>no</td>
          <td>public</td>
          <td>public<br />named</td>
          <td>8.2+</td>
          <td><p>[string]</p>
          <p>When performing transparent forward proxy captive portal authentication, the "named" profileScope allows authenticated identity information from the authentication profile to be shared with the proxy.</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">profileScopeValue</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>8.2+</td>
          <td><p>[string]</p>
          <p>When profileScope is named, this setting is required and defines a unique name value that is shared between then captive portal and security policy profiles</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">primaryAuthUri</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>8.2+</td>
          <td><p>[string]</p>
          <p>When profileScope is named, this setting is required and defines the fully-qualified domain name of the captive portal authentication site</p>
          </td>
        </tr>

      </tbody>
    </table>

|

Parameters: topologyOutboundExplicit
------------------------------------
Description: defines the properties of an outbound explicit forward proxy topology

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
          <td colspan="2" rowspan="1">ipFamily</td>
          <td>no</td>
          <td>ipv4</td>
          <td>ipv4<br />ipv6</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The IP family expected for this security device</p>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">source</td>
          <td>no</td>
          <td>0.0.0.0%0/0</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>A source IP address filter</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">proxyIp</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The explicit proxy listening IP address</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">proxyPort</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[int]</p>
          <p>The explicit proxy listening port</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">vlans</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of client-facing VLANs</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">snat</td>
          <td>no</td>
          <td>none</td>
          <td>none<br />automap<br />snatpool<br />snatlist</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>An egress source NAT option</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">snatlist</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>If snat is snatpool, this is a list of SNAT IP addresses</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">snatpool</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>If snat is snatpool, this is the name of an existing SNAT pool</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">gateway</td>
          <td>no</td>
          <td>system</td>
          <td>system<br />pool<br />iplist</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>An egress gateway option</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">gatewaylist</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>If gateway is gatewaylist, this is the list of gateway IP addresses</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">gatewaypool</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>If gateway is gatewaypool, this is the name of an existing gateway pool</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">authProfile</td>
          <td>no</td>
          <td>&nbsp</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of a custom SWG-Explicit authentication access profile</p>
          </td>
        </tr>

      </tbody>
    </table>

|

Parameters: topologyInboundL3
-----------------------------
Description: defines the properties of an inbound layer 3 (reverse proxy) topology

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
          <td colspan="2" rowspan="1">ipFamily</td>
          <td>no</td>
          <td>ipv4</td>
          <td>ipv4<br />ipv6</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The IP family expected for this security device</p>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">protocol</td>
          <td>no</td>
          <td>tcp</td>
          <td>tcp<br />udp<br />other</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The matching layer 4 protocol</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">source</td>
          <td>no</td>
          <td>0.0.0.0%0/0</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>A source IP address filter</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">dest</td>
          <td>no</td>
          <td>0.0.0.0%0/0</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>A destination IP address filter</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">port</td>
          <td>no</td>
          <td>0</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[int]</p>
          <p>A destination port filter</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">vlans</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of client-facing VLANs</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">snat</td>
          <td>no</td>
          <td>none</td>
          <td>none<br />automap<br />snatpool<br />snatlist</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>An egress source NAT option</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">snatlist</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>If snat is snatpool, this is a list of SNAT IP addresses</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">snatpool</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>If snat is snatpool, this is the name of an existing SNAT pool</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">gateway</td>
          <td>no</td>
          <td>system</td>
          <td>system<br />pool<br />iplist</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>An egress gateway option</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">gatewaylist</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>If gateway is gatewaylist, this is the list of gateway IP addresses</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">gatewaypool</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>If gateway is gatewaypool, this is the name of an existing gateway pool</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">pool</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of a destination pool</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">tcpSettingsClient</td>
          <td>no</td>
          <td><nobr>/Common/f5-tcp-wan</nobr></td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of a custom client side TCP profile</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">tcpSettingsServer</td>
          <td>no</td>
          <td><nobr>/Common/f5-tcp-lan</nobr></td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of a custom server side TCP profile</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">L7ProfileType</td>
          <td>no</td>
          <td>http</td>
          <td>none<br />http</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>If required, this selects a specific L7 profile type</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">L7Profile</td>
          <td>no</td>
          <td>/Common/http</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>If L7ProfileType is http, this is the name of a specific HTTP profile</p>
          </td>
        </tr>

      </tbody>
    </table>

|

Parameters: logging
-------------------
Description: defines the logging properties of the topology

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
          <td colspan="2" rowspan="1">sslo</td>
          <td>no</td>
          <td>error</td>
          <td>emergency<br />alert<br />critical<br />warning<br />error<br />notice<br />information<br />debug</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>Logging level for SSL Orchestrator summary information</p>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">perRequestPolicy</td>
          <td>no</td>
          <td>error</td>
          <td>&lt;same&gt;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>Logging level for SSL Orchestrator security policy information</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">ftp</td>
          <td>no</td>
          <td>error</td>
          <td>&lt;same&gt;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>Logging level for FTP information</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">imap</td>
          <td>no</td>
          <td>error</td>
          <td>&lt;same&gt;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>Logging level for IMAP information</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">pop3</td>
          <td>no</td>
          <td>error</td>
          <td>&lt;same&gt;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>Logging level for POP3 information</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">smtps</td>
          <td>no</td>
          <td>error</td>
          <td>&lt;same&gt;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>Logging level for SMTPS information</p>
          </td>
        </tr>
       
      </tbody>
    </table>

|  

Examples
--------

.. code-block:: yaml

    - name: Create SSLO Topology (simple outbound L3 - atomic)
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
        - name: SSLO topology
          bigip_sslo_config_topology:
            provider: "{{ provider }}"
            name: "demoOutL3"        
            configReferences:
              sslSettings: "demossl"
              securityPolicy: "demopolicy"
            topologyOutboundL3:
              vlans:
                - "/Common/client-vlan"
              snat: snatlist
              snatlist:
                - 10.1.20.110
                - 10.1.20.111
              gateway: "iplist"
              gatewaylist: 
                - ratio: 1
                  ip: 10.1.20.1
                - ratio: 2
                  ip: 10.1.20.2          
            logging:
              sslo: debug
              perRequestPolicy: debug
          delegate_to: localhost

.. code-block:: yaml

    - name: Create SSLO Topology (complex outbound L3 - atomic)
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
        - name: SSLO topology
          bigip_sslo_config_topology:
            provider: "{{ provider }}"
            name: "demoOutL3"
            configReferences:
              sslSettings: "demossl"
              securityPolicy: "demopolicy"
            topologyOutboundL3:
              protocol: "tcp"
              ipFamily: ipv4
              vlans:
                - "/Common/client-vlan"
              source: 10.0.0.0/24
              port: 65535
              additionalProtocols:
                - ftp
                - smtps
              snat: snatpool
              snatpool: "/Common/my-snatpool"
              gateway: "pool"
              gatewaypool: "/Common/gwpool"          
              accessProfile: "/Common/my-custom-sslo-policy"
              profileScope: "named"
              profileScopeValue: "SSLO"
              primaryAuthUri: "https://login.f5labs.com/"
            logging:
              sslo: debug
              perRequestPolicy: warning
              ftp: warning
          delegate_to: localhost

.. code-block:: yaml

    - name: Create SSLO Topology (explicit proxy - atomic)
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
        - name: SSLO topology
          bigip_sslo_config_topology:
            provider: "{{ provider }}"
            name: "demoxp1"
            configReferences:
              sslSettings: "demossl"
              securityPolicy: "demopolicy"
            topologyOutboundExplicit:
              proxyIp: "10.1.10.150"
              proxyPort: 3128
              vlans:
                - "/Common/client-vlan"
              gateway: "iplist"
              gatewaylist:
                - ip: 10.1.20.1
              snat: automap          
          delegate_to: localhost

.. code-block:: yaml

    - name: Create SSLO Topology (inbound L3 - atomic)
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
        - name: SSLO topology
          bigip_sslo_config_topology:
            provider: "{{ provider }}"
            name: "demoin1"
            configReferences:
              sslSettings: "demoinssl"
              securityPolicy: "demoinpolicy"
            topologyInboundL3:
              dest: "10.1.20.120/32"
              pool: "/Common/test-pool"
              vlans: 
                - "/Common/client-vlan"
          delegate_to: localhost

.. code-block:: yaml

    - name: Create SSLO Topology (complex outbound L3 with internal Jinja2 references - aggregate)
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
        #### services #################################
        - name: SSLO LAYER2 service
          bigip_sslo_service_layer2:
            provider: "{{ provider }}"
            name: "layer2"
            devices:
              - name: "FEYE1"
                interfaceIn: "1.3"
                interfaceOut: "1.4"
            portRemap: 8080
            mode: output
          register: service_layer2
          delegate_to: localhost

        - name: SSLO ICAP service
          bigip_sslo_service_icap:
            provider: "{{ provider }}"
            name: "icap"
            devices: 
              - ip: "198.19.97.50"
                port: 1344
            mode: output
          register: service_icap
          delegate_to: localhost

        #### ssl ######################################
        - name: SSLO SSL settings
          bigip_sslo_config_ssl:
            provider: "{{ provider }}"
            name: "demossl"
            clientSettings:
              caCert: "/Common/subrsa.f5labs.com"
              caKey: "/Common/subrsa.f5labs.com"
            mode: output
          register: sslsettings
          delegate_to: localhost
        
        #### service chains ###########################
        - name: SSLO service chain
          bigip_sslo_config_service_chain:
            provider: "{{ provider }}"
            name: "service_chain_1"
            services:
              - name: layer2
                serviceType: L2
                ipFamily: ipv4
              - name: icap
                serviceType: icap
                ipFamily: ipv4
            mode: output
          register: servicechain1
          delegate_to: localhost
        
        - name: SSLO service chain
          bigip_sslo_config_service_chain:
            provider: "{{ provider }}"
            name: "service_chain_2"
            services:
              - name: layer2
                serviceType: L2
                ipFamily: ipv4
            mode: output
          register: servicechain2
          delegate_to: localhost

        #### policy ###################################
        - name: SSLO security policy
          bigip_sslo_config_policy:
            provider: "{{ provider }}"
            name: "demopolicy"
            policyType: "outbound"
            defaultRule:
              allowBlock: "allow"
              tlsIntercept: "intercept"
              serviceChain: "service_chain_1"
            trafficRules:
              - name: "pinners"
                conditions:
                  - condition: "pinnersRule"
              - name: "bypass_Finance_Health"
                matchType: "or"
                allowBlock: "allow"
                tlsIntercept: "bypass"
                serviceChain: "service_chain_2"
                conditions:
                  - condition: "categoryLookupAll"
                    values:
                      - "/Common/Financial_Data_and_Services"
                      - "/Common/Health_and_Medicine"
            mode: output
          register: securitypolicy
          delegate_to: localhost

        #### topology #################################
        - name: SSLO topology
          bigip_sslo_config_topology:
            provider: "{{ provider }}"
            name: "demoOutL3"
            configReferences:
              sslSettings: "{{ sslsettings }}"
              securityPolicy: "{{ securitypolicy }}"
              services:
                - "{{ service_layer2 }}"
                - "{{ service_icap }}"
              serviceChains:
                - "{{ servicechain1 }}"
                - "{{ servicechain2 }}"
            topologyOutboundL3:
              vlans:
                - "/Common/client-vlan"
              snat: automap
              gateway: "iplist"
              gatewaylist: 
                - ip: 10.1.20.1        
          delegate_to: localhost