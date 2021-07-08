F5 SSL Orchestrator Ansible Automation Collection
+++++++++++++++++++++++++++++++++++++++++++++++++

Documentation - Security Policy
===============================

Module: bigip_sslo_config_policy
--------------------------------

Description
-----------
An SSL Orchestrator security policy is a set of traffic rules that define a set of actions: allow/block, TLS intercept/bypass, and service chain assignment. The traffic rules within a security policy are the set of traffic matching conditions. From a configuration and automation perspective, a security policy minimally requires the defaultRule settings to define what happens when no traffic rules are matched. There are multiple types of traffic conditions to choose from, as documented below.

Sample with all options defined
-------------------------------
.. code-block:: yaml

    - name: SSLO policy
      bigip_sslo_config_policy:
        provider: "{{ provider }}"
        name: securitypolicy_1
        state: present
        policyType: "inbound"

        trafficRules:
          - name: "traffic-rule-1"
            matchType: "or"
            allowBlock: "allow"
            tlsIntercept: "bypass"
            serviceChain: "service_chain_1"
            conditions:
              - condition: [<see below>]
              - condition: [<see below>]

        defaultRule:
          allowBlock: "allow"
          tlsIntercept: "intercept"
          serviceChain: None

        serverCertValidation: False

        proxyConnect:
          enabled: True
          pool: "/Common/upstream-proxy-pool"

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
          <p>The name of the security service (ex. securitypolicy_1)</p>
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
          <td colspan="2" rowspan="1">policyType</td>
          <td>yes</td>
          <td>outbound</td>
          <td>outbound<br />inbound</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>Defines the type of security policy, forward proxy (outbound), or reverse proxy (inbound)</p>
          </td>
        </tr>


        <tr>
          <td colspan="2" rowspan="1">trafficRules</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of traffic rules</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>name</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of this specific traffic rule</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>matchType</td>
          <td>no</td>
          <td>or</td>
          <td>and<br />or</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The match type for this rule if multiple conditions are applied</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>allowBlock</td>
          <td>no</td>
          <td>allow</td>
          <td>allow<br />block</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The allow/block behavior if this traffic rule is matched</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>tlsIntercept</td>
          <td>no</td>
          <td>bypass</td>
          <td>intercept<br />bypass</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The TLS intercept/bypass behavior is this traffic rule is matched</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>serviceChain</td>
          <td>no</td>
          <td>None</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of the service chain to send traffic to if this traffic rule is matched</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>conditions</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of traffic conditions (see conditions below)</p>
          </td>
        </tr>


        <tr>
          <td colspan="2" rowspan="1">defaultRule</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[dict]</p>
          <p>The set of default behaviors if no traffic rules are matched</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>allowBlock</td>
          <td>no</td>
          <td>allow</td>
          <td>allow<br />block</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The allow/block behavior if this traffic rule is matched</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>tlsIntercept</td>
          <td>no</td>
          <td>bypass</td>
          <td>intercept<br />bypass</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The TLS intercept/bypass behavior is this traffic rule is matched</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>serviceChain</td>
          <td>no</td>
          <td>None</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of the service chain to send traffic to if this traffic rule is matched</p>
          </td>
        </tr>


        <tr>
          <td colspan="2" rowspan="1">serverCertValidation</td>
          <td>no</td>
          <td>False</td>
          <td>True<br />False</td>
          <td>7.0+</td>
          <td><p>[bool]</p>
          <p>Switch to enable or disable server certificate validation. When enabled and the server certificate is found to be expired or untrusted, the user receives a blocking page. The blockExpired and blockUntrusted options in the SSL configuration must be set to ignore for this option to work</p>
          </td>
        </tr>


        <tr>
          <td colspan="2" rowspan="1">proxyConnect</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[dict]</p>
          <p>A set of properties used to enable upstream explicit proxy gateway access</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>enabled</td>
          <td>no</td>
          <td>False</td>
          <td>True<br />False</td>
          <td>all</td>
          <td><p>[bool]</p>
          <p>Switch to enable or disable forwarding egress traffic to an upstream explicit proxy gateway</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>pool</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of the upstream explicit proxy pool</p>
          </td>
        </tr>

      </tbody>
    </table>

|

Condition: pinnersRule
----------------------
Description: when defined, no additional settings are required, and no other conditions can be included in the traffic rule. This condition sets up a custom URL category match based on the built-in "pinners" custom URL category.

|

Condition: categoryLookupAll
----------------------------
Description: defines a URL category lookup for all HTTP and HTTPS traffic (SNI and HTTP Host) information.

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
          <td colspan="2" rowspan="1">values</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <td>A list of URL category names *</td>
        </tr>
      </tbody>
    </table>

|

Condition: categoryLookupConnect
--------------------------------
Description: defines a URL category lookup based on explicit forward proxy HTTP Connect information.
    
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
          <td colspan="2" rowspan="1">values</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of URL category names *</p>
          </td>
        </tr>
      </tbody>
    </table>

|

Condition: categoryLookupSNI
----------------------------
Description: defines a category lookup based on TLS handshake server name indication (SNI) information only.
    
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
          <td colspan="2" rowspan="1">values</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of URL category names *</p>
          </td>
        </tr>
      </tbody>
    </table>

|

Condition: clientIpGeolocation
------------------------------
Description: defines an IP Geolocation lookup based on client IP address information.
    
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
          <td colspan="2" rowspan="1">values</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of geolocation type:value properties</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>type</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>countryCode<br />countryName<br />continent<br />state</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The type of geolocation information to match on</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>value</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The corresponding geolocation value to match</p>
          </td>
        </tr>
      </tbody>
    </table>

|

Condition: serverIpGeolocation
------------------------------
Description: defines an IP Geolocation lookup based on server IP address information.
    
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
          <td colspan="2" rowspan="1">values</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of geolocation type:value properties</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>type</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>countryCode<br />countryName<br />continent<br />state</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The type of geolocation information to match on</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>value</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The corresponding geolocation value to match</p>
          </td>
        </tr>
      </tbody>
    </table>

|

Condition: clientIpReputation
-----------------------------
Description: defines an IP Reputation service lookup based on client IP address information.
    
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
          <td colspan="2" rowspan="1">value</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>good<br />bad<br />category</td>
          <td>category(7.0+)</td>
          <td><p>[string]</p>
          <p>The type of IP reputation match</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">values</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>category(7.0+)</td>
          <td><p>[list]</p>
          <p>The list of IP reputation values to match if category is defined **</p>
          </td>
        </tr>
      </tbody>
    </table>

|

Condition: serverIpReputation
-----------------------------
Description: defines an IP Reputation service lookup based on server IP address information.
    
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
          <td colspan="2" rowspan="1">value</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>good<br />bad<br />category</td>
          <td>category(7.0+)</td>
          <td><p>[string]</p>
          <p>The type of IP reputation match</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">values</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>category(7.0+)</td>
          <td><p>[list]</p>
          <p>The list of IP reputation values to match if category is defined **</p>
          </td>
        </tr>
      </tbody>
    </table>

|

Condition: clientIpSubnet
-------------------------
Description: defines a traffic match based on client IP subnet information.
    
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
          <td colspan="2" rowspan="1">values</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>datagroups(8.2+)</td>
          <td><p>[list]</p>
          <p>The list of IP addresses, IP subnets, or address-type datagroups(8.0+)</p>
          </td>
        </tr>
      </tbody>
    </table>

|

Condition: serverIpSubnet
-------------------------
Description: defines a traffic match based on server IP subnet information.
    
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
          <td colspan="2" rowspan="1">values</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>datagroups(8.2+)</td>
          <td><p>[list]</p>
          <p>The list of IP addresses, IP subnets, or address-type datagroups(8.0+)</p>
          </td>
        </tr>
      </tbody>
    </table>

|

Condition: clientPort
---------------------
Description: defines a traffic match based on client port information.
    
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
          <td colspan="2" rowspan="1">type</td>
          <td>yes</td>
          <td>value</td>
          <td>value<br />range</td>
          <td>range(8.2+)</td>
          <td><p>[string]</p>
          <p>The type of value to match on, either a single "value", or "range" of ports</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">values</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of ports</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">fromPort</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>8.2+</td>
          <td><p>[int]</p>
          <p>For a port range, the starting port</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">toPort</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>8.2+</td>
          <td><p>[int]</p>
          <p>For a port range, the ending port</p>
          </td>
        </tr>
      </tbody>
    </table>

|

Condition: serverPort
---------------------
Description: defines a traffic match based on server port information.
    
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
          <td colspan="2" rowspan="1">type</td>
          <td>yes</td>
          <td>value</td>
          <td>value<br />range</td>
          <td>range(8.2+)</td>
          <td><p>[string]</p>
          <p>The type of value to match on, either a single "value", or "range" of ports</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">values</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of ports</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">fromPort</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>8.2+</td>
          <td><p>[int]</p>
          <p>For a port range, the starting port</p>
          </td>
        </tr>
        <tr>
          <td colspan="2" rowspan="1">toPort</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>8.2+</td>
          <td><p>[int]</p>
          <p>For a port range, the ending port</p>
          </td>
        </tr>
      </tbody>
    </table>

|

Condition: sslCheck
-------------------
Description: defines a traffic match based on the existence of a TLS handshake.
    
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
          <td colspan="2" rowspan="1">value</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>True<br />False</td>
          <td>all</td>
          <td><p>[bool]</p>
          <p>Switch to enable or disable an SSL check condition (presence of TLS handshake)</p>
          </td>
        </tr>
      </tbody>
    </table>

|

Condition: L7ProtocolCheckTcp
-----------------------------
Description: defines a traffic match based on the layer 7 TCP protocol.
    
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
          <td colspan="2" rowspan="1">values</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>dns<br />ftp<br />http<br />https<br />httpConnect<br />imap<br />pop3<br />smtps<br />telnet</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>The list of layer 7 TCP protocols to match</p>
          </td>
        </tr>
      </tbody>
    </table>

|

Condition: L7ProtocolCheckUdp
-----------------------------
Description: defines a traffic match based on the layer 7 UDP protocol.
    
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
          <td colspan="2" rowspan="1">values</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>dns<br />quic</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>The list of layer 7 UDP protocols to match</p>
          </td>
        </tr>
      </tbody>
    </table>

|

Condition: urlMatch
-------------------
Description: defines a traffic match based on the unencrypted HTTP Host and URI information.
    
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
          <td colspan="2" rowspan="1">values</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[list]</p>
          <p>A list of URL string matches</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>type</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>equals<br />substring<br />prefix<br />suffix<br />glob</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The type of URL match to make</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>value</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The corresponding URL value</p>
          </td>
        </tr>
      </tbody>
    </table>


Footnotes
---------

- \* The names of the URL categories can be found using this command in the BIG-IP console:

    `tmsh list sys url-db url-category one-line | awk -F" " '{ print $4 }'`

- \*\* The list of IP reputation categories can be found here: https://techdocs.f5.com/en-us/bigip-14-0-0/big-ip-local-traffic-manager-implementations-14-0-0/enabling-ip-address-intelligence.html

Examples
--------

.. code-block:: yaml

    - name: Create SSLO Security Policy (simple)
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
        - name: SSLO security policy
          bigip_sslo_config_policy:
            provider: "{{ provider }}"
            name: "securitypolicy_1"
            policyType: "outbound"
            
            trafficRules:            
                - name: "Pinners"
                  conditions:
                    - condition: "pinnersRule"
                
                - name: "Bypass_Finance_Health"
                  allowBlock: "allow"
                  tlsIntercept: "bypass"
                  serviceChain: "service_chain_1"
                  conditions:
                    - condition: "categoryLookupAll"
                      values:
                        - "/Common/Financial_Data_and_Services"
                        - "/Common/Health_and_Medicine"
          delegate_to: localhost

.. code-block:: yaml

    - name: Create SSLO Security Policy (complex)
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
        - name: SSLO security policy
          bigip_sslo_config_policy:
            provider: "{{ provider }}"
            name: "securitypolicy_1"
            policyType: "outbound"
            
            defaultRule:
                allowBlock: "allow"
                tlsIntercept: "intercept"
                serviceChain: "service_chain_1"
            
            trafficRules: 
                - name: "Pinners"
                  conditions:
                    - condition: "pinnersRule"
                
                - name: "Bypass_Finance_Health_All"
                  allowBlock: "allow"
                  tlsIntercept: "bypass"
                  serviceChain: "service_chain_1"
                  conditions:
                    - condition: "categoryLookupAll"
                      values:
                        - "/Common/Financial_Data_and_Services"
                        - "/Common/Health_and_Medicine"

                - name: "Bypass_Finance_Health_SNI"
                  matchType: "and"
                  allowBlock: "allow"
                  tlsIntercept: "bypass"
                  serviceChain: "service_chain_1"
                  conditions:
                    - condition: "sslCheck"
                      value: True
                    - condition: "categoryLookupSNI"
                      values:
                        - "/Common/Financial_Data_and_Services"
                        - "/Common/Health_and_Medicine"

                - name: "Bypass by source or destination geolocation"
                  matchType: "or"
                  allowBlock: "allow"
                  tlsIntercept: "bypass"
                  serviceChain: "service_chain_1"
                  conditions:
                    - condition: "clientIpGeolocation"
                      values:
                        - type: "countryCode"
                          value: "US"
                        - type: "countryCode"
                          value: "UK"
                    - condition: "serverIpGeolocation"
                      values:
                        - type: "countryCode"
                          value: "/Common/remoteCountryCodes_datagroup"

                - name: "Bypass by source and destination IP subnet"
                  matchType: "and"
                  allowBlock: "allow"
                  tlsIntercept: "bypass"
                  serviceChain: "service_chain_1"
                  conditions:
                    - condition: "clientIpSubnet"
                      values:
                        - "10.1.10.0/24"
                        - "10.1.20.0/24"
                    - condition: "serverIpSubnet"
                      values:
                        - "/Common/server-subnet-datagroup"

                - name: "Bypass by source and destination port"
                  matchType: "and"
                  allowBlock: "allow"
                  tlsIntercept: "bypass"
                  serviceChain: "service_chain_1"
                  conditions:
                    - condition: "clientPort"
                      type: "range"
                      fromPort: 1024
                      toPort: 65000
                    - condition: "serverPort"
                      type: "value"
                      values:
                        - 80
                        - 443                    

                - name: "Block on client or server IP reputation"
                  matchType: "or"
                  allowBlock: "block"
                  conditions:
                    - condition: "clientIpReputation"
                      value: "bad"
                    - condition: "serverIpReputation"
                      value: "category"
                      values:
                        - "Spam Sources"
                        - "Web Attacks"
          delegate_to: localhost

.. code-block:: yaml

    - name: Create SSLO Security Policy (with upstream proxy pool)
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
        - name: Create upstream proxy pool
          bigip_pool:
            provider: "{{ provider }}"
            name: upstream-proxy-pool
          delegate_to: localhost

        - name: Add member to upstream proxy pool
          bigip_pool_member:
            provider: "{{ provider }}"
            pool: upstream-proxy-pool
            host: "10.1.20.130"
            port: 8080
          delegate_to: localhost

        - name: SSLO security policy
          bigip_sslo_config_policy:
            provider: "{{ provider }}"
            name: "securitypolicy_1"
            policyType: "outbound"
            
            trafficRules:
              - name: "pinners"
                conditions:
                  - condition: "pinnersRule"
              
              - name: "Bypass_Finance_Health_All"
                matchType: "or"
                allowBlock: "allow"
                tlsIntercept: "bypass"
                serviceChain: "service_chain_1"
                conditions:
                  - condition: "categoryLookupAll"
                    values:
                      - "/Common/Financial_Data_and_Services"
                      - "/Common/Health_and_Medicine"

            defaultRule:
              allowBlock: "allow"
              tlsIntercept: "intercept"
              serviceChain: "service_chain_2"
            
            proxyConnect: 
              enabled: True
              pool: "/Common/upstream-proxy-pool"
          delegate_to: localhost

Best Practices and Considerations
---------------------------------
- As security policy rules are nested, it is generally best practice to place the traffic rules in OSI order. IP and port based conditions should be placed first, above URL category and sslCheck conditions, and then TLS bypass conditions should be above TLS intercept conditions. Layer 7 (TCP/UDP) protocol matches, and the urlMatch condition should be placed last in the set of rules.