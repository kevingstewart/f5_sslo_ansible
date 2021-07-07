F5 SSL Orchestrator Ansible Automation Collection
+++++++++++++++++++++++++++++++++++++++++++++++++

Documentation - SSL Settings
============================

Module: bigip_sslo_config_ssl
-----------------------------

Description
-----------
The SSL configuration encompasses all decryption and re-encryption properties of an SSL Orchestrator topology (client and server SSL settings).

From a configuration and automation perspective, a forward proxy is minimally identified by the presence of a signing CA certificate and key. A reverse proxy minimally requires the (server) certificate and private key to be defined. Most other settings can be left as default.

Sample with all options defined
-------------------------------
.. code-block:: yaml

    - name: SSLO SSL config
      bigip_sslo_config_ssl:
        provider: "{{ provider }}"
        name: sslsettings
        state: present

        clientSettings:
          cipherType: "string"
          cipher: "DEFAULT"
          enableTLS1_3: True
          cert: "/Common/default.crt"
          key: "/Common/default.key"
          chain: "/Common/cert-chain"
          caCert: "/Common/ca.crt"
          caKey: "/Common/ca.key"
          caChain: "/Common/ca-chain.crt"
        
        serverSettings:
          cipherType: "string"
          cipher: "DEFAULT"
          enableTLS1_3: True
          caBundle: "/Common/ca-bundle.crt"
          blockExpired: False
          blockUntrusted: False
          ocsp: "/Common/my-ocsp"
          crl: "/Common/my-crl"

        bypassHandshakeFailure: False
        bypassClientCertFailure: False
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
          <p>The name of the security service (ex. sslsettings)</p>
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
          <td colspan="2" rowspan="1">clientSettings</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[dict]</p>
          <p>The set of client side TLS settings (for decryption)</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>cipherType</td>
          <td>no</td>
          <td>string</td>
          <td>string<br />group</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The cipher type, either a cipher string, or cipher group</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>cipher</td>
          <td>no</td>
          <td>DEFAULT</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The applied cipher. If cipher string is defined, this is the string. If cipher group is defined, this is the name of the cipher group</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>enableTLS1_3</td>
          <td>no</td>
          <td>False</td>
          <td>True<br />False</td>
          <td>all</td>
          <td><p>[bool]</p>
          <p>Switch to enable or disable TLS 1.3 support</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>cert</td>
          <td>no</td>
          <td>/Common/default.crt</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The certificate to apply to client side TLS. If this is a forward proxy, the certificate is used as a forging template. If this is a reverse proxy, this is the server certificate</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>key</td>
          <td>no</td>
          <td>/Common/default.key</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The corresponding private key</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>chain</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>If required, this is the name of a certificate key chain (used for reverse proxy)</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>caCert *</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>For forward proxy, this is the signing CA certificate</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>caKey *</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The corresponding signing CA private key</p>
          </td>
        </tr>


        <tr>
          <td colspan="2" rowspan="1">serverSettings</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[dict]</p>
          <p>The set of server side TLS settings (for re-encryption)</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>cipherType</td>
          <td>no</td>
          <td>string</td>
          <td>string<br />group</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The cipher type, either a cipher string, or cipher group</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>cipher</td>
          <td>no</td>
          <td>DEFAULT</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The applied cipher. If cipher string is defined, this is the string. If cipher group is defined, this is the name of the cipher group</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>enableTLS1_3</td>
          <td>no</td>
          <td>False</td>
          <td>True<br />False</td>
          <td>all</td>
          <td><p>[bool]</p>
          <p>Switch to enable or disable TLS 1.3 support</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>caBundle</td>
          <td>no</td>
          <td><nobr>/Common/ca-bundle.crt</nobr></td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of a CA certificate bundle (used for forward proxy)</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>blockExpired</td>
          <td>no</td>
          <td>**</td>
          <td>True<br />False</td>
          <td>all</td>
          <td><p>[bool]</p>
          <p>Switch to enable blocking of expired server certificates</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>blockUntrusted</td>
          <td>no</td>
          <td>***</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[bool]</p>
          <p>Switch to enable or disable blocking of untrusted server certificates</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>ocsp</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of an OCSP (certificate revocation) configuration</p>
          </td>
        </tr>
        <tr>
          <td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
          <td>crl</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[string]</p>
          <p>The name of a CRL (certificate revocation) configuration</p>
          </td>
        </tr>


        <tr>
          <td colspan="2" rowspan="1">bypassHandshakeFailure</td>
          <td>no</td>
          <td>False</td>
          <td>True<br />False</td>
          <td>all</td>
          <td><p>[bool]</p>
          <p>Switch to enable or disable TLS bypass on detection of a server side TLS handshake failure</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">bypassClientCertFailure</td>
          <td>no</td>
          <td>False</td>
          <td>True<br />False</td>
          <td>all</td>
          <td><p>[bool]</p>
          <p>Switch to enable or disable TLS bypass on detection of a server side client certificate request</p>
          </td>
        </tr>

      </tbody>
    </table>

Footnotes
---------
- \* The presence of the caCert and caKey options defines a forward proxy SSL configuration
- \*\* blockExpired defaults to True for forward proxy, and defaults to False for reverse proxy
- \*\*\* blockUntrusted defaults to True for forward proxy, and defaults to False for reverse proxy
    

Examples
--------

.. code-block:: yaml

    - name: Create SSLO SSL Forward Proxy Settings (simple)
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
        - name: SSLO SSL forward proxy settings
          bigip_sslo_config_ssl:
            provider: "{{ provider }}"
            name: "demo_ssl"
            clientSettings:
              caCert: "/Common/subrsa.f5labs.com"
              caKey: "/Common/subrsa.f5labs.com"
          delegate_to: localhost

.. code-block:: yaml

    - name: Create SSLO SSL Forward Proxy Settings
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
        - name: SSLO SSL settings
          bigip_sslo_config_ssl:
            provider: "{{ provider }}"
            name: "demo_ssl"
            clientSettings:
              cipherType: "group"
              cipher: "/Common/f5-default"
              enableTLS1_3: True
              cert: "/Common/default.crt"
              key: "/Common/default.key"
              caCert: "/Common/subrsa.f5labs.com"
              caKey: "/Common/subrsa.f5labs.com"
              caChain: "/Common/my-ca-chain"
            serverSettings:
              cipherType: "group"
              cipher: "/Common/f5-default"
              enableTLS1_3: True
              caBundle: "/Common/local-ca-bundle.crt"
              blockExpired: False
              blockUntrusted: False
              ocsp: "/Common/my-ocsp"
              crl: "/Common/my-crl"
            bypassHandshakeFailure: True
            bypassClientCertFailure: True
          delegate_to: localhost

.. code-block:: yaml

    - name: Create SSLO SSL Reverse Proxy Settings (simple)
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
        - name: SSLO SSL settings
          bigip_sslo_config_ssl:
            provider: "{{ provider }}"
            name: "demo_ssl"
            clientSettings:
              cert: "/Common/myserver.f5labs.com"
              key: "/Common/myserver.f5labs.com"
          delegate_to: localhost

.. code-block:: yaml

    - name: Create SSLO SSL Reverse Proxy Settings
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
        - name: SSLO SSL settings
          bigip_sslo_config_ssl:
            provider: "{{ provider }}"
            name: "demo_ssl"
            clientSettings:
              cipherType: "group"
              cipher: "/Common/f5-default"
              enableTLS1_3: True
              cert: "/Common/myserver.f5labs.com"
              key: "/Common/myserver.f5labs.com"
              chain: "/Common/my-ca-chain"
            serverSettings:
              cipherType: "group"
              cipher: "/Common/f5-default"
              enableTLS1_3: True
              caBundle: "/Common/local-ca-bundle.crt"
              blockExpired: False
              blockUntrusted: False
          delegate_to: localhost
