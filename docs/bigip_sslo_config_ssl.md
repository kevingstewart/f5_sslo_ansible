# F5 SSL Orchestrator Ansible Automation Collection
## Documentation - SSL Settings
#### Module: bigip_sslo_config_ssl

**Description**

The SSL configuration encompasses all decryption and re-encryption properties of an SSL Orchestrator topology (client and server SSL settings).

From a configuration and automation perspective, a forward proxy is minimally identified by the presence of a signing CA certificate and key. A reverse proxy minimally requires the (server) certificate and private key to be defined. Most other settings can be left as default.

**Sample wth all options defined**
```yaml
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
```

**Options**
| Key | Required | Default | Options | Support | Description |
| ------ | ------ | ------ | ------ | ------ | ------ |
| provider | yes |  |  | all | The BIG-IP connection provider information |
| name | yes |  |  | all | [string]<br />The name of the SSL configuration (ex. sslsettings) |
| state | no | present | present<br />absent | all | [string]<br />Value to determine create/modify (present) or delete (absent) action |
| clientSettings | yes |  |  | all | [dict]<br />The set of client side TLS settings (for decryption) |
| clientSettings:<br />cipherType | no | string | string<br />group | all | [string]<br />The cipher type, either a cipher string, or cipher group |
| clientSettings:<br />cipher | no | DEFAULT |  | all | [string]<br />The applied cipher. If cipher string is defined, this is the string. If cipher group is defined, this is the name of the cipher group |
| clientSettings:<br />enableTLS1_3 | no | False | True<br />False | all | [bool]<br />Switch to enable or disable TLS 1.3 support |
| clientSettings:<br />cert | no | /Common/default.crt |  | all | [string]<br />The certificate to apply to client side TLS. If this is a forward proxy, the certificate is used as a forging template. If this is a reverse proxy, this is the server certificate |
| clientSettings:<br />key | no | /Common/default.key |  | all | [string]<br />The corresponding private key |
| clientSettings:<br />chain | no |  |  | all | [string]<br />If required, this is the name of a certificate key chain (used for reverse proxy) |
| clientSettings:<br />caCert* | no |  |  | all | [string]<br />For forward proxy, this is the signing CA certificate |
| clientSettings:<br />caKey* | no |  |  | all | [string]<br />The corresponding signing CA private key |
| clientSettings:<br />caChain | no |  |  | all | [string]<br />If required, this is the name of a certificate key chain (used for forward proxy) |
| serverSettings | no |  |  | all | [dict]<br />The set of server side TLS settings (for re-encryption) |
| serverSettings:<br />cipherType | no | string | string<br />group | all | [string]<br />The cipher type, either a cipher string, or cipher group |
| serverSettings:<br />cipher | no | DEFAULT |  | all | [string]<br />The applied cipher. If cipher string is defined, this is the string. If cipher group is defined, this is the name of the cipher group |
| serverSettings:<br />enableTLS1_3 | no | False | True<br />False | all | [bool]<br />Switch to enable or disable TLS 1.3 support |
| serverSettings:<br />caBundle | no | /Common/ca-bundle.crt |  | all | [string]<br />The name of a CA certificate bundle (used for forward proxy) |
| serverSettings:<br />blockExpired | no | ** | True<br />False | all | [bool]<br />Switch to enable blocking of expired server certificates |
| serverSettings:<br />blockUntrusted | no | *** | True<br />False | all | [bool]<br />Switch to enable or disable blocking of untrusted server certificates |
| serverSettings:<br />ocsp | no |  |  | all | [string]<br />The name of an OCSP (certificate revocation) configuration |
| serverSettings:<br />crl | no |  |  | all | [string]<br />The name of a CRL (certificate revocation) configuration |
| bypassHandshakeFailure | no | False | True<br />False | all | [bool]<br />Switch to enable or disable TLS bypass on detection of a server side TLS handshake failure |
| bypassClientCertFailure | no | False | True<br />False | all | [bool]<br />Switch to enable or disable TLS bypass on detection of a server side client certificate request |

*Footnotes:*
- \* The presence of the caCert and caKey options defines a forward proxy SSL configuration
- \** blockExpired defaults to True for forward proxy, and defaults to False for reverse proxy
- \*** blockUntrusted defaults to True for forward proxy, and defaults to False for reverse proxy

**Examples**
```YAML
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
```
```YAML
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
```
```YAML
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
```
```YAML
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
```

 