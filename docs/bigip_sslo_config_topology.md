# F5 SSL Orchestrator Ansible Automation Collection
## Documentation - Topology
#### Module: bigip_sslo_config_topology

<br />

**Description**<br />
An SSL Orchestrator topology is generally defined as the set of the properties that constitute a complete security inspection environment. Topologies are classified by a type that identifies how they attach to a network and consume traffic (i.e. transparent forward proxy, explicit forward proxy, reverse proxy), and include the setting that control decryption and re-encryption, and dynamic service chain management.

From a configuration and automation perspective, topologies can be further categorized by two deployment methods:

- **Atomic**: where the topology configuration minimally defines itelf, and references to SSL and security policy settings. In this mode, the other dependent objects (i.e. security services, service chains, security policy, and SSL settings) must all be created first. In an Ansible playbook these could simply be separate tasks that are created in parent-child dependent order, or they could be created in separate playbooks at different times. Creating all of the SSL Orchestrator objects as atomic tasks in a playbook will take a while to complete, as each object creation task must finish before the next is started.
- **Aggregate**: where dependent object creation is deferred and its configuration block referenced inside a single topology creation task. This method uses a special "mode" option in the dependent objects to defer sending the configuration to the target host. When the mode is set to "output", the object task bypasses creation, and simply returns the JSON configuration block in a registered variable. The topology declaration can then reference this JSON block as a Jinja2 variable, and combine all of the JSON blocks into a single all-encompassing creation task. The advantage of this approach is a much faster creation time.

A topology declaration must minimally contain SSL and security policy settings, and one (and only one) topology definition.

<br />

**Sample wth all options defined**
```yaml
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
      perRequestPolicy:	error
      ftp: error
      imap: error
      pop3: error
      smtps: error

delegate_to: localhost
```

<br />

**Options**
| Key | Required | Default | Options | Support | Description |
| ------ | ------ | ------ | ------ | ------ | ------ |
| provider | yes |  |  | all | The BIG-IP connection provider information |
| name | yes |  |  | all | [string]<br />The name of the topology (ex. topology_1) |
| state | no | present | present<br />absent | all | [string]<br />Value to determine create/modify (present) or delete (absent) action |

<br />

**Options: configReferences**<br />
Description: defines a set of external configuration references
| Key | Required | Default | Options | Support | Description |
| ------ | ------ | ------ | ------ | ------ | ------ |
| sslSettings | yes |  |  | all | [string]<br />The name of an SSL configuration, or Jinja2 reference to a local SSL configuration task |
| securityPolicy | yes |  |  | all | [string]<br />The name of a security policy, or Jinja2 reference to a local security policy task |
| services | no |  |  | all | [list]<br />A list of Jinja2 references for local service creation tasks |
| serviceChains | no |  |  | all | [list]<br />A list of Jinja2 references for local service chain creation tasks |
| resolver | no |  |  | all | [string]<br />A Jinja2 reference to a local resolver configuration task |

<br />

**Options: topologyOutboundL3**<br />
Description: defines the properties of an outbound layer 3 (transparent forward proxy) topology
| Key | Required | Default | Options | Support | Description |
| ------ | ------ | ------ | ------ | ------ | ------ |
| ipFamily | no | ipv4 | ipv4<br />ipv6 | all | [string]<br />The IP family expected for this security device |
| protocol | no | tcp | tcp<br />udp<br />other | all | [string]<br />The matching layer 4 protocol |
| source | no | 0.0.0.0%0/0 |  | all | [string]<br />A source IP address filter |
| dest | no | 0.0.0.0%0/0 |  | all | [string]<br />A destination IP address filter |
| port | no | 0 |  | all | [int]<br />A destination port filter |
| vlans | no |  |  | all | [list]<br />A list of client-facing VLANs |
| snat | no | none | none<br />automap<br />snatpool<br />snatlist | all | [string]<br />An egress source NAT option |
| snatlist | no |  |  | all | [list]<br />If snat is snatpool, this is a list of SNAT IP addresses |
| snatpool | no |  |  | all | [string]<br />If snat is snatpool, this is the name of an existing SNAT pool |
| gateway | no | system | system<br />pool<br />iplist | all | [string]<br />An egress gateway option |
| gatewaylist | no |  |  | all | [list]<br />If gateway is gatewaylist, this is the list of gateway IP addresses |
| gatewaypool | no |  |  | all | [string]<br />If gateway is gatewaypool, this is the name of an existing gateway pool |
| tcpSettingsClient | no | /Common/f5-tcp-lan |  | all | [string]<br />The name of a custom client side TCP profile |
| tcpSettingsServer | no | /Common/f5-tcp-wan |  | all | [string]<br />The name of a custom server side TCP profile |
| L7ProfileType | no | none | none<br />http | all | [string]<br />If required, this selects a specific L7 profile type |
| L7Profile | no | none |  | all | [string]<br />If L7ProfileType is http, this is the name of a specific HTTP profile |
| additionalProtocols | no |  | ftp<br />imap<br />pop3<br />smtps | all | [list]<br />A list of additional protocols to create listeners for |
| accessProfile | no | (generated profile) |  | all | [string]<br />The name of a custom SSL Orchestrator access profile |
| profileScope | no | public |  | 8.2+ | [string]<br />When performing transparent forward proxy captive portal authentication, the "named" profileScope allows authenticated identity information from the authentication profile to be shared with the proxy. |
| profileScopeValue | no |  |  | 8.2+ | [string]<br />When profileScope is named, this setting is required and defines a unique name value that is shared between then captive portal and security policy profiles |
| primaryAuthUri | no |  |  | 8.2+ | [string]<br />When profileScope is named, this setting is required and defines the fully-qualified domain name of the captive portal authentication site |

<br />

**Options: topologyOutboundExplicit**<br />
Description: defines the properties of an outbound explicit forward proxy topology
| Key | Required | Default | Options | Support | Description |
| ------ | ------ | ------ | ------ | ------ | ------ |
| ipFamily | no | ipv4 | ipv4<br />ipv6 | all | [string]<br />The IP family expected for this security device |
| source | no | 0.0.0.0%0/0 |  | all | [string]<br />A source IP address filter |
| proxyIp | yes |  |  | all | [string]<br />The explicit proxy listening IP address |
| proxyPort | yes |  |  | all | [int]<br />The explicit proxy listening port |
| vlans | no |  |  | all | [list]<br />A list of client-facing VLANs |
| snat | no | none | none<br />automap<br />snatpool<br />snatlist | all | [string]<br />An egress source NAT option |
| snatlist | no |  |  | all | [list]<br />If snat is snatpool, this is a list of SNAT IP addresses |
| snatpool | no |  |  | all | [string]<br />If snat is snatpool, this is the name of an existing SNAT pool |
| gateway | no | system | system<br />pool<br />iplist | all | [string]<br />An egress gateway option |
| gatewaylist | no |  |  | all | [list]<br />If gateway is gatewaylist, this is the list of gateway IP addresses |
| gatewaypool | no |  |  | all | [string]<br />If gateway is gatewaypool, this is the name of an existing gateway pool |
| authProfile | no |  |  | all | [string]<br />The name of a custom SWG-Explicit authentication access profile |

<br />

**Options: topologyInboundL3**<br />
Description: defines the properties of an inbound layer 3 (reverse proxy) topology
| Key | Required | Default | Options | Support | Description |
| ------ | ------ | ------ | ------ | ------ | ------ |
| ipFamily | no | ipv4 | ipv4<br />ipv6 | all | [string]<br />The IP family expected for this security device |
| protocol | no | tcp | tcp<br />udp<br />other | all | [string]<br />The matching layer 4 protocol |
| source | no | 0.0.0.0%0/0 |  | all | [string]<br />A source IP address filter |
| dest | no | 0.0.0.0%0/0 |  | all | [string]<br />A destination IP address filter |
| port | no | 0 |  | all | [int]<br />A destination port filter |
| vlans | no |  |  | all | [list]<br />A list of client-facing VLANs |
| snat | no | none | none<br />automap<br />snatpool<br />snatlist | all | [string]<br />An egress source NAT option |
| snatlist | no |  |  | all | [list]<br />If snat is snatpool, this is a list of SNAT IP addresses |
| snatpool | no |  |  | all | [string]<br />If snat is snatpool, this is the name of an existing SNAT pool |
| gateway | no | system | system<br />pool<br />iplist | all | [string]<br />An egress gateway option |
| gatewaylist | no |  |  | all | [list]<br />If gateway is gatewaylist, this is the list of gateway IP addresses |
| gatewaypool | no |  |  | all | [string]<br />If gateway is gatewaypool, this is the name of an existing gateway pool |
| pool | no |  |  | all | [string]<br />The name of a destination pool |
| tcpSettingsClient | no | /Common/f5-tcp-wan |  | all | [string]<br />The name of a custom client side TCP profile |
| tcpSettingsServer | no | /Common/f5-tcp-lan |  | all | [string]<br />The name of a custom server side TCP profile |
| L7ProfileType | no | http | none<br />http | all | [string]<br />If required, this selects a specific L7 profile type |
| L7Profile | no | /Common/http |  | all | [string]<br />If L7ProfileType is http, this is the name of a specific HTTP profile |

<br />

**Options: logging**<br />
Description: defines the logging properties of the topology
| Key | Required | Default | Options | Support | Description |
| ------ | ------ | ------ | ------ | ------ | ------ |
| sslo | no | error | emergency<br />alert<br />critical<br />warning<br />error<br />notice<br />information<br />debug | all | [string]<br />Logging level for SSL Orchestrator summary information |
| perRequestPolicy | no | error | &lt;same&gt; | all | [string]<br />Logging level for SSL Orchestrator security policy information |
| ftp | no | error | &lt;same&gt; | all | [string]<br />Logging level for FTP information |
| imap | no | error | &lt;same&gt; | all | [string]<br />Logging level for IMAP information |
| pop3 | no | error | &lt;same&gt; | all | [string]<br />Logging level for POP3 information |
| smtps | no | error | &lt;same&gt; | all | [string]<br />Logging level for SMTPS information |

<br />

**Examples**
```YAML
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
```
```YAML
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
```
```YAML
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
```
```YAML
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
```
```YAML
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
```

<br />

 