# F5 SSL Orchestrator Ansible Automation Collection
## Documentation - Security Policy
#### Module: bigip_sslo_config_policy

<br />

**Description**<br />
An SSL Orchestrator security policy is a set of traffic rules that define a set of actions: allow/block, TLS intercept/bypass, and service chain assignment. The traffic rules within a security policy are the set of traffic matching conditions. From a configuration and automation perspective, a security policy minimally requires the defaultRule settings to define what happens when no traffic rules are matched. There is multiple types of traffic conditions to choose from, as documented below.*

<br />

**Sample wth all options defined**
```yaml
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
```

<br />

**Options**
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| provider | yes |  |  | all | The BIG-IP connection provider information |
| name | yes |  |  | all | [string]<br />The name of the security policy (ex. securitypolicy_1) |
| state | no | present | present<br />absent | all | [string]<br />Value to determine create/modify (present) or delete (absent) action |
| policyType | yes | outbound | outbound<br />inbound | all | [string]<br />Defines the type of security policy, forward proxy (outbound), or reverse proxy (inbound) |
| trafficRules | no |  |  | all | [list]<br />A list of traffic rules |
| trafficRules:<br />name | no |  |  | all | [string]<br />The name of this specific trffic rule |
| trafficRules:<br />matchType | no | or | and<br />or | all | [string]<br />The match type for this rule if multiple conditions are applied |
| trafficRules:<br />allowBlock | no | allow | allow<br />block | all | [string]<br />The allow/block behavior if this traffic rule is matched |
| trafficRules:<br />tlsIntercept | no | bypass | intercept<br />bypass | all | [string]<br />The TLS intercept/bypass behavior is this traffic rule is matched |
| trafficRules:<br />serviceChain | no | None |  | all | [string]<br />The name of the service chain to send traffic to if this traffic rule is matched |
| trafficRules:<br />conditions | no |  |  | all | [list]<br />A list of traffic conditions (see conditions below) |
| defaultRule | no |  |  | all | [dict]<br />The set of default behaviors if no traffic rules are matched |
| defaultRule:<br />allowBlock | no | allow | allow<br />block | all | [string]<br />The allow/block behavior if no traffic rule is matched |
| defaultRule:<br />tlsIntercept | no | bypass | intercept<br />bypass | all | [string]<br />The TLS intercept/bypass behavior if no traffic rule is matched |
| defaultRule:<br />serviceChain | no | None |  | all | [string]<br />The service chain to send traffic to if no traffic rule is matched |
| serverCertValidation | no | False | True<br />False | 7.0+ | [bool]<br />Switch to enable or disable server certificate validation. When enabled and the server certificate is found to be expired or untrusted, the user receives a blocking page. The blockExpired and blockUntrusted options in the SSL configuration must be set to ignore for this option to work |
| proxyConnect | no |  |  |  | [dict]<br />A set of properties used to enable upstream explicit proxy gateway access |
| proxyConnect:<br />enabled | no | False | True<br />False | all | [bool]<br />Switch to enable or disable forwarding egress traffic to an upstream explicit proxy gateway |
| proxyConnect:<br />pool | no |  |  | all | [string]<br />The name of the upstream explicit proxy pool |

<br />

**Condition: pinnersRule**<br />
Description: when defined, no additional settings are required, and no other conditions can be included in the traffic rule. This condition sets up a custom URL category match based on the built-in "pinners" custom URL category.

<br />

**Condition: categoryLookupAll**<br />
Description: defines a URL category lookup for all HTTP and HTTPS traffic (SNI and HTTP Host) information.
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| values | yes |  |  | all | [list]<br />A list of URL category names** |

<br />

**Condition: categoryLookupConnect**<br />
Description: defines a URL category lookup based on explicit forward proxy HTTP Connect information.
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| values | yes |  |  | all | [list]<br />A list of URL category names** |

<br />

**Condition: categoryLookupSNI**<br />
Description: defines a category lookup based on TLS handshake server name indication (SNI) information only.
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| values | yes |  |  | all | [list]<br />A list of URL category names** |

<br />

**Condition: clientIpGeolocation**<br />
Description: defines an IP Geolocation lookup based on client IP address information.
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| values | yes |  |  | all | [list]<br />A list of geolocation type:value properties |
| values:<br />type | yes |  | countryCode<br />countryName<br />continent<br />state | all | [string]<br />The type of geolocation information to match on |
| values:<br />value | yes |  |  | all | [string]<br />The corresponding geolocation value to match |

<br />

**Condition: serverIpGeolocation**<br />
Description: defines an IP Geolocation lookup based on server IP address information. 
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| values | yes |  |  | all | [list]<br />A list of geolocation type:value properties |
| values:<br />type | yes |  | countryCode<br />countryName<br />continent<br />state | all | [string]<br />The type of geolocation information to match on |
| values:<br />value | yes |  |  | all | [string]<br />The corresponding geolocation value to match |

<br />

**Condition: clientIpReputation**<br />
Description: defines an IP Reputation service lookup based on client IP address information. 
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| value | yes |  | good<br />bad<br />category | category(7.0+) | [string]<br />The type of IP reputation match |
| values | yes |  |  | category(7.0+) | [list]<br />The list of IP reputation values to match if category is defined |

<br />

**Condition: serverIpReputation**<br />
Description: defines an IP Reputation service lookup based on server IP address information. 
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| value | yes |  | good<br />bad<br />category | category(7.0+) | [string]<br />The type of IP reputation match |
| values | yes |  |  | category(7.0+) | [list]<br />The list of IP reputation values to match if category is defined |

<br />

**Condition: clientIpSubnet**<br />
Description: defines a traffic match based on client IP subnet information. 
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| values | yes |  |  | datagroups(8.0+) | [list]<br />The list of IP addresses, IP subnets, or address-type datagroups(8.0+) |

<br />

**Condition: serverIpSubnet**<br />
Description: defines a traffic match based on server IP subnet information.
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| values | yes |  |  | datagroups(8.0+) | [list]<br />The list of IP addresses, IP subnets, or address-type datagroups(8.0+) |

<br />

**Condition: clientPort**<br />
Description: defines a traffic match based on client port information.
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| type | yes | value | value<br />range | range(8.0+) | [string]<br />The type of value to match on, either a single "value", or "range" of ports |
| values | no |  |  | all | [list]<br />A list of ports |
| fromPort | no |  |  | 8.0+ | [int]<br />For a port range, the starting port |
| toPort | no |  |  | 8.0+ | [int]<br />For a port range, the ending port |

<br />

**Condition: serverPort**<br />
Description: defines a traffic match based on server port information.
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| type | yes | value | value<br />range | range(8.0+) | [string]<br />The type of value to match on, either a single "value", or "range" of ports |
| values | no |  |  | all | [list]<br />A list of ports |
| fromPort | no |  |  | 8.0+ | [int]<br />For a port range, the starting port |
| toPort | no |  |  | 8.0+ | [int]<br />For a port range, the ending port |

<br />

**Condition: sslCheck**<br />
Description: defines a traffic match based on the existence of a TLS handshake.
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| value | yes |  | True<br />False | all | [bool]<br />Switch to enable or disable an SSL check condition (presence of TLS handshake) |

<br />

**Condition: L7ProtocolCheckTcp**<br />
Description: defines a traffic match based on the layer 7 TCP protocol.
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| values | yes |  | dns<br />ftp<br />http<br />https<br />httpConnect<br />imap<br />pop3<br />smtps<br />telnet | all | [list]<br />The list of layer 7 TCP protocols to match |

<br />

**Condition: L7ProtocolCheckUdp**<br />
Description: defines a traffic match based on the layer 7 UDP protocol.
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| values | yes |  | dns<br />quic | all | [list]<br />The list of layer 7 UDP protocols to match |

<br />

**Condition: urlMatch**<br />
Description: defines a traffic match based on the unencrypted HTTP Host and URI information.
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| values | yes |  |  | all | [list]<br />A list of URL string matches |
| values:<br />type | yes |  | equals<br />substring<br />prefix<br />suffix<br />glob | all | [string]<br />The type of URL match to make |
| values:<br />value | yes |  |  | all | [string]<br />The corresponding URL value |

<br />

**Examples**
```YAML
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
```
```YAML
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
```
```YAML
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
```
<br />

**Best Practices and Considerations**
- As security policy rules are nested, it is generally best practice to place the traffic rules in OSI order. IP and port based conditions should be placed first, above URL category and sslCheck conditions, and then TLS bypass conditions should be above TLS intercept conditions. Layer 7 (TCP/UDP) protocol matches, and the urlMatch condition should be placed last in the set of rules.

- The names of the URL categories can be found using this command in the BIG-IP console: 
    ```
    tmsh list sys url-db url-category one-line | awk -F" " '{ print $4 }'
    ```
- The list of IP reputation categories can be found here: https://techdocs.f5.com/en-us/bigip-14-0-0/big-ip-local-traffic-manager-implementations-14-0-0/enabling-ip-address-intelligence.html






