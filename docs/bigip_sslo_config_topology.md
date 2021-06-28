# F5 SSL Orchestrator Ansible Automation Collection
## Documentation - Topology
#### Module: bigip_sslo_config_topology

<br />

**Description**<br />


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
| sslSettings | yes |  |  | all | [string]<br />The name of an SSL configuration, or jinja2 reference to a local SSL configuration task |
| securityPolicy | yes |  |  | all | [string]<br />The name of a security policy, or jinja2 reference to a local security policy task |
| services | no |  |  | all | [list]<br />A list of jinja2 references for local service creation tasks |
| serviceChains | no |  |  | all | [list]<br />A list of jinja2 references for local service chain creation tasks |
| resolver | no |  |  | all | [string]<br />A jinja2 reference to a local resolver configuration task |

<br />

**Options: topologyOutboundL3**<br />
Description: blah
| Key | Required | Default | Options | Support | Description |
| ------ | ------ | ------ | ------ | ------ | ------ |
|  |  |  |  |  |  |

<br />

**Options: topologyOutboundExplicit**<br />
Description: blah
| Key | Required | Default | Options | Support | Description |
| ------ | ------ | ------ | ------ | ------ | ------ |
|  |  |  |  |  |  |

<br />

**Options: topologyInboundL3**<br />
Description: blah
| Key | Required | Default | Options | Support | Description |
| ------ | ------ | ------ | ------ | ------ | ------ |
|  |  |  |  |  |  |

<br />

**Examples**
```YAML

```

<br />

**Best Practices and Considerations**
- None
 