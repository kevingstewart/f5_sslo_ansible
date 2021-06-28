# F5 SSL Orchestrator Ansible Automation Collection
## Documentation - DNS Resolver Configuration
#### Module: bigip_sslo_config_resolver

<br />

**Description**<br />
The resolver configuration is the set of system-wide DNS resolution settings. From a configuration and automation perspective, a resolver minimally requires a list of forwardingNameserver IP addresses, or a list of forwardingZones zone:nameservers properties.

<br />

**Sample wth all options defined**
```yaml
- name: SSLO resolver
  bigip_sslo_config_resolver:
    provider: "{{ provider }}"
    state: present

    forwardingNameservers:
      - 10.1.20.1
      - 10.1.20.2

    forwardingZones:
      - zone: "."
        nameservers:
          - 10.1.20.1
          - 10.1.20.2
      - zone: "foo.com"
        nameservers:
          - 8.8.8.8
          - 8.8.4.4

    enableDNSsec: False
delegate_to: localhost
```
<br />

**Options**
| Key | Required | Default | Options | Support | Description |
| ------ | ------ | ------ | ------ | ------ | ------ |
| provider | yes |  |  | all | The BIG-IP connection provider information |
| state | no | present | present<br />absent | all | [string]<br />Value to determine create/modify (present) or delete (absent) action |
| forwardingNameServers | no* |  |  | all | [list]<br />List of name server IP addresses |
| forwardingZones | no* |  |  | all | [list]<br />List of zone:nameserver properties |
| forwardingZones:<br />zone | no** |  |  | all | [string]<br />A domain match pattern (ex. ".") |
| forwardingZones:<br />nameservers | no** |  |  | all | [list]<br />The corresponding list of name servers for this zone |
| enableDNSsec | no | False | True<br />False | all | [bool]<br />Switch to enable or disable DNSsec support |

*Footnotes:*
- \* The forwardingNameServers and forwardingZones options mutually exclusive, but at least one must be defined
- \** If forwardingZones is defined, at least one zone:nameserver property pair must also be defined

<br />

**Examples**
```YAML
- name: Create SSLO DNS resolver (forwarding nameservers)
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
    - name: SSLO dns resolver
      bigip_sslo_config_resolver:
        provider: "{{ provider }}"

        forwardingNameservers:
          - "10.1.20.1"
          - "10.1.20.2"
          - "fd66:2735:1533:46c1:68c8:0:0:7110"
          - "fd66:2735:1533:46c1:68c8:0:0:7111"
      delegate_to: localhost
```
```YAML
- name: Create SSLO DNS resolver (forwarding zones)
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
    - name: SSLO dns resolver
      bigip_sslo_config_resolver:
        provider: "{{ provider }}"

        forwardingZones:
          - zone: "."
            nameservers:
              - "10.1.20.1"
              - "10.1.20.5"
          - zone: "foo."
            nameservers:
              - "8.8.8.8"
              - "8.8.4.4"
              - "fd66:2735:1533:46c1:68c8:0:0:7113"

        enableDNSsec: True
      delegate_to: localhost
```

 