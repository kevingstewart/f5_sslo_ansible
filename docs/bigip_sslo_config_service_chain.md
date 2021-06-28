# F5 SSL Orchestrator Ansible Automation Collection
## Documentation - Security Service Chain
#### Module: bigip_sslo_config_service_chain

**Description**

A security service chain is a container object for an ordered set of security services. Service chains are then applied to SSL Orchestrator security policies. From a configuration and automation perspective, a service chain minimally contains a list of services (by service name), and the respective service type.


**Sample wth all options defined**
```yaml
- name: SSLO service chain
  bigip_sslo_config_service_chain:
    provider: "{{ provider }}"
    name: service_chain_1
    state: present
    services:
      - name: "layer2_1"
        serviceType: "L2"
        ipFamily: "ipv4"
      - name: "layer3_1"
        serviceType: "L3"
        ipFamily: "ipv4"
      - name: "http_1"
        serviceType: "http-proxy"
        ipFamily: "ipv4"
      - name: "icap_1"
        serviceType: "icap"
        ipFamily: "ipv4"
      - name: "tap_1"
        serviceType: "tap"
        ipFamily: "ipv4"
delegate_to: localhost
```

**Options**
| Key | Required | Default | Options | Support | Description |
| ------ | ------ | ------ | ------ | ------ | ------ |
| provider | yes |  |  | all | The BIG-IP connection provider information |
| name | yes |  |  | all | [string]<br />The name of the service chain (ex. service_chain_1) |
| state | no | present | present<br />absent | all | [string]<br />Value to determine create/modify (present) or delete (absent) action |
| services | yes |  |  | all | [list]<br />A list of services to add to this service chain |
| services:<br />name | yes |  |  | all | [string]<br />The name of specific service (ex. layer2_1) |
| services:<br />serviceType | yes |  | L2<br />L3<br /><nobr>http-proxy</nobr><br />icap<br />tap | all | [string]<br />The service type |
| services:<br />ipFamily | no | ipv4 | ipv4<br />ipv6 | all | [string]<br />The ipFamily supported |

**Examples**
```YAML
- name: Create SSLO Service Chain
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
    - name: SSLO service chain
      bigip_sslo_config_service_chain:
        provider: "{{ provider }}"
        name: "service_chain_1"
        
        services:
          - name: "icap_1"
            serviceType: "icap"
            ipFamily: "ipv4"

          - name: "layer3_1"
            serviceType: "L3"
            ipFamily: "ipv4"

          - name: "layer2_1"
            serviceType: "L2"
            ipFamily: "ipv4"

          - name: "http_1"
            serviceType: "http-proxy"
            ipFamily: "ipv4"

          - name: "tap_1"
            serviceType: "tap"
            ipFamily: "ipv4"

      delegate_to: localhost
```

 