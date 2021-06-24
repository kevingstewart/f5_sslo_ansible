# F5 SSL Orchestrator Ansible Automation Collection
## Documentation - Inline Layer 2 Service

**Sample wth all options**
```yaml
- name: SSLO LAYER2 service
  bigip_sslo_service_layer2:
  provider: "{{ provider }}"
    name: layer2_1
    state: present
    devices: 
      - name: FEYE1
        ratio: 1
        vlanIn:	"/Common/L2service1_in"
        interfaceIn: "1.4"
        tagIn: "100"
        vlanOut: "/Common/L2service1_out"
        interfaceOut: "1.5"
        tagOut:	101
    monitor: "/Common/gateway_icmp"
    serviceDownAction: "ignore"
    ipOffset: 1
    portRemap: 8080
    rules: 
      - rule1
      - rule2
  delegate_to: localhost
```

**Options**
| Key | Required | Default | Options | Description |
| ------ | ------ | ------ | ------ |------ |
| provider | yes |  |  | The BIG-IP connection provider information |
| name | yes |  |  | [string] The name of the security service (ex. layer2_1) |
| state | no | present | present:absent | [string] Value to determing create/modify (present) or delete (absent) action |
| devices | yes |  |  | [list] The list of devices in this security service |
| devices : name | yes |  |  | [string] The name of a specific device in the security service list (ex. FEYE1) |
| devices : ratio | no | 1 |  | [int] The load balancing ratio for this specific device |
| devices : vlanIn | yes* |  |  | [string] The incoming (to-service) VLAN associated with this device - the vlanIn and interfaceIn options are mutually exclusive |
| devices : interfaceIn | yes* |  |  | [string] The incoming (to-service) interface associated with this device - the vlanIn and interfaceIn options are mutually exclusing |
| devices : tagIn | no | 0 |  | [int] The VLAN tag (if any) for the to-service interface associated with this device |
| devices : vlanOut | yes** |  |  | [string] The outgoing (from-service) VLAN associated with this device - the vlanIn and interfaceIn options are mutually exclusive |
| devices : interfaceOut | yes** |  |  | [string] The outgoing (from-service) interface associated with this device - the vlanIn and interfaceIn options are mutually exclusing |
| devices : tagOut | no | 0 |  | [int] The VLAN tag (if any) for the from-service interface associated with this device |
| monitor | no | /Common/gateway_icmp |  | [string] The load balancing health monitor to assign to this security service |
| serviceDownAction | no | ignore | ignore:reset:drop | [string] The action to take if all service pool members are marked down. The reset and drop options reset and drop the connection, respectively, while the ignore option causes traffic to bypass this service |
| ipOffset | no | 0 |  | [int] When deployed in an external tiered architecture, the ipOffset increments the internal VLAn self-IPs for this service to avoid conflict with other standalone SSL Orchestrator devices in the tiered architecture |
| portRemap | no |  |  | [int] The port to remap decrypted http traffic to (if required) |
| rules | no |  |  | [list] A list of iRules to attach to this security service |

\* The vlanIn and interfaceIn options are mutually exclusive

\** The vlanOut and interfaceOut options are mutually exclusive

**Examples**
```YAML
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
    - name: SSLO LAYER 2 service
      bigip_sslo_service_layer2:
        provider: "{{ provider }}"
        name: "layer2a"
        devices:
            - name: FEYE1
              interfaceIn: 1.5
              tagIn: 100
              interfaceOut: 1.5
              tagOut: 101
            - name: FEYE2
              interfaceIn: 1.5
              tagIn: 200
              interfaceOut: 1.5
              tagOut: 201
      delegate_to: localhost
```
```YAML
- name: Create SSLO service(s) - externally referenced VLANs
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
    - name: SSLO LAYER 2 service
      bigip_sslo_service_layer2:
        provider: "{{ provider }}"
        name: "layer2a"
        devices:
            - name: FEYE1
              interfaceIn: 1.5
              tagIn: 100
              interfaceOut: 1.5
              tagOut: 101
            - name: FEYE2
              vlanIn: "/Common/l2service1-in-vlan"
              vlanOut: "/Common/l2service1-out-vlan"
        monitor: "/Common/gw1"
        serviceDownAction: "reset"
        ipOffset: 1
        portRemap: 8080
        rules:
            - "/Common/rule1"
            - "/Common/rule1"
      delegate_to: localhost
```
```YAML
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

    - name: create L2 service inbound VLAN
      bigip_vlan:
        provider: "{{ provider }}"
        name: L2service_vlan_in
        tagged_interface: 1.5
        tag: 600
      delegate_to: localhost

    - name: create L2 service outbound VLAN
      bigip_vlan:
        provider: "{{ provider }}"
        name: L2service_vlan_out
        tagged_interface: 1.5
        tag: 601
      delegate_to: localhost

    - name: SSLO LAYER2 service
      bigip_sslo_service_layer2:
        provider: "{{ provider }}"
        name: "layer2a"
        devices:
          - name: "FEYE1"
            vlanIn: "/Common/L2service_vlan_in"
            vlanOut: "/Common/L2service_vlan_out"
        monitor: "/Common/gw2"
      delegate_to: localhost
```
**Best Practice Considerations**
- It is generally better to create the VLANs outside of the service definition and reference within (third example).
- iRules applied in the service definition are applied at the incoming (to-service) side of the service. If the specific use case for adding an iRule is to inject an HTTP header, where that header should be stripped on the other side, it would be better to customize the service after its created using the native F5 BIG-IP iRule module. For an inline layer 2 service, and TCP traffic, SSL Orchestrator creates: 
    - A sending to-service virtual server (**/Common/ssloS_[name].app/ssloS_[name]-t-4**)
    - A receiving from-server virtual server (**/Common/ssloS_[name].app/ssloS_[name]-D-0-t-4**).
 





