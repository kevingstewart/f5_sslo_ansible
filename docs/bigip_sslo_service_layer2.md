# F5 SSL Orchestrator Ansible Automation Collection
## Documentation - Inline Layer 2 Service
#### Module: bigip_sslo_service_layer2

<br />

**Description**<br />
An inline layer 2 security service is generally defined as any security device that possesses separate inbound and outbound interfaces, and does not participate in layer 3 (routing) of traffic. In many cases the inbound and outbound interfaces are connected by an internal bridge. Under the hood, SSL Orchestrator creates a set of private networks (a pair of VLANs, internal self-IPs, a route domain, virtual servers and a pool) to effectively route traffic *across* a layer 2 device. This allows layers 2 devices to be actively load balanced and monitored.

From a configuration and automation perspective, SSL Orchestrator only requires that you define the interfaces that connect to a layer 2 device, the respective to-service "in" and from-service "out" interfaces. Each physical device in a layer 2 service requires a separate set of interfaces, and SSL Orchestrator handles the internal network plumbing. The to-service and from-service connectivity can be defined as an interface or existing VLAN (but not both). If the layer 2 device supports 802.1Q, tags can also be defined, but must be different on each side.

<br />

**Sample wth all options defined**
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
        tagIn: 100
        vlanOut: "/Common/L2service1_out"
        interfaceOut: "1.5"
        tagOut:	101
    
    monitor: "/Common/gateway_icmp"
    serviceDownAction: "ignore"
    ipOffset: 1
    portRemap: 8080
    rules: 
      - "/Common/rule1"
      - "/Common/rule2"
  delegate_to: localhost
```

<br />

**Options**
| Key | Required | Default | Options | Support | Description |
| ------ | ------ | ------ | ------ | ------ | ------ |
| provider | yes |  |  | all | The BIG-IP connection provider information |
| name | yes |  |  | all | [string]<br />The name of the security service (ex. layer2_1) |
| state | no | present | present<br />absent | all | [string]<br />Value to determine create/modify (present) or delete (absent) action |
| devices | yes |  |  | all | [list]<br />The list of devices in this security service |
| devices:<br />name | yes |  |  | all | [string]<br />The name of a specific device in the security service list (ex. FEYE1) |
| devices:<br />ratio | no | 1 |  | all | [int]<br />The load balancing ratio for this specific device |
| devices:<br />vlanIn | yes* |  |  | all | [string]<br />The incoming (to-service) VLAN associated with this device - the vlanIn and interfaceIn options are mutually exclusive |
| devices:<br />interfaceIn | yes* |  |  | all | [string]<br />The incoming (to-service) interface associated with this device - the vlanIn and interfaceIn options are mutually exclusing |
| devices:<br />tagIn | no | 0 |  | all | [int]<br />The VLAN tag (if any) for the to-service interface associated with this device |
| devices:<br />vlanOut | yes** |  |  | all | [string]<br />The outgoing (from-service) VLAN associated with this device - the vlanIn and interfaceIn options are mutually exclusive |
| devices:<br />interfaceOut | yes** |  |  | all | [string]<br />The outgoing (from-service) interface associated with this device - the vlanIn and interfaceIn options are mutually exclusing |
| devices:<br />tagOut | no | 0 |  | all | [int]<br />The VLAN tag (if any) for the from-service interface associated with this device |
| monitor | no | /Common/gateway_icmp |  | all | [string]<br />The load balancing health monitor to assign to this security service |
| serviceDownAction | no | ignore | ignore<br />reset<br />drop | all | [string]<br />The action to take if all service pool members are marked down. The reset and drop options reset and drop the connection, respectively, while the ignore option causes traffic to bypass this service |
| ipOffset | no | 0 |  | 7.0+ | [int]<br />When deployed in an external tiered architecture, the ipOffset increments the internal VLAn self-IPs for this service to avoid conflict with other standalone SSL Orchestrator devices in the tiered architecture |
| portRemap | no |  |  | all | [int]<br />The port to remap decrypted http traffic to (if required) |
| rules | no |  |  | all | [list]<br />A list of iRules to attach to this security service |

*Footnotes:*
- \* The vlanIn and interfaceIn options are mutually exclusive
- \** The vlanOut and interfaceOut options are mutually exclusive

<br />

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

<br />

**Best Practices and Considerations**
- It is generally better to create the VLANs outside of the service definition and reference within (third example).
- iRules applied in the service definition are applied at the incoming (to-service) side of the service. If the specific use case for adding an iRule is to inject an HTTP header, where that header should be stripped on the other side, it would be better to customize the service after its created using the native F5 BIG-IP iRule module. For an inline layer 2 service, and TCP traffic, SSL Orchestrator creates: 
    - A sending to-service virtual server (**/Common/ssloS_[name].app/ssloS_[name]-t-4**)
    - A receiving from-server virtual server (**/Common/ssloS_[name].app/ssloS_[name]-D-0-t-4**).
 





