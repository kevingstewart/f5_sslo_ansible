# F5 SSL Orchestrator Ansible Automation Collection
## Documentation - Inline Layer 3 Service
#### Module: bigip_sslo_service_layer3

<br />

**Description**<br />
An inline layer 3 device is generally defined as any security device that possesses separate inbound and outbound interfaces, and participates in layer 3 (routing) of traffic. A layer 3 device will have separate to-service "in" and from-service "out" interfaces on different IP subnets. These could also be *logically* separated using 802.1Q VLAN tags attached to a single interface.

From a configuration and automation perspective, SSL Orchestrator requires that you define the to-service and from-service networking attributes.

<br />

**Sample wth all options defined**
```yaml
- name: SSLO LAYER3 service
  bigip_sslo_service_layer3:
    provider: "{{ provider }}"
    name: layer3_1
    state: present
    
    devicesTo:
        vlan: "/Common/L3service1_in"
        interface: "1.3"
        tag: 30
        selfIp:	"198.19.64.7"
        netmask: "255.255.255.128"
    
    devicesFrom:
        vlan: "/Common/L3service1_out"
        interface: "1.3"
        tag: 40
        selfIp:	"198.19.64.245"
        netmask: "255.255.255.128"
    
    devices:
        - ip: "198.19.64.30"
    
    ipFamily: "ipv4"
    monitor: "/Common/gateway_icmp"
    serviceDownAction: "ignore"
    portRemap: 8080

    snat: "automap"
    snatlist: 
        - "198.19.64.140"
        - "198.19.64.141"
    snatpool: "/Common/my-L3service-snatpool"
    
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
| name | yes |  |  | all | [string]<br />The name of the security service (ex. layer3_1) |
| state | no | present | present<br />absent | all | [string]<br />Value to determine create/modify (present) or delete (absent) action |
| devicesTo | yes |  |  | all | [dict]<br />The set of networking properties associated with traffic flowing to the security service from the F5 |
| devicesTo:<br />vlan | yes* |  |  | all | [string]<br />The name of a VLAN connected to the to-service side of the security device - the vlan and interface options are mutually exclusive |
| devicesTo:<br />interface | yes* |  |  | all | [string]<br />The interface connected to the to-service side of the security device - the vlan and interface options are mutually exclusive |
| devicesTo:<br />tag | no |  |  | all | [string]<br />The VLAN tag associated with the to-service side of the security service, and only if requried, and using the interface option |
| devicesTo:<br />selfIp | yes |  |  | all | [string]<br />The BIG-IP self-IP address on the to-service side of the security service |
| devicesTo:<br />netmask | yes |  |  | all | [string]<br />The respective netmask for the to-service self-IP |
| devicesFrom | yes |  |  | all | [dict]<br />The set of networking properties associated with traffic flowing from the security service back to the F5 |
| devicesFrom:<br />vlan | yes** |  |  | all | [string]<br />The name of a VLAN connected to the from-service side of the security device - the vlan and interface options are mutually exclusive |
| devicesFrom:<br />interface | yes** |  |  | all | [string]<br />The interface connected to the from-service side of the security device - the vlan and interface options are mutually exclusive |
| devicesFrom:<br />tag | no |  |  | all | [string]<br />The VLAN tag associated with the from-service side of the security service, and only if requried, and using the interface option |
| devicesFrom:<br />selfIp | yes |  |  | all | [string]<br />The BIG-IP self-IP address on the from-service side of the security service |
| devicesFrom:<br />netmask | yes |  |  | all | [string]<br />The respective netmask for the from-service self-IP |
| devices | yes |  |  | all | [list]<br />A list of device IP addresses. These will be addresses in the to-service IP subnet |
| devices:<br />ip | yes |  |  | all | [string]<br />The to-service IP address of a specific security device |
| ipFamily | no | ipv4 | ipv4<br />ipv6 | all | [string]<br />The IP family expected for this security device |
| monitor | no | /Common/gateway_icmp |  | all | [string]<br />The load balancing health monitor to assign to this security service |
| serviceDownAction | no | ignore | ignore<br />reset<br />drop | all | [string]<br />The action to take if all service pool members are marked down. The reset and drop options reset and drop the connection, respectively, while the ignore option causes traffic to bypass this service |
| portRemap | no |  |  | all | [int]<br />The port to remap decrypted http traffic to (if required) |
| snat | no |  | automap<br />snatpool<br />snatlist | all | [string]<br />The option to use if source NAT is required to the security device |
| snatlist | no |  |  | all | [list]<br />A list of source NAT addresses to use if the snat option is 'snatlist' |
| snatpool | no |  |  | all | [string]<br />The name of an existing SNAT pool if the snat option is 'snatpool' |
| rules | no |  |  | all | [list]<br />A list of iRules to attach to this security service  |

*Footnotes:*
- \* The devicesTo vlan and devicesTo interface options are mutually exclusive
- \** The devicesFrom vlan and devicesFrom interface options are mutually exclusive

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
    - name: SSLO LAYER 3 service
      bigip_sslo_service_layer3:
        provider: "{{ provider }}"
        name: "layer3_1"
        devicesTo:
            interface: "1.3"
            tag: 40
            selfIp: "198.19.64.7"
            netmask: "255.255.255.128"
        devicesFrom:
            interface: "1.3"
            tag: 50
            selfIp: "198.19.64.245"
            netmask: "255.255.255.128"
        devices: 
          - ip: "198.19.64.30"
          - ip: "198.19.64.31"
        snat: automap
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
    - name: Create a monitor
      bigip_monitor_gateway_icmp:
        provider: "{{ provider }}"
        name: gw2
        state: present
      delegate_to: localhost

    - name: SSLO LAYER 3 service
      bigip_sslo_service_layer3:
        provider: "{{ provider }}"
        name: "layer3_1"
        devicesTo:
            vlan: "/Common/layer3-in-vlan"
            selfIp: "198.19.64.7"
            netmask: "255.255.255.128"
        devicesFrom:
            vlan: "/Common/layer3-out-vlan"
            selfIp: "198.19.64.245"
            netmask: "255.255.255.128"
        devices: 
          - ip: "198.19.64.30"
          - ip: "198.19.64.31"
        ipFamily: "ipv4"
        monitor: "/Common/gw2"
        serviceDownAction: "reset"
        portRemap: 8080
        snat: snatpool
        snatpool: "/Common/layer3-snatpool"
        rules:
          - "/Common/layer3-rule-1"
          - "/Common/layer3-rule-2"
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

    - name: create L3 service inbound VLAN
      bigip_vlan:
        provider: "{{ provider }}"
        name: L3service_vlan_in
        tagged_interface: 1.5
        tag: 600
      delegate_to: localhost

    - name: create L3 service outbound VLAN
      bigip_vlan:
        provider: "{{ provider }}"
        name: L3service_vlan_out
        tagged_interface: 1.5
        tag: 601
      delegate_to: localhost

    - name: SSLO LAYER 3 service
      bigip_sslo_service_layer3:
        provider: "{{ provider }}"
        name: "layer3a"
        devicesTo:
            vlan: "/Common/L3service_vlan_in"
            selfIp: "198.19.64.7"
            netmask: "255.255.255.128"
        devicesFrom:
            vlanL "/Common/L3service_vlan_out"
            selfIp: "198.19.64.245"
            netmask: "255.255.255.128"
        devices: 
          - ip: "198.19.64.30"
          - ip: "198.19.64.31"
        ipFamily: "ipv4"
        monitor: "/Common/gw2"
        serviceDownAction: "reset"
        portRemap: 8080
        snat: snatlist
        snatlist:
          - "198.19.64.140"
          - "198.19.64.141"
        rules:
          - "/Common/layer3-rule-1"
          - "/Common/layer3-rule-2"
      delegate_to: localhost
```

<br />

**Best Practices and Considerations**
- It is generally better to create the VLANs outside of the service definition and reference within (third example).
- iRules applied in the service definition are applied at the incoming (to-service) side of the service. If the specific use case for adding an iRule is to inject an HTTP header, where that header should be stripped on the other side, it would be better to customize the service after its created using the native F5 BIG-IP iRule module. For an inline layer 3 service, and TCP traffic, SSL Orchestrator creates: 
    - A sending to-service virtual server (**/Common/ssloS_[name].app/ssloS_[name]-t-4**)
    - A receiving from-server virtual server (**/Common/ssloS_[name].app/ssloS_[name]-D-0-t-4**).
 