# F5 SSL Orchestrator Ansible Automation Collection
## Documentation - TAP Service
#### Module: bigip_sslo_service_tap

<br />

**Description**<br />
A TAP service is generally defined as a device that receives a passive copy of traffic. From a configuration and automation perspective, a TAP service minimally requires connectivity information.

<br />

**Sample wth all options defined**
```yaml
- name: SSLO TAP service
  bigip_sslo_service_tap:
    provider: "{{ provider }}"
    name: tap_1
    state: present
    devices:
      vlan: "/Common/my-tap-vlan"
      interface: "1.6"
      tag: 400
    macAddress: "12:12:12:12:12:12"
    portRemap: 8080
  delegate_to: localhost
```

<br />

**Options**
| Key | Required | Default | Options | Support | Description |
| ------ | :----: | ------ | ------ | :----: | ------ |
| provider | yes |  |  | all | The BIG-IP connection provider information |
| name | yes |  |  | all | [string]<br />The name of the security service (ex. tap_1) |
| state | no | present | present<br />absent | all | [string]<br />Value to determine create/modify (present) or delete (absent) action |
| devices | yes |  |  | all | [dict]<br />Connection information for the TAP device |
| devices:<br />vlan | yes* |  |  | all | [string]<br />An existing VLAN connected to the TAP service |
| devices:<br />interface | yes* |  |  | all | [string]<br />An interface connected to the TAP service |
| devices:<br />tag | no |  |  | all | [int]<br />A VLAN tag, if required, and if interface is defined |
| macAddress | no | <hash-of-name> |  | all | [string]<br />A unique local MAC address to map traffic to |
| portRemap | no |  |  | all | [int]<br />The port to remap decrypted http traffic to (if required) |

*Footnotes:*
- \* The vlan and interface options are mutually exclusive

<br />

**Examples**
```YAML
- name: Create SSLO service(s)
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
    - name: create TAP service VLAN
      bigip_vlan:
        provider: "{{ provider }}"
        name: TAPservice_vlan
        tagged_interface: 1.7
      delegate_to: localhost

    - name: SSLO TAP service
      bigip_sslo_service_tap:
        provider: "{{ provider }}"
        name: "tap_1"
        devices: 
          vlan: "/Common/TAPservice_vlan"
      delegate_to: localhost
```
```YAML
- name: Create SSLO service(s)
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
    - name: SSLO TAP service
      bigip_sslo_service_tap:
        provider: "{{ provider }}"
        name: "tap_1"
        state: "present"
        devices: 
          interface: "1.7"
          port: 1000
        macAddress: "12:12:12:12:12:12"
        portRemap: 8080
      delegate_to: localhost
```

<br />

**Best Practices and Considerations**
- It is generally better to create the VLANs outside of the service definition and reference within (first example).

 