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

.. raw:: html

<table border="1" cellpadding="1" cellspacing="1" style="width:50%;background-color:#ffffcc;border-collapse:collapse;border:1px solid #ffcc00">
	<tbody>
		<tr>
			<td colspan="2" rowspan="1" style="text-align: center;">Key</td>
			<td style="text-align: center;">Required</td>
			<td style="text-align: center;">Default</td>
			<td style="text-align: center;">Options</td>
			<td style="text-align: center;">Support</td>
			<td style="text-align: center;">Description</td>
		</tr>
		<tr>
			<td colspan="2" rowspan="1">provider</td>
			<td>yes</td>
			<td>&nbsp;</td>
			<td>&nbsp;</td>
			<td>all</td>
			<td>The BIG-IP connection provider information</td>
		</tr>
		<tr>
			<td colspan="2" rowspan="1">name</td>
			<td>yes</td>
			<td>&nbsp;</td>
			<td>&nbsp;</td>
			<td>all</td>
			<td><p>[string]</p>

			<p>The name of the security service (ex. tap_1)</p>
			</td>
		</tr>
		<tr>
			<td colspan="2" rowspan="1">state</td>
			<td>no</td>
			<td>present</td>
			<td><p>present</p>

			<p>absent</p>
			</td>
			<td>all</td>
			<td><p>[string]</p>

			<p>Value to determine create/modify (present) or delete (absent) action</p>
			</td>
		</tr>
		<tr>
			<td colspan="2" rowspan="1">devices</td>
			<td>yes</td>
			<td>&nbsp;</td>
			<td>&nbsp;</td>
			<td>all</td>
			<td><p>[dict]</p>

			<p>Connection information for the TAP service</p>
			</td>
		</tr>
		<tr>
			<td>&nbsp; &nbsp; &nbsp; &nbsp;</td>
			<td>vlan</td>
			<td>yes*</td>
			<td>&nbsp;</td>
			<td>&nbsp;</td>
			<td>all</td>
			<td><p>[string]</p>

			<p>An interface connected to the TAP service</p>
			</td>
		</tr>
		<tr>
			<td>&nbsp;</td>
			<td>interface</td>
			<td>yes*</td>
			<td>&nbsp;</td>
			<td>&nbsp;</td>
			<td>all</td>
			<td><p>[string]</p>

			<p>A VLAN tag, if required, and if interface is defined</p>
			</td>
		</tr>
		<tr>
			<td colspan="2" rowspan="1">macAddress</td>
			<td>no</td>
			<td>&nbsp;</td>
			<td>&nbsp;</td>
			<td>all</td>
			<td><p>[string]</p>

			<p>A unique local MAC address to map traffic to</p>
			</td>
		</tr>
		<tr>
			<td colspan="2" rowspan="1">portRemap</td>
			<td>no</td>
			<td>&nbsp;</td>
			<td>&nbsp;</td>
			<td>all</td>
			<td><p>[in]</p>

			<p>The port to remap decrypted http traffic to (if required)</p>
			</td>
		</tr>
	</tbody>
</table>


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

 