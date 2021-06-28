# F5 SSL Orchestrator Ansible Automation Collection
## Documentation - ICAP Service
#### Module: bigip_sslo_service_icap

<br />

**Description**<br />
An ICAP service is generally defined as any service that is controlled using the Internet Content Adaptation Protocol (ICAP) process. ICAP is essentially an encapsulation protocol for multiple types of services, but is often used in anti-virus, anti-malware, and data loss prevention (DLP) solutions.

From a configuration and automation persepective, an SSL Orchestrator ICAP security service an ICAP client that targets an external ICAP service (AV, DLP). This minimally requires knowledge of the service's listening IP address and port, and request/response URLs. You may also activate additional headers, a custom preview length, and apply a policy to control when and how the ICAP client engages the ICAP server.

<br />

**Sample wth all options defined**
```yaml
- name: SSLO ICAP service
  bigip_sslo_service_icap:
    provider: "{{ provider }}"
    name: icap_1
    state: present
    
    devices:
      - ip: "10.1.30.50"
        port: 1344
    
    ipFamily: "ipv4"
    monitor: "/Common/tcp"
    headers: True
    header_referrer: "foo"
    header_host: "bar"
    header_user_agent: "this"
    header_from: "that"
    enableOneConnect: True
    requestURI:	"/avscan"
    responseURI: "/avscan"
    previewLength: 4096
    serviceDownAction: "ignore"
    allowHttp10: True
    cpmPolicies: /Common/my-icap-policy
  delegate_to: localhost
```

<br />

**Options**
| Key | Required | Default | Options | Support | Description |
| ------ | ------ | ------ | ------ | ------ | ------ |
| provider | yes |  |  | all | The BIG-IP connection provider information |
| name | yes |  |  | all | [string]<br />The name of the security service (ex. icap_1) |
| state | no | present | present<br />absent | all | [string]<br />Value to determine create/modify (present) or delete (absent) action |
| devices | yes |  |  | all | [list]<br />A list of device IP addresses and ports |
| devices:<br />ip | yes |  |  | all | [string]<br />ICAP service listening IP address |
| devices:<br />port | yes |  |  | all | [int]<br />ICAP service listening port (usually 1344) |
| ipFamily | no | ipv4 | ipv4<br />ipv6 | all | [string]<br />The IP family expected for this security device |
| monitor | no | /Common/tcp |  | all | [string]<br />The load balancing health monitor to assign to this security service |
| headers | no | False | True<br />False | all | [bool]<br />Switch to enable or disable custom headers. When enabled (True), the below header values can be set |
| header_referrer | no |  |  | all | [string]<br />A custom Referrer header |
| header_host | no |  |  | all | [string]<br />A custom Host header |
| header_user_agent | no |  |  | all | [string]<br />A custom User-Agent header |
| header_from | no |  |  | all | [string]<br />A custom From header |
| enableOneConnect | no | True | True<br />False | all | [bool]<br />Switch to enable or disable OneConnect optimization. When enabled (True), the server side is kept open between ICAP requests to optimize traffic flow |
| requestURI | no | / |  | all | [string]<br />The ICAP service request URI |
| responseURI | no | / |  | all | [string]<br />The ICAP service response URI |
| previewLength | no | 1024 |  | all | [int]<br />The ICAP service's required preview length |
| serviceDownAction | no | ignore | ignore<br />reset<br />drop | all | [string]<br />The action to take if all service pool members are marked down. The reset and drop options reset and drop the connection, respectively, while the ignore option causes traffic to bypass this service |
| allowHttp10 | no | True | True<br />False | all | [bool]<br />Switch to enable or disable HTTP/1.0 processing. When enabled (True), the ICAP client accepts HTTP/1.1 and HTTP/1.0 responses |
| cpmPolicies | no |  |  | all | [string]<br />The name of an LTM CPM policy used to control ICAP processing |

<br />

**Examples**
```YAML
- name: Create SSLO service(s) - simple
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
    - name: SSLO ICAP service
      bigip_sslo_service_icap:
        provider: "{{ provider }}"
        name: "icap_1"
        devices: 
          - ip: "10.1.30.50"
            port: 1344
          - ip: "10.1.30.51"
            port: 1344
        requestURI: "/avscan"
        responseURI: "/avscan"
        previewLength: 1024
      delegate_to: localhost
```
```YAML
- name: Create SSLO service(s) - complex
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
    - name: SSLO ICAP service
      bigip_sslo_service_icap:
        provider: "{{ provider }}"
        name: "icap_1"
        state: "present"
        ipFamily: "ipv4"
        devices: 
          - ip: "10.1.30.50"
            port: 1344
          - ip: "10.1.30.51"
            port: 1344
        headers: true
        header_from: "foo_from"
        header_host: "foo_host"
        header_user_agent: "foo_ua"
        header_referrer: "foo_referrer"
        enableOneConnect: True
        requestURI: "/avscan"
        responseURI: "/avscan"
        previewLength: 1024
        serviceDownAction: "ignore"
        allowHttp10: True
        cpmPolicies: "/Common/icap_policy"
      delegate_to: localhost
```
