#!/usr/bin/python
# -*- coding: utf-8 -*-
# 
# Copyright: (c) 2021, kevin-dot-g-dot-stewart-at-gmail-dot-com
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# Version: 1.0

#### Updates:
#### 1.0.1 - added 9.0 support
#          - changed max version
#          - added "verifyAccept" key for outbound L3/explicit topologies
#          - added "ocspAuth" key for outbound L3/explicit topologies
#          - added "dnsResolver" key for outbound explicit topology
#          - updated version and previousVersion keys to match target SSLO version
#          - added L2 vwire inbound/outbound topology support
#          - modified code in ssloGS_global_fetch() to ensure ssloGS_global lookup does not trigger an error (20210917)


from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: bigip_sslo_config_topology
short_description: Manage an SSL Orchestrator Topology
description:
  - Manage an SSL Orchestrator topology
version_added: "1.0.0"
options:
    name:
        description:
        - Specifies the name of the topology. Configuration auto-prepends "sslo_" to topology. Topology name should be less than 14 characters and not contain dashes "-".
        type: str
        required: True
  
    configReferences:
        description:
        - Defines any external object references to apply to the topology.
        required: True
        type: list
        elements: dict
        suboptions:
        sslSettings:
            description: 
                - Defines the name of the SSL settings object if already created, or a jinja2 reference name for an SSL settings task in the same playbook.
            type: str
            required: True
        securityPolicy:
            description: 
                - Defines the name of the security policy object if already created, or a jinja2 reference name for the security policy task in the same playbook.
            type: str
            required: True
        services: 
            description: 
                - Defines a list of jinja2 references for security services created in the same playbook.
            type: list
        serviceChains:
            description: 
                - Defines a list of jinja2 references for service chains created in the same playbook.
            type: list
        resolver:
            description:
                - Defines a jinja2 reference for resolver settings created in the same playbook.
            type: str
    
    topologyOutboundL3
        description:
        - Defines the set of options used for an outbound layer 3 SSL Orchestrator topology.
        type: str
        suboptions:
        ipFamily:
            description:
            - Defines the IP family for this topology.
            type: str
            choices: 
            - ipv4
            - ipv6
            default: ipv4
        protocol:
            description:
            - Defines the topology protocol, either tcp, udp, or other (non-tcp/non-udp).
            type: str
            choices: 
            - tcp
            - udp
            - other
            default: tcp
        source:
            description:
            - Defines the source address filter and optional route domain for the topology listener.
            type: str
            default: 0.0.0.0%0/0
        dest:
            description:
            - Defines the destination address filter and optional route domain for the topology listener.
            type: str
            default: 0.0.0.0%0/0
        port:
            description:
            - Defines the port filter for the topology listener.
            type: int
            default: 0
        vlans:
            description:
            - Defines the list of listening VLANs for the topology listener.
            type: list
            default: None
        snat:
            description:
            - Defines the type egress source NAT used (if any). The 'none' options means no outbound SNAT. The 'automap' option enables AutoMap SNAT. The 'snatpool' option defines that an existing SNAT pool will be used, and also requires the separate 'snatpool' key. The 'snatlist' option in combination with a separate 'snatlist' key defines a list of SNAT IPs.
            type: str
            choices: 
            - none
            - automap
            - snatpool
            - snatlist
            default: None
        snatlist:
            description:
            - When the 'snat' key is set to 'snatlist', this setting defines the list of SNAT IPs to use for egress traffic.
            type: list
            default: None
        snatpool:
            description:
            - When the 'snat' key is set to 'snatpool', this setting defines the name of an existing SNAT pool to use for egress traffic.
            type: str
            default: None
        gateway:
            description:
            - Defines the type of egress gateway to use. The 'system' option means to use the system-defined gateway route. The 'pool' option defines that an existing gateway pool will be used, and also requires the separate 'gatewaypool' key. The 'iplist' option in combination with a separate 'gatewaylist' key defines a list of gateway IPs.
            type: str
            choices: 
            - system
            - pool
            - iplist
            default: system
        gatewaylist:
            description:
            - When the 'gateway' key is set to 'iplist', this setting defines the list of gateway IPs to use for egress traffic.
            type: str
            default: None
        gatewaypool:
            description:
            - When the 'gateway' key is set to 'pool', this setting defines the name of an existing gateway pool to use for egress traffic.
            type: str
            default: None
        tcpSettingsClient:
            description:
            - Defines a custom client side TCP profile to use.
            type: str
            default: /Common/f5-tcp-lan
        tcpSettingsServer:
            description:
            - Defines a custom server side TCP profile to use.
            type: str
            default: /Common/f5-tcp-wan
        L7ProfileType:
            description:
            - Defines the L7 protocol type, and can either be 'none' for all protocols, or 'http'.
            type: str
            choices: 
            - None
            - http
            default: None
        L7Profile:
            description:
            - Defines the specific HTTP profile (ex. /Common/http) if the L7ProfileType is set to 'http'.
            type: str
            default: None
        additionalProtocols:
            description:
            - Defines a list of additional protocols to create listeners for.
            type: str
            choices: 
            - ftp
            - imap
            - pop3
            - smtps
            default: None
        accessProfile:
            description:
            - Defines a custom access profile to use. In the absence of this setting, a topology-defined access profile will be created.
            type: str
        profileScope:
            description:
            - Available in SSL Orchestrator 8.2, this setting defines the access profile scope. In an outbound L3 (transparent proxy) topology with (captive portal) authentication, the 'named' profile scope is used to allow the transparent proxy and authentication service to communicate authenticated session information.
            type: str
            choices: 
            - public
            - named
            default: public
        profileScopeValue:
            description:
            - Available in 8.2 and required when the 'profileScope' option is set to 'named'. This setting defines a string name shared between the transparent proxy SSL Orchestrator profile and the captive portal authentication access profile.
            type: str
            default: None
        primaryAuthUri:
            description:
            - Available in 8.2 and required when the 'profileScope' option is set to 'named'. This setting defines the authentication service (ie. captive portal) to redirect new users to. This setting should contain a fully-qualified domain name (ex. https://auth.f5labs.com)
            type: str
            default: None
        verifyAccept:
            description:
            - Available in 9.0. Enables TCP Verify Accept proxy through an outbound topology.
            type: bool
            default: False
        ocspAuth:
            description:
            - Available in 9.0. This setting defines an OCSP Authentication profile.
            type: str
            default: None

    topologyOutboundExplicit
      description:
        - Defines the set of options used for an SSL Orchestrator outbound explicit proxy topology.
      type: str
      suboptions:
        ipFamily:
          description:
            - Defines the IP family for this topology.
          type: str
          choices: 
            - ipv4
            - ipv6
          default: ipv4
        source:
          description:
            - Defines the source address filter and optional route domain for the topology listener.
          type: str
          default: 0.0.0.0%0/0
        proxyIp:
          description:
            - Defines the explicit proxy listener IP address.
          type: str
          default: None
          required: True
        proxyPort:
          description:
            - Defines the explicit proxy listener port.
          type: int
          default: None
        vlans:
          description:
            - Defines the list of listening VLANs for the topology listener.
          type: list
          default: None
        snat:
          description:
            - Defines the type egress source NAT used (if any). The 'none' options means no outbound SNAT. The 'automap' option enables AutoMap SNAT. The 'snatpool' option defines that an existing SNAT pool will be used, and also requires the separate 'snatpool' key. The 'snatlist' option in combination with a separate 'snatlist' key defines a list of SNAT IPs.
          type: str
          choices: 
            - none
            - automap
            - snatpool
            - snatlist
          default: None
        snatlist:
          description:
            - When the 'snat' key is set to 'snatlist', this setting defines the list of SNAT IPs to use for egress traffic.
          type: list
          default: None
        snatpool:
          description:
            - When the 'snat' key is set to 'snatpool', this setting defines the name of an existing SNAT pool to use for egress traffic.
          type: str
          default: None
        gateway:
          description:
            - Defines the type of egress gateway to use. The 'system' option means to use the system-defined gateway route. The 'pool' option defines that an existing gateway pool will be used, and also requires the separate 'gatewaypool' key. The 'iplist' option in combination with a separate 'gatewaylist' key defines a list of gateway IPs.
          type: str
          choices: 
            - system
            - pool
            - iplist
          default: system
        gatewaylist:
          description:
            - When the 'gateway' key is set to 'iplist', this setting defines the list of gateway IPs to use for egress traffic.
          type: str
          default: None
        gatewaypool:
          description:
            - When the 'gateway' key is set to 'pool', this setting defines the name of an existing gateway pool to use for egress traffic.
          type: str
          default: None
        authProfile:
          description:
            - Defines an access profile to use for explicit proxy authentication.
          type: str
        verifyAccept:
          description:
            - Available in 9.0. Enables TCP Verify Accept proxy through an outbound topology.
          type: bool
          default: False
        ocspAuth:
          description:
            - Available in 9.0. This setting defines an OCSP Authentication profile.
          type: str
          default: None
        dnsResolver:
          description:
            - Available and required in 9.0. This setting defines a per-topology DNS resolver configuration object.
          type: str
          required: True
          default: None

    topologyInboundL3
      description:
        - Defines the set of options used for an inbound layer 3 SSL Orchestrator topology.
      type: str
      suboptions:
        ipFamily:
          description:
            - Defines the IP family for this topology.
          type: str
          choices: 
            - ipv4
            - ipv6
          default: ipv4
        protocol:
          description:
            - Defines the topology protocol, either tcp, udp, or other (non-tcp/non-udp).
          type: str
          choices: 
            - tcp
            - udp
            - other
          default: tcp
        source:
          description:
            - Defines the source address filter and optional route domain for the topology listener.
          type: str
          default: 0.0.0.0%0/0
        dest:
          description:
            - Defines the destination address filter and optional route domain for the topology listener.
          type: str
          default: 0.0.0.0%0/0
        port:
          description:
            - Defines the port filter for the topology listener.
          type: int
          default: 0
        vlans:
          description:
            - Defines the list of listening VLANs for the topology listener.
          type: list
          default: None
        snat:
          description:
            - Defines the type egress source NAT used (if any). The 'none' options means no outbound SNAT. The 'automap' option enables AutoMap SNAT. The 'snatpool' option defines that an existing SNAT pool will be used, and also requires the separate 'snatpool' key. The 'snatlist' option in combination with a separate 'snatlist' key defines a list of SNAT IPs.
          type: str
          choices: 
            - none
            - automap
            - snatpool
            - snatlist
          default: None
        snatlist:
          description:
            - When the 'snat' key is set to 'snatlist', this setting defines the list of SNAT IPs to use for egress traffic.
          type: list
          default: None
        snatpool:
          description:
            - When the 'snat' key is set to 'snatpool', this setting defines the name of an existing SNAT pool to use for egress traffic.
          type: str
          default: None
        gateway:
          description:
            - Defines the type of egress gateway to use. The 'system' option means to use the system-defined gateway route. The 'pool' option defines that an existing gateway pool will be used, and also requires the separate 'gatewaypool' key. The 'iplist' option in combination with a separate 'gatewaylist' key defines a list of gateway IPs.
          type: str
          choices: 
            - system
            - pool
            - iplist
          default: system
        gatewaylist:
          description:
            - When the 'gateway' key is set to 'iplist', this setting defines the list of gateway IPs to use for egress traffic.
          type: str
          default: None
        gatewaypool:
          description:
            - When the 'gateway' key is set to 'pool', this setting defines the name of an existing gateway pool to use for egress traffic.
          type: str
          default: None
        pool:
          description:
            - Defines a server pool to use in an application mode inbound topology.
          type: str
          default: None
        tcpSettingsClient:
          description:
            - Defines a custom client side TCP profile to use.
          type: str
          default: /Common/f5-tcp-wan
        tcpSettingsServer:
          description:
            - Defines a custom server side TCP profile to use.
          type: str
          default: /Common/f5-tcp-lan
        L7ProfileType:
          description:
            - Defines the L7 protocol type, and can either be 'none' for all protocols, or 'http'.
          type: str
          choices: 
            - None
            - http
          default: http
        L7Profile:
          description:
            - Defines the specific HTTP profile (ex. /Common/http) if the L7ProfileType is set to 'http'.
          type: str
          default: /Common/http

    topologyOutboundL2
        description:
        - Defines the set of options used for an outbound layer 2 SSL Orchestrator topology.
        type: str
        suboptions:
        ipFamily:
            description:
            - Defines the IP family for this topology.
            type: str
            choices: 
            - ipv4
            - ipv6
            default: ipv4
        protocol:
            description:
            - Defines the topology protocol, either tcp, udp, or other (non-tcp/non-udp).
            type: str
            choices: 
            - tcp
            - udp
            - other
            default: tcp
        source:
            description:
            - Defines the source address filter and optional route domain for the topology listener.
            type: str
            default: 0.0.0.0%0/0
        dest:
            description:
            - Defines the destination address filter and optional route domain for the topology listener.
            type: str
            default: 0.0.0.0%0/0
        port:
            description:
            - Defines the port filter for the topology listener.
            type: int
            default: 0
        vlans:
            description:
            - Defines the list of listening VLANs for the topology listener.
            type: list
            default: None
        tcpSettingsClient:
            description:
            - Defines a custom client side TCP profile to use.
            type: str
            default: /Common/f5-tcp-lan
        tcpSettingsServer:
            description:
            - Defines a custom server side TCP profile to use.
            type: str
            default: /Common/f5-tcp-wan
        L7ProfileType:
            description:
            - Defines the L7 protocol type, and can either be 'none' for all protocols, or 'http'.
            type: str
            choices: 
            - None
            - http
            default: None
        L7Profile:
            description:
            - Defines the specific HTTP profile (ex. /Common/http) if the L7ProfileType is set to 'http'.
            type: str
            default: None
        accessProfile:
            description:
            - Defines a custom access profile to use. In the absence of this setting, a topology-defined access profile will be created.
            type: str
        profileScope:
            description:
            - Available in SSL Orchestrator 8.2, this setting defines the access profile scope. In an outbound L3 (transparent proxy) topology with (captive portal) authentication, the 'named' profile scope is used to allow the transparent proxy and authentication service to communicate authenticated session information.
            type: str
            choices: 
            - public
            - named
            default: public
        profileScopeValue:
            description:
            - Available in 8.2 and required when the 'profileScope' option is set to 'named'. This setting defines a string name shared between the transparent proxy SSL Orchestrator profile and the captive portal authentication access profile.
            type: str
            default: None
        primaryAuthUri:
            description:
            - Available in 8.2 and required when the 'profileScope' option is set to 'named'. This setting defines the authentication service (ie. captive portal) to redirect new users to. This setting should contain a fully-qualified domain name (ex. https://auth.f5labs.com)
            type: str
            default: None
        verifyAccept:
            description:
            - Available in 9.0. Enables TCP Verify Accept proxy through an outbound topology.
            type: bool
            default: False
        ocspAuth:
            description:
            - Available in 9.0. This setting defines an OCSP Authentication profile.
            type: str
            default: None

    topologyInboundL2
      description:
        - Defines the set of options used for an inbound layer 2 SSL Orchestrator topology.
      type: str
      suboptions:
        ipFamily:
          description:
            - Defines the IP family for this topology.
          type: str
          choices: 
            - ipv4
            - ipv6
          default: ipv4
        protocol:
          description:
            - Defines the topology protocol, either tcp, udp, or other (non-tcp/non-udp).
          type: str
          choices: 
            - tcp
            - udp
            - other
          default: tcp
        source:
          description:
            - Defines the source address filter and optional route domain for the topology listener.
          type: str
          default: 0.0.0.0%0/0
        dest:
          description:
            - Defines the destination address filter and optional route domain for the topology listener.
          type: str
          default: 0.0.0.0%0/0
        port:
          description:
            - Defines the port filter for the topology listener.
          type: int
          default: 0
        vlans:
          description:
            - Defines the list of listening VLANs for the topology listener.
          type: list
          default: None
        tcpSettingsClient:
          description:
            - Defines a custom client side TCP profile to use.
          type: str
          default: /Common/f5-tcp-wan
        tcpSettingsServer:
          description:
            - Defines a custom server side TCP profile to use.
          type: str
          default: /Common/f5-tcp-lan
        L7ProfileType:
          description:
            - Defines the L7 protocol type, and can either be 'none' for all protocols, or 'http'.
          type: str
          choices: 
            - None
            - http
          default: http
        L7Profile:
          description:
            - Defines the specific HTTP profile (ex. /Common/http) if the L7ProfileType is set to 'http'.
          type: str
          default: /Common/http
        accessProfile:
            description:
            - Defines a custom access profile to use. In the absence of this setting, a topology-defined access profile will be created.
            type: str
    
    logging:
        description:
        - Defines the setting of logging characteristics for an SSL Orchestrator topology.
        type: str
        suboptions:
            sslo:
            description:
                - Defines the logging facility used for the SSL Orchestrator summary logging.
            type: str
            choices:
                - emergency
                - alert
                - critical
                - warning
                - error
                - notice
                - information
                - debug
            default: error
            perRequestPolicy:
            description:
                - Defines the logging facility used for the SSL Orchestrator security policy logging.
            type: str
            choices:
                - emergency
                - alert
                - critical
                - warning
                - error
                - notice
                - information
                - debug
            default: error
            ftp:
            description:
                - Defines the logging facility used for the SSL Orchestrator ftp listener logging.
            type: str
            choices:
                - emergency
                - alert
                - critical
                - warning
                - error
                - notice
                - information
                - debug
            default: error
            imap:
            description:
                - Defines the logging facility used for the SSL Orchestrator imap listener logging.
            type: str
            choices:
                - emergency
                - alert
                - critical
                - warning
                - error
                - notice
                - information
                - debug
            default: error
            pop3:
            description:
                - Defines the logging facility used for the SSL Orchestrator pop3 listener logging.
            type: str
            choices:
                - emergency
                - alert
                - critical
                - warning
                - error
                - notice
                - information
                - debug
            default: error
            smtps:
            description:
                - Defines the logging facility used for the SSL Orchestrator smtps listener logging.
            type: str
            choices:
                - emergency
                - alert
                - critical
                - warning
                - error
                - notice
                - information
                - debug
            default: error

    mode:
        description:
        - Defines how this task is handled. With the default setting of 'update', the module performs the tasks required to update the target resource. With the 'output' setting, the resulting JSON object blocks are returned without updating the target resource. This option is useful for debugging, and when subordinate objects (ex. SSL, services, service chains, policy, resolver) are created in the same playbook, and their respectice output JSON referenced in a single Topology create task.
        type: str
        choices:
        - update
        - output
        default: update

    state:
        description:
            - Specifies the present/absent state required.
        type: str
        choices: 
            - absent
            - present
        default: present

extends_documentation_fragment: f5networks.f5_modules.f5
author:
  - Kevin Stewart (kevin-dot-g-dot-stewart-at-gmail-dot-com)
'''

EXAMPLES = r'''
- name: Create SSLO Topology (simple outbound L3)
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
    - name: SSLO topology
      bigip_sslo_config_topology:
        provider: "{{ provider }}"
        name: "demoOutL3"        
        configReferences:
          sslSettings: "demossl"
          securityPolicy: "demopolicy"
        topologyOutboundL3:
          vlans:
            - "/Common/client-vlan"
          snat: snatlist
          snatlist:
            - 10.1.20.110
            - 10.1.20.111
            - 10.1.20.115
          gateway: "iplist"
          gatewaylist: 
            - ratio: 1
              ip: 10.1.20.1
            - ratio: 2
              ip: 10.1.20.2          
        logging:
          sslo: debug
          perRequestPolicy: debug
      delegate_to: localhost

- name: Create SSLO Topology (complex outbound L3)
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
    - name: SSLO topology
      bigip_sslo_config_topology:
        provider: "{{ provider }}"
        name: "demoOutL3"
        configReferences:
          sslSettings: "demossl"
          securityPolicy: "demopolicy"
        topologyOutboundL3:
          protocol: "tcp"
          ipFamily: ipv4
          vlans:
            - "/Common/client-vlan"
          source: 10.0.0.0/24
          port: 65535
          additionalProtocols:
            - ftp
            - smtps
          snat: snatpool
          snatpool: "/Common/my-snatpool"
          gateway: "pool"
          gatewaypool: "/Common/gwpool"          
          accessProfile: "/Common/my-custom-sslo-policy"
          profileScope: "named"
          profileScopeValue: "SSLO"
          primaryAuthUri: "https://login.f5labs.com/"
        logging:
          sslo: debug
          perRequestPolicy: warning
          ftp: warning
      delegate_to: localhost

- name: Create SSLO Topology (explicit proxy)
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
    - name: SSLO topology
      bigip_sslo_config_topology:
        provider: "{{ provider }}"
        name: "demoxp1"
        configReferences:
          sslSettings: "demossl"
          securityPolicy: "demopolicy"
        topologyOutboundExplicit:
          proxyIp: "10.1.10.150"
          proxyPort: 3128
          vlans:
            - "/Common/client-vlan"
          gateway: "iplist"
          gatewaylist:
            - ip: 10.1.20.1
          snat: automap          
      delegate_to: localhost

- name: Create SSLO Topology (inbound L3)
  hosts: localhost
  gather_facts: False
  connection: local

  collections:
    - kevingstewart.f5_sslo_ansible

  vars: 
    provider:
      server: 10.1.14
      user: admin
      password: admin
      validate_certs: no
      server_port: 443

  tasks:
    - name: SSLO topology
      bigip_sslo_config_topology:
        provider: "{{ provider }}"
        name: "demoin1"
        configReferences:
          sslSettings: "demoinssl"
          securityPolicy: "demoinpolicy"
        topologyInboundL3:
          dest: "10.1.20.120/32"
          pool: "/Common/test-pool"
          vlans: 
            - "/Common/client-vlan"
      delegate_to: localhost

- name: Create SSLO Topology (complex outbound L3 with internal jinja2 references)
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
    #### services #################################
    - name: SSLO LAYER2 service
      bigip_sslo_service_layer2:
        provider: "{{ provider }}"
        name: "layer2"
        devices:
          - name: "FEYE1"
            interfaceIn: "1.3"
            interfaceOut: "1.4"
        portRemap: 8080
        mode: output
      register: service_layer2
      delegate_to: localhost

    - name: SSLO ICAP service
      bigip_sslo_service_icap:
        provider: "{{ provider }}"
        name: "icap"
        devices: 
          - ip: "198.19.97.50"
            port: 1344
        mode: output
      register: service_icap
      delegate_to: localhost

    #### ssl ######################################
    - name: SSLO SSL settings
      bigip_sslo_config_ssl:
        provider: "{{ provider }}"
        name: "demossl"
        clientSettings:
          caCert: "/Common/subrsa.f5labs.com"
          caKey: "/Common/subrsa.f5labs.com"
        mode: output
      register: sslsettings
      delegate_to: localhost
    
    #### service chains ###########################
    - name: SSLO service chain
      bigip_sslo_config_service_chain:
        provider: "{{ provider }}"
        name: "service_chain_1"
        services:
          - name: layer2
            serviceType: L2
            ipFamily: ipv4
          - name: icap
            serviceType: icap
            ipFamily: ipv4
        mode: output
      register: servicechain1
      delegate_to: localhost
    
    - name: SSLO service chain
      bigip_sslo_config_service_chain:
        provider: "{{ provider }}"
        name: "service_chain_2"
        services:
          - name: layer2
            serviceType: L2
            ipFamily: ipv4
        mode: output
      register: servicechain2
      delegate_to: localhost

    #### policy ###################################
    - name: SSLO security policy
      bigip_sslo_config_policy:
        provider: "{{ provider }}"
        name: "demopolicy"
        policyType: "outbound"
        defaultRule:
          allowBlock: "allow"
          tlsIntercept: "intercept"
          serviceChain: "service_chain_1"
        trafficRules:
          - name: "pinners"
            conditions:
              - condition: "pinnersRule"
          - name: "bypass_Finance_Health"
            matchType: "or"
            allowBlock: "allow"
            tlsIntercept: "bypass"
            serviceChain: "service_chain_2"
            conditions:
              - condition: "categoryLookupAll"
                values:
                  - "/Common/Financial_Data_and_Services"
                  - "/Common/Health_and_Medicine"
        mode: output
      register: securitypolicy
      delegate_to: localhost

    #### topology #################################
    - name: SSLO topology
      bigip_sslo_config_topology:
        provider: "{{ provider }}"
        name: "demoOutL3"
        configReferences:
          sslSettings: "{{ sslsettings }}"
          securityPolicy: "{{ securitypolicy }}"
          services:
            - "{{ service_layer2 }}"
            - "{{ service_icap }}"
          serviceChains:
            - "{{ servicechain1 }}"
            - "{{ servicechain2 }}"
        topologyOutboundL3:
          vlans:
            - "/Common/client-vlan"
          snat: automap
          gateway: "iplist"
          gatewaylist: 
            - ip: 10.1.20.1        
      delegate_to: localhost

- name: Create SSLO Topology (explicit proxy - atomic 9.0 with inline OCSP Auth)
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
      #### ocsp authentication ####################
      - name: SSLO authentication
        bigip_sslo_config_authentication:
            provider: "{{ provider }}"
            name: "ocsp2"
            ocsp:
                fqdn: "ocsp2.f5labs.com"
                dest: "10.1.10.133/32"
                sslProfile: "demossl"
                vlans: 
                - "/Common/client-vlan"
            mode: output
        register: auth_ocsp
        delegate_to: localhost
    
      #### explicit proxy topology ################
      - name: SSLO topology
        bigip_sslo_config_topology:
            provider: "{{ provider }}"
            name: "demoxp1"
            configReferences:
                sslSettings: "demossl"
                securityPolicy: "demopolicy"
            topologyOutboundExplicit:
                proxyIp: "10.1.10.150"
                proxyPort: 3128
                vlans:
                - "/Common/client-vlan"
                gateway: "iplist"
                gatewaylist:
                - ip: 10.1.20.1
                snat: automap
                ocspAuth: "{{ auth_ocsp }}"
        delegate_to: localhost

- name: Create SSLO Topology (outbound Layer 2)
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
      #### ssl ######################################
      - name: SSLO SSL settings
        bigip_sslo_config_ssl:
            provider: "{{ provider }}"
            name: "demossl"
            clientSettings:
                caCert: "/Common/subrsa.f5labs.com"
                caKey: "/Common/subrsa.f5labs.com"
            mode: output
        register: sslsettings
        delegate_to: localhost

    #### resolver #################################
    - name: SSLO dns resolver
        bigip_sslo_config_resolver:
            provider: "{{ provider }}"
            forwardingNameservers:
                - "10.1.20.1"
            mode: output
        register: myresolver
        delegate_to: localhost

      #### policy ###################################
      - name: SSLO security policy
        bigip_sslo_config_policy:
            provider: "{{ provider }}"
            name: "demopolicy"
            policyType: "outbound"
            defaultRule:
                allowBlock: "allow"
                tlsIntercept: "intercept"
                serviceChain: ""
            trafficRules:
                - name: "pinners"
                conditions:
                    - condition: "pinnersRule"
                - name: "bypass_Finance_Health"
                matchType: "or"
                allowBlock: "allow"
                tlsIntercept: "bypass"
                serviceChain: ""
                conditions:
                    - condition: "categoryLookupAll"
                    values:
                        - "/Common/Financial_Data_and_Services"
                        - "/Common/Health_and_Medicine"
            mode: output
        register: securitypolicy
        delegate_to: localhost

      #### topology #################################
      - name: SSLO topology
        bigip_sslo_config_topology:
            provider: "{{ provider }}"
            name: "demoOutL2"  
            configReferences:
                sslSettings: "{{ sslsettings }}"
                securityPolicy: "{{ securitypolicy }}"
                resolver: "{{ myresolver }}"
            topologyOutboundL2:
                vlans:
                - "/Common/vwire_vlan_4096_1_631"
        delegate_to: localhost
'''

RETURN = r'''
name:
  description:
    - Changed name of topology.
  type: str
  sample: demo

configReferences:
  description: set of external object references
  type: complex
  contains:
    sslSettings:
       description: defines the name of an SSL settings object, or jinja2 reference.
       type: str
       sample: sslsettings  - or -  "{{ sslsettings }}"
    securityPolicy:
       description: defines the name of a security policy object, or jinja2 reference.
       type: str
       sample: securitypolicy  - or -  "{{ securitypolicy }}"
    services:
       description: defines a list of security service jinja2 references.
       type: str
       sample: 
         - "{{ service1 }}"
         - "{{ service2 }}"
    serviceChains:
       description: defines a list of service chain jinja2 references.
       type: str
       sample:
         - "{{ servicechain1 }}"
         - "{{ servicechain2 }}"
    resolver:
       description: defines a resolver configuration jinja2 reference.
       type: str
       sample: "{{ resolver }}"

topologyOutboundL3:
  description: describes the set of options for an SSL Orchestrator outbound layer 3 topology
  type: complex
  contains:
    ipFamily:
       description: describes the IP family to use for this topology.
       type: str
       sample: ipv4
    protocol:
       description: describes the protocol to use for this topology.
       type: str
       sample: tcp
    source:
       description: describes the source address filter to use.
       type: str
       sample: 0.0.0.0%0/0
    dest:
       description: describes the destination address filter to use.
       type: str
       sample: 0.0.0.0%0/0
    port:
       description: describes the port filter to use.
       type: int
       sample: 0
    vlans:
       description: describes the list of VLANs to listen on.
       type: str
       sample:
         - /Common/client-vlan1
         - /Common/client-vlan2
    snat:
       description: describes the SNAT method to use.
       type: str
       sample: automap
    snatlist:
       description: describes the list of SNAT IPs to use if snat is set to 'snatlist'.
       type: str
       sample: 
         - 10.1.20.10
         - 10.1.20.11
         - 10.1.20.12
    snatpool:
       description: describes the exiting SNAT pool to use if snat is set to 'snatpool'
       type: str
       sample: /Common/my-snatpool
    gateway:
       description: describes the gateway method to use.
       type: str
       sample: 
    gatewaylist:
       description: describes the list of gateway IPs to use if gateway is set to 'iplist'.
       type: str
       sample: 
         - 10.1.20.1
         - 10.1.20.2
    gatewaypool:
       description: describes the existing gateway pool if gateway is set to 'pool'
       type: str
       sample: /Common/my-gatewaypool
    tcpSettingsClient:
       description: describes the client side TCP profile to use.
       type: str
       sample: /Common/f5-tcp-lan
    tcpSettingsServer:
       description: describes the server side TCP profile to use.
       type: str
       sample: /Common/f5-tcp-wan
    L7ProfileType:
       description: describes the L7 profile type.
       type: str
       sample: http
    L7Profile:
       description: describes the corresponding L7 profile to use.
       type: str
       sample: /Common/http
    additionalProtocols:
       description: describes the list of additional protocol listeners to use.
       type: str
       sample: 
         - ftp
         - imap
         - pop3
         - smtps
    accessProfile:
       description: describes a custom SSL Orchestrator-type access profile to apply.
       type: str
       sample: /Common/my-custom-sslo-profile
    profileScope:
       description: in 8.2 and above, describes the profile scope to apply.
       type: str
       sample: named
    profileScopeValue:
       description: in 8.2 and above, and when profileScope is set to 'named', describes the string name that is shared between this profile and the captive portal authentication access profile.
       type: str
       sample: SSLO
    primaryAuthUri:
       description: in 8.2 and above, and when profileScope is set to 'named', describes the captive portal authentication service URL.
       type: str
       sample: https://auth.f5labs.com
    verifyAccept:
       description: in 9.0 and above, enabled or disables TCP Verify Accept proxy.
       type: bool
       sample: False
    ocspAuth:
       description: in 9.0 and above, defines an OCSP Authentication profile object.
       type: str
       sample: ssloA_my_ocsp

topologyOutboundExplicit:
  description: describes the set of options for an SSL Orchestrator outbound explicit proxy topology
  type: complex
  contains:
    ipFamily:
       description: describes the IP family to use for this topology.
       type: str
       sample: ipv4
    source:
       description: describes the source address filter to use.
       type: str
       sample: 0.0.0.0%0/0
    proxyIp:
       description: describes the explicit proxy listener IP address.
       type: str
       sample: 10.1.10.150
    prpxyPort:
       description: describes the explicit proxy listener port to use.
       type: int
       sample: 3128
    vlans:
       description: describes the list of VLANs to listen on.
       type: str
       sample:
         - /Common/client-vlan1
         - /Common/client-vlan2
    snat:
       description: describes the SNAT method to use.
       type: str
       sample: automap
    snatlist:
       description: describes the list of SNAT IPs to use if snat is set to 'snatlist'.
       type: str
       sample: 
         - 10.1.20.10
         - 10.1.20.11
         - 10.1.20.12
    snatpool:
       description: describes the exiting SNAT pool to use if snat is set to 'snatpool'
       type: str
       sample: /Common/my-snatpool
    gateway:
       description: describes the gateway method to use.
       type: str
       sample: 
    gatewaylist:
       description: describes the list of gateway IPs to use if gateway is set to 'iplist'.
       type: str
       sample: 
         - 10.1.20.1
         - 10.1.20.2
    gatewaypool:
       description: describes the existing gateway pool if gateway is set to 'pool'
       type: str
       sample: /Common/my-gatewaypool
    authProfile:
       description: describes a custom authentication per-session access profile to apply to the explicit proxy.
       type: str
       sample: /Common/my-auth-profile
    verifyAccept:
       description: in 9.0 and above, enabled or disables TCP Verify Accept proxy.
       type: bool
       sample: False
    ocspAuth:
       description: in 9.0 and above, defines an OCSP Authentication profile object.
       type: str
       sample: ssloA_my_ocsp
    dnsResolver:
       description: required in 9.0 and above, defines a per-topology DNS resolver configuration.
       type: str
       sample: /Common/my_dns_resolver

topologyInboundL3:
  description: describes the set of options for an SSL Orchestrator inbound layer 3 topology
  type: complex
  contains:
    ipFamily:
       description: describes the IP family to use for this topology.
       type: str
       sample: ipv4
    protocol:
       description: describes the protocol to use for this topology.
       type: str
       sample: tcp
    source:
       description: describes the source address filter to use.
       type: str
       sample: 0.0.0.0%0/0
    dest:
       description: describes the destination address filter to use.
       type: str
       sample: 0.0.0.0%0/0
    port:
       description: describes the port filter to use.
       type: int
       sample: 0
    vlans:
       description: describes the list of VLANs to listen on.
       type: str
       sample:
         - /Common/client-vlan1
         - /Common/client-vlan2
    snat:
       description: describes the SNAT method to use.
       type: str
       sample: automap
    snatlist:
       description: describes the list of SNAT IPs to use if snat is set to 'snatlist'.
       type: str
       sample: 
         - 10.1.20.10
         - 10.1.20.11
         - 10.1.20.12
    snatpool:
       description: describes the exiting SNAT pool to use if snat is set to 'snatpool'
       type: str
       sample: /Common/my-snatpool
    gateway:
       description: describes the gateway method to use.
       type: str
       sample: 
    gatewaylist:
       description: describes the list of gateway IPs to use if gateway is set to 'iplist'.
       type: str
       sample: 
         - 10.1.20.1
         - 10.1.20.2
    gatewaypool:
       description: describes the existing gateway pool if gateway is set to 'pool'
       type: str
       sample: /Common/my-gatewaypool
    pool:
       description: describes a server pool to forward traffic to.
       type: str
       sample: /Common/my-server-pool
    tcpSettingsClient:
       description: describes the client side TCP profile to use.
       type: str
       sample: /Common/f5-tcp-lan
    tcpSettingsServer:
       description: describes the server side TCP profile to use.
       type: str
       sample: /Common/f5-tcp-wan
    L7ProfileType:
       description: describes the L7 profile type.
       type: str
       sample: http
    L7Profile:
       description: describes the corresponding L7 profile to use.
       type: str
       sample: /Common/http

topologyOutboundL2:
  description: describes the set of options for an SSL Orchestrator outbound layer 2 topology
  type: complex
  contains:
    ipFamily:
       description: describes the IP family to use for this topology.
       type: str
       sample: ipv4
    protocol:
       description: describes the protocol to use for this topology.
       type: str
       sample: tcp
    source:
       description: describes the source address filter to use.
       type: str
       sample: 0.0.0.0%0/0
    dest:
       description: describes the destination address filter to use.
       type: str
       sample: 0.0.0.0%0/0
    port:
       description: describes the port filter to use.
       type: int
       sample: 0
    vlans:
       description: describes the list of VLANs to listen on.
       type: str
       sample:
         - /Common/client-vlan1
         - /Common/client-vlan2
    tcpSettingsClient:
       description: describes the client side TCP profile to use.
       type: str
       sample: /Common/f5-tcp-lan
    tcpSettingsServer:
       description: describes the server side TCP profile to use.
       type: str
       sample: /Common/f5-tcp-wan
    L7ProfileType:
       description: describes the L7 profile type.
       type: str
       sample: http
    L7Profile:
       description: describes the corresponding L7 profile to use.
       type: str
       sample: /Common/http
    accessProfile:
       description: describes a custom SSL Orchestrator-type access profile to apply.
       type: str
       sample: /Common/my-custom-sslo-profile
    profileScope:
       description: in 8.2 and above, describes the profile scope to apply.
       type: str
       sample: named
    profileScopeValue:
       description: in 8.2 and above, and when profileScope is set to 'named', describes the string name that is shared between this profile and the captive portal authentication access profile.
       type: str
       sample: SSLO
    primaryAuthUri:
       description: in 8.2 and above, and when profileScope is set to 'named', describes the captive portal authentication service URL.
       type: str
       sample: https://auth.f5labs.com
    verifyAccept:
       description: in 9.0 and above, enabled or disables TCP Verify Accept proxy.
       type: bool
       sample: False
    ocspAuth:
       description: in 9.0 and above, defines an OCSP Authentication profile object.
       type: str
       sample: ssloA_my_ocsp

topologyInboundL2:
  description: describes the set of options for an SSL Orchestrator inbound layer 2 topology
  type: complex
  contains:
    ipFamily:
       description: describes the IP family to use for this topology.
       type: str
       sample: ipv4
    protocol:
       description: describes the protocol to use for this topology.
       type: str
       sample: tcp
    source:
       description: describes the source address filter to use.
       type: str
       sample: 0.0.0.0%0/0
    dest:
       description: describes the destination address filter to use.
       type: str
       sample: 0.0.0.0%0/0
    port:
       description: describes the port filter to use.
       type: int
       sample: 0
    vlans:
       description: describes the list of VLANs to listen on.
       type: str
       sample:
         - /Common/client-vlan1
         - /Common/client-vlan2
    tcpSettingsClient:
       description: describes the client side TCP profile to use.
       type: str
       sample: /Common/f5-tcp-lan
    tcpSettingsServer:
       description: describes the server side TCP profile to use.
       type: str
       sample: /Common/f5-tcp-wan
    L7ProfileType:
       description: describes the L7 profile type.
       type: str
       sample: http
    L7Profile:
       description: describes the corresponding L7 profile to use.
       type: str
       sample: /Common/http
    accessProfile:
       description: describes a custom SSL Orchestrator-type access profile to apply.
       type: str
       sample: /Common/my-custom-sslo-profile

logging:
  description: describes the set of options for an SSL Orchestrator inbound layer 3 topology
  type: complex
  contains:
    sslo:
      description: describes the log facility to use for SSL Orchestrator summary logging
      type:
      sample: error
    perRequestPolicy:
      description: describes the log facility to use for SSL Orchestrator security policy logging
      type:
      sample: error
    ftp:
      description: describes the log facility to use for FTP topology listener logging
      type:
      sample: error
    imap:
      description: describes the log facility to use for IMAP topology listener logging
      type:
      sample: error
    pop3:
      description: describes the log facility to use for POP3 topology listener logging
      type:
      sample: error
    smtps:
      description: describes the log facility to use for SMTPS topology listener logging
      type:
      sample: error

mode:
  description: describes the action to take on the task.
  type: str
  sample: update

state:
  description:
    - Changed state.
  type: str
  sample: present
'''

from datetime import datetime
from ansible.module_utils.basic import (
    AnsibleModule, env_fallback
)
from ansible_collections.f5networks.f5_modules.plugins.module_utils.bigip import F5RestClient
from ansible_collections.f5networks.f5_modules.plugins.module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, transform_name, f5_argument_spec
)
from ansible_collections.f5networks.f5_modules.plugins.module_utils.icontrol import tmos_version
import json, time, re, hashlib, ipaddress, copy, ast

global print_output
global json_template
global obj_attempts
global min_version
global max_version

print_output = []

## define object creation attempts count (with 1 seconds pause between each attempt)
obj_attempts = 60

## define minimum supported tmos version - min(SSLO 5.x)
min_version = 5.0

## define maximum supported tmos version - max(SSLO 8.x)
max_version = 9.0

json_template = {
   "name": "proxy-f5-ssl-orchestrator-topology-CREATE",
   "inputProperties": [
       {
           "id": "f5-ssl-orchestrator-operation-context",
           "type": "JSON",
           "value": {
               "version": "7.2",
               "partition": "Common",
               "strictness": False,
               "operationType": "CREATE",
               "deploymentName": "TEMPLATE_NAME",
               "deploymentType": "TOPOLOGY",
               "deploymentReference": ""
           }
       },
       {
           "id": "f5-ssl-orchestrator-topology",
           "type": "JSON",
           "value": {
               "name": "TEMPLATE_NAME",
               "type": "TEMPLATE_TYPE",
               "version": "7.2",
               "previousVersion": "7.2",
               "partition": "Common",
               "strictness": False,
               "userCreated": False,
               "description": "",
               "deployedNetwork": "",
               "ipFamily": "ipv4",               
               "ruleType": "Outbound",
               "ruleLabel": "Outbound",
               "dnsResolver": "",
               "serviceDef": {
                   "description": "",
                   "source": "0.0.0.0%0/0",
                   "protocol": "tcp",
                   "destination": {
                       "mask": "",
                       "port": 0,
                       "prefix": 0,
                       "address": "0.0.0.0%0/0"
                   }
               },
               "pool": "",
               "tlsEnabled": True,
               "iRules": [
                  {
                    "name": "",
                    "value": ""
                  }
               ],
               "l7Protocols": [],
               "l7Profile": "",
               "l7ProfileType": "",
               "tcpSettings": {
                   "clientTcpProfile": "/Common/f5-tcp-lan",
                   "serverTcpProfile": "/Common/f5-tcp-wan"
               },
               "udpSettings": {
                   "clientUdpProfile": "",
                   "serverUdpProfile": ""
               },
               "fastL4Settings": {
                   "all": ""
               },
               "ingressNetwork": {
                  "vlans": []
               },
               "egressNetwork": {
                  "clientSnat": "None", 
                  "snat": {
                     "referredObj": "",
                     "ipv4SnatAddresses": [],
                     "ipv6SnatAddresses": []
                   },
                   "gatewayOptions": "useDefault",
                   "outboundGateways": {
                     "referredObj": "",
                     "ipv4OutboundGateways": [],
                     "ipv6OutboundGateways": []
                   }
               },
               "proxySettings": {
                  "proxyType": "transparent",
                  "forwardProxy": {
                      "explicitProxy": {
                          "ipv4Port": 3128.0,
                          "ipv6Port": 3128.0,
                          "ipv4Address": "",
                          "ipv6Address": ""
                      },
                      "transparentProxy": {
                          "passNonTcpNonUdpTraffic": False,
                          "tcpTrafficPassThroughType": True
                      }
                  },
                  "reverseProxy": {
                     "ipv4Address": "",
                     "ipv4Port": 0,
                     "ipv6Address": "",
                     "ipv6Port": 0
                  }
               },
               "advancedMode": "off",
               "iRulesList": [],
                "loggingConfig": {
                    "logPublisher": "none",
                    "statsToRecord": 0,
                    "perRequestPolicy": "err",
                    "ftp": "err",
                    "imap": "err",
                    "pop3": "err",
                    "smtps": "err",
                    "sslOrchestrator": "err"
               },
               "authProfile": "",
               "sslSettingReference": "TEMPLATE_REFERENCE_SSL",
               "securityPolicyReference": "TEMPLATE_REFERENCE_POLICY",
               "accessProfile": "/Common/ssloDefault_accessProfile",
               "accessProfileScope": "public",
               "accessProfileNameScopeValue": "",
               "primaryAuthenticationURI": "",
               "existingBlockId": ""
           }
       },
       {
           "id": "f5-ssl-orchestrator-general-settings",
           "type": "JSON",
           "value": {},
       },
       {
           "id": "f5-ssl-orchestrator-tls",
           "type": "JSON",
           "value": {}
       },
       {
           "id": "f5-ssl-orchestrator-service-chain",
           "type": "JSON",
           "value": []
       },
       {
           "id": "f5-ssl-orchestrator-service",
           "type": "JSON",
           "value": []
       },
       {
           "id": "f5-ssl-orchestrator-network",
           "type": "JSON",
           "value": []
       },
       {
           "id": "f5-ssl-orchestrator-intercept-rule",
           "type": "JSON",
           "value": []
       },
       {
           "id": "f5-ssl-orchestrator-policy",
           "type": "JSON",
           "value": {}
       }
   ],
   "configurationProcessorReference": {
       "link": "https://localhost/mgmt/shared/iapp/processors/f5-iappslx-ssl-orchestrator-gc"
   },
   "configProcessorTimeoutSeconds": 120,
   "statsProcessorTimeoutSeconds": 60,
   "configProcessorAffinity": {
        "processorPolicy": "LOCAL",
        "affinityProcessorReference": {
            "link": "https://localhost/mgmt/shared/iapp/affinity/local"
        }
   },
   "state": "BINDING",
   "presentationHtmlReference": {
       "link": "https://localhost/iapps/f5-iappslx-ssl-orchestrator/sgc/sgcIndex.html"
   },
   "operation": "CREATE"
}

json_template_gs = {
    "name":"ssloGS_global",
    "previousVersion":"7.2",
    "version":"7.2",
    "configModified":True,
    "ipFamily":"ipv4",
    "dns":{
        "enableDnsSecurity":False,
        "enableLocalDnsQueryResolution":False,
        "enableLocalDnsZones":False,
        "localDnsZones":[],
        "localDnsNameservers":[]
    },
    "loggingConfig": {
        "logLevel": 0,
        "logPublisher": "none",
        "statsToRecord": 0
    },
    "egressNetwork":{
        "gatewayOptions":"useDefault",
        "outboundGateways":{
            "referredObj":"",
            "ipv4OutboundGateways":[{"ip":"","ratio":1}],
            "ipv6NonPublicGateways":[{"ip":""}],
            "ipv6OutboundGateways":[{"ip":"","ratio":1}]
        }
    },
    "partition":"Common",
    "strictness":False
}


class Parameters(AnsibleF5Parameters):
    api_map = {}
    updatables = []
    api_attributes = []
    returnables = []

class ApiParameters(Parameters):
    pass

class ModuleParameters(Parameters):
    global print_output

    @property
    def name(self):
        name = self._values['name']
        name = "sslo_" + name
        return name

    # ConfigReferences

    @property
    def configref_ssl(self):
        try:
            configref_ssl = self._values['configReferences']['sslSettings']
            if configref_ssl == None:
                return None
            return configref_ssl
        except:
            return None
    
    @property
    def configref_policy(self):
        try:
            configref_policy = self._values['configReferences']['securityPolicy']
            if configref_policy == None:
                return None
            return configref_policy
        except:
            return None

    @property
    def configref_services(self):
        try:
            configref_services = self._values['configReferences']['services']
            if configref_services == None:
                return None
            return configref_services
        except:
            return None

    @property
    def configref_chains(self):
        try:
            configref_chains = self._values['configReferences']['serviceChains']
            if configref_chains == None:
                return None
            return configref_chains
        except:
            return None

    @property
    def configref_resolver(self):
        try:
            configref_resolver = self._values['configReferences']['resolver']
            if configref_resolver == None:
                return None
            return configref_resolver
        except:
            return None

    # Outbound L3 Topology

    @property
    def topo_outboundl3(self):
        try:
            topo_outboundl3 = self._values['topologyOutboundL3']
            if topo_outboundl3 == None:
                return False
            return True
        except:
            return False

    @property
    def topo_outboundl3_ipfamily(self):
        try:
            topo_outboundl3_ipfamily = self._values['topologyOutboundL3']['ipFamily']
            if topo_outboundl3_ipfamily == None:
                return "ipv4"
            return topo_outboundl3_ipfamily
        except:
            return "ipv4"

    @property
    def topo_outboundl3_proto(self):
        try:
            topo_outboundl3_proto = self._values['topologyOutboundL3']['protocol']
            if topo_outboundl3_proto == None:
                return "tcp"
            return topo_outboundl3_proto
        except:
            return "tcp"

    @property
    def topo_outboundl3_source(self):
        try:
            topo_outboundl3_source = self._values['topologyOutboundL3']['source']
            if topo_outboundl3_source == None:
                return "0.0.0.0%0/0"
            return topo_outboundl3_source
        except:
            return "0.0.0.0%0/0"

    @property
    def topo_outboundl3_dest(self):
        try:
            topo_outboundl3_dest = self._values['topologyOutboundL3']['dest']
            if topo_outboundl3_dest == None:
                return "0.0.0.0%0/0"
            return topo_outboundl3_dest
        except:
            return "0.0.0.0%0/0"

    @property
    def topo_outboundl3_port(self):
        try:
            topo_outboundl3_port = self._values['topologyOutboundL3']['port']
            if topo_outboundl3_port == None:
                return 0
            return topo_outboundl3_port
        except:
            return 0

    @property
    def topo_outboundl3_vlans(self):
        try:
            topo_outboundl3_vlans = self._values['topologyOutboundL3']['vlans']
            if topo_outboundl3_vlans == None:
                return None
            return topo_outboundl3_vlans
        except:
            return None

    @property
    def topo_outboundl3_snat(self):
        try:
            topo_outboundl3_snat = self._values['topologyOutboundL3']['snat']
            if topo_outboundl3_snat == None:
                return None
            return topo_outboundl3_snat
        except:
            return None

    @property
    def topo_outboundl3_snatlist(self):
        try:
            topo_outboundl3_snatlist = self._values['topologyOutboundL3']['snatlist']
            if topo_outboundl3_snatlist == None:
                return None
            return topo_outboundl3_snatlist
        except:
            return None

    @property
    def topo_outboundl3_snatpool(self):
        try:
            topo_outboundl3_snatpool = self._values['topologyOutboundL3']['snatpool']
            if topo_outboundl3_snatpool == None:
                return None
            return topo_outboundl3_snatpool
        except:
            return None

    @property
    def topo_outboundl3_gateway(self):
        try:
            topo_outboundl3_gateway = self._values['topologyOutboundL3']['gateway']
            if topo_outboundl3_gateway == None:
                return "system"
            return topo_outboundl3_gateway
        except:
            return "system"

    @property
    def topo_outboundl3_gatewaylist(self):
        try:
            topo_outboundl3_gatewaylist = self._values['topologyOutboundL3']['gatewaylist']
            if topo_outboundl3_gatewaylist == None:
                return None
            return topo_outboundl3_gatewaylist
        except:
            return None

    @property
    def topo_outboundl3_gatewaypool(self):
        try:
            topo_outboundl3_gatewaypool = self._values['topologyOutboundL3']['gatewaypool']
            if topo_outboundl3_gatewaypool == None:
                return None
            return topo_outboundl3_gatewaypool
        except:
            return None

    @property
    def topo_outboundl3_tcp_client(self):
        try:
            topo_outboundl3_tcp_client = self._values['topologyOutboundL3']['tcpSettingsClient']
            if topo_outboundl3_tcp_client == None:
                return "/Common/f5-tcp-lan"
            return topo_outboundl3_tcp_client
        except:
            return "/Common/f5-tcp-lan"

    @property
    def topo_outboundl3_tcp_server(self):
        try:
            topo_outboundl3_tcp_server = self._values['topologyOutboundL3']['tcpSettingsServer']
            if topo_outboundl3_tcp_server == None:
                return "/Common/f5-tcp-wan"
            return topo_outboundl3_tcp_server
        except:
            return "/Common/f5-tcp-wan"

    @property
    def topo_outboundl3_L7profiletype(self):
        try:
            topo_outboundl3_L7profiletype = self._values['topologyOutboundL3']['L7ProfileType']
            if topo_outboundl3_L7profiletype == None:
                return None
            return topo_outboundl3_L7profiletype
        except:
            return None

    @property
    def topo_outboundl3_L7profile(self):
        try:
            topo_outboundl3_L7profile = self._values['topologyOutboundL3']['L7Profile']
            if topo_outboundl3_L7profile == None:
                return None
            return topo_outboundl3_L7profile
        except:
            return None

    @property
    def topo_outboundl3_additionalprotocols(self):
        try:
            topo_outboundl3_additionalprotocols = self._values['topologyOutboundL3']['additionalProtocols']
            if topo_outboundl3_additionalprotocols == None:
                return None
            return topo_outboundl3_additionalprotocols
        except:
            return None

    @property
    def topo_outboundl3_accessprofile(self):
        try:
            topo_outboundl3_accessprofile = self._values['topologyOutboundL3']['accessProfile']
            if topo_outboundl3_accessprofile == None:
                return None
            return topo_outboundl3_accessprofile
        except:
            return None

    @property
    def topo_outboundl3_profilescope(self):
        try:
            topo_outboundl3_profilescope = self._values['topologyOutboundL3']['profileScope']
            if topo_outboundl3_profilescope == None:
                return "public"
            return topo_outboundl3_profilescope
        except:
            return "public"

    @property
    def topo_outboundl3_profilescopevalue(self):
        try:
            topo_outboundl3_profilescopevalue = self._values['topologyOutboundL3']['profileScopeValue']
            if topo_outboundl3_profilescopevalue == None:
                return None
            return topo_outboundl3_profilescopevalue
        except:
            return None

    @property
    def topo_outboundl3_primaryauthuri(self):
        try:
            topo_outboundl3_primaryauthuri = self._values['topologyOutboundL3']['primaryAuthUri']
            if topo_outboundl3_primaryauthuri == None:
                return None
            return topo_outboundl3_primaryauthuri
        except:
            return None

    @property
    def topo_outboundl3_verifyAccept(self):
        try:
            topo_outboundl3_verifyAccept = self._values['topologyOutboundL3']['verifyAccept']
            if topo_outboundl3_verifyAccept == None:
                return False
            return topo_outboundl3_verifyAccept
        except:
            return False

    @property
    def topo_outboundl3_ocspAuth(self):
        try:
            topo_outboundl3_ocspAuth = self._values['topologyOutboundL3']['ocspAuth']
            if topo_outboundl3_ocspAuth == None:
                return None
            return topo_outboundl3_ocspAuth
        except:
            return None

    # Outbound Explicit Topology

    @property
    def topo_outboundxp(self):
        try:
            topo_outboundxp = self._values['topologyOutboundExplicit']
            if topo_outboundxp == None:
                return False
            return True
        except:
            return False

    @property
    def topo_outboundxp_ipfamily(self):
        try:
            topo_outboundxp_proto = self._values['topologyOutboundExplicit']['ipFamily']
            if topo_outboundxp_proto == None:
                return "ipv4"
            return topo_outboundxp_proto
        except:
            return "ipv4"

    @property
    def topo_outboundxp_source(self):
        try:
            topo_outboundxp_source = self._values['topologyOutboundExplicit']['source']
            if topo_outboundxp_source == None:
                return "0.0.0.0%0/0"
            return topo_outboundxp_source
        except:
            return "0.0.0.0%0/0"

    @property
    def topo_outboundxp_proxyip(self):
        try:
            topo_outboundxp_proxyip = self._values['topologyOutboundExplicit']['proxyIp']
            if topo_outboundxp_proxyip == None:
                return None
            return topo_outboundxp_proxyip
        except:
            return None

    @property
    def topo_outboundxp_proxyport(self):
        try:
            topo_outboundxp_proxyport = self._values['topologyOutboundExplicit']['proxyPort']
            if topo_outboundxp_proxyport == None:
                return 0
            return topo_outboundxp_proxyport
        except:
            return 0

    @property
    def topo_outboundxp_vlans(self):
        try:
            topo_outboundxp_vlans = self._values['topologyOutboundExplicit']['vlans']
            if topo_outboundxp_vlans == None:
                return None
            return topo_outboundxp_vlans
        except:
            return None

    @property
    def topo_outboundxp_snat(self):
        try:
            topo_outboundxp_snat = self._values['topologyOutboundExplicit']['snat']
            if topo_outboundxp_snat == None:
                return None
            return topo_outboundxp_snat
        except:
            return None

    @property
    def topo_outboundxp_snatlist(self):
        try:
            topo_outboundxp_snatlist = self._values['topologyOutboundExplicit']['snatlist']
            if topo_outboundxp_snatlist == None:
                return None
            return topo_outboundxp_snatlist
        except:
            return None

    @property
    def topo_outboundxp_snatpool(self):
        try:
            topo_outboundxp_snatpool = self._values['topologyOutboundExplicit']['snatpool']
            if topo_outboundxp_snatpool == None:
                return None
            return topo_outboundxp_snatpool
        except:
            return None

    @property
    def topo_outboundxp_gateway(self):
        try:
            topo_outboundxp_gateway = self._values['topologyOutboundExplicit']['gateway']
            if topo_outboundxp_gateway == None:
                return "system"
            return topo_outboundxp_gateway
        except:
            return "system"

    @property
    def topo_outboundxp_gatewaylist(self):
        try:
            topo_outboundxp_gatewaylist = self._values['topologyOutboundExplicit']['gatewaylist']
            if topo_outboundxp_gatewaylist == None:
                return None
            return topo_outboundxp_gatewaylist
        except:
            return None

    @property
    def topo_outboundxp_gatewaypool(self):
        try:
            topo_outboundxp_gatewaypool = self._values['topologyOutboundExplicit']['gatewaypool']
            if topo_outboundxp_gatewaypool == None:
                return None
            return topo_outboundxp_gatewaypool
        except:
            return None

    @property
    def topo_outboundxp_authprofile(self):
        try:
            topo_outboundxp_authprofile = self._values['topologyOutboundExplicit']['authProfile']
            if topo_outboundxp_authprofile == None:
                return None
            return topo_outboundxp_authprofile
        except:
            return None

    @property
    def topo_outboundxp_verifyAccept(self):
        try:
            topo_outboundxp_verifyAccept = self._values['topologyOutboundExplicit']['verifyAccept']
            if topo_outboundxp_verifyAccept == None:
                return False
            return topo_outboundxp_verifyAccept
        except:
            return False

    @property
    def topo_outboundxp_ocspAuth(self):
        try:
            topo_outboundxp_ocspAuth = self._values['topologyOutboundExplicit']['ocspAuth']
            if topo_outboundxp_ocspAuth == None:
                return None
            return topo_outboundxp_ocspAuth
        except:
            return None

    @property
    def topo_outboundxp_dnsResolver(self):
        try:
            topo_outboundxp_dnsResolver = self._values['topologyOutboundExplicit']['dnsResolver']
            if topo_outboundxp_dnsResolver == None:
                return None
            return topo_outboundxp_dnsResolver
        except:
            return None


    # Inbound L3 Topology

    @property
    def topo_inboundl3(self):
        try:
            topo_inboundl3 = self._values['topologyInboundL3']
            if topo_inboundl3 == None:
                return False
            return True
        except:
            return False

    @property
    def topo_inboundl3_proto(self):
        try:
            topo_inboundl3_proto = self._values['topologyInboundL3']['protocol']
            if topo_inboundl3_proto == None:
                return "tcp"
            return topo_inboundl3_proto
        except:
            return "tcp"

    @property
    def topo_inboundl3_ipfamily(self):
        try:
            topo_inboundl3_ipfamily = self._values['topologyInboundL3']['ipFamily']
            if topo_inboundl3_ipfamily == None:
                return "ipv4"
            return topo_inboundl3_ipfamily
        except:
            return "ipv4"

    @property
    def topo_inboundl3_source(self):
        try:
            topo_inboundl3_source = self._values['topologyInboundL3']['source']
            if topo_inboundl3_source == None:
                return "0.0.0.0%0/0"
            return topo_inboundl3_source
        except:
            return "0.0.0.0%0/0"

    @property
    def topo_inboundl3_dest(self):
        try:
            topo_inboundl3_dest = self._values['topologyInboundL3']['dest']
            if topo_inboundl3_dest == None:
                return "0.0.0.0%0/0"
            return topo_inboundl3_dest
        except:
            return "0.0.0.0%0/0"

    @property
    def topo_inboundl3_port(self):
        try:
            topo_inboundl3_port = self._values['topologyInboundL3']['port']
            if topo_inboundl3_port == None:
                return 0
            return topo_inboundl3_port
        except:
            return 0

    @property
    def topo_inboundl3_vlans(self):
        try:
            topo_inboundl3_vlans = self._values['topologyInboundL3']['vlans']
            if topo_inboundl3_vlans == None:
                return None
            return topo_inboundl3_vlans
        except:
            return None

    @property
    def topo_inboundl3_snat(self):
        try:
            topo_inboundl3_snat = self._values['topologyInboundL3']['snat']
            if topo_inboundl3_snat == None:
                return None
            return topo_inboundl3_snat
        except:
            return None

    @property
    def topo_inboundl3_snatlist(self):
        try:
            topo_inboundl3_snatlist = self._values['topologyInboundL3']['snatlist']
            if topo_inboundl3_snatlist == None:
                return None
            return topo_inboundl3_snatlist
        except:
            return None

    @property
    def topo_inboundl3_snatpool(self):
        try:
            topo_inboundl3_snatpool = self._values['topologyInboundL3']['snatpool']
            if topo_inboundl3_snatpool == None:
                return None
            return topo_inboundl3_snatpool
        except:
            return None

    @property
    def topo_inboundl3_gateway(self):
        try:
            topo_inboundl3_gateway = self._values['topologyInboundL3']['gateway']
            if topo_inboundl3_gateway == None:
                return "system"
            return topo_inboundl3_gateway
        except:
            return "system"

    @property
    def topo_inboundl3_gatewaylist(self):
        try:
            topo_inboundl3_gatewaylist = self._values['topologyInboundL3']['gatewaylist']
            if topo_inboundl3_gatewaylist == None:
                return None
            return topo_inboundl3_gatewaylist
        except:
            return None

    @property
    def topo_inboundl3_gatewaypool(self):
        try:
            topo_inboundl3_gatewaypool = self._values['topologyInboundL3']['gatewaypool']
            if topo_inboundl3_gatewaypool == None:
                return None
            return topo_inboundl3_gatewaypool
        except:
            return None

    @property
    def topo_inboundl3_pool(self):
        try:
            topo_inboundl3_pool = self._values['topologyInboundL3']['pool']
            if topo_inboundl3_pool == None:
                return None
            return topo_inboundl3_pool
        except:
            return None

    @property
    def topo_inboundl3_tcp_client(self):
        try:
            topo_inboundl3_tcp_client = self._values['topologyInboundL3']['tcpSettingsClient']
            if topo_inboundl3_tcp_client == None:
                return "/Common/f5-tcp-wan"
            return topo_inboundl3_tcp_client
        except:
            return "/Common/f5-tcp-wan"

    @property
    def topo_inboundl3_tcp_server(self):
        try:
            topo_inboundl3_tcp_server = self._values['topologyInboundL3']['tcpSettingsServer']
            if topo_inboundl3_tcp_server == None:
                return "/Common/f5-tcp-lan"
            return topo_inboundl3_tcp_server
        except:
            return "/Common/f5-tcp-lan"

    @property
    def topo_inboundl3_L7profiletype(self):
        try:
            topo_inboundl3_L7profiletype = self._values['topologyInboundL3']['L7ProfileType']
            if topo_inboundl3_L7profiletype == None:
                return "http"
            return topo_inboundl3_L7profiletype
        except:
            return "http"

    @property
    def topo_inboundl3_L7profile(self):
        try:
            topo_inboundl3_L7profile = self._values['topologyInboundL3']['L7Profile']
            if topo_inboundl3_L7profile == None:
                return "/Common/http"
            return topo_inboundl3_L7profile
        except:
            return "/Common/http"

    @property
    def topo_inboundl3_accessprofile(self):
        try:
            topo_inboundl3_accessprofile = self._values['topologyInboundL3']['accessProfile']
            if topo_inboundl3_accessprofile == None:
                return None
            return topo_inboundl3_accessprofile
        except:
            return None

    
    # Outbound L2 Topology

    @property
    def topo_outboundl2(self):
        try:
            topo_outboundl2 = self._values['topologyOutboundL2']
            if topo_outboundl2 == None:
                return False
            return True
        except:
            return False

    @property
    def topo_outboundl2_ipfamily(self):
        try:
            topo_outboundl2_ipfamily = self._values['topologyOutboundL2']['ipFamily']
            if topo_outboundl2_ipfamily == None:
                return "ipv4"
            return topo_outboundl2_ipfamily
        except:
            return "ipv4"

    @property
    def topo_outboundl2_proto(self):
        try:
            topo_outboundl2_proto = self._values['topologyOutboundL2']['protocol']
            if topo_outboundl2_proto == None:
                return "tcp"
            return topo_outboundl2_proto
        except:
            return "tcp"

    @property
    def topo_outboundl2_source(self):
        try:
            topo_outboundl2_source = self._values['topologyOutboundL2']['source']
            if topo_outboundl2_source == None:
                return "0.0.0.0%0/0"
            return topo_outboundl2_source
        except:
            return "0.0.0.0%0/0"

    @property
    def topo_outboundl2_dest(self):
        try:
            topo_outboundl2_dest = self._values['topologyOutboundL2']['dest']
            if topo_outboundl2_dest == None:
                return "0.0.0.0%0/0"
            return topo_outboundl2_dest
        except:
            return "0.0.0.0%0/0"

    @property
    def topo_outboundl2_port(self):
        try:
            topo_outboundl2_port = self._values['topologyOutboundL2']['port']
            if topo_outboundl2_port == None:
                return 0
            return topo_outboundl2_port
        except:
            return 0

    @property
    def topo_outboundl2_vlans(self):
        try:
            topo_outboundl2_vlans = self._values['topologyOutboundL2']['vlans']
            if topo_outboundl2_vlans == None:
                return None
            return topo_outboundl2_vlans
        except:
            return None

    @property
    def topo_outboundl2_tcp_client(self):
        try:
            topo_outboundl2_tcp_client = self._values['topologyOutboundL2']['tcpSettingsClient']
            if topo_outboundl2_tcp_client == None:
                return "/Common/f5-tcp-lan"
            return topo_outboundl2_tcp_client
        except:
            return "/Common/f5-tcp-lan"

    @property
    def topo_outboundl2_tcp_server(self):
        try:
            topo_outboundl2_tcp_server = self._values['topologyOutboundL2']['tcpSettingsServer']
            if topo_outboundl2_tcp_server == None:
                return "/Common/f5-tcp-wan"
            return topo_outboundl2_tcp_server
        except:
            return "/Common/f5-tcp-wan"

    @property
    def topo_outboundl2_L7profiletype(self):
        try:
            topo_outboundl2_L7profiletype = self._values['topologyOutboundL2']['L7ProfileType']
            if topo_outboundl2_L7profiletype == None:
                return None
            return topo_outboundl2_L7profiletype
        except:
            return None

    @property
    def topo_outboundl2_L7profile(self):
        try:
            topo_outboundl2_L7profile = self._values['topologyOutboundL2']['L7Profile']
            if topo_outboundl2_L7profile == None:
                return None
            return topo_outboundl2_L7profile
        except:
            return None

    @property
    def topo_outboundl2_accessprofile(self):
        try:
            topo_outboundl2_accessprofile = self._values['topologyOutboundL2']['accessProfile']
            if topo_outboundl2_accessprofile == None:
                return None
            return topo_outboundl2_accessprofile
        except:
            return None

    @property
    def topo_outboundl2_profilescope(self):
        try:
            topo_outboundl2_profilescope = self._values['topologyOutboundL2']['profileScope']
            if topo_outboundl2_profilescope == None:
                return "public"
            return topo_outboundl2_profilescope
        except:
            return "public"

    @property
    def topo_outboundl2_profilescopevalue(self):
        try:
            topo_outboundl2_profilescopevalue = self._values['topologyOutboundL2']['profileScopeValue']
            if topo_outboundl2_profilescopevalue == None:
                return None
            return topo_outboundl2_profilescopevalue
        except:
            return None

    @property
    def topo_outboundl2_primaryauthuri(self):
        try:
            topo_outboundl2_primaryauthuri = self._values['topologyOutboundL2']['primaryAuthUri']
            if topo_outboundl2_primaryauthuri == None:
                return None
            return topo_outboundl2_primaryauthuri
        except:
            return None

    @property
    def topo_outboundl2_ocspAuth(self):
        try:
            topo_outboundl2_ocspAuth = self._values['topologyOutboundL2']['ocspAuth']
            if topo_outboundl2_ocspAuth == None:
                return None
            return topo_outboundl2_ocspAuth
        except:
            return None

    @property
    def topo_outboundl2_verifyAccept(self):
        try:
            topo_outboundl2_verifyAccept = self._values['topologyOutboundL2']['verifyAccept']
            if topo_outboundl2_verifyAccept == None:
                return False
            return topo_outboundl2_verifyAccept
        except:
            return False


    # Inbound L2 Topology

    @property
    def topo_inboundl2(self):
        try:
            topo_inboundl2 = self._values['topologyInboundL2']
            if topo_inboundl2 == None:
                return False
            return True
        except:
            return False

    @property
    def topo_inboundl2_proto(self):
        try:
            topo_inboundl2_proto = self._values['topologyInboundL2']['protocol']
            if topo_inboundl2_proto == None:
                return "tcp"
            return topo_inboundl2_proto
        except:
            return "tcp"

    @property
    def topo_inboundl2_ipfamily(self):
        try:
            topo_inboundl2_ipfamily = self._values['topologyInboundL2']['ipFamily']
            if topo_inboundl2_ipfamily == None:
                return "ipv4"
            return topo_inboundl2_ipfamily
        except:
            return "ipv4"

    @property
    def topo_inboundl2_source(self):
        try:
            topo_inboundl2_source = self._values['topologyInboundL2']['source']
            if topo_inboundl2_source == None:
                return "0.0.0.0%0/0"
            return topo_inboundl2_source
        except:
            return "0.0.0.0%0/0"

    @property
    def topo_inboundl2_dest(self):
        try:
            topo_inboundl2_dest = self._values['topologyInboundL2']['dest']
            if topo_inboundl2_dest == None:
                return "0.0.0.0%0/0"
            return topo_inboundl2_dest
        except:
            return "0.0.0.0%0/0"

    @property
    def topo_inboundl2_port(self):
        try:
            topo_inboundl2_port = self._values['topologyInboundL2']['port']
            if topo_inboundl2_port == None:
                return 0
            return topo_inboundl2_port
        except:
            return 0

    @property
    def topo_inboundl2_vlans(self):
        try:
            topo_inboundl2_vlans = self._values['topologyInboundL2']['vlans']
            if topo_inboundl2_vlans == None:
                return None
            return topo_inboundl2_vlans
        except:
            return None

    @property
    def topo_inboundl2_tcp_client(self):
        try:
            topo_inboundl2_tcp_client = self._values['topologyInboundL2']['tcpSettingsClient']
            if topo_inboundl2_tcp_client == None:
                return "/Common/f5-tcp-wan"
            return topo_inboundl2_tcp_client
        except:
            return "/Common/f5-tcp-wan"

    @property
    def topo_inboundl2_tcp_server(self):
        try:
            topo_inboundl2_tcp_server = self._values['topologyInboundL2']['tcpSettingsServer']
            if topo_inboundl2_tcp_server == None:
                return "/Common/f5-tcp-lan"
            return topo_inboundl2_tcp_server
        except:
            return "/Common/f5-tcp-lan"

    @property
    def topo_inboundl2_L7profiletype(self):
        try:
            topo_inboundl2_L7profiletype = self._values['topologyInboundL2']['L7ProfileType']
            if topo_inboundl2_L7profiletype == None:
                return "http"
            return topo_inboundl2_L7profiletype
        except:
            return "http"

    @property
    def topo_inboundl2_L7profile(self):
        try:
            topo_inboundl2_L7profile = self._values['topologyInboundL2']['L7Profile']
            if topo_inboundl2_L7profile == None:
                return "/Common/http"
            return topo_inboundl2_L7profile
        except:
            return "/Common/http"

    @property
    def topo_inboundl2_accessprofile(self):
        try:
            topo_inboundl2_accessprofile = self._values['topologyInboundL2']['accessProfile']
            if topo_inboundl2_accessprofile == None:
                return None
            return topo_inboundl2_accessprofile
        except:
            return None


    # Logging

    @property
    def logging_sslo(self):
        try:
            logging_sslo = self._values['logging']['sslo']
            if logging_sslo == None:
                return "error"
            return logging_sslo
        except:
            return "error"

    @property
    def logging_prp(self):
        try:
            logging_prp = self._values['logging']['perRequestPolicy']
            if logging_prp == None:
                return "error"
            return logging_prp
        except:
            return "error"

    @property
    def logging_ftp(self):
        try:
            logging_ftp = self._values['logging']['ftp']
            if logging_ftp == None:
                return "error"
            return logging_ftp
        except:
            return "error"

    @property
    def logging_imap(self):
        try:
            logging_imap = self._values['logging']['imap']
            if logging_imap == None:
                return "error"
            return logging_imap
        except:
            return "error"

    @property
    def logging_pop3(self):
        try:
            logging_pop3 = self._values['logging']['pop3']
            if logging_pop3 == None:
                return "error"
            return logging_pop3
        except:
            return "error"

    @property
    def logging_smtps(self):
        try:
            logging_smtps = self._values['logging']['smtps']
            if logging_smtps == None:
                return "error"
            return logging_smtps
        except:
            return "error"


    # Mode

    @property
    def mode(self):
        mode = self._values['mode']
        return mode


class ModuleManager(object):
    global print_output
    global json_template
    global obj_attempts
    global min_version
    global max_version


    def __init__(self, *args, **kwargs):
        self.module = kwargs.pop('module', None)
        self.client = F5RestClient(**self.module.params)
        self.want = ModuleParameters(params=self.module.params)


    def getSsloVersion(self):
        ## use this method to get the SSLO version (first two digits (x.y))
        uri = "https://{0}:{1}/mgmt/shared/iapp/installed-packages".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        try:
            resp = self.client.api.get(uri).json()
            for x in resp["items"]:
                if x["appName"] == "f5-iappslx-ssl-orchestrator":
                    tmpversion = x["release"].split(".")
                    version = tmpversion[0] + "." + tmpversion[1]
                    return float(version)
                    break
        except:
            raise F5ModuleError("SSL Orchestrator package does not appear to be installed. Aborting.")
    

    def deleteOperation(self, id):
        ## use this method to delete an operation that failed
        uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/{2}".format(
            self.client.provider['server'],
            self.client.provider['server_port'],
            id
        )
        resp = self.client.api.delete(uri)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            return True
        else:
            return False


    def getIpFamily(self,ipaddr):
        ## use this method to get the ip family
        try:
            ip = ipaddress.ip_address(ipaddr)
            return(ip.version)
        except ValueError:
            return(1)


    def ssloGS_global_fetch(self):
        ## use this method to get the existing ssloGS_global config (for SSLO 5.x) and import into the topology config
        uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        query = "?$filter=name+eq+'ssloGS_global'"
        resp = self.client.api.get(uri + query)

        try:
            if len(resp.json()["items"]) > 0:
                ## ssloGS_global exists - send value back
                response = resp.json()
                response = response["items"][0]["inputProperties"][0]["value"]
                return response
        except:
            return None
        
    
    def logFacilityConverter(self,value):
        ## use this method to convert Ansible log facility inputs to required inputs
        facility = {
            "emergency":"emerg",
            "alert":"alert",
            "critical":"crit",
            "warning":"warn",
            "error":"err",
            "notice":"notice",
            "information":"info",
            "debug":"debug"
        }
        return facility.get(value)


    def update_json(self, operation):

        ## use this to method to create and return a modified copy of the JSON template
        self.config = json_template

        ## get base name
        self.local_name = re.sub('sslo_', '', self.want.name)

        ## perform some general input validation


        ## process general json settings for all operations
        self.config["inputProperties"][0]["value"]["deploymentName"] = self.want.name
        self.config["inputProperties"][0]["value"]["operationType"] = operation
        self.config["inputProperties"][1]["value"]["name"] = self.want.name

        ## accessProfileScope, accessProfileNameScopeValue, and primaryAuthenticationURI only exist in 8.2 and above
        if self.ssloVersion < 8.2:
            del self.config["inputProperties"][1]["value"]["accessProfileScope"]
            del self.config["inputProperties"][1]["value"]["accessProfileNameScopeValue"]
            del self.config["inputProperties"][1]["value"]["primaryAuthenticationURI"]

        ## authProfile added in 6.2
        if self.ssloVersion < 6.2:
            del self.config["inputProperties"][1]["value"]["authProfile"]

        ## loggingConfig only exists in 6.0 and above
        if self.ssloVersion < 6.0:
            del self.config["inputProperties"][1]["value"]["loggingConfig"]
        else:
            if self.want.logging_sslo != None:
                self.config["inputProperties"][1]["value"]["loggingConfig"]["sslOrchestrator"] = self.logFacilityConverter(self.want.logging_sslo)
            if self.want.logging_prp != None:
                self.config["inputProperties"][1]["value"]["loggingConfig"]["perRequestPolicy"] = self.logFacilityConverter(self.want.logging_prp)
            if self.want.logging_ftp != None:
                self.config["inputProperties"][1]["value"]["loggingConfig"]["ftp"] = self.logFacilityConverter(self.want.logging_ftp)
            if self.want.logging_imap != None:
                self.config["inputProperties"][1]["value"]["loggingConfig"]["imap"] = self.logFacilityConverter(self.want.logging_imap)
            if self.want.logging_pop3 != None:
                self.config["inputProperties"][1]["value"]["loggingConfig"]["pop3"] = self.logFacilityConverter(self.want.logging_pop3)
            if self.want.logging_smtps != None:
                self.config["inputProperties"][1]["value"]["loggingConfig"]["smtps"] = self.logFacilityConverter(self.want.logging_smtps)
        
        ## define SNAT
        if self.want.topo_outboundl3 == True:
            self.snat = self.want.topo_outboundl3_snat
            self.snatlist = self.want.topo_outboundl3_snatlist
            self.snatpool = self.want.topo_outboundl3_snatpool
            self.ipfamily = self.want.topo_outboundl3_ipfamily
        elif self.want.topo_outboundxp == True:
            self.snat = self.want.topo_outboundxp_snat
            self.snatlist = self.want.topo_outboundxp_snatlist
            self.snatpool = self.want.topo_outboundxp_snatpool
            self.ipfamily = self.want.topo_outboundxp_ipfamily
        elif self.want.topo_inboundl3 == True:
            self.snat = self.want.topo_inboundl3_snat
            self.snatlist = self.want.topo_inboundl3_snatlist
            self.snatpool = self.want.topo_inboundl3_snatpool
            self.ipfamily = self.want.topo_inboundl3_ipfamily
        elif self.want.topo_outboundl2 == True:
            self.snat = None
        elif self.want.topo_inboundl2 == True:
            self.snat = None

        if self.snat != None:
            ## input validation: snatpool and snatlist cannot both be defined
            if self.snatpool != None and self.snatlist != None:
                raise F5ModuleError("SNAT cannot define a snatpool and snatlist at the same time.")

            ## input validation: if snat == snatpool, a snatpool must be defined
            if self.snat == "snatpool" and self.snatpool == None:
                raise F5ModuleError("SNAT set to snatpool must also have a snatpool defined.")

            ## input validation: if snat == snalist, a snatlist must be defined
            if self.snat == "snatlist" and self.snatlist == None:
                raise F5ModuleError("SNAT set to snatlist must also have a snatlist defined.")

            if self.snat == "none":
                self.config["inputProperties"][1]["value"]["egressNetwork"]["clientSnat"] = "None"
                self.config["inputProperties"][1]["value"]["egressNetwork"]["snat"]["referredObj"] = ""
            elif self.snat == "automap":
                self.config["inputProperties"][1]["value"]["egressNetwork"]["clientSnat"] = "AutoMap"
                self.config["inputProperties"][1]["value"]["egressNetwork"]["snat"]["referredObj"] = ""
            elif self.snat == "snatlist":
                self.config["inputProperties"][1]["value"]["egressNetwork"]["clientSnat"] = "SNAT"
                self.config["inputProperties"][1]["value"]["egressNetwork"]["snat"]["referredObj"] = ""
                self.this_snatlist = []
                for key in self.snatlist:
                    self.this_snatlist.append({"ip":"" + key + ""})
                if self.ipfamily == "ipv4":
                    self.config["inputProperties"][1]["value"]["egressNetwork"]["snat"]["ipv4SnatAddresses"] = self.this_snatlist
                elif self.want.ipfamily == "ipv6":
                    self.config["inputProperties"][1]["value"]["egressNetwork"]["snat"]["ipv6SnatAddresses"] = self.this_snatlist                        
            elif self.snat == "snatpool":
                self.config["inputProperties"][1]["value"]["egressNetwork"]["clientSnat"] = "existingSNAT"
                self.config["inputProperties"][1]["value"]["egressNetwork"]["snat"]["referredObj"] = self.snatpool        

        ## define gateway
        if self.want.topo_outboundl3 == True:
            self.gw = self.want.topo_outboundl3_gateway
            self.gwlist = self.want.topo_outboundl3_gatewaylist
            self.gwpool = self.want.topo_outboundl3_gatewaypool
            self.ipfamily = self.want.topo_outboundl3_ipfamily
        elif self.want.topo_outboundxp == True:
            self.gw = self.want.topo_outboundxp_gateway
            self.gwlist = self.want.topo_outboundxp_gatewaylist
            self.gwpool = self.want.topo_outboundxp_gatewaypool
            self.ipfamily = self.want.topo_outboundxp_ipfamily
        elif self.want.topo_inboundl3 == True:
            self.gw = self.want.topo_inboundl3_gateway
            self.gwlist = self.want.topo_inboundl3_gatewaylist
            self.gwpool = self.want.topo_inboundl3_gatewaypool
            self.ipfamily = self.want.topo_inboundl3_ipfamily
        elif self.want.topo_outboundl2 == True:
            self.gw = None
        elif self.want.topo_inboundl2 == True:
            self.gw = None

        ## input validation: if gw == pool, gwpool must also be defined
        if self.gw == "pool" and self.gwpool == None:
            raise F5ModuleError("Gateway set to pool but no gateway pool defined.")

        ## input validation: if gw == iplist, gwlist must also be defined
        if self.gw == "iplist" and self.gwlist == None:
            raise F5ModuleError("Gateway set to iplist but no gateway IP addresses defined.")

        if self.gw == "system":
            self.config["inputProperties"][1]["value"]["egressNetwork"]["gatewayOptions"] = "useDefault"
        if self.gw == "pool":
            self.config["inputProperties"][1]["value"]["egressNetwork"]["gatewayOptions"] = "existingGatewayPool"
            self.config["inputProperties"][1]["value"]["egressNetwork"]["outboundGateways"]["referredObj"] = self.gwpool
        if self.gw == "iplist":
            self.config["inputProperties"][1]["value"]["egressNetwork"]["gatewayOptions"] = "newGatewayPool"
            for gw in self.gwlist:
                if "ratio" not in gw:
                    gw["ratio"] = 1
                if "ip" not in gw:
                    raise F5ModuleError("A gateway IP list must minimally contain an 'ip' key.")
                if self.ipfamily == "ipv4":
                    self.config["inputProperties"][1]["value"]["egressNetwork"]["outboundGateways"]["ipv4OutboundGateways"].append(gw)
                elif self.ipfamily == "ipv6":
                    self.config["inputProperties"][1]["value"]["egressNetwork"]["outboundGateways"]["ipv6OutboundGateways"].append(gw)
        

        ## add 9.0+ keys (verifyAccept, dnsResolver, ocspAuth)
        if self.ssloVersion >= 9.0:
            self.config["inputProperties"][1]["value"]["ocspAuth"] = ""
            self.config["inputProperties"][1]["value"]["proxySettings"]["tcpProfile"] = {}
            self.config["inputProperties"][1]["value"]["proxySettings"]["tcpProfile"]["verifyAccept"] = False


        ## =================================
        ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
        ## =================================
        self.config["inputProperties"][0]["value"]["version"] = self.ssloVersion
        self.config["inputProperties"][1]["value"]["version"] = self.ssloVersion
        self.config["inputProperties"][1]["value"]["previousVersion"] = self.ssloVersion


        ## format json based on topology defined
        
        ## =================================
        ## OUTBOUND L3 TOPOLOGY
        ## =================================
        if self.want.topo_outboundl3 == True:

            ## input validation: a tcp protocol outboundl3 topology requires the sslSettings key
            if (self.want.configref_ssl == None) and (self.want.topo_outboundl3_proto == "tcp"):
                raise F5ModuleError("The Outbound L3 topology for TCP traffic requires an sslSettings key.")

            ## input validation: a udp protocol outboundl3 topology cannot have the sslSettings key
            if (self.want.configref_ssl != None) and (self.want.topo_outboundl3_proto == "udp"):
                raise F5ModuleError("The Outbound L3 topology for UDP traffic cannot contain an sslSettings key.")

            ## input validation: an other protocol outboundl3 topology cannot have the sslSettings key
            if (self.want.configref_ssl != None) and (self.want.topo_outboundl3_proto == "other"):
                raise F5ModuleError("The Outbound L3 topology for non-TCP/non-UDP traffic cannot contain an sslSettings key.")

            ## input validation: an other protocol outboundl3 topology cannot have the securityPolicy key
            if (self.want.configref_policy != None) and (self.want.topo_outboundl3_proto == "other"):
                raise F5ModuleError("The Outbound L3 topology for non-TCP/non-UDP traffic cannot contain a securityPolicy key.")

            ## input validation: the additionalprotocols key can only be used with outboundl3 TCP
            if (self.want.topo_outboundl3_proto != "tcp") and (self.want.topo_outboundl3_additionalprotocols != None):
                raise F5ModuleError("The additionalProtocols key can only be used with TCP traffic.")

            ## input validation: the additionalprotocols key can only contain "ftp", "imap", "pop3", and "smtps"
            if (self.want.topo_outboundl3_proto == "tcp") and (self.want.topo_outboundl3_additionalprotocols != None):
                for proto in self.want.topo_outboundl3_additionalprotocols:
                    if proto not in {"ftp","imap","pop3","smtps"}:
                        raise F5ModuleError("Acceptable values for the additionalProtocols key are 'ftp', 'imap', 'pop3', and 'smtps'. Received: \'" + str(proto) + "\'")

            ## input validation: profileScopeValue, and primaryAuthUri require TCP
            if (self.want.topo_outboundl3_proto != "tcp") and (self.want.topo_outboundl3_profilescopevalue != None):
                raise F5ModuleError("The profileScopeValue key can only be used with an outbound L3 TCP topology.")
            if (self.want.topo_outboundl3_proto != "tcp") and (self.want.topo_outboundl3_primaryauthuri != None):
                raise F5ModuleError("The primaryAuthUri key can only be used with an outbound L3 TCP topology.")

            ## input validation: if profileScope == named, profileScopeValue and primaryAuthUri must also be defined (not None)
            if (self.want.topo_outboundl3_profilescope == "named") and (self.want.topo_outboundl3_profilescopevalue == None):
                raise F5ModuleError("When the profileScope key is set to 'named', the profileScopeValue and primaryAuthUri values must also be set.")
            if (self.want.topo_outboundl3_profilescope == "named") and (self.want.topo_outboundl3_primaryauthuri == None):
                raise F5ModuleError("When the profileScope key is set to 'named', the profileScopeValue and primaryAuthUri values must also be set.")

            ## input validation: source and dest must be in the same ipFamily
            source = re.sub('/.*', '', re.sub('%.*', '', self.want.topo_outboundl3_source))
            dest = re.sub('/.*', '', re.sub('%.*', '', self.want.topo_outboundl3_dest))
            if self.getIpFamily(source) != self.getIpFamily(dest):
                raise F5ModuleError("Source and destination addresses must be in the same IP family.")

            ## input validation: source must include subnet
            try:
                m = re.search('^.*/(\d+)$', self.want.topo_outboundl3_source)
                if int(m.group(1)) > 32:
                    raise F5ModuleError("Source address must contain a subnet (CIDR) value <= 32.")
            except AttributeError:
                raise F5ModuleError("Source address must contain a subnet (CIDR) value <= 32.")

            ## input validation: source address must contain a route domain - if it doesn't, auto-add %0
            m = re.search('^.*%(\d+).*$', self.want.topo_outboundl3_source)            
            try:
                tmp = m.group(1)
                self.source = self.want.topo_outboundl3_source
            except:
                iplist = self.want.topo_outboundl3_source.split("/")
                iplist[0] = re.sub('%.*', '', iplist[0])
                self.source = iplist[0] + "%0/" + iplist[1]

            ## input validation: destination must include subnet
            try:
                m = re.search('^.*/(\d+)$', self.want.topo_outboundl3_dest)
                if int(m.group(1)) > 32:
                    raise F5ModuleError("Destination address must contain a subnet (CIDR) value <= 32.")
            except AttributeError:
                raise F5ModuleError("Destination address must contain a subnet (CIDR) value <= 32.")

            ## input validation: destination address must contain a route domain - if it doesn't, auto-add %0
            m = re.search('^.*%(\d+).*$', self.want.topo_outboundl3_dest)            
            try:
                tmp = m.group(1)
                self.dest = self.want.topo_outboundl3_dest
            except:
                iplist = self.want.topo_outboundl3_dest.split("/")
                iplist[0] = re.sub('%.*', '', iplist[0])
                self.dest = iplist[0] + "%0/" + iplist[1]

            ## input validation: source port must be an integer between 0 and 65535
            if self.want.topo_outboundl3_port >= 0 and self.want.topo_outboundl3_port <= 65535:
                self.port = self.want.topo_outboundl3_port
            else:
                raise F5ModuleError("A defined port must be an integer between 0 and 65535.")

            ## input validation: vlan key must contain at least one entry
            if self.want.topo_outboundl3_vlans == None:
                raise F5ModuleError("At least one VLAN must be defined.")


            ## update json for outbound L3 topology - basic settings
            self.config["inputProperties"][1]["value"]["type"] = "topology_l3_outbound"
            self.config["inputProperties"][1]["value"]["ruleType"] = "Outbound"
            self.config["inputProperties"][1]["value"]["ruleLabel"] = "Outbound"
            self.config["inputProperties"][1]["value"]["proxySettings"]["proxyType"] = "transparent"
            self.config["inputProperties"][1]["value"]["ipFamily"] = self.want.topo_outboundl3_ipfamily

            ## update json for outbound L3 topology - serviceDef
            self.config["inputProperties"][1]["value"]["serviceDef"]["source"] = self.source
            self.config["inputProperties"][1]["value"]["serviceDef"]["destination"]["protocol"] = self.want.topo_outboundl3_proto
            self.config["inputProperties"][1]["value"]["serviceDef"]["destination"]["address"] = self.dest
            self.config["inputProperties"][1]["value"]["serviceDef"]["destination"]["port"] = self.port
            
            ## update json for outbound L3 topology - L7Protocols
            if self.want.topo_outboundl3_additionalprotocols != None:
                for proto in self.want.topo_outboundl3_additionalprotocols:
                    protolist = {}
                    protolist["name"] = proto.upper()
                    protolist["value"] = proto
                    self.config["inputProperties"][1]["value"]["l7Protocols"].append(protolist)

            ## update json for outbound L3 topology - tcp profile settings
            if self.want.topo_outboundl3_tcp_client != None:
                self.config["inputProperties"][1]["value"]["tcpSettings"]["clientTcpProfile"] = self.want.topo_outboundl3_tcp_client
            if self.want.topo_outboundl3_tcp_server != None:
                self.config["inputProperties"][1]["value"]["tcpSettings"]["serverTcpProfile"] = self.want.topo_outboundl3_tcp_server

            ## update json for outbound L3 topology - vlans
            for vlan in self.want.topo_outboundl3_vlans:
                vlanlist = {}
                vlanlist["name"] = vlan
                vlanlist["value"] = vlan
                self.config["inputProperties"][1]["value"]["ingressNetwork"]["vlans"].append(vlanlist)

            ## update json for outbound L3 topology - L7Profile and L7Profiletype
            if self.want.topo_outboundl3_L7profiletype != "none":
                self.config["inputProperties"][1]["value"]["l7ProfileType"] = self.want.topo_outboundl3_L7profiletype
            else:
                self.config["inputProperties"][1]["value"]["l7ProfileType"] = ""
            if self.want.topo_outboundl3_L7profile != None:
                self.config["inputProperties"][1]["value"]["l7Profile"] = self.want.topo_outboundl3_L7profile

            ## update json for outbound L3 topology - profileScope, profileScopeValue, and primaryAuthenticationUri (if SSLO >= 8.2)
            if self.ssloVersion >= 8.2:
                if self.want.topo_outboundl3_profilescope != None:
                    self.config["inputProperties"][1]["value"]["accessProfileScope"] = self.want.topo_outboundl3_profilescope
                if self.want.topo_outboundl3_profilescopevalue != None:
                    self.config["inputProperties"][1]["value"]["accessProfileNameScopeValue"] = self.want.topo_outboundl3_profilescopevalue
                if self.want.topo_outboundl3_primaryauthuri != None:
                    self.config["inputProperties"][1]["value"]["primaryAuthenticationURI"] = self.want.topo_outboundl3_primaryauthuri

            ## update json for outbound L3 topology - accessprofile
            if self.want.topo_outboundl3_accessprofile != None:
                self.config["inputProperties"][1]["value"]["accessProfile"] = self.want.topo_outboundl3_accessprofile
            else:
                self.config["inputProperties"][1]["value"]["accessProfile"] = self.want.name + "_accessProfile"


            ## =================================
            ## 9.0 Update: verifyAccept
            ## =================================
            if self.ssloVersion >= 9.0:
                self.config["inputProperties"][1]["value"]["proxySettings"]["tcpProfile"]["verifyAccept"] = self.want.topo_outboundl3_verifyAccept


        ## =================================
        ## OUTBOUND EXPLICIT TOPOLOGY
        ## =================================
        elif self.want.topo_outboundxp == True:
            pass
            
            ## input validation: source and proxyip must be in the same ipFamily
            source = re.sub('/.*', '', re.sub('%.*', '', self.want.topo_outboundxp_source))
            dest = re.sub('/.*', '', re.sub('%.*', '', self.want.topo_outboundxp_proxyip))
            
            if self.getIpFamily(source) != self.getIpFamily(dest):
                raise F5ModuleError("Source and proxy addresses must be in the same IP family.")

            ## input validation: source must include subnet
            try:
                m = re.search('^.*/(\d+)$', self.want.topo_outboundxp_source)
                if int(m.group(1)) > 32:
                    raise F5ModuleError("Source address must contain a subnet (CIDR) value <= 32.")
            except AttributeError:
                raise F5ModuleError("Source address must contain a subnet (CIDR) value <= 32.")

            ## input validation: source address must contain a route domain - if it doesn't, auto-add %0
            m = re.search('^.*%(\d+).*$', self.want.topo_outboundxp_source)            
            try:
                tmp = m.group(1)
                self.source = self.want.topo_outboundxp_source
            except:
                iplist = self.want.topo_outboundxp_source.split("/")
                iplist[0] = re.sub('%.*', '', iplist[0])
                self.source = iplist[0] + "%0/" + iplist[1]
                
            ## input validation: vlan key must contain at least one entry
            if self.want.topo_outboundxp_vlans == None:
                raise F5ModuleError("At least one VLAN must be defined.")


            ## update json for outbound explicit topology - basic settings
            self.config["inputProperties"][1]["value"]["type"] = "topology_l3_explicit_proxy"
            self.config["inputProperties"][1]["value"]["ruleType"] = "Outbound"
            self.config["inputProperties"][1]["value"]["ruleLabel"] = "Outbound"
            self.config["inputProperties"][1]["value"]["proxySettings"]["proxyType"] = "explicit"
            self.config["inputProperties"][1]["value"]["tcpSettings"]["clientTcpProfile"] = ""
            self.config["inputProperties"][1]["value"]["tcpSettings"]["serverTcpProfile"] = ""
            self.config["inputProperties"][1]["value"]["ipFamily"] = self.want.topo_outboundxp_ipfamily

            ## update json for outbound explicit topology - serviceDef
            self.config["inputProperties"][1]["value"]["serviceDef"]["source"] = self.source
            self.config["inputProperties"][1]["value"]["serviceDef"]["destination"]["protocol"] = "tcp"
            self.config["inputProperties"][1]["value"]["serviceDef"]["destination"]["address"] = "0.0.0.0%0/0"
            self.config["inputProperties"][1]["value"]["serviceDef"]["destination"]["port"] = 0

            ## update json for outbound explicit topology - vlans
            for vlan in self.want.topo_outboundxp_vlans:
                vlanlist = {}
                vlanlist["name"] = vlan
                vlanlist["value"] = vlan
                self.config["inputProperties"][1]["value"]["ingressNetwork"]["vlans"].append(vlanlist)

            ## update json for outbound explicit topology - proxyip and proxyport
            if self.want.topo_outboundxp_ipfamily == "ipv4":
                self.config["inputProperties"][1]["value"]["proxySettings"]["forwardProxy"]["explicitProxy"]["ipv4Address"] = self.want.topo_outboundxp_proxyip
                self.config["inputProperties"][1]["value"]["proxySettings"]["forwardProxy"]["explicitProxy"]["ipv4Port"] = self.want.topo_outboundxp_proxyport
            elif self.want.topo_outboundxp_ipfamily == "ipv6":
                self.config["inputProperties"][1]["value"]["proxySettings"]["forwardProxy"]["explicitProxy"]["ipv6Address"] = self.want.topo_outboundxp_proxyip
                self.config["inputProperties"][1]["value"]["proxySettings"]["forwardProxy"]["explicitProxy"]["ipv6Port"] = self.want.topo_outboundxp_proxyport

            ## update json for outbound explicit topology - accessprofile
            self.config["inputProperties"][1]["value"]["accessProfile"] = self.want.name + "_accessProfile"

            ## update json for outbound explicit topology - authprofile
            if self.want.topo_outboundxp_authprofile != None:
                self.config["inputProperties"][1]["value"]["authProfile"] = self.want.topo_outboundxp_authprofile


            ## =================================
            ## 9.0 Update: verifyAccept
            ## =================================
            if self.ssloVersion >= 9.0:
                self.config["inputProperties"][1]["value"]["proxySettings"]["tcpProfile"]["verifyAccept"] = self.want.topo_outboundxp_verifyAccept

            ## =================================
            ## 9.0 Update: add httpProfile value
            ## =================================
            if self.ssloVersion >= 9.0:
                self.config["inputProperties"][1]["value"]["httpProfile"] = "/Common/" + self.want.name + ".app/" + self.want.name + "-xp-http"

            ## =================================
            ## 9.0 Update: dnsResolver (required in 9.0)
            ## =================================
            if self.ssloVersion >= 9.0 and self.want.topo_outboundxp_dnsResolver != None and self.want.topo_outboundxp_dnsResolver != "":
                self.config["inputProperties"][1]["value"]["dnsResolver"] = self.want.topo_outboundxp_dnsResolver
            #else:
            #    raise F5ModuleError("An outbound explicit proxy topology in 9.0+ requires a dnsResolver value. Aborting")


        ## =================================
        ## INBOUND L3 TOPOLOGY
        ## =================================
        elif self.want.topo_inboundl3 == True:

            ## input validation: pool, gateway|gatewaylist|gatewaypool are mutually exclusive
            if (self.want.topo_inboundl3_pool != None) and (self.want.topo_inboundl3_gateway != "system"):
                raise F5ModuleError("An inbound L3 topology can have a pool assigned, or a gateway, but not both.")
            if (self.want.topo_inboundl3_pool != None) and (self.want.topo_inboundl3_gatewaylist != None):
                raise F5ModuleError("An inbound L3 topology can have a pool assigned, or a gateway, but not both.")
            if (self.want.topo_inboundl3_pool != None) and (self.want.topo_inboundl3_gatewaypool != None):
                raise F5ModuleError("An inbound L3 topology can have a pool assigned, or a gateway, but not both.")

            ## input validation: if pool assigned, dest cannot be 0.0.0.0
            if (self.want.topo_inboundl3_pool != None) and (self.want.topo_inboundl3_dest != None) and ("0.0.0.0" in self.want.topo_inboundl3_dest):
                raise F5ModuleError("An inbound L3 topology with a pool assigned must also have a destination address defined, and cannot be a wildcard (0.0.0.0) address.")

            ## input validation: source and dest must be in the same ipFamily
            source = re.sub('/.*', '', re.sub('%.*', '', self.want.topo_inboundl3_source))
            dest = re.sub('/.*', '', re.sub('%.*', '', self.want.topo_inboundl3_dest))
            if self.getIpFamily(source) != self.getIpFamily(dest):
                raise F5ModuleError("Source and destination addresses must be in the same IP family.")

            ## input validation: source must include subnet
            try:
                m = re.search('^.*/(\d+)$', self.want.topo_inboundl3_source)
                if int(m.group(1)) > 32:
                    raise F5ModuleError("Source address must contain a subnet (CIDR) value <= 32.")
            except AttributeError:
                raise F5ModuleError("Source address must contain a subnet (CIDR) value <= 32.")

            ## input validation: source address must contain a route domain - if it doesn't, auto-add %0
            m = re.search('^.*%(\d+).*$', self.want.topo_inboundl3_source)            
            try:
                tmp = m.group(1)
                self.source = self.want.topo_inboundl3_source
            except:
                iplist = self.want.topo_inboundl3_source.split("/")
                iplist[0] = re.sub('%.*', '', iplist[0])
                self.source = iplist[0] + "%0/" + iplist[1]

            ## input validation: destination must include subnet
            try:
                m = re.search('^.*/(\d+)$', self.want.topo_inboundl3_dest)
                if int(m.group(1)) > 32:
                    raise F5ModuleError("Destination address must contain a subnet (CIDR) value <= 32.")
            except AttributeError:
                raise F5ModuleError("Destination address must contain a subnet (CIDR) value <= 32.")

            ## input validation: destination address must contain a route domain - if it doesn't, auto-add %0
            m = re.search('^.*%(\d+).*$', self.want.topo_inboundl3_dest)            
            try:
                tmp = m.group(1)
                self.dest = self.want.topo_inboundl3_dest
            except:
                iplist = self.want.topo_inboundl3_dest.split("/")
                iplist[0] = re.sub('%.*', '', iplist[0])
                self.dest = iplist[0] + "%0/" + iplist[1]

            ## input validation: source port must be an integer between 0 and 65535
            if self.want.topo_outboundl3_port >= 0 and self.want.topo_outboundl3_port <= 65535:
                self.port = self.want.topo_outboundl3_port
            else:
                raise F5ModuleError("A defined port must be an integer between 0 and 65535.")

            ## input validation: vlan key must contain at least one entry
            if self.want.topo_inboundl3_vlans == None:
                raise F5ModuleError("At least one VLAN must be defined.")


            ## update json for inbound L3 topology - basic settings
            self.config["inputProperties"][1]["value"]["type"] = "topology_l3_inbound"
            self.config["inputProperties"][1]["value"]["ruleType"] = "Inbound"
            self.config["inputProperties"][1]["value"]["ruleLabel"] = "Inbound"
            self.config["inputProperties"][1]["value"]["proxySettings"]["proxyType"] = ""
            self.config["inputProperties"][1]["value"]["ipFamily"] = self.want.topo_inboundl3_ipfamily

            ## update json for inbound L3 topology - serviceDef
            self.config["inputProperties"][1]["value"]["serviceDef"]["source"] = self.source
            self.config["inputProperties"][1]["value"]["serviceDef"]["destination"]["protocol"] = self.want.topo_inboundl3_proto
            self.config["inputProperties"][1]["value"]["serviceDef"]["destination"]["address"] = self.dest
            self.config["inputProperties"][1]["value"]["serviceDef"]["destination"]["port"] = self.port

            ## update json for inbound L3 topology - pool
            if self.want.topo_inboundl3_pool != None:
                self.config["inputProperties"][1]["value"]["pool"] = self.want.topo_inboundl3_pool

            ## update json for inbound L3 topology - tcp profile settings
            if self.want.topo_inboundl3_tcp_client != None:
                self.config["inputProperties"][1]["value"]["tcpSettings"]["clientTcpProfile"] = self.want.topo_inboundl3_tcp_client
            if self.want.topo_inboundl3_tcp_server != None:
                self.config["inputProperties"][1]["value"]["tcpSettings"]["serverTcpProfile"] = self.want.topo_inboundl3_tcp_server

            ## update json for inbound L3 topology - vlans
            for vlan in self.want.topo_inboundl3_vlans:
                vlanlist = {}
                vlanlist["name"] = vlan
                vlanlist["value"] = vlan
                self.config["inputProperties"][1]["value"]["ingressNetwork"]["vlans"].append(vlanlist)

            ## update json for outbound L3 topology - L7Profile and L7Profiletype
            if self.want.topo_inboundl3_L7profiletype != None:
                self.config["inputProperties"][1]["value"]["l7ProfileType"] = self.want.topo_inboundl3_L7profiletype
            else:
                self.config["inputProperties"][1]["value"]["l7ProfileType"] = "http"
            if self.want.topo_inboundl3_L7profile != None:
                self.config["inputProperties"][1]["value"]["l7Profile"] = self.want.topo_inboundl3_L7profile
            else:
                self.config["inputProperties"][1]["value"]["l7Profile"] = "/Common/http"

            ## update json for inbound L3 topology - accessprofile
            if self.want.topo_inboundl3_accessprofile != None:
                self.config["inputProperties"][1]["value"]["accessProfile"] = self.want.topo_inboundl3_accessprofile
            else:
                self.config["inputProperties"][1]["value"]["accessProfile"] = self.want.name + "_accessProfile"

            ## update json for inbound L3 topology - pool
            if self.want.topo_inboundl3_pool != None:
                self.config["inputProperties"][1]["value"]["pool"] = self.want.topo_inboundl3_pool


        ## =================================
        ## OUTBOUND L2 TOPOLOGY
        ## =================================
        if self.want.topo_outboundl2 == True:

            ## input validation: a tcp protocol outboundl2 topology requires the sslSettings key
            if (self.want.configref_ssl == None) and (self.want.topo_outboundl2_proto == "tcp"):
                raise F5ModuleError("The Outbound L2 topology for TCP traffic requires an sslSettings key.")

            ## input validation: a udp protocol outboundl2 topology cannot have the sslSettings key
            if (self.want.configref_ssl != None) and (self.want.topo_outboundl2_proto == "udp"):
                raise F5ModuleError("The Outbound L2 topology for UDP traffic cannot contain an sslSettings key.")

            ## input validation: an other protocol outboundl2 topology cannot have the sslSettings key
            if (self.want.configref_ssl != None) and (self.want.topo_outboundl2_proto == "other"):
                raise F5ModuleError("The Outbound L2 topology for non-TCP/non-UDP traffic cannot contain an sslSettings key.")

            ## input validation: an other protocol outboundl2 topology cannot have the securityPolicy key
            if (self.want.configref_policy != None) and (self.want.topo_outboundl2_proto == "other"):
                raise F5ModuleError("The Outbound L2 topology for non-TCP/non-UDP traffic cannot contain a securityPolicy key.")

            ## input validation: profileScopeValue, and primaryAuthUri require TCP
            if (self.want.topo_outboundl2_proto != "tcp") and (self.want.topo_outboundl2_profilescopevalue != None):
                raise F5ModuleError("The profileScopeValue key can only be used with an outbound L2 TCP topology.")
            if (self.want.topo_outboundl2_proto != "tcp") and (self.want.topo_outboundl2_primaryauthuri != None):
                raise F5ModuleError("The primaryAuthUri key can only be used with an outbound L2 TCP topology.")

            ## input validation: if profileScope == named, profileScopeValue and primaryAuthUri must also be defined (not None)
            if (self.want.topo_outboundl2_profilescope == "named") and (self.want.topo_outboundl2_profilescopevalue == None):
                raise F5ModuleError("When the profileScope key is set to 'named', the profileScopeValue and primaryAuthUri values must also be set.")
            if (self.want.topo_outboundl2_profilescope == "named") and (self.want.topo_outboundl2_primaryauthuri == None):
                raise F5ModuleError("When the profileScope key is set to 'named', the profileScopeValue and primaryAuthUri values must also be set.")

            ## input validation: source and dest must be in the same ipFamily
            source = re.sub('/.*', '', re.sub('%.*', '', self.want.topo_outboundl2_source))
            dest = re.sub('/.*', '', re.sub('%.*', '', self.want.topo_outboundl2_dest))
            if self.getIpFamily(source) != self.getIpFamily(dest):
                raise F5ModuleError("Source and destination addresses must be in the same IP family.")

            ## input validation: source must include subnet
            try:
                m = re.search('^.*/(\d+)$', self.want.topo_outboundl2_source)
                if int(m.group(1)) > 32:
                    raise F5ModuleError("Source address must contain a subnet (CIDR) value <= 32.")
            except AttributeError:
                raise F5ModuleError("Source address must contain a subnet (CIDR) value <= 32.")

            ## input validation: source address must contain a route domain - if it doesn't, auto-add %0
            m = re.search('^.*%(\d+).*$', self.want.topo_outboundl2_source)            
            try:
                tmp = m.group(1)
                self.source = self.want.topo_outboundl2_source
            except:
                iplist = self.want.topo_outboundl2_source.split("/")
                iplist[0] = re.sub('%.*', '', iplist[0])
                self.source = iplist[0] + "%0/" + iplist[1]

            ## input validation: destination must include subnet
            try:
                m = re.search('^.*/(\d+)$', self.want.topo_outboundl2_dest)
                if int(m.group(1)) > 32:
                    raise F5ModuleError("Destination address must contain a subnet (CIDR) value <= 32.")
            except AttributeError:
                raise F5ModuleError("Destination address must contain a subnet (CIDR) value <= 32.")

            ## input validation: destination address must contain a route domain - if it doesn't, auto-add %0
            m = re.search('^.*%(\d+).*$', self.want.topo_outboundl2_dest)            
            try:
                tmp = m.group(1)
                self.dest = self.want.topo_outboundl2_dest
            except:
                iplist = self.want.topo_outboundl2_dest.split("/")
                iplist[0] = re.sub('%.*', '', iplist[0])
                self.dest = iplist[0] + "%0/" + iplist[1]

            ## input validation: source port must be an integer between 0 and 65535
            if self.want.topo_outboundl2_port >= 0 and self.want.topo_outboundl2_port <= 65535:
                self.port = self.want.topo_outboundl2_port
            else:
                raise F5ModuleError("A defined port must be an integer between 0 and 65535.")

            ## input validation: vlan key must contain at least one entry
            if self.want.topo_outboundl2_vlans == None:
                raise F5ModuleError("At least one VLAN must be defined.")


            ## update json for outbound L2 topology - basic settings
            self.config["inputProperties"][1]["value"]["type"] = "topology_l2_outbound"
            self.config["inputProperties"][1]["value"]["ruleType"] = "Outbound"
            self.config["inputProperties"][1]["value"]["ruleLabel"] = "Outbound"
            self.config["inputProperties"][1]["value"]["proxySettings"]["proxyType"] = "transparent"
            self.config["inputProperties"][1]["value"]["ipFamily"] = self.want.topo_outboundl2_ipfamily

            ## update json for outbound L2 topology - serviceDef
            self.config["inputProperties"][1]["value"]["serviceDef"]["source"] = self.source
            self.config["inputProperties"][1]["value"]["serviceDef"]["destination"]["protocol"] = self.want.topo_outboundl2_proto
            self.config["inputProperties"][1]["value"]["serviceDef"]["destination"]["address"] = self.dest
            self.config["inputProperties"][1]["value"]["serviceDef"]["destination"]["port"] = self.port

            ## update json for outbound L2 topology - tcp profile settings
            if self.want.topo_outboundl2_tcp_client != None:
                self.config["inputProperties"][1]["value"]["tcpSettings"]["clientTcpProfile"] = self.want.topo_outboundl2_tcp_client
            if self.want.topo_outboundl2_tcp_server != None:
                self.config["inputProperties"][1]["value"]["tcpSettings"]["serverTcpProfile"] = self.want.topo_outboundl2_tcp_server

            ## update json for outbound L2 topology - vlans
            for vlan in self.want.topo_outboundl2_vlans:
                vlanlist = {}
                vlanlist["name"] = vlan
                vlanlist["value"] = vlan
                self.config["inputProperties"][1]["value"]["ingressNetwork"]["vlans"].append(vlanlist)

            ## update json for outbound L2 topology - L7Profile and L7Profiletype
            if self.want.topo_outboundl2_L7profiletype != "none":
                self.config["inputProperties"][1]["value"]["l7ProfileType"] = self.want.topo_outboundl2_L7profiletype
            else:
                self.config["inputProperties"][1]["value"]["l7ProfileType"] = ""
            if self.want.topo_outboundl2_L7profile != None:
                self.config["inputProperties"][1]["value"]["l7Profile"] = self.want.topo_outboundl2_L7profile

            ## update json for outbound L2 topology - profileScope, profileScopeValue, and primaryAuthenticationUri (if SSLO >= 8.2)
            if self.ssloVersion >= 8.2:
                if self.want.topo_outboundl2_profilescope != None:
                    self.config["inputProperties"][1]["value"]["accessProfileScope"] = self.want.topo_outboundl2_profilescope
                if self.want.topo_outboundl2_profilescopevalue != None:
                    self.config["inputProperties"][1]["value"]["accessProfileNameScopeValue"] = self.want.topo_outboundl2_profilescopevalue
                if self.want.topo_outboundl2_primaryauthuri != None:
                    self.config["inputProperties"][1]["value"]["primaryAuthenticationURI"] = self.want.topo_outboundl2_primaryauthuri

            ## update json for outbound L2 topology - accessprofile
            if self.want.topo_outboundl2_accessprofile != None:
                self.config["inputProperties"][1]["value"]["accessProfile"] = self.want.topo_outboundl2_accessprofile
            else:
                self.config["inputProperties"][1]["value"]["accessProfile"] = self.want.name + "_accessProfile"

            ## update json for outbound L2 topology - deployedNetwork
            self.config["inputProperties"][1]["value"]["deployedNetwork"] = "l2_network"

            ## =================================
            ## 9.0 Update: verifyAccept
            ## =================================
            if self.ssloVersion >= 9.0:
                self.config["inputProperties"][1]["value"]["proxySettings"]["tcpProfile"]["verifyAccept"] = self.want.topo_outboundl3_verifyAccept

        
        ## =================================
        ## INBOUND L2 TOPOLOGY
        ## =================================
        elif self.want.topo_inboundl2 == True:

            ## input validation: source and dest must be in the same ipFamily
            source = re.sub('/.*', '', re.sub('%.*', '', self.want.topo_inboundl2_source))
            dest = re.sub('/.*', '', re.sub('%.*', '', self.want.topo_inboundl2_dest))
            if self.getIpFamily(source) != self.getIpFamily(dest):
                raise F5ModuleError("Source and destination addresses must be in the same IP family.")

            ## input validation: source must include subnet
            try:
                m = re.search('^.*/(\d+)$', self.want.topo_inboundl2_source)
                if int(m.group(1)) > 32:
                    raise F5ModuleError("Source address must contain a subnet (CIDR) value <= 32.")
            except AttributeError:
                raise F5ModuleError("Source address must contain a subnet (CIDR) value <= 32.")

            ## input validation: source address must contain a route domain - if it doesn't, auto-add %0
            m = re.search('^.*%(\d+).*$', self.want.topo_inboundl2_source)            
            try:
                tmp = m.group(1)
                self.source = self.want.topo_inboundl2_source
            except:
                iplist = self.want.topo_inboundl2_source.split("/")
                iplist[0] = re.sub('%.*', '', iplist[0])
                self.source = iplist[0] + "%0/" + iplist[1]

            ## input validation: destination must include subnet
            try:
                m = re.search('^.*/(\d+)$', self.want.topo_inboundl2_dest)
                if int(m.group(1)) > 32:
                    raise F5ModuleError("Destination address must contain a subnet (CIDR) value <= 32.")
            except AttributeError:
                raise F5ModuleError("Destination address must contain a subnet (CIDR) value <= 32.")

            ## input validation: destination address must contain a route domain - if it doesn't, auto-add %0
            m = re.search('^.*%(\d+).*$', self.want.topo_inboundl2_dest)            
            try:
                tmp = m.group(1)
                self.dest = self.want.topo_inboundl2_dest
            except:
                iplist = self.want.topo_inboundl2_dest.split("/")
                iplist[0] = re.sub('%.*', '', iplist[0])
                self.dest = iplist[0] + "%0/" + iplist[1]

            ## input validation: source port must be an integer between 0 and 65535
            if self.want.topo_outboundl2_port >= 0 and self.want.topo_outboundl2_port <= 65535:
                self.port = self.want.topo_outboundl2_port
            else:
                raise F5ModuleError("A defined port must be an integer between 0 and 65535.")

            ## input validation: vlan key must contain at least one entry
            if self.want.topo_inboundl2_vlans == None:
                raise F5ModuleError("At least one VLAN must be defined.")


            ## update json for inbound L2 topology - basic settings
            self.config["inputProperties"][1]["value"]["type"] = "topology_l2_inbound"
            self.config["inputProperties"][1]["value"]["ruleType"] = "Inbound"
            self.config["inputProperties"][1]["value"]["ruleLabel"] = "Inbound"
            self.config["inputProperties"][1]["value"]["proxySettings"]["proxyType"] = ""
            self.config["inputProperties"][1]["value"]["ipFamily"] = self.want.topo_inboundl2_ipfamily

            ## update json for inbound L2 topology - serviceDef
            self.config["inputProperties"][1]["value"]["serviceDef"]["source"] = self.source
            self.config["inputProperties"][1]["value"]["serviceDef"]["destination"]["protocol"] = self.want.topo_inboundl2_proto
            self.config["inputProperties"][1]["value"]["serviceDef"]["destination"]["address"] = self.dest
            self.config["inputProperties"][1]["value"]["serviceDef"]["destination"]["port"] = self.port

            ## update json for inbound L2 topology - tcp profile settings
            if self.want.topo_inboundl2_tcp_client != None:
                self.config["inputProperties"][1]["value"]["tcpSettings"]["clientTcpProfile"] = self.want.topo_inboundl2_tcp_client
            if self.want.topo_inboundl2_tcp_server != None:
                self.config["inputProperties"][1]["value"]["tcpSettings"]["serverTcpProfile"] = self.want.topo_inboundl2_tcp_server

            ## update json for inbound L2 topology - vlans
            for vlan in self.want.topo_inboundl2_vlans:
                vlanlist = {}
                vlanlist["name"] = vlan
                vlanlist["value"] = vlan
                self.config["inputProperties"][1]["value"]["ingressNetwork"]["vlans"].append(vlanlist)

            ## update json for outbound L2 topology - L7Profile and L7Profiletype
            if self.want.topo_inboundl2_L7profiletype != None:
                self.config["inputProperties"][1]["value"]["l7ProfileType"] = self.want.topo_inboundl2_L7profiletype
            else:
                self.config["inputProperties"][1]["value"]["l7ProfileType"] = "http"
            if self.want.topo_inboundl2_L7profile != None:
                self.config["inputProperties"][1]["value"]["l7Profile"] = self.want.topo_inboundl2_L7profile
            else:
                self.config["inputProperties"][1]["value"]["l7Profile"] = "/Common/http"

            ## update json for inbound L2 topology - accessprofile
            if self.want.topo_inboundl2_accessprofile != None:
                self.config["inputProperties"][1]["value"]["accessProfile"] = self.want.topo_inboundl2_accessprofile
            else:
                self.config["inputProperties"][1]["value"]["accessProfile"] = self.want.name + "_accessProfile"

            ## update json for inbound L2 topology - accessprofile
            if self.want.topo_inboundl2_accessprofile != None:
                self.config["inputProperties"][1]["value"]["accessProfile"] = self.want.topo_inboundl2_accessprofile
            else:
                self.config["inputProperties"][1]["value"]["accessProfile"] = self.want.name + "_accessProfile"

            ## update json for inbound L2 topology - deployedNetwork
            self.config["inputProperties"][1]["value"]["deployedNetwork"] = "l2_network"


        ## =================================
        ## GENERAL POST-CONFIG
        ## =================================

        ## config references - service chains
        if self.want.configref_chains != None:
            for sc in self.want.configref_chains:
                try:
                    chain = sc["print_output"][0]["inputProperties"][1]["value"]
                    self.config["inputProperties"][4]["value"].append(chain)
                except:
                    raise F5ModuleError("A service chain reference is corrupt or contains incorrect information. Aborting")

        ## config references - ssl
        if re.match(r'^.*\'print_output\':', self.want.configref_ssl):
            ## this is a JSON config            
            try:
                ## extract main content from JSON
                ssl = self.want.configref_ssl
                ssl = ast.literal_eval(ssl)
                ssl = ssl["print_output"][0]["inputProperties"][1]["value"]            
                ## extract main content from JSON
                this_name = ssl["name"]
                ## set name reference in topology OB
                self.config["inputProperties"][1]["value"]["sslSettingReference"] = this_name
                ## set JSON in f5-ssl-orchestrator-tls OB
                self.config["inputProperties"][3]["value"] = ssl
            except:
                raise F5ModuleError("The SSL reference is corrupt or contains incorrect information. Aborting")        
        elif self.want.configref_ssl != None:
            ## this is presumably an SSL config name
            if not self.want.configref_ssl.startswith("ssloT_"):
                self.configref_ssl = "ssloT_" + self.want.configref_ssl
            else:
                self.configref_ssl = self.want.configref_ssl
            self.config["inputProperties"][1]["value"]["sslSettingReference"] = self.configref_ssl

        ## config reference - resolver or generic-settings
        ## if resolver is defined - add JSON OB
        ## if resolver not defined and no ssloGS_global exists on the target - add empty generic-settings OB
        if self.want.configref_resolver != None:
            ## add the resolver JSON to general-settings OB
            try:
                ## extract main content from JSON
                resolver = self.want.configref_resolver["print_output"][0]["inputProperties"][1]["value"]
                ## set JSON in f5-ssl-orchestrator-tls OB
                self.config["inputProperties"][2]["value"] = resolver
                ## go get ID of existing ssloGS_global if it exists
                gs = self.ssloGS_global_fetch()
                if gs != None:
                    self.config["inputProperties"][2]["value"]["existingBlockId"] = gs["existingBlockId"]
            except:
                raise F5ModuleError("The Resolver reference is corrupt or contains incorrect information. Aborting")
        else:
            ## check if ssloGS_global already exists on the target, and if not add an empty general-settings OB
            gs = self.ssloGS_global_fetch()
            if gs != None:
                ## add gs to general-settings OB
                self.config["inputProperties"][2]["value"] = gs
            else:
                ## add an empty gs to general-settings OB
                gs = json_template_gs
                if self.ssloVersion >= 6.0:
                    del gs["loggingConfig"]
                
                ## =================================
                ## 1.0.1 general update: modify version and previousVersion values to match target BIG-IP version
                ## =================================
                gs["version"] = self.ssloVersion
                gs["previousVersion"] = self.ssloVersion
                
                self.config["inputProperties"][2]["value"] = gs

        ## config reference - policy
        if re.match(r'^.*\'print_output\':', self.want.configref_policy):
            ## this is a JSON config
            try:
                ## extract main content from JSON
                policy = self.want.configref_policy
                policy = ast.literal_eval(policy)
                policy = policy["print_output"][0]["inputProperties"][1]["value"]
                ## extract name reference from JSON
                this_name = policy["name"]
                ## set name reference in topology OB
                self.config["inputProperties"][1]["value"]["securityPolicyReference"] = this_name
                ## set JSON in f5-ssl-orchestrator-tls OB
                self.config["inputProperties"][8]["value"] = policy
            except:
                raise F5ModuleError("The Security Policy reference is corrupt or contains incorrect information. Aborting")
        elif self.want.configref_policy != None:
            ## this is presumably a policy config name
            if not self.want.configref_policy.startswith("ssloP_"):
                   self.configref_policy = "ssloP_" + self.want.configref_policy
            else:
                self.configref_policy = self.want.configref_policy
            self.config["inputProperties"][1]["value"]["securityPolicyReference"] = self.configref_policy

        ## config reference - services
        if self.want.configref_services != None:
            try:
                for svc in self.want.configref_services:
                    try:
                        service = svc["print_output"][0]["inputProperties"]
                        ## loop through service OB JSON and look for -network and -service blocks
                        for obj in service:
                            if obj["id"] == "f5-ssl-orchestrator-network" and obj["value"] != []:
                                if type(obj["value"]) is dict:
                                    this_obj = obj["value"]
                                    self.config["inputProperties"][6]["value"].append(this_obj)
                                elif type(obj["value"]) is list:
                                    for x in obj["value"]:
                                        self.config["inputProperties"][6]["value"].append(x)
                            
                            elif obj["id"] == "f5-ssl-orchestrator-service":
                                if type(obj["value"]) is dict:
                                    this_obj = obj["value"]
                                elif type(obj["value"]) is list:
                                    this_obj = obj["value"][0]
                                self.config["inputProperties"][5]["value"].append(this_obj)
                    except:
                        raise F5ModuleError("A Service reference is corrupt or contains incorrect information (1). Aborting")
            except:
                raise F5ModuleError("A Service reference is corrupt or contains incorrect information (2). Aborting")


        ## =================================
        ## 9.0 Update: ocspAuth (could be a string or jinja2 reference)
        ## =================================
        #if self.ssloVersion >= 9.0 and self.want.topo_outboundl3_ocspAuth != None and self.want.topo_outboundl3_ocspAuth != "":
        #    self.config["inputProperties"][1]["value"]["ocspAuth"] = self.want.topo_outboundl3_ocspAuth
        if self.ssloVersion >= 9.0 and (self.want.topo_outboundl3 == True or self.want.topo_outboundxp == True): 
            ocspAuth = ""
            if (self.want.topo_outboundl3 == True and self.want.topo_outboundl3_ocspAuth != None and self.want.topo_outboundl3_ocspAuth != ""):
                ocspAuth = self.want.topo_outboundl3_ocspAuth
            elif (self.want.topo_outboundxp == True and self.want.topo_outboundxp_ocspAuth != None and self.want.topo_outboundxp_ocspAuth != ""):
                ocspAuth = self.want.topo_outboundxp_ocspAuth

            if ocspAuth != "":
                if re.match(r'^.*\'print_output\':', ocspAuth):
                    ## this is a JSON config - extract main content from JSON
                    auth = ocspAuth
                    auth = ast.literal_eval(auth)
                    auth = auth["print_output"][0]["inputProperties"][1]
                    ## make sure this is valid json and minimall contains 'name' and 'ocsp' keys
                    try:
                        if "name" in auth["value"] and "ocsp" in auth["value"]:
                            self.config["inputProperties"][1]["value"]["ocspAuth"] = auth["value"]["name"]
                            self.config["inputProperties"].append(auth)
                    except:
                        raise F5ModuleError("The referenced OCSP Authentication appears to be corrupt. Aborting")
                    
                else:
                    ## this is a static configuration reference - make sure the string starts with ssloA_
                    if not ocspAuth.startswith("ssloA_"):
                        ocspAuth = "ssloA_" + ocspAuth
                    ## add to json config
                    self.config["inputProperties"][1]["value"]["ocspAuth"] = ocspAuth


        ## create operation
        if operation == "CREATE":            
            #### TO DO: update JSON code for CREATE operation
            self.config["name"] = "sslo_obj_TOPOLOGY_CREATE_" + self.want.name
            


        ## modify/delete operations
        elif operation in ["DELETE", "MODIFY"]:
            self.config["name"] = "sslo_obj_TOPOLOGY_MODIFY_" + self.want.name

            ## get object ID and add to deploymentReference and existingBlockId values
            uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                self.client.provider['server'],
                self.client.provider['server_port']
            )
            query = "?$filter=name+eq+'{0}'&$select=id".format(self.want.name)
            resp = self.client.api.get(uri + query)
            
            try:
                response = resp.json()
            except ValueError as ex:
                raise F5ModuleError(str(ex))

            if resp.status not in [200, 201, 202] or 'code' in response and response['code'] not in [200, 201, 202]:
                raise F5ModuleError(resp.content)

            try:
                id = response["items"][0]['id']
                self.config["inputProperties"][0]["value"]["deploymentReference"] = "https://localhost/mgmt/shared/iapp/blocks/" + id
                self.config["inputProperties"][1]["value"]["existingBlockId"] = id
            except:
                raise F5ModuleError("Failure to create/modify - unable to fetch object ID")


            if operation in ["MODIFY"]:
                #### TO DO: update JSON code for MODIFY operation
                pass
                

        return self.config


    def exec_module(self):
        start = datetime.now().isoformat()
        self.ssloVersion = self.getSsloVersion()
        changed = False
        result = dict()
        state = self.want.state

        ## test for correct TMOS version
        if self.ssloVersion < min_version or self.ssloVersion > max_version:
            raise F5ModuleError("Unsupported SSL Orchestrator version, requires a version between min(" + str(min_version) + ") and max(" + str(max_version) + ")")

        
        ## enable/disable testdev to output to JSON only for testing (1) or push config to server (0)
        testdev = 0
        if testdev:
            self.exists()
            jsonstr = self.update_json("CREATE")
            print_output.append("jsonstr = " + str(jsonstr))
        
        else:
            if state == 'present':
                changed = self.update()
            elif state == 'absent':
                changed = self.absent()


        result.update(dict(changed=changed))
        print_output.append('changed=' + str(changed))
        return result


    def update(self):
        if self.module.check_mode:
            return True

        ## use this method to create the objects (if not exists) or modify (if exists)
        if self.exists():
            ## MODIFY: object exists - perform modify - get modified json first
            jsonstr = self.update_json("MODIFY")

            if self.want.mode == "output":
                print_output.append(str(jsonstr))

            else:
                ## post the object modify json
                uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                    self.client.provider['server'],
                    self.client.provider['server_port']
                )
                resp = self.client.api.post(uri, json=jsonstr)
                try:
                    response = resp.json()
                except ValueError as ex:
                    raise F5ModuleError(str(ex))

                if resp.status not in [200, 201, 202] or 'code' in response and response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(resp.content)

                ## get operation id from last request and loop through check
                self.operationId = str(response["id"])
                attempts = 1
                error = ""
                while attempts <= obj_attempts:
                    uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                        self.client.provider['server'],
                        self.client.provider['server_port']
                    )
                    query = "?$filter=id+eq+'{0}'".format(self.operationId)
                    resp = self.client.api.get(uri + query).json()
                    try:
                        if resp["items"][0]["state"] == "BOUND":
                            return True
                            break
                        elif resp["items"][0]["state"] == "ERROR":
                            error = str(resp["items"][0]["error"])
                            break
                    except:
                        time.sleep(1)
                        attempts += 1
                
                if error != "":
                    ## delete attempted configuration and raise error
                    self.deleteOperation(self.operationId)
                    raise F5ModuleError("Creation error: " + error)
                else:
                    raise F5ModuleError("Object " + self.want.name + " create/modify operation timeout")

        else:
            ## CREATE: object doesn't exist - perform create - get modified json first
            jsonstr = self.update_json("CREATE")
            
            if self.want.mode == "output":
                print_output.append(str(jsonstr))

            else:
                ## post the object create json
                uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                    self.client.provider['server'],
                    self.client.provider['server_port']
                )
                resp = self.client.api.post(uri, json=jsonstr)
                try:
                    response = resp.json()
                except ValueError as ex:
                    raise F5ModuleError(str(ex))

                if resp.status not in [200, 201, 202] or 'code' in response and response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(resp.content)

                ## get operation id from last request and loop through check
                self.operationId = str(response["id"])
                attempts = 1
                error = ""
                while attempts <= obj_attempts:
                    uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                        self.client.provider['server'],
                        self.client.provider['server_port']
                    )
                    query = "?$filter=id+eq+'{0}'".format(self.operationId)
                    resp = self.client.api.get(uri + query).json()

                    try:
                        if resp["items"][0]["state"] == "BOUND":
                            return True
                            break
                        elif resp["items"][0]["state"] == "ERROR":
                            error = str(resp["items"][0]["error"])
                            break
                    except:
                        time.sleep(1)
                        attempts += 1
                
                if error != "":
                    ## delete attempted configuration and raise error
                    self.deleteOperation(self.operationId)
                    raise F5ModuleError("Creation error: " + self.operationId + ":" + error)
                else:
                    raise F5ModuleError("Object " + self.want.name + " create/modify operation timeout")


    def absent(self):
        ## use this method to delete the objects (if exists)
        if self.exists():
            if self.module.check_mode:
                return True

            ## DELETE: object doesn't exist - perform create - get modified json first
            jsonstr = self.update_json("DELETE")
            
            if self.want.mode == "output":
                print_output.append(str(jsonstr))

            else:
                ## post the object create json
                uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                    self.client.provider['server'],
                    self.client.provider['server_port']
                )
                resp = self.client.api.post(uri, json=jsonstr)
                try:
                    response = resp.json()
                except ValueError as ex:
                    raise F5ModuleError(str(ex))

                if resp.status not in [200, 201, 202] or 'code' in response and response['code'] not in [200, 201, 202]:
                    raise F5ModuleError(resp.content)

                ## get operation id from last request and loop through check
                self.operationId = str(response["id"])
                attempts = 1
                error = ""
                while attempts <= obj_attempts:
                    uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
                        self.client.provider['server'],
                        self.client.provider['server_port']
                    )
                    query = "?$filter=id+eq+'{0}'".format(self.operationId)
                    resp = self.client.api.get(uri + query).json()
                    try:
                        if resp["items"][0]["state"] == "BOUND":
                            return True
                            break
                        elif resp["items"][0]["state"] == "ERROR":
                            error = str(resp["items"][0]["error"])
                            break
                    except:
                        time.sleep(1)
                        attempts += 1
                
                if error != "":
                    ## delete attempted configuration and raise error
                    self.deleteOperation(self.operationId)
                    raise F5ModuleError("Creation error: " + self.operationId + ":" + error)
                else:
                    raise F5ModuleError("Object " + self.want.name + " create/modify operation timeout")

        else:
            ## object doesn't exit - just exit (changed = False)
            return False


    def exists(self):
        ## use this method to see if the objects already exists - queries for the respective application service object
        uri = "https://{0}:{1}/mgmt/shared/iapp/blocks/".format(
            self.client.provider['server'],
            self.client.provider['server_port']
        )
        query = "?$filter=name+eq+'{0}'".format(self.want.name)
        resp = self.client.api.get(uri + query)

        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status in [200, 201] or 'code' in response and response['code'] in [200, 201]:
            
            foundit = 0
            for i in range(0, len(response["items"])):
                try:
                    if str(response["items"][i]["name"]) == self.want.name:
                        foundit = 1
                        self.existing_config = response["items"][i]
                        break
                except:
                    pass    
            
            if foundit == 1:
                return True
            else:
                return False

        else:
            return False


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            configReferences=dict(
                type='dict',
                options=dict(
                    sslSettings=dict(type=str),
                    securityPolicy=dict(type=str),
                    services=dict(type=list),
                    serviceChains=dict(type=list),
                    resolver=dict(type=dict)
                ),
            ),
            topologyOutboundL3=dict(
                type='dict',
                options=dict(
                    protocol=dict(
                        choices=["tcp","udp","other"],
                        default="tcp"
                    ),
                    ipFamily=dict(
                        choices=["ipv4","ipv6"],
                        default="ipv4"
                    ),
                    source=dict(
                        default="0.0.0.0%0/0"
                    ),
                    dest=dict(
                        default="0.0.0.0%0/0"
                    ),
                    port=dict(
                        type='int',
                        default=0
                    ),
                    vlans=dict(
                        type='list',
                        default=None
                    ),
                    snat=dict(
                        choices=["none","automap","snatpool","snatlist"],
                        default="none"
                    ),
                    snatlist=dict(
                        type='list',
                        default=None
                    ),
                    snatpool=dict(
                        default=None
                    ),
                    gateway=dict(
                        choices=["system","pool","iplist"],
                        default="system"
                    ),
                    gatewaylist=dict(
                        type='list',
                        default=None
                    ),
                    gatewaypool=dict(
                        default=None
                    ),
                    tcpSettingsClient=dict(
                        default="/Common/f5-tcp-lan"
                    ),
                    tcpSettingsServer=dict(
                        default="/Common/f5-tcp-wan"
                    ),
                    L7ProfileType=dict(
                        choices=["none","http"],
                        default="none"
                    ),
                    L7Profile=dict(
                        default=None
                    ),
                    additionalProtocols=dict(
                        type='list',
                        default=None
                    ),
                    accessProfile=dict(
                        default=None
                    ),
                    profileScope=dict(
                        choices=["public","named"],
                        default="public"
                    ),
                    profileScopeValue=dict(
                        default=None
                    ),
                    primaryAuthUri=dict(
                        default=None
                    ),
                    verifyAccept=dict(
                        type='bool',
                        default=False
                    ),
                    ocspAuth=dict(
                        default=None
                    )
                )
            ),
            topologyOutboundExplicit=dict(
                type='dict',
                options=dict(
                    source=dict(
                        default="0.0.0.0%0/0"
                    ),
                    ipFamily=dict(
                        choices=["ipv4","ipv6"],
                        default="ipv4"
                    ),
                    proxyIp=dict(
                        required=True
                    ),
                    proxyPort=dict(
                        type='int',
                        required=True
                    ),
                    vlans=dict(
                        type='list',
                        default=None
                    ),
                    snat=dict(
                        choices=["none","automap","snatpool","snatlist"],
                        default="none"
                    ),
                    snatlist=dict(
                        type='list',
                        default=None
                    ),
                    snatpool=dict(
                        default=None
                    ),
                    gateway=dict(
                        choices=["system","pool","iplist"],
                        default="system"
                    ),
                    gatewaylist=dict(
                        type='list',
                        default=None
                    ),
                    gatewaypool=dict(
                        default=None
                    ),
                    authProfile=dict(
                        default=None
                    ),
                    verifyAccept=dict(
                        type='bool',
                        default=False
                    ),
                    ocspAuth=dict(
                        default=None
                    ),
                    dnsResolver=dict(
                        default=None
                    )
                )
            ),
            topologyInboundL3=dict(
                type='dict',
                options=dict(
                    protocol=dict(
                        choices=["tcp","udp","other"],
                        default="tcp"
                    ),
                    ipFamily=dict(
                        choices=["ipv4","ipv6"],
                        default="ipv4"
                    ),
                    source=dict(
                        default="0.0.0.0%0/0"
                    ),
                    dest=dict(
                        default="0.0.0.0%0/0"
                    ),
                    port=dict(
                        type='int',
                        default=0
                    ),
                    vlans=dict(
                        type='list',
                        default=None
                    ),
                    snat=dict(
                        choices=["none","automap","snatpool","snatlist"],
                        default="none"
                    ),
                    snatlist=dict(
                        type='list',
                        default=None
                    ),
                    snatpool=dict(
                        default=None
                    ),
                    gateway=dict(
                        choices=["system","pool","iplist"],
                        default="system"
                    ),
                    gatewaylist=dict(
                        type='list',
                        default=None
                    ),
                    gatewaypool=dict(
                        default=None
                    ),
                    pool=dict(
                        default=None
                    ),
                    tcpSettingsClient=dict(
                        default="/Common/f5-tcp-lan"
                    ),
                    tcpSettingsServer=dict(
                        default="/Common/f5-tcp-wan"
                    ),
                    L7ProfileType=dict(
                        choices=["none","http"],
                        default="http"
                    ),
                    L7Profile=dict(
                        default="/Common/http"
                    ),
                    accessProfile=dict(
                        default=None
                    )
                )
            ),
            topologyOutboundL2=dict(
                type='dict',
                options=dict(
                    protocol=dict(
                        choices=["tcp","udp","other"],
                        default="tcp"
                    ),
                    ipFamily=dict(
                        choices=["ipv4","ipv6"],
                        default="ipv4"
                    ),
                    source=dict(
                        default="0.0.0.0%0/0"
                    ),
                    dest=dict(
                        default="0.0.0.0%0/0"
                    ),
                    port=dict(
                        type='int',
                        default=0
                    ),
                    vlans=dict(
                        type='list',
                        default=None
                    ),
                    tcpSettingsClient=dict(
                        default="/Common/f5-tcp-lan"
                    ),
                    tcpSettingsServer=dict(
                        default="/Common/f5-tcp-wan"
                    ),
                    L7ProfileType=dict(
                        choices=["none","http"],
                        default="none"
                    ),
                    L7Profile=dict(
                        default=None
                    ),
                    accessProfile=dict(
                        default=None
                    ),
                    profileScope=dict(
                        choices=["public","named"],
                        default="public"
                    ),
                    profileScopeValue=dict(
                        default=None
                    ),
                    primaryAuthUri=dict(
                        default=None
                    ),
                    ocspAuth=dict(
                        default=None
                    ),
                    verifyAccept=dict(
                        type='bool',
                        default=False
                    )
                )
            ),
            topologyInboundL2=dict(
                type='dict',
                options=dict(
                    protocol=dict(
                        choices=["tcp","udp","other"],
                        default="tcp"
                    ),
                    ipFamily=dict(
                        choices=["ipv4","ipv6"],
                        default="ipv4"
                    ),
                    source=dict(
                        default="0.0.0.0%0/0"
                    ),
                    dest=dict(
                        default="0.0.0.0%0/0"
                    ),
                    port=dict(
                        type='int',
                        default=0
                    ),
                    vlans=dict(
                        type='list',
                        default=None
                    ),
                    tcpSettingsClient=dict(
                        default="/Common/f5-tcp-lan"
                    ),
                    tcpSettingsServer=dict(
                        default="/Common/f5-tcp-wan"
                    ),
                    L7ProfileType=dict(
                        choices=["none","http"],
                        default="http"
                    ),
                    L7Profile=dict(
                        default="/Common/http"
                    ),
                    accessProfile=dict(
                        default=None
                    )
                )
            ),
            logging=dict(
                type='dict',
                options=dict(
                    sslo=dict(
                        choices=["emergency","alert","critical","warning","error","notice","information","debug"],
                        default="error"
                    ),
                    perRequestPolicy=dict(
                        choices=["emergency","alert","critical","warning","error","notice","information","debug"],
                        default="error"
                    ),
                    ftp=dict(
                        choices=["emergency","alert","critical","warning","error","notice","information","debug"],
                        default="error"
                    ),
                    imap=dict(
                        choices=["emergency","alert","critical","warning","error","notice","information","debug"],
                        default="error"
                    ),
                    pop3=dict(
                        choices=["emergency","alert","critical","warning","error","notice","information","debug"],
                        default="error"
                    ),
                    smpts=dict(
                        choices=["emergency","alert","critical","warning","error","notice","information","debug"],
                        default="error"
                    )
                )
            ),
            state=dict(
                default='present',
                choices=['absent','present']
            ),
            mode=dict(
                choices=["update","output"],
                default="update"
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)
        self.mutually_exclusive=[
            ['topologyOutboundL3', 'topologyOutboundExplicit', 'topologyInboundL3', 'topologyOutboundL2', 'topologyInboundL2']
        ]
        self.required_one_of=[
            ['topologyOutboundL3', 'topologyOutboundExplicit', 'topologyInboundL3', 'topologyOutboundL2', 'topologyInboundL2']
        ]

def main():
    ## start here
    
    ## define global print_output
    global print_output
    print_output = []

    ## define argumentspec
    spec = ArgumentSpec()
    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        mutually_exclusive=spec.mutually_exclusive,
        required_one_of=spec.required_one_of
    )

    ## send to exec_module, result contains output of tasks
    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        result = dict(
          **results,
          print_output=print_output
        )
        module.exit_json(**result)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()