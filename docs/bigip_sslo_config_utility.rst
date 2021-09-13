F5 SSL Orchestrator Ansible Automation Collection
+++++++++++++++++++++++++++++++++++++++++++++++++

Documentation - Utility Functions
=================================

Module: bigip_sslo_config_utility
---------------------------------

Description
-----------
This module is used to perform the various SSL Orchestrator utility functions. The utility capabilities in this module will grow over time.

Sample with all options defined
-------------------------------
.. code-block:: yaml

    - name: SSLO Utility Functions
      bigip_sslo_config_utility:
        provider: "{{ provider }}"

        utility: delete-all
          
      delegate_to: localhost

    - name: SSLO Utility Functions
      bigip_sslo_config_utility:
        provider: "{{ provider }}"

        utility: rpm-update
        package: /home/bob/downloads/f5-iappslx-ssl-orchestrator-16.0.1.1-8.4.15.noarch.rpm
          
      delegate_to: localhost

Utilities
---------
The following list of utility functions will grow over time:

- **delete-all**: This function deletes the entire SSL Orchestrator configuration.
- **rpm-update**: This function updates the SSL Orchestrator RPM package.


Parameters
----------

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
          <td colspan="2" rowspan="1">utility</td>
          <td>yes</td>
          <td>&nbsp;</td>
          <td><nobr>delete-all</nobr><br /><nobr>rpm-update</nobr></td>
          <td>all</td>
          <td><p>[str]</p>
          <p>The name of the utility function to perform</p>
          </td>
        </tr>

        <tr>
          <td colspan="2" rowspan="1">package</td>
          <td>no</td>
          <td>&nbsp;</td>
          <td>&nbsp;</td>
          <td>all</td>
          <td><p>[str]</p>
          <p>Required with rpm-update function, species the local path of the RPM file to push to the BIG-IP</p>
          </td>
        </tr>

      </tbody>
    </table>

Examples
--------

.. code-block:: yaml

    - name: Create SSLO Utility Functions
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
        - name: SSLO Utility Delete-All
          bigip_sslo_config_utility:
            provider: "{{ provider }}"

            utility: delete-all

          delegate_to: localhost


.. code-block:: yaml

    - name: Create SSLO Utility Functions
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
        - name: SSLO Utility RPM Update
          bigip_sslo_config_utility:
            provider: "{{ provider }}"

            utility: rpm-update
            package: /home/bob/downloads/f5-iappslx-ssl-orchestrator-16.0.1.1-8.4.15.noarch.rpm

          delegate_to: localhost