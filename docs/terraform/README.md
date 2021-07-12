# F5 SSL Orchestrator Ansible Automation Collection
## Terraform examples

Terraform can be used to call Ansible playbooks. This page describes a method for doing this.


- Install Terraform:
  ```Bash
  mkdir terraform && cd terraform
  sudo apt-get update && sudo apt-get install -y gnupg software-properties-common curl
  curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
  sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
  sudo apt-get update && sudo apt-get install terraform
  terraform -version
  ```

- Create a main.tf file:
  ```Bash
  resource "null_resource" "install_playbook" {
    connection {
        type = "ssh"
        host = "10.1.1.4"
        user = "admin"
        password = "admin"
        port = "22"
    }
    provisioner "local-exec" {
        command = "ansible-playbook ../ansible/sample-playbooks/config-topology-outboundL3-full.yaml"
    }
  }
  ```

- Initiate Terrafom
  ```Bash
  terraform init
  ```

- Generate a plan and then apply
  ```Bash
  terraform plan
  terraform apply
  ```

<br />

As Ansible playbooks are called through a terraform local-exec provisioner, there is no native "terraform destroy" function, nor can a single SSL Orchestrator topology configuration destroy all of the dependent objects. To destroy the dependent objects, create a separate playbook task for each (atomic method) and set their state to "absent". In Terraform, call each of these as separate provisioners.