# Roles Documentation

To install the role:
--------------------

```ansible-galaxy install barracudanetworks_waf.waf_ansible```

Structure of the installed role:
--------------------------------

```
├── README.md
├── defaults
│   └── main.yml
├── examples
├── handlers
│   └── main.yml
├── library
│   ├── __init__.py
│   ├── cudawaf_configuration_checkpoints.py
│   ├── cudawaf_content_rule_servers.py
│   ├── cudawaf_content_rules.py
│   ├── cudawaf_export_configuration.py
│   ├── cudawaf_security_policies.py
│   ├── cudawaf_self_signed_certificate.py
│   ├── cudawaf_servers.py
│   ├── cudawaf_services.py
│   └── cudawaf_ssl.py
├── meta
│   └── main.yml
├── module_utils
│   └── cudawaf
│       ├── __init__.py
│       └── cudawaf.py
├── roles-doc
│   └── readme.md
├── tasks
│   └── main.yml
├── tests
│   ├── inventory
│   └── test.yml
└── vars
    └── main.yml
```
Tasks – Contains the main list of tasks that are to be executed by the role. It contains the main.yml file for that particular role. Every task directory includes a main.yml file where the code for the role is written.


In the working environment, create a *test.yml* with the following content:

```
---
- hosts: localhost
  roles:
    - barracudanetworks_waf.waf_ansible 
```

Run the ansible-playbook
------------------------

```
ansible-playbook test.yml
```

This command will check for the role barracudanetworks_waf.waf_ansible in the following directories:

```
1. /home-directory/roles or 
2. /home-directory/.ansible/roles
3. /usr/share/ansible/roles
4. /etc/ansible/roles
```

In the *roles/role-name/tasks/* directory, there should be a *main.yml* file

**Sample main.yml file.**

```
  - name: test 
    cudawaf_services:
      waf_host: 'waf1'
      name: 'secure_testsvc_1'
      app_id: 'testsvc_1'
      port: 9443
      vsite: default
      group: default
      service_type: 'HTTPS'
      certificate: 'juiceshop1'
      ip_address: '1.2.3.4'
      mask: 255.255.255.255
      enable_access_logs: 'Yes'
      state: 'present'
      session_timeout: '120'
    register: result
  - debug: var=result

```

For more documentation on roles and their usage visit:

https://docs.ansible.com/ansible/latest/user_guide/playbooks_reuse_roles.html

