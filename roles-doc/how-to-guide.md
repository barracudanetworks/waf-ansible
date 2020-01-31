# Step by Step guide for using the Barracuda WAF Ansible role

Introduction
------------

This guide provides the steps for installing and using this Ansible Role on an Ubuntu OS (running 16.04 or higher) ans assumes that you are logged in as user 'ubuntu'

Steps
-----
1. Install python3 if its not already installed

```sudo apt-get install python3 python3-pip```

2. Create a virtual environment to work in

```python3 -m venv workspace```

3. Activate the workspace

```cd workspace```
```source bin/activate```

4. Install the required modules and python packages

```
cat > requirements.txt  <<EOF
ansible==2.9.2
certifi==2019.11.28
cffi==1.13.2
chardet==3.0.4
cryptography==2.8
http-basic-auth==1.2.0
idna==2.8
Jinja2==2.10.3
MarkupSafe==1.1.1
pkg-resources==0.0.0
pycparser==2.19
PyYAML==5.2
requests==2.22.0
six==1.13.0
urllib3==1.25.7
EOF
```
5. Install the waf_ansible role

```ansible-galaxy install barracudanetworks_waf.waf_ansible```

This role will be installed under ``` */home/ubuntu/.ansible/roles/* ```

6. Create the *wafcreds.json*

```
cat > /etc/wafcreds.json <<EOF
{
"waf1":
	{
	"waf_ip":"<waf ip address for management>",
	"waf_port":"< management port number>",
	"waf_admin":"<api-user>",
	"waf_password":"<api-password>",
	"secure": "no"
	}
}
EOF
```
Note: Replace the JSON key values in the above command according to the Barracuda WAF instance details in your environment

7. Create the playbook file *waf_config.yml*

```
cat > waf_config.yml <<EOF
---
- hosts: localhost
  roles:
    - barracudanetworks_waf.waf_ansible
EOF
```

8. Create the *main.yml* file under the *roles/barracudanetworks_waf.waf_ansible/tasks/* directory

```
cat > /home/ubuntu/.ansible/roles/barracudanetworks_waf.waf_ansible/tasks/main.yml <<EOF
  - name: test 
    cudawaf_self_signed_certificate:
      waf_host: 'waf1'
      name: 'juiceshop1'
      allow_private_key_export: 'Yes'
      city: 'san jose'
      state: 'CA'
      country_code: 'US'
      common_name: 'testapp.cudademo.local'
      organization_name: 'Barracuda Networks'
      organizational_unit: 'PM'
      status: 'present' 
    register: result
  - debug: var=result
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
EOF
```
9. Run the playbook

```ansible-playbook install waf_config.yml```

10. Result

The above command should invoke the file /home/ubuntu/.ansible/roles/barracudanetworks_waf.waf_ansible/tasks/main.yml and create the configuration mentioned that file. Login to the WAF and check if the configuration is successfully completed.

