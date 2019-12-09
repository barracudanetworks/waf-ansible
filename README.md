Role Name
=========

This role can be used to configure and manage Barracuda WAF Instances.

Requirements
------------

Any pre-requisites that may not be covered by Ansible itself or the role should be mentioned here. For instance, if the role uses the EC2 module, it may be a good idea to mention in this section that the boto package is required.
1. Modules to be installed:
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
To install all these modules, the best option would be to copy the module names into a requirements.txt file. And then run pip install -requirement requirements.txt.

2. Create a wafcreds.json file:
Place a file called wafcreds.json in the location from where the playbook will be run. Format should be as follows:
```
{
"waf1":
    {
    "waf_ip":"<waf ip address for management>",
    "waf_port":"< management port number>",
    "waf_admin":"<api-user>",
    "waf_password":"<api-password>",
    "secure": "no"
    },
```
The wafcreds.json can have multiple waf entries. This is useful if you would like to configure multiple waf instances at the same time.

Role Variables
--------------

A description of the settable variables for this role should go here, including any variables that are in defaults/main.yml, vars/main.yml, and any variables that can/should be set via parameters to the role. Any variables that are read from other roles and/or the global scope (ie. hostvars, group vars, etc.) should be mentioned here as well.

Dependencies
------------

A list of other roles hosted on Galaxy should go here, plus any details in regards to parameters that may need to be set for other roles, or variables that are used from other roles.

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: servers
      roles:
         - { role: username.rolename, x: 42 }

License
-------

BSD

Author Information
------------------

An optional section for the role authors to include contact information, or a website (HTML is not allowed).
