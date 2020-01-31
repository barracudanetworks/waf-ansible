Role Name
=========

This role can be used to configure and manage Barracuda WAF Instances. One or more Barracuda WAF instances can be managed at the same time..


Requirements
------------

1. Modules to be installed i.e the requirements.txt file:
	```
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
	```
To install all these modules, the best option would be to copy the module names into a requirements.txt file. And then run pip3 install -requirement requirements.txt.

2. Create a wafcreds.json file:
Place a file called wafcreds.json in the /etc/ location of your filesystem. Format should be as follows:
	```
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
	```

The **wafcreds.json** can have multiple waf entries. This is useful if you would like to configure multiple waf instances at the same time.

Notes
-----

```
	a. Please make sure that the wafcreds.json is a valid/syntactically correct JSON document.
	b. No additional JSON keys other than specified in the sample wafcreds.json file are supported.
	c. All the keys in the above example are mandatory keys in the wafcreds.json
```

3. [Optional]Create a "logs" directory in the location from where the playbook will be run, for debugging the underlying API calls.

Dependencies
------------
1. **Python3**

Example Playbook
----------------
Examples for the ansible playbooks for Barracuda WAF can be found in the **examples** directory.

Documentation
-------------
More about the waf_ansible role: *https://github.com/barracudanetworks/waf-ansible/blob/master/roles-doc/readme.md*

How-to-guide: *https://github.com/barracudanetworks/waf-ansible/blob/master/roles-doc/how-to-guide.md* 

License
-------

BSD

Author Information
------------------

Aravindan Anandan (aravindan@barracuda.com)
