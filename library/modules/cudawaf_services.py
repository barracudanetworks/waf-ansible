#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019 Aravindan Anandan (aravindan@barracuda.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: cudawaf_service
short_description: Manages services on Barracuda WAF
version_added: "2.10"
description:
  - THIS MODULE CAN BE USED TO CREATE, UPDATE OR DELETE SERVICES ON THE BARRACUDA WAF. 
  - WAF DEVICE CONF IS MAINTAINED AND THE JSON FILE IS READ FROM THE WORKING DIRECTORY.
extends_documentation_fragment: "barracuda_networks"
options:
  name:
    description:
      - Service name
    type: 'str'
  port:
    description:
      - Specifies the listening port for the service.
    type: 'str'
  address_version:
    description:
      - Specifies the IP Protocol to be used with the service. Must be 'IPv4'.
    type: 'str'
  status:
    description:
      - Specifies if the service should be enabled 'On' or disabled 'Off'.
    type: 'str'
  comments:
    description:
      - Specifies the description for the service.
    type: 'str'
  enable_access_logs:
    description:
      - Specifies if the service should be created with the access logs enabled i.e 'Yes' or disabled i.e 'No'.
    type: 'str'
  session_timeout:
    description:
      - Specifies the session idle timeout. Must be a valid number or 0.
    type: 'int'
  app_id:
    description:
      - Specifies the app-id for the service.
    type: 'str'
  group:
    description:
      - Specifies the service group in which the Service is to be created. Must be a group present in the WAF.
    type: 'str'
  vsite:
    description:
      - Specifies the vsite object in which the Service will be created.
    type: 'str'
  dps_enabled:
    description:
      - Specifies if the service should have Advanced DdoS Prevention service enabled i.e "Yes" or disabled i.e "No".
    type: 'str'
  ip_address:
    description:
      - Specifies the listening ip address for the service.
    type: 'str'
  mask:
    description:
      - Specifies the subnet mask for the service.
    type: 'str'
  type: dict     
author: "Barracuda Support"
notes:
    - Other things consumers of your module should know.
requirements:
    - list of required things.
    - requests
'''

EXAMPLES = '''
- name: Create testSvc service
  hosts: localhost
  tasks:
  - name: test 
    cudawaf_service:
      name: 'testsvc'
      port: 80
      type: 'HTTP'
      ip_address: '1.2.3.4'
      state: 'present'
    register: result
  - debug: var=result
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.cudawaf_utils import logger
from ansible.module_utils.cudawaf_utils import token
import json
import requests

def result_func(r):
    message = json.loads(r.text)
    result = {"status_code": r.status_code, "msg": message['msg'] }
    return result

def waf_svc_update(data):
    logs=logger()
    headers,waf_ip,waf_port,proto = token(data['waf_host'])
    service_url=proto+waf_ip+":"+waf_port+"/restapi/v3.1/services/"
    service_url_get=service_url+data['name']
    svc_info=requests.get(service_url_get,headers=headers, verify=False)
    config = json.loads(svc_info.text)
    svc_config=config["data"][data['name']]
    update_data_list = ["app-id","comments","enable-access-logs","ip-address","mask","port","session-timeout",
        "status"]
    existing_config = dict()
    ansible_config = dict()
    for attribute in update_data_list:
        existing_config[attribute] = config['data'][data['name']][attribute]
    svc_type = config['data'][data['name']]['type']
    if svc_type == 'HTTPS':
        existing_config["secure-site-domain"] = config['data'][data['name']]['Instant SSL']['secure-site-domain']
    else:
        pass
    logs.debug(existing_config)
    ansible_config = {
            "app-id": data['app_id'],
            "comments": data['comments'],
            "enable-access-logs": data['enable_access_logs'],
            "ip-address": data['ip_address'],
            "mask": data['mask'],
            "port": data['port'],
            "session-timeout": data['session_timeout'],
            "status": data['status'],
            "secure-site-domain": data['secure_site_domain'],
        }
    if existing_config.items() == ansible_config.items():
        result={"msg": "existing configuration and ansible configuration are same. No changes made"}
        return False, False, result
    else:
        update_config_payload = dict()
        update_config_payload['waf_host'] = data['waf_host']
        delete_list=[key for key,value in ansible_config.items() if value is None]
        logs.debug(delete_list)
        for key in delete_list:
            del ansible_config[key]
        del ansible_config['secure-site-domain']
        update_config_payload = ansible_config
        #del update_config_payload['waf_host']
        logs.debug("***")
        logs.debug(update_config_payload)
        put_url = proto+waf_ip+":"+waf_port+"/restapi/v3.1/services/"+data['name']
        r=requests.put(put_url, headers=headers, data=json.dumps(update_config_payload), verify=False)
        logs.debug(r.text)
        if r.status_code == 200:
            #result = {"status_code": r.status_code, "msg": "Configuration Updated"}
            #logs.debug(result)
            return False, True, result_func(r)
        else:
            #result = {"status_code": r.status_code, "msg": r.text[1]}
            return True, False, result_func(r)


def waf_svc_create(data):
    #Picks up the service attributes from the payload var, 
    # makes an API call to the waf to create the service
    headers, waf_ip, waf_port, proto = token(data['waf_host'])
    service_url=proto+waf_ip+":"+waf_port+"/restapi/v3.1/services/"
    
    logs=logger()
    del data['state']
    
    service_data={
    "name":data['name'],
    "ip-address":data['ip_address'],
    "port":data['port'],
    "app-id":data['app_id'],
    "comments":data['comments'],
    "address-version":data['address_version'],
    "vsite":data['vsite'],
    "type": data['service_type'],
    "group":data['group'],
    "mask":data['mask'],
    "certificate":data['certificate'],
    "secure-site-domain": data['secure_site_domain'],
    }
    
    service_url_get=service_url+data['name']
    svc_info=requests.get(service_url_get,headers=headers, verify=False)
    #when service exists and an update is required. 
    #need to compare the service_data attributes with the existing configuration and then 
    #issue a put command for the changed attribute.
    
    if svc_info.status_code == 200:
        # compare the service attributes with the payload
        
        return waf_svc_update(data)
    
    #when there is no service, create a service
    if svc_info.status_code == 404:
        delete_list = [key for key,value in service_data.items() if value is None]
        for key in delete_list:
            del service_data[key]

        logs.debug(service_data)

        r=requests.post(service_url,data=json.dumps(service_data),headers=headers, verify=False)
        
        if r.status_code == 201:
            if data['service_type'] == "Instant SSL":
                #result={"status_code": r.status_code, "msg":r.text[1]}
                return False, True, result_func(r)
            else:
                logs.debug("service created, checking for updates")
                return waf_svc_update(data)
        
        if r.status_code != 201:
            #result= {"status_code":r.status_code, "msg": r.text[1]}
            return True, False, result_func(r)
    
#Picks up the service name from the payload var, makes an API to the waf to delete the service
def waf_svc_delete(data=None):
    headers, waf_ip, waf_port, proto = token(data['waf_host'])
    service_name=data['name']
    service_url=proto+waf_ip+":"+waf_port+"/restapi/v3.1/services/"+service_name
    r=requests.delete(service_url,headers=headers, verify=False)
    #result={"status_code":r.status_code, "msg":r.text[1]}
    if r.status_code == 200:
        return False, True, result_func(r)
    if r.status_code != 200:
        return True, False, result_func(r)

def main():
    # define available arguments/parameters a user can pass to the module

    payload = dict(
        waf_host=dict(type='str', required=True),
        name=dict(type='str', required=True),
        port=dict(type='int', required=True),
        ip_address=dict(type='str', required=True),
        service_type=dict(type='str', required=True),
        state=dict(type='str', required=True),
        address_version=dict(type='str', default='IPv4'),
        app_id=dict(type='str'),
        certificate=dict(type='str'),
        vsite=dict(type='str'),
        group=dict(type='str'),
        mask=dict(type='str'),
        status=dict(type='str', default='On'),
        comments=dict(type='str', default='Created by Ansible Playbook'),
        enable_access_logs=dict(type='str'),
        session_timeout=dict(type='int'),
        secure_site_domain=dict(type='list'),
        dps_enabled=dict(type='str'),
    )

    choice_map = {
        "present": waf_svc_create,
        "absent": waf_svc_delete
    }
    
    module = AnsibleModule(argument_spec=payload)
    
    is_error, has_changed, result = choice_map.get(
        module.params['state'])(module.params)
    logs=logger()

    if not is_error:
        logs.debug("success condition")
        logs.debug(result)
        module.exit_json(changed=has_changed, meta=result)

    else:
        logs.debug("failure condition")
        logs.debug(result)
        module.fail_json(msg="Error executing this request", meta=result)
    
    
if __name__ == '__main__':
    main()