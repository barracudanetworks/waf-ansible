#! /usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019 Aravindan Anandan (aravindan@barracuda.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.cudawaf_utils import logger
from ansible.module_utils.cudawaf_utils import token
import json
import requests

ANSIBLE_METADATA = {
    'metadata_version': '2.7.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''

'''

EXAMPLES = '''
# Server Creation:
- name: testSvc
  hosts: localhost
  tasks:
  - name: test 
    cudawaf_rule_group_server:
      waf_host: 'waf1'
      name: 'testsvr'
      port: '80'
      ip_address: '1.2.3.5'
      address_version: 'IPv4'
      comments: 'test server'
      status: 'In Service'
      state: 'present'
      service_name: 'testsvc'
      identifier: 'IP Address'
      hostname: 'none'
      rule_group_name: 'testrg'
    register: result
  - debug: var=result

# Server deletion

- name: testSvc
  hosts: localhost
  tasks:
  - name: test 
    cudawaf_rule_group_server:
      waf_host: 'waf1'
      name: 'testsvr'
      port: '80'
      ip_address: '1.2.3.5'
      address_version: 'IPv4'
      comments: 'test server'
      status: 'In Service'
      state: 'absent'
      service_name: 'testsvc'
      identifier: 'IP Address'
      hostname: 'none'
      rule_group_name: 'testrg'
    register: result
  - debug: var=result
'''
def svr_update(data):
    headers,waf_ip,waf_port,proto = token(data['waf_host'])
    svr_name=data['name']
    svc_name=data['service_name']
    svr_url=proto+waf_ip+":"+waf_port+"/restapi/v3/services/"+svc_name+"/content-rules/"+data['rule_group_name']+"/content-rule-servers/"+svr_name
    
    update_payload = {
    "hostname": data['hostname'],
    "port": data['port'],
    "status": data['status'],
    "ip-address": data['ip_address'],
    "identifier": data['identifier'],
    "comments": data['comments']  
    }

    delete_list = list()
    for key in update_payload.keys():
        if update_payload.values() is None:
            delete_list = list.append[key]
    for key in delete_list:
        del update_payload[key]
    r=requests.put(svr_url, headers=headers, data=json.dumps(update_payload), verify=False)
    if r.status_code == 200:
        result={"status_code":r.status_code, "msg": r.text}
        return False, True, result
    else:
        result={"status_code":r.status_code, "msg": r.text}
        return True, False, result

def svr_create(data):
    headers,waf_ip,waf_port,proto = token(data['waf_host'])
    svr_name=data['name']
    svc_name=data['service_name']
    
    svr_url=proto+waf_ip+":"+waf_port+"/restapi/v3/services/"+svc_name+"/content-rules/"+data['rule_group_name']+"/content-rule-servers/"+svr_name
    
    svr_info = requests.get(svr_url,headers=headers,verify=False)
    del data['waf_host']
    del data['state']
    del data['service_name']

    if svr_info.status_code == 200:
        #check for server parameters to figure if PUT is required
        #if svr_info = data_info: 
        return svr_update(data)
    if svr_info.status_code == 404:
        
        svr_payload={
        "ip-address": data['ip_address'],
        "comments": data['comments'],
        "name": data['name'],
        "status": data['status'],
        "port": data['port'],
        "identifier": data['identifier'],
        "address-version": data['address_version'],
        "hostname": data['hostname']
        }

        if data['identifier'] != "Hostname":
            del svr_payload['hostname']

        svr_common_url=proto+waf_ip+":"+waf_port+"/restapi/v3/services/"+svc_name+"/content-rules/"+data['rule_group_name']+"/content-rule-servers"
        r = requests.post(svr_common_url, data=json.dumps(svr_payload), headers=headers, verify=False)

        if r.status_code == 201:
            return svr_update(data)
        else:
            result={"status_code":r.status_code, "msg": r.text}
            return True, False, result
        

def svr_delete(data=None):
    
    headers,waf_ip,waf_port,proto = token(data['waf_host'])
    svr_del_url = proto+waf_ip+":"+waf_port+"/restapi/v3/services/"+svc_name+"/content-rules/"+data['rule_group_name']+"/content-rule-servers/"+svr_name
    r = requests.delete(svr_del_url, headers=headers, verify=False)
    if r.status_code == 200:
        result={"status_code":r.status_code, "msg": r.text}
        return False, True, result
    if r.status_code !=200:
        result={"status_code":r.status_code, "msg": r.text}
        return True, False, result
    
def main():

    payload = dict(
        name=dict(type='str', required=True),
        ip_address=dict(type='str', required=True),
        port=dict(type='int', required=True),
        identifier=dict(type='str', required=True),
        waf_host=dict(type='str', required=True),
        service_name=dict(type='str', required=True),
        rule_group_name=dict(type='str', required=True),
        comments=dict(type='str', required=True),
        status=dict(type='str', required=True),
        address_version=dict(type='str', required=True),
        hostname=dict(type='str', required=True),
        state=dict(type='str', required=True)
    )

    choice_map={"present": svr_create, "absent": svr_delete }

    module = AnsibleModule(argument_spec=payload)

    is_error, has_changed, result = choice_map.get(module.params['state'])(module.params)
    
    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error executing this request", meta=result)
    
if __name__ == "__main__":
    main()