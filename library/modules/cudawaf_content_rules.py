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
# Rule group creation
- name: testSvc
  hosts: localhost
  tasks:
  - name: test 
    cudawaf_rule_group:
      waf_host: 'waf1'
      name: 'rule_grp'
      url_match: '/index.html'
      host_match: '*'
      state: 'present'
      service_name: 'testsvc'
    register: result
  - debug: var=result

# Rule group deletion
- name: testSvc
  hosts: localhost
  tasks:
  - name: test 
    cudawaf_rule_group:
      waf_host: 'waf1'
      name: 'testrg'
      url_match: '/home/'
      host_match: '*'
      state: 'absent'
      service_name: 'testsvc'
      rule_group_name: 'testrg'
    register: result
  - debug: var=result
'''
def rule_grp_update(data):
    headers,waf_ip,waf_port,proto = token(data['waf_host'])
    get_rule_grp = proto+waf_ip+":"+waf_port+"/restapi/v3.1/services/"+data['service_name']+"/"+"content-rules/"+data['name']
    get_rule_grp_request= requests.get(get_rule_grp, headers=headers, verify=False)
    
    config=json.loads(get_rule_grp_request.text)
    existing_payload=dict()
    update_data = ["app-id", "mode", "extended-match-sequence", "extended-match", "web-firewall-policy", "host-match", "status",
        "url-match", "comments"]
    for key in update_data:
        existing_payload[key] = config["data"][data['name']][key]
    existing_payload['access-log'] = config["data"][data['name']]["Logging"]["access-log"]
        
    ansible_config = dict()
    ansible_config = {
            "app-id": data['app_id'],
            "access-log": data['access_log'],
            "mode": data['mode'],
            "extended-match-sequence": data['extended_match_sequence'],
            "extended-match": data['extended_match'],
            "web-firewall-policy": data['web_firewall_policy'],
            "host-match": data['host_match'],
            "status": data['status'],
            "url-match": data['url_match'],
            "comments": data['comments']
        }
        
    for key in ansible_config.keys():
        if ansible_config[key] is None:
            del ansible_config[key]
        if ansible_config.items() == existing_payload.items():
            result = "configuration is same. Nothing to be done"
            return False, False, result
        else:
            r = requests.put(get_rule_grp, headers=headers, data=json.dumps(ansible_config), verify=False)
            result = {"status_code":r.status_code, "msg": r.text}
            return False, True, result

def rule_grp_create(data):
    headers,waf_ip,waf_port,proto = token(data['waf_host'])

    get_rule_grp = proto+waf_ip+":"+waf_port+"/restapi/v3.1/services/"+data['service_name']+"/"+"content-rules/"+data['name']
    get_rule_grp_request= requests.get(get_rule_grp, headers=headers, verify=False)
    if get_rule_grp_request.status_code == 200:
        #check for PUT requests
        return rule_grp_update(data)
    if get_rule_grp_request.status_code == 404:
        rule_grp_payload = {
                "comments": data['comments'],
                "url-match": data['url_match'],
                "name": data['name'],
                "extended-match-sequence": data['extended_match_sequence'],
                "extended-match": data['extended_match'],
                "web-firewall-policy": data['web_firewall_policy'],
                "host-match": data['host_match'],
                "status": data['status'],
                "app-id": data['app_id'],
                "access-log": data['access_log'],
                "mode": data['mode']
                }
        if rule_grp_payload['app-id'] is None:
            del rule_grp_payload['app-id']
        if rule_grp_payload['comments'] is None:
            del rule_grp_payload['comments']
        if rule_grp_payload['extended-match-sequence'] is None:
            del rule_grp_payload['extended-match-sequence']
        post_rule_grp_request_url = proto+waf_ip+":"+waf_port+"/restapi/v3.1/services/"+data['service_name']+"/content-rules"
        r = requests.post(post_rule_grp_request_url, headers=headers, data=json.dumps(rule_grp_payload), verify=False)
        if r.status_code == 201:
            return rule_grp_update(data)
        else:
            result={"status_code":r.status_code, "msg": r.text}
            return True, False, result

def rule_grp_delete(data=None):
    headers,waf_ip,waf_port,proto = token(data['waf_host'])
    del_rule_grp_url = proto+waf_ip+":"+waf_port+"/restapi/v3.1/services/"+data['service_name']+"/"+"content-rules/"+data['name']
    r = requests.delete(del_rule_grp_url, headers=headers, verify=False)
    if r.status_code == 200:
        result = {"status_code":r.status_code, "msg": r.text}
        return False, True, result
    else:
        result = {"status_code":r.status_code, "msg": r.text}
        return True, False, result



def main():
    payload=dict(
        name=dict(type='str', required=True),
        comments=dict(type='str'),
        url_match=dict(type='str', required=True),
        extended_match_sequence=dict(type='int', required=False, default=1000),
        extended_match=dict(type='str', default="*"),
        web_firewall_policy=dict(type='str', default="default"),
        host_match=dict(type='str', required=True),
        status=dict(type='str', default="On"),
        app_id=dict(type='str'),
        access_log=dict(type='str', default="Enable"),
        mode=dict(type='str', default="Passive"),
        waf_host=dict(type='str', required=True),
        service_name=dict(type='str', required=True),
        state=dict(type='str', required=True)
    )

    choice_map={
        "present": rule_grp_create,
        "absent": rule_grp_delete
    }
    logs=logger()
    module=AnsibleModule(argument_spec=payload)

    is_error, has_changed, result=choice_map.get(
            module.params['state'])(module.params)
    
    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error executing this request", meta=result)

if __name__ == "__main__":
    main()