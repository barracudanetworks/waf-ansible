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
'''
def result_func(r):
    message = json.loads(r.text)
    result = {"status_code": r.status_code, "msg": message['msg'] }
    return result

def sec_policy_create(data):

    headers,waf_ip,waf_port,proto = token(data['waf_host'])
    sec_policy_name=data['name']
    sec_policy_get_url=proto+waf_ip+":"+waf_port+"/restapi/v3/security-policies/"+sec_policy_name
    get_sec_policy=requests.get(sec_policy_get_url, headers=headers, verify=False)
    if get_sec_policy.status_code == 200:
        #result={"msg":"Policy exists"}
        return True, False, result_func(r)
    else:
        sec_policy_url=proto+waf_ip+":"+waf_port+"/restapi/v3/security-policies"
        del data['waf_host']
        del data['state']
        sec_policy_payload={
        "name": data['name'],
        "based-on": data['based_on']
        }
        r=requests.post(sec_policy_url,data=json.dumps(sec_policy_payload),headers=headers, verify=False)
        if r.status_code == 201:
            #result={"status_code":r.status_code, "msg":r.text}
            return False, True, result_func(r)
        else:
            #result={"status_code":r.status_code, "msg":r.text}
            return True, False, result_func(r)

def sec_policy_delete(data=None):
    headers,waf_ip,waf_port,proto = token(data['waf_host'])
    sec_policy_name=data['name']
    sec_policy_del_url=proto+waf_ip+":"+waf_port+"/restapi/v3/security-policies/"+sec_policy_name
    r=requests.delete(sec_policy_del_url, headers=headers, verify=False)
    #result={"status_code":r.status_code, "msg":r.text}
    if r.status_code == 200:
        return False, True, result_func(r)
    else:
        return True, False, result_func(r)

def main():
    payload=dict(
        waf_host=dict(type='str',required=True),
        based_on=dict(type='str',required=True),
        name=dict(type='str', required=True),
        state=dict(type='str', required=True),
    )
    
    choice_map={
        "present": sec_policy_create,
        "absent": sec_policy_delete,
    }

    module = AnsibleModule(argument_spec=payload)

    is_error, has_changed, result = choice_map.get(
        module.params['state'])(module.params)
    
    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else: 
        module.fail_json(msg="Error executing this request", meta=result)
    
if __name__ == "__main__":
    main()
