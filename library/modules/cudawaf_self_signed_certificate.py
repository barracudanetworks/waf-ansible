#! /usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019 Aravindan Anandan (aravindan@barracuda.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.cudawaf_utils import logger
from ansible.module_utils.cudawaf_utils import token
import json
import requests

DOCUMENTATION = '''
---

'''

EXAMPLES = '''
---
# certificate creation
- name: testSvc
  hosts: localhost
  tasks:
  - name: test 
    cudawaf_certificates:
      waf_host: 'waf1'
      name: 'testsvc_cert'
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

# certificate deletion
- name: testSvc
  hosts: localhost
  tasks:
  - name: test 
    cudawaf_certificates:
      waf_host: 'waf1'
      name: 'testcert'
      status: 'absent' 
    register: result
  - debug: var=result
'''
def result_func(r):
    message = json.loads(r.text)
    #result = {"status_code": r.status_code, "msg": message['msg'] }
    result = {"status_code": r.status_code, "msg": message }
    return result

def create_self_signed_cert(data):
    headers,waf_ip,waf_port,proto = token(data['waf_host'])
    cert_create_url = proto+waf_ip+":"+waf_port+"/restapi/v3.1/certificates/self-signed-certificate"
    cert_get_url = cert_create_url+"/"+data['name']
    r = requests.get(cert_get_url, headers=headers, verify=False)
    if r.status_code == 200:
        #certificate exists
        #result={"msg":"certificate exists"}
        return False, False, result_func(r)
    if r.status_code == 404:
        payload_data={
            "allow-private-key-export": data['allow_private_key_export'],
            "city": data['city'],
            "common-name": data['common_name'],
            "country-code": data['country_code'],
            "elliptic-curve-name": "secp256r1",
            "key-size": data['key_size'],
            "key-type": data['key_type'],
            "name": data['name'],
            "organization-name": data['organization_name'],
            "organizational-unit": data['organizational_unit'],
            "san-certificate": data['san_certificate'],
            "state": data['state'],
            "status": data['status']
        }
        del payload_data['status']
        r = requests.post(cert_create_url, data=json.dumps(payload_data), headers=headers, verify=False)

        if r.status_code == 201:
            #result={"status_code":r.status_code, "msg": r.text}
            return False, True, result_func(r)
        else:
            #result={"status_code":r.status_code, "msg": r.text}
            return True, False, result_func(r)

def delete_self_signed_cert(data=None):
    headers,waf_ip,waf_port,proto = token(data['waf_host'])
    cert_delete_url = proto+waf_ip+":"+waf_port+"/restapi/v3.1/certificates/self-signed-certificate/"+data['name']
    r = requests.delete(cert_delete_url, headers=headers, verify=False)

    if r.status_code == 200:
        #result={"status_code":r.status_code, "msg": r.text}
        return False, True, result_func(r)
    else:
        #result={"status_code":r.status_code, "msg": r.text}
        return True, False, result_func(r)

def main():
    payload=dict(
        allow_private_key_export = dict(type='str',required=True),
        city = dict(type='str',required=True),
        common_name = dict(type='str',required=True),
        country_code = dict(type='str',required=True),
        elliptic_curve_name = dict(type='str', default='secp256r1'),
        key_size = dict(type='int', default=1024),
        key_type = dict(type='str', default='RSA'),
        name = dict(type='str',required=True),
        organization_name = dict(type='str',required=True),
        organizational_unit = dict(type='str',required=True),
        san_certificate = dict(type='str',required=False, default=None),
        state = dict(type='str',required=True),
        status = dict(type='str',required=True),
        waf_host = dict(type='str',required=True)
    )

    module = AnsibleModule(argument_spec=payload)

    choice_map = {
        "present": create_self_signed_cert,
        "absent": delete_self_signed_cert
    }
    is_error, has_changed, result = choice_map.get(
        module.params['status'])(module.params)
    
    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error executing this request", meta=result)
    
if __name__ == "__main__":
        main()
    

