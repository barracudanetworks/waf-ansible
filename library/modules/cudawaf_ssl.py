#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019 Aravindan Anandan (aravindan@barracuda.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.cudawaf_utils import logger
from ansible.module_utils.cudawaf_utils import token
import json
import requests

def result_func(r):
    message = json.loads(r.text)
    result = {"status_code": r.status_code, "msg": message['msg'] }
    return result

def ssl_config_update(data):
    logs = logger()
    headers,waf_ip,waf_port,proto = token(data['waf_host'])
    svc_name = data['service_name']
    svc_get_url = proto+waf_ip+":"+waf_port+"/restapi/v3.1/services/"+svc_name
    r = requests.get(svc_get_url, headers=headers, verify=False)
    existing_config = json.loads(r.text)
    service_type = existing_config["data"][svc_name]["type"]
    logs.debug(service_type)
    if r.status_code == 200:
        # build update payload
        ssl_config_url = proto+waf_ip+":"+waf_port+"/restapi/v3.1/services/"+svc_name+"/ssl-security"
        logs.debug("test message")
        r = requests.get(ssl_config_url, headers=headers, verify=False)
        existing_values = json.loads(r.text)
        existing_config = existing_values["data"][svc_name]["SSL Security"]
        ansible_config = {
                "enable-tls-1-2": data['enable_tls_1_2'],
                "sni-certificate": data['sni_certificate'],
                "sni-ecdsa-certificate": data['sni_ecdsa_certificate'],
                "override-ciphers-ssl3": data['override_ciphers_ssl3'],
                "ciphers": data['ciphers'],
                "selected-ciphers": data['selected_ciphers'],
                "enable-strict-sni-check": data['enable_strict_sni_check'],
                "enable-tls-1-3": data['enable_tls_1_3'],
                "certificate": data['certificate'],
                "override-ciphers-tls-1-1": data['override_ciphers_tls_1_1'],
                "enable-pfs": data['enable_pfs'],
                "status": data['status'],
                "enable-tls-1-1": data['enable_tls_1_1'],
                "domain": data['domain'],
                "enable-ssl-3": data['enable_ssl_3'],
                "hsts-max-age": data['hsts_max_age'],
                "ecdsa-certificate": data['ecdsa_certificate'],
                "override-ciphers-tls-1": data['override_ciphers_tls_1'],
                "include-hsts-sub-domains": data['include_hsts_sub_domains'],
                "enable-tls-1": data['enable_tls_1'],
                "enable-sni": data['enable_sni'],
                "enable-hsts": data['enable_hsts'],
                }
        if existing_config.items() == ansible_config.items():
            result={"msg": "existing configuration and ansible configuration are same. No changes made"}
            return False, False, result
        else:
            update_config_payload = dict()
            update_config_payload['waf_host'] = data['waf_host']
            delete_list = [key for key,value in ansible_config.items() if value is None]
            for key in delete_list:
                del ansible_config[key]
            update_config_payload = ansible_config
            logs.debug(update_config_payload)
            r = requests.put(ssl_config_url, data=json.dumps(update_config_payload), headers=headers, verify=False)
            if r.status_code == 200:
                #result = {"status_code": r.status_code, "msg": r.text}
                return False, True, result_func(r)
            else:
                #result = {"status_code": r.status_code, "msg": r.text}
                return True, False, result_func(r)
    else:
        #result={"msg":"service does not exist"}
        return True, False, result_func(r)

def main():
    payload = dict(
    waf_host = dict(type='str', required=True),
    service_name = dict(type='str', required=True),
    enable_hsts = dict(type='str'),
    include_hsts_sub_domains = dict(type='list'),
    enable_tls_1_3 = dict(type='str'),
    override_ciphers_tls_1_1 = dict(type='str'),
    enable_pfs = dict(type='str'),
    selected_ciphers = dict(type='list'),
    override_ciphers_tls_1 = dict(type='str'),
    enable_sni = dict(type='str'),
    override_ciphers_ssl3 = dict(type='str'),
    certificate = dict(type='str'),
    enable_tls_1_1 = dict(type='str'),
    sni_ecdsa_certificate = dict(type='str'),
    ciphers = dict(type='list'),
    enable_strict_sni_check = dict(type='str'),
    enable_tls_1_2 = dict(type='str'),
    enable_ssl_3 = dict(type='str'),
    ecdsa_certificate = dict(type='str'),
    enable_tls_1 = dict(type='str'),
    status = dict(type='str', required=True),
    hsts_max_age = dict(type='int'),
    domain = dict(type='list'),
    sni_certificate = dict(type='str'),
    )
    logs=logger()
    config_map = {
        "on": ssl_config_update,
        "off": ssl_config_update,
    }

    module = AnsibleModule(argument_spec=payload)
    logs.debug(type(module))
    is_error, has_changed, result = config_map.get(module.params['status'])(module.params)
    

    if not is_error:
    
        module.exit_json(changed=has_changed, meta=result)

    else:
    
        module.fail_json(msg="Error executing this request", meta=result)
    
    
if __name__ == '__main__':
    main()