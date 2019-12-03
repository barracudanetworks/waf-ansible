#! /usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019 Aravindan Anandan (aravindan@barracuda.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.cudawaf_utils import logger
from ansible.module_utils.cudawaf_utils import token
import json
import requests
import os

def result_func(r):
    message = json.loads(r.text)
    result = {"status_code": r.status_code, "msg": message['msg'] }
    return result

def configuration_export_create(data):
    backup_type = data['backup_type']
    if backup_type == "partial":
        headers,waf_ip,waf_port,proto = token(data['waf_host'])
        config_check_point_name = data['name']
        config_checkpoint_get_url = proto+waf_ip+":"+waf_port+"/restapi/v3.1/configuration-checkpoints/"+config_check_point_name
        r = requests.get(config_checkpoint_get_url, headers=headers, verify=False)
        if r.status_code == 200: 
            export_post_url = proto+waf_ip+":"+waf_port+"/restapi/v3.1/ops/export-configuration"
            export_payload = {
                "backup-type" : "partial",
                "name": config_check_point_name,
            }
            r = requests.post(export_post_url, data=json.dumps(export_payload), headers=headers, verify=False)
            if r.status_code == 200:
                json_data = json.loads(r.text)
                with open('config_file.json', 'w') as json_file:
                    json.dump(json_data, json_file)
                #result={"status_code": r.status_code, "msg": "configuration exported"}
                return False, True, result_func(r)
            else:
                #result={"status_code": r.status_code, "msg": r.text}
                return True, False, result_func(r)
        else:
            #result = {"msg": "configuration checkpoint name not found"}
            return True, False, result_func(r)
    elif backup_type == "full":
        headers,waf_ip,waf_port,proto = token(data['waf_host'])
        export_post_url = proto+waf_ip+":"+waf_port+"/restapi/v3.1/ops/export-configuration"
        export_payload = {
            "backup-type": "full",
        }
        r = requests.post(export_post_url, headers=headers, data=json.dumps(export_payload), verify=False)
        if r.status_code == 200:
            json_data = json.loads(r.text)
            with open('config_file.json', 'w') as json_file:
                json.dump(json_data, json_file)
            #result={"status_code": r.status_code, "msg": "configuration exported"}
            return False, True, result_func(r)
        else:
            #result={"status_code": r.status_code, "msg": "error executing this request"}
            return True, False, result_func(r)
    '''else:
        result = "Request error"
        return True, False, result
    '''
def main():
    payload = dict (
        waf_host=dict(type='str',required=True),
        name=dict(type='str'),
        backup_type=dict(type='str', required=True)
    )

    choice_map={
        "full": configuration_export_create,
        "partial": configuration_export_create
    }

    module=AnsibleModule(argument_spec=payload)

    is_error,has_changed,result=choice_map.get(
        module.params['backup_type'])(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error executing this request", meta=result)

if __name__ == "__main__":
    main()