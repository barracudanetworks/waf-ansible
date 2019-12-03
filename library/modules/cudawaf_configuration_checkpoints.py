#! /usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019 Aravindan Anandan (aravindan@barracuda.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.cudawaf_utils import logger
from ansible.module_utils.cudawaf_utils import token
import json
import requests


def configuration_checkpoint_create(data):
    headers,waf_ip,waf_port,proto = token(data['waf_host'])
    config_check_point_name = data['name']
    config_checkpoint_get_url = proto+waf_ip+":"+waf_port+"/restapi/v3.1/configuration-checkpoints/"+config_check_point_name
    r = requests.get(config_checkpoint_get_url, headers=headers, verify=False)
    if r.status_code == 200:
        result={"status_code": r.status_code, "msg": "Checkpoint exists"}
        return False, False, result
    else:
        post_url = proto+waf_ip+":"+waf_port+"/restapi/v3.1/configuration-checkpoints"
        config_checkpoint_payload = {
            "name": data['name'],
            "comment": data['comment']
        }
        r=requests.post(post_url, headers=headers, data=json.dumps(config_checkpoint_payload), verify=False)
        if r.status_code == 201:
            result={"status_code": r.status_code, "msg": r.text}
            return False, True, result
        else:
            result={"status_code": r.status_code, "msg": r.text}
            return True, False, result

def configuration_checkpoint_delete(data=None):
    headers,waf_ip,waf_port,proto = token(data['waf_host'])
    config_check_point_name = data['name']
    delete_url = proto+waf_ip+":"+waf_port+"/restapi/v3.1/configuration-checkpoints/"+config_check_point_name
    r = requests.delete(delete_url, headers=headers, verify=False)
    if r.status_code == 200:
        result = {"status_code": r.status_code, "msg": r.text}
        return False, True, result
    else:
        result = {"status_code": r.status_code, "msg": r.text}
        return True, False, result


def main():
    payload = dict (
        waf_host=dict(type='str',required=True),
        state=dict(type='str', required=True),
        comment=dict(type='str'),
        name=dict(type='str', required=True),
    )

    choice_map={
        "present": configuration_checkpoint_create,
        "absent": configuration_checkpoint_delete,
    }
    module=AnsibleModule(argument_spec=payload)

    is_error,has_changed,result=choice_map.get(
        module.params['state'])(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error executing this request", meta=result)

if __name__ == "__main__":
    main()