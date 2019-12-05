#! /usr/bin/python

from ansible.module_utils.basic import AnsibleModule
import json
from urllib.parse import urlparse
import requests
from http_basic_auth import generate_header, parse_header
import os
import logging


def logger():
    logging.basicConfig(filename="logs/newfile.log", 
                        format='%(asctime)s %(message)s', 
                        filemode='w')
    logger=logging.getLogger()
    logger.setLevel(logging.DEBUG)
    return logger

def token(waf_host):

    logs=logger()
        
    waf_info=open('wafcreds.json','r')
    waf_info_dict=json.load(waf_info)
    waf=(waf_info_dict[waf_host])
        
    if (waf["secure"]) == "yes":
        logs.debug("HTTPS Protocol will be used for all transactions")
        login_proto="https://"
    if (waf["secure"]) == "no":
        logs.debug("HTTP Protocol will be used for all transactions")
        login_proto="http://"
    else:
        logs.debug("Configure the secure attribute as 'yes' or 'no'. Defaulting to HTTPS")
        login_proto="https://"
        pass

    waf_login_ip=(waf["waf_ip"])
    logs.debug("waf host is "+waf_login_ip)
    waf_login_port=(waf["waf_port"])
    url=login_proto+waf_login_ip+":"+waf_login_port+"/restapi/v3/login"

    headers={"Content-Type":"application/json"}
    data={"username":waf["waf_admin"],"password":waf["waf_password"]}
        
    login_request=requests.post(url,data=json.dumps(data), headers=headers, verify=False)
    token_str=login_request.text.split(':')
    token1 = token_str[1].replace('"','').rstrip('}')+':'
    basic_auth_token=generate_header('',token1)
    req_headers={"Content-Type":"application/json",'Authorization': basic_auth_token}
    return req_headers, waf_login_ip, waf_login_port, login_proto