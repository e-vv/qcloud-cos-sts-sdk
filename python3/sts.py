# -*- coding:utf-8 -*-

import hashlib, base64, hmac, time
import urllib.request
from functools import reduce

import requests

class Sts:

    POLICY = r'''{"statement": [{"action": ["name/cos:*"],"effect": "allow","resource":"*"}],"version": "2.0"}'''
    DURATION = 1800

    def __init__(self, config = {}):
        if 'policy' in config:
            self.policy = config.get('policy')
        else:
            self.policy = self.POLICY

        if 'duration_in_seconds' in config:
            self.duration = config.get('duration_in_seconds')
        else:
            self.duration = self.DURATION

        self.secret_id = config.get('secret_id')
        self.secret_key = config.get('secret_key')
        self.proxy = config.get('proxy')

    def get_credential(self):
        try:
            import ssl
        except ImportError:
            print("error: no ssl support")

        policy = self.policy
        secret_id = self.secret_id
        secret_key = self.secret_key
        duration = self.duration
        real_url = self.__get_url(policy, duration, secret_id, secret_key)
        try:
            response = requests.get(real_url, proxies=self.proxy)
            return response
        except urllib.request.HTTPError as e:
            print ("error with : " ,e)

    def __get_url(self, policy, duration, secret_id, secret_key, name=''):
        method = 'GET'
        path = 'sts.api.qcloud.com/v2/index.php'
        scheme = 'https://'

        params = {'Action': 'GetFederationToken',
                  'codeMode': 'base64',
                  'Nonce': str(int(time.time()) % 1000000),
                  'Region': '',
                  'RequestClient': 'tac-storage-python',
                  'SecretId': secret_id,
                  'Timestamp': str(int(time.time())),
                  'name': name,
                  'policy': policy,
                  'durationSeconds': str(duration)
                  }

        sign = self.__encrypt(method, path, params)
        params['Signature'] = sign.decode()
        flat_params_str = Tools.flat_params(params)

        return scheme + path + '?' + flat_params_str


    def __encrypt(self, method, path, key_values):
        source = Tools.flat_params(key_values)
        source = method + path + '?' + source
        signTmp = hmac.new(self.secret_key.encode('utf-8'), source.encode('utf-8'), hashlib.sha1).digest()
        sign = base64.b64encode(signTmp)
        return sign



class Tools(object):
# 生成 URL QueryString 的格式
    @staticmethod
    def _flat_key_values(a):
        return a[0] + '=' + a[1]

    @staticmethod
    def _link_key_values(a, b):
        return a + '&' + b

    @staticmethod
    def flat_params(key_values):
        key_values = sorted(key_values.items(), key=lambda d: d[0])
        return reduce(Tools._link_key_values, map(Tools._flat_key_values, key_values))