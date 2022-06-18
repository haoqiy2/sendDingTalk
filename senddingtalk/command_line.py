# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals

import python_atom_sdk as sdk
from .error_code import ErrorCode
import json
import requests
import hmac
import hashlib
import base64
import time
try:
    import urllib.parse as urllib
except ImportError:
    import urllib


err_code = ErrorCode()


def exit_with_error(error_type=None, error_code=None, error_msg="failed"):
    """
    @summary: exit with error
    """
    if not error_type:
        error_type = sdk.OutputErrorType.PLUGIN
    if not error_code:
        error_code = err_code.PLUGIN_ERROR
    sdk.log.error("error_type: {}, error_code: {}, error_msg: {}".format(error_type, error_code, error_msg))

    output_data = {
        "status":    sdk.status.FAILURE,
        "errorType": error_type,
        "errorCode": error_code,
        "message":   error_msg,
        "type":      sdk.output_template_type.DEFAULT
    }
    sdk.set_output(output_data)

    exit(error_code)


def exit_with_succ(data=None, quality_data=None, msg="run succ"):
    """
    @summary: exit with succ
    """
    if not data:
        data = {}

    output_template = sdk.output_template_type.DEFAULT
    if quality_data:
        output_template = sdk.output_template_type.QUALITY

    output_data = {
        "status":  sdk.status.SUCCESS,
        "message": msg,
        "type":    output_template,
        "data":    data
    }

    if quality_data:
        output_data["qualityData"] = quality_data

    sdk.set_output(output_data)

    sdk.log.info("finish")
    exit(err_code.OK)


class SendDingTalk(object):

    def __init__(self, appkey, appsecret, sign):
        self.appkey = appkey
        self.appsecret = appsecret
        self.sign = sign

    def exec_sign(self):
        timestamp = str(int(time.time() * 1000))
        secret = self.sign
        secret_enc = secret.encode('utf-8')
        string_to_sign = '{}\n{}'.format(timestamp, secret)
        string_to_sign_enc = string_to_sign.encode('utf-8')
        hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
        sign = urllib.quote_plus(base64.b64encode(hmac_code))
        return timestamp, sign

    def get_token(self):
        api_url = "https://oapi.dingtalk.com/gettoken?appkey={appkey}&appsecret={appsecret}".format(appkey=self.appkey,
                                                                                                appsecret=self.appsecret)
        res = requests.get(api_url)
        access_token = json.loads(res.content).get("access_token")
        return access_token

    def get_user_info(self, token):
        ret = dict()
        api_url = "https://oapi.dingtalk.com/topapi/user/listsimple?access_token={token}".format(token=token)
        json_text = {
            "dept_id": 1,
            "cursor": 0,
            "size": 100,
        }
        resp = self.post_req(api_url, json_text)
        res = json.loads(resp.content)
        res_list = res.get("result").get("list")
        for u_obj in res_list:
            # try:
            #     if isinstance(u_obj['name'], unicode):
            #         name = u_obj['name'].encode("utf-8")
            #         user_id = u_obj['userid'].encode("utf-8")
            #     else:
            #         name = u_obj['name']
            #         user_id = u_obj['userid']
            # except NameError:
            #     paas
            name = u_obj['name']
            user_id = u_obj['userid']
            ret[name] = user_id
        return ret

    def get_user_mobile(self, token, userid):
        api_url = "https://oapi.dingtalk.com/topapi/v2/user/get?access_token={token}".format(token=token)
        json_text = {
            "userid": userid
        }
        resp = self.post_req(api_url, json_text)
        res = json.loads(resp.content)
        return res.get('result').get('mobile')

    def msg(self, token, text, msg_type, userid=[], mobile=[], title="", send_all=False):
        timestamp, sign = self.exec_sign()
        api_url = "https://oapi.dingtalk.com/robot/send?access_token={}&timestamp={}&sign={}".format(token, timestamp,
                                                                                                    sign)
        json_text = {
            "at": {
                "atMobiles": mobile,
                "atUserIds": userid,
                "isAtAll": send_all
            },
            "msgtype": msg_type,  # 信息格式
            "text": {
                "content": text
            }
        }
        if msg_type == "markdown":
            for user in mobile:
                if mobile.index(user) == 0:
                    text += "\n" + "@" + user
                else:
                    text += "@" + user
            if send_all:
                text += "\n" + "@all"
            json_text = {
                "msgtype": msg_type,
                "markdown": {
                    "title": title,
                    "text": text
                },
                "at": {
                    "atMobiles": mobile,
                    "atUserIds": userid,
                    "isAtAll": send_all,
                }
            }
        sdk.log.info("json_text is {}".format(json_text))
        self.post_req(api_url, json_text)

    @staticmethod
    def post_req(url, json_text):
        headers = {'Content-Type': 'application/json;charset=utf-8'}
        resp = requests.post(url, json.dumps(json_text), headers=headers)
        if resp.status_code != 200:
            exit_with_error(error_type=sdk.output_error_type.THIRD_PARTY,
                            error_code=err_code.THIRD_SYSTEM_ERROR,
                            error_msg=resp.text)
        res = resp.json()
        if res.get('errcode') != 0:
            exit_with_error(error_type=sdk.output_error_type.THIRD_PARTY,
                            error_code=err_code.THIRD_SYSTEM_ERROR,
                            error_msg=res.get("errmsg"))
        return resp


def main():
    """
    @summary: main
    """
    sdk.log.info("enter main")

    # 输入
    input_params = sdk.get_input()

    # 获取名为input_demo的输入字段值
    sign = input_params.get("sign", None)
    sdk.log.info("sign is {}".format(sign))
    if not sign:
        exit_with_error(error_type=sdk.output_error_type.USER,
                        error_code=err_code.USER_CONFIG_ERROR,
                        error_msg="sign is None")
    webhook = input_params.get("webhook", None)
    sdk.log.info("webhook is {}".format(webhook))
    if not webhook:
        exit_with_error(error_type=sdk.output_error_type.USER,
                        error_code=err_code.USER_CONFIG_ERROR,
                        error_msg="webhook is None")
    msgtype = input_params.get("msgtype", None)
    sdk.log.info("msgtype is {}".format(msgtype))
    if not msgtype:
        exit_with_error(error_type=sdk.output_error_type.USER,
                        error_code=err_code.USER_CONFIG_ERROR,
                        error_msg="msgtype is None")
    content = input_params.get("t_content") if msgtype == "text" else input_params.get("m_content")
    if not content:
        exit_with_error(error_type=sdk.output_error_type.USER,
                        error_code=err_code.USER_CONFIG_ERROR,
                        error_msg="content is None")
    userid = input_params.get("userid", "")
    sdk.log.info("提醒人员：{}".format(userid))
    appkey = sdk.get_sensitive_conf("appkey")
    appsecret = sdk.get_sensitive_conf("appsecret")
    title = input_params.get("title", "")
    if not appkey:
        exit_with_error(error_type=sdk.output_error_type.USER,
                        error_code=err_code.USER_CONFIG_ERROR,
                        error_msg="appkey is None")
    if not appsecret:
        exit_with_error(error_type=sdk.output_error_type.USER,
                        error_code=err_code.USER_CONFIG_ERROR,
                        error_msg="appkey is None")

    # 插件逻辑
    try:
        import sys
        reload(sys)
        sys.setdefaultencoding('utf8')
    except NameError:
        pass
    send_all = False
    userids = []
    mobiles = []
    send = SendDingTalk(appkey, appsecret, sign)
    access_token = send.get_token()
    user_info_list = send.get_user_info(access_token)
    # try:
    #     if isinstance(userid, unicode):
    #         userid = userid.encode("utf-8")
    #         sdk.log.info("3 userid type is {}".format(type(userid)))
    # except NameError:
    #     pass
    userid_list = userid.split(',') if userid else []
    if "@all" in userid_list:
        send_all = True
    else:
        for user in userid_list:
            if userid_list.index(user) == 0:
                uid = user_info_list.get(user)
                userids.append(uid)
                mobile = send.get_user_mobile(access_token, uid)
                mobiles.append(mobile)
            else:
                uid = user_info_list.get(user)
                userids.append(uid)
                mobile = send.get_user_mobile(access_token, uid)
                mobiles.append(mobile)
    send.msg(webhook, content, msgtype, userids, mobiles, title, send_all)

    # 插件执行结果、输出数据
    data = {
        "output_demo": {
            "type": sdk.output_field_type.STRING,
            "value": "test output"
        }
    }
    exit_with_succ(data=data)

    exit(0)
