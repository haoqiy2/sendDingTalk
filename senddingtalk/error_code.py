# -*- coding: utf-8 -*-


class ErrorCode(object):
    OK = 0                        # 无异常
    PLUGIN_ERROR = 2199001        # 插件自身异常
    USER_CONFIG_ERROR = 2199002   # 用户配置有误
    THIRD_SYSTEM_ERROR = 2199003  # 外部API调用失败

