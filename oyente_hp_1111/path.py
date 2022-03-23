#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
File: path.py
Author: heppen
Email: heppen@qq.com
Description: 符号执行过程中每一条路径的信息
"""


class Path(object):

    """Path类的实现"""

    def __init__(self, methodid, params, addrs, is_end):
        """初始化

        :methodid: str
        :gt: list
        :lt: list
        :is_zero: list
        :eq: list
        :jumpi_flag: list
        :is_end: 是否完整结束

        """
        self._methodid = methodid
        self._gt = params.gt_in_path
        self._lt = params.lt_in_path
        self._is_zero = params.iszero_in_path
        self._eq = params.eq_in_path
        self._jumpi_flag = params.jumpi_flags_in_path
        self._sstore = params.sstore_info_in_path
        self._event = params.event_info_in_path
        self._has_call = params.has_call_in_path
        self._addrs = addrs
        self._is_end = is_end

    def get_methodid(self):
        return self._methodid

    def get_gt(self):
        return self._gt

    def get_lt(self):
        return self._lt

    def get_is_zero(self):
        return self._is_zero

    def get_eq(self):
        return self._eq

    def get_jumpi_flag(self):
        return self._jumpi_flag

    def get_sstore(self):
        return self._sstore

    def get_event(self):
        return self._event

    def get_has_call(self):
        return self._has_call

    def get_addrs(self):
        return self._addrs

    def get_is_end(self):
        return self._is_end
