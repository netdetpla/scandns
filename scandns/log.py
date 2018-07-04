#!python2
# coding=utf-8
import time
import os
import sys

import config

separator = ';'
line = '\n'
LOG_PATH = '/tmp/log'


# def start_log(task_id):
#     """查找指定task id的最新的log文件，若最新的log文件超过7M或不存在指定task id的日志文件
#     则新建log文件。
#     """
#     global task_log
#     log_path = '/tmp/log'
#     if not os.path.exists(log_path):  # 创建目录
#         os.makedirs(log_path)
#
#     log_files = [f for f in os.listdir(log_path)
#                  if os.path.isfile(os.path.join(log_path, f))]
#     pattern = re.compile('^' + task_id + '_(.*)')
#     log_files = [f for f in log_files if pattern.match(f)]
#
#     if not log_files:  # 没有对应任务的日志文件则新建
#         log_file_path = os.path.join(log_path, task_id + '_0000.log')
#     else:
#         log_file_path = os.path.join(log_path, log_files[-1])
#         if utils.get_file_size(log_file_path) >= 7:  # 文件大小超过7M则新建
#             file_id = pattern.match(log_files[-1]).group()[0]
#             log_file_path = os.path.join(log_path, task_id + '_' +
#                                          utils.number_file_id(file_id) + '.log')
#     with open(log_file_path, 'a') as f:
#         f.write(utils.print_format_time() + separator + 'INFO' + separator +
#                 'task start' + line)
#     return log_file_path
def create_log_file(log_name):
    if not os.path.exists(LOG_PATH):  # 创建目录
        os.makedirs(LOG_PATH)
    with open(os.path.join(LOG_PATH, log_name), 'w+'):
        pass


def task_start():
    log_name = str(int(time.time())) + '-1100.log'
    create_log_file(log_name)


def get_conf():
    log_name = str(int(time.time())) + '-1200.log'
    create_log_file(log_name)


def get_conf_success():
    log_name = str(int(time.time())) + '-1202.log'
    create_log_file(log_name)


def get_conf_fail():
    log_name = str(int(time.time())) + '-1201.log'
    create_log_file(log_name)


def task_run():
    log_name = str(int(time.time())) + '-1300.log'
    create_log_file(log_name)


def task_run_success():
    log_name = str(int(time.time())) + '-1301.log'
    create_log_file(log_name)


def task_run_fail():
    log_name = str(int(time.time())) + '-1302.log'
    create_log_file(log_name)


def write_result():
    log_name = str(int(time.time())) + '-1400.log'
    create_log_file(log_name)


def write_result_success():
    log_name = str(int(time.time())) + '-1401.log'
    create_log_file(log_name)


def write_result_fail():
    log_name = str(int(time.time())) + '-1402.log'
    create_log_file(log_name)


def task_success():
    log_name = str(int(time.time())) + '-1102.log'
    create_log_file(log_name)


def task_fail():
    log_name = str(int(time.time())) + '-1101.log'
    create_log_file(log_name)


def connect_fail():
    log_name = str(int(time.time())) + '-1111.log'
    create_log_file(log_name)


# 错误写入appstatus
def write_error_to_appstatus(error_message, error_code):
    print(error_message)
    task_fail()
    with open(os.path.join(config.APP_STATUS, '1'), 'w') as f:
        f.write(error_message)
    sys.exit(error_code)


# 任务完成写入appstatus
def write_success_to_appstatus():
    task_success()
    with open(os.path.join(config.APP_STATUS, '0'), 'w') as f:
        f.write('success')
# def end_log(task_log, task_id):
#     """关闭日志文件"""
#     with open(task_log, 'a') as f:
#         f.write(utils.print_format_time() + separator + 'INFO' + separator +
#                 'task end' + line)
#
#
# def debug_log(log_content, log_file):
#     """调试日志输出"""
#     with open(log_file, 'a') as f:
#         f.write(utils.print_format_time() + separator + 'DEBUG' + separator +
#                     log_content + line)
#
#
# def info_log(log_content, log_file):
#     """通常日志输出"""
#     with open(log_file, 'a') as f:
#         f.write(utils.print_format_time() + separator + 'INFO' + separator +
#                     log_content + line)
#
#
# def warning_log(log_content, log_file):
#     """警告日志输出"""
#     with open(log_file, 'a') as f:
#         f.write(utils.print_format_time() + separator + 'WARNING' + separator +
#                     log_content + line)
#
#
# def error_log(log_content, log_file):
#     """错误日志输出"""
#     with open(log_file, 'a') as f:
#         f.write(utils.print_format_time() + separator + 'ERROR' + separator +
#                     log_content + line)
