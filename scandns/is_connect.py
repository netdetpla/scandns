# coding:utf-8
import os
import re
import subprocess
import log

separator = ';'
line = '\n'
APPSTATUS_PATH = '/tmp/appstatus'


def create_appstatus_file(appstatus_name):
    if not os.path.exists(APPSTATUS_PATH):  # 创建目录
        os.makedirs(APPSTATUS_PATH)
    f = open(os.path.join(APPSTATUS_PATH, appstatus_name), 'w+')
    with f:
        f.write('erro_reason:connect erro')
        f.close()


def NetCheck(ip):
    try:
        p = subprocess.Popen(["ping -c 10 -w 1 " + ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out = str(p.stdout.read())
        # err=p.stderr.read()
        regex = re.compile('100% packet loss')
        # print out
        # print regex
        # print err
        if len(regex.findall(out)) == 0:

            return True
        else:

            return False
    except:
        return 'ERR'


def Update():
    i = 0
    while i < 6:
        flag = NetCheck('114.114.114.114')
        if not flag:
            flag = NetCheck('8.8.8.8')
        else:
            return
        if not flag:
            pass
        else:
            return
        i = i + 1
    log.connect_fail()
    log.write_error_to_appstatus('Can not connect to the Internet.', 2)


if __name__ == '__main__':
    NetCheck('114.114.114.114')
    print("hi")
    Update()
    print("hi")
