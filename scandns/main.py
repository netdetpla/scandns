import base64
import os
import sys
import subprocess
import json
import traceback
import xml.etree.ElementTree as ET
import config
import urllib.request as urllib2
import log
import is_connect
import process

task_id = ''
subtask_id = ''
uuid = ''
task_name = ''
# 白名单(0) or 云平台(1)
platform = ''


# 获取配置
def get_config():
    global task_id
    global task_name
    global uuid
    global platform

    with open(config.CONFIG_FILE, 'r') as f:
        task = str(base64.b64decode(f.read())).split(';')
    print(task)
    task_id = task[0][2:]
    uuid = task[4][:-1]
    task_name = task[1]
    platform = task[2]
    with open(config.TARGET_LIST, 'w') as dns_f:
        dns_f.write(task[3])
    if os.path.getsize(config.TARGET_LIST) <= 0:
        e = 'No target IP.'
        log.get_conf_fail()
        log.write_error_to_appstatus(e, 3)

        
# zdns测试dns服务器功能
def zdns_test():
    command = 'echo {random_string} | zdns A --name-servers={ip}:53 --output-file={output_file} -retries 1 -timeout 3'
    with open(config.DNS_LIST, 'r') as f:
        ip_list = f.read().split('\n')
    ips_for_nmap = []
    for ip in ip_list:
        subprocess.call([command.format(
            random_string='aaa',
            ip=ip,
            output_file=config.ZDNS_FILE
        )], shell=True)
        with open(config.ZDNS_FILE, 'r') as f:
            zdns_result = f.read()
        if 'TIMEOUT' not in zdns_result:
            ips_for_nmap.append(ip)
        os.remove(config.ZDNS_FILE)
    with open(config.DNS_LIST, 'w') as f:
        f.write('\n'.join(ips_for_nmap))


# 使用masscan扫描，确定开放53端口的目标
def masscan(mac):
    with open(config.MASSCAN_JSON, 'w') as f:
        f.write('')
    if platform == '1':
        process = os.popen("route | grep '172' | grep 'tap' |head -n 1| awk '{print $8}' ")  # return file
        output = process.read()
        output = ' -e ' + output[:-1]
        process.close()
    else:
        output = ''
    command = '{masscan} -iL {target_list} -p53,U:53 --rate 1000{output} --exclude 10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,127.0.0.1/8,0.0.0.0/8 --wait=0 -oJ {mid_json}'.format(
        masscan=config.MASSCAN,
        target_list=config.TARGET_LIST,
        output=output,
        mid_json=config.MASSCAN_JSON
    )
    print(command)
    subprocess.call([command], shell=True)
    dns = ''
    with open(config.MASSCAN_JSON, 'r') as f:
        temp = f.read().replace(" ", "").replace("\n", "")
        print('temp: ' + temp)
    if len(temp):
        masscan_json = json.loads(temp[:-2] + temp[-1])
    else:
        masscan_json = []
    for item in masscan_json:
        dns += (item['ip'] + '\n')
    with open(config.DNS_LIST, 'w') as f:
        f.write(dns)
    with  open(config.DNS_LIST, 'r') as f:
        print(f.read())


def arp():
    try :
        subprocess.call('arp ethi')
    except Exception as e:
        pass
    try :
        p = subprocess.Popen("arp | grep -v HWaddress | awk '{print $3}'",stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out = str(p.stdout.read())
        return out
    except Exception as e :
        return str(e)


# 使用nmap扫描详细信息
def nmap(mac):
    print('nmap: ' + 'nmap -sUS -p53 --script dns-nsid --script=dns-recursion -iL ' +
          config.DNS_LIST + ' -oX ' + config.NMAP_XML)
    subprocess.call(['nmap -sUS -p53 --script dns-nsid --script=dns-recursion -iL ' +
                     config.DNS_LIST + ' -oX ' + config.NMAP_XML], shell=True)
    if os.path.getsize(config.NMAP_XML) > 0:
        with open(config.NMAP_XML, 'r') as f:
            xml = ET.ElementTree(file=f)
    else:
        return ''
    result = ''
    for host in xml.findall('.//host'):
        ip = host.find('./address').attrib['addr']
        tcp_status = host.find('.//port[@protocol=\'tcp\']/state').attrib['state']
        udp_status = host.find('.//port[@protocol=\'udp\']/state').attrib['state']
        recursion_ele = host.find('.//script[@id=\'dns-recursion\']')
        recursion = '0'
        if recursion_ele is not None:
            if 'Recursion appears to be enabled' in recursion_ele.attrib['output']:
                recursion = '1'
        version_ele = host.find('.//script[@id=\'dns-nsid\']/elem')
        version = 'none'
        if version_ele is not None and version_ele.text is not None:
            version = version_ele.text
        result += (','.join([ip, tcp_status, udp_status, recursion, version]) + "\n")

    print('result: ' + result)
    return result


if __name__ == '__main__':
    log.task_start()
    try:
        os.makedirs(config.LOG_FILE)
    except FileExistsError:
        pass
    try:
        os.makedirs(config.APP_STATUS)
    except FileExistsError:
        pass
    try:
        os.makedirs(config.RESULT_FILE)
    except FileExistsError:
        pass
    # 判断网络
    # if not is_connect.NetCheck('114.114.114.114'):
    #     log.task_fail()
    #     log.write_result_fail()
    #     e = 'Can not connect to the Internet.'
    #     print(e)
    #     write_error_to_appstatus(e)
    #     sys.exit(-1)
    is_connect.Update()
    try:
        ex_ip = urllib2.urlopen("http://ip.6655.com/ip.aspx").read().decode()
    except:
        ex_ip = ''
    if ex_ip is '':
        log.task_fail()
        log.write_result_fail()
        e = 'Can not get external IP address.'
        print(e)
        log.write_error_to_appstatus(e, 2)
    # 获取配置
    log.get_conf()
    try:
        get_config()
        log.get_conf_success()
    except Exception as e:
        log.get_conf_fail()
        log.write_error_to_appstatus(str(e), -1)
    # 计次初始化
    processer = process.processManager()
    prtaskid=task_id.split("-")
    try:
        prtaskid=prtaskid[-1]
    except:
        prtaskid=task_id
    processer.set_taskid(prtaskid, uuid)
    # 执行任务
    log.task_run()
    try:
        mac = arp()
        print(mac)
        masscan(mac)
        zdns_test()
        result = nmap(mac)
        log.task_run_success()
    except Exception as e:
        traceback.print_exc()
        result = ''
        log.task_run_fail()
        log.write_error_to_appstatus(str(e), -1)
    # 计次结束
    processer.resultCreate()
    processer.final_send()
    # 写结果
    log.write_result()
    result = ','.join([task_id, task_name, subtask_id, ex_ip]) + "\n" + result+""
    try:
        with open(os.path.join(config.RESULT_FILE, task_id + '.result'), 'w') as f:
            f.write(result)
        log.write_result_success()
    except Exception as e:
        traceback.print_exc()
        log.write_result_fail()
        log.write_error_to_appstatus(str(e), -1)
    log.write_success_to_appstatus()
