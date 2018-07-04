
import time
import threading
import socket
import json
import os


lock=threading.Lock()

def is_json(myjson):
    try:
        json.loads(myjson)
    except ValueError:
        return False
    return True

class processManager:

    result_num=0
    sendednum=0
    updateip=""
    updateport=7011
    taskid=""
    checkt=""
    stop=False
    id_uuid=""
    image_type=""

    def __init__(self):
        self.result_num = 0
        self.sendednum = 0
        self.updateip = "10.96.129.4"
        self.updateport = 7011
        self.stop=False
        self.id_uuid=""
        self.image_type="scanInfo"
        if os.path.isfile('/tmp/conf/sid'):
            with open('/tmp/conf/sid', 'r') as f:
                self.sid = f.read()
        else:
            self.sid = ''



    def set_taskid(self,taskid,id_uuid):
        self.taskid=taskid.split('-')[-1]
        self.id_uuid=id_uuid
        self.checkt = threading.Thread(target=self.checkP)
        self.checkt.setDaemon(True)
        self.checkt.start()
    def resultCreate(self):
        lock.acquire()
        self.result_num = self.result_num + 1
        lock.release()

    def getUdateJson(self,addnum,final):
        resultjson={}
        resultjson["taskid"]=self.taskid
        resultjson["addnum"]=addnum
        resultjson["id_uuid"]=self.id_uuid
        resultjson["image_type"] =self.image_type
        resultjson["final"] = final
        if self.sid != '':
            resultjson["sid"] = self.sid
        return resultjson

    def sendjason(self,addnum,final):

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = self.updateip
        port = self.updateport
        updatejason=self.getUdateJson(addnum,final)
        updatejasonstr=json.dumps(updatejason)
        try:
            #s.connect((ip, port))
            #s.send(updatejasonstr.encode())
            s.sendto(updatejasonstr.encode(), (ip, port))
            s.close()
        except Exception as e:
            print("send erro to : ip "+ip+" port "+str(port)+" "+str(e))
            s.close()
        return


    def checkP(self):
        while True:
            if self.stop==True:
                break
            # time.sleep(2)
            result=self.result_num
            send=self.sendednum
            addnum=result-send
            print("result"+str(result)+" send"+str(send)+" addnum"+str(addnum))
            self.sendjason(addnum,False)
            self.sendednum=result
            time.sleep(5)


    def final_send(self):
        time.sleep(10)
        self.stop=True
        time.sleep(10)
        result = self.result_num
        send = self.sendednum
        addnum = result - send
        print("result" + str(result) + " send" + str(send) + " addnum" + str(addnum))
        self.sendjason(addnum,True)

if __name__ == '__main__':
    processer = processManager()
    processer.set_taskid(taskid, "zyqtest")
    processer.resultCreate()
    processer.final_send()


