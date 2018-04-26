import requests
import json
import time
import pickle
import os
import threading
import smtplib
import math
import signal

# Declare global variables
_next_call = time.time()
_number_entry = None
_url = ''
_update_interval = ''
_smtp_server = ''
_smtp_port = None
_smtp_username = ''
_smtp_password = ''
_smtp_recipients = []
_thread_lock = threading.Lock()
_exit_event = threading.Event()


def write_log(log_entry):
    _thread_lock.acquire()
    try:
        log_file = open('vulinfo.log', 'a')
        log_file.write(log_entry)
        log_file.close()
    except:
        print("[!] Can not open log file")
    _thread_lock.release()

def print_vuln_entry(entry):
    print("CVE ID: {}".format(entry["cve_id"]))
    print("CWE ID: {}".format(entry["cwe_id"]))
    print("Summary: {}".format(entry["summary"]))
    print("CVSS Score: {}".format(entry["cvss_score"]))
    print("Exploit Count: {}".format(entry["exploit_count"]))
    print("Publish Date: {}".format(entry["publish_date"]))
    print("Update Date: {}".format(entry["update_date"]))
    print("URL: {}".format(entry["url"]))


def save_respond(decoded_resp):
    try:
        pklOut = open("data.plk", "wb")
        pickle.dump(decoded_resp, pklOut)
        pklOut.close()
    except pickle.PickleError as errPlk:
        print(errPlk)
        return -1
    return 0


def check_new_entry(decoded_resp):
    try:
        pklIn = open("data.plk", "rb")
        entryData = pickle.load(pklIn)
    except pickle.UnpicklingError as errPlk:
        print(errPlk)
        return -1

    if decoded_resp == entryData:
        return 0
    index = 0
    for entry in decoded_resp:
        if entryData[0] == entry:
            break
        else:
            index = index + 1
    return index


def send_mail(decoded_resp, index=0):
    if index == 0:
        global _number_entry
        index = _number_entry
    subject = "New CVE vulnerabilities on {}".format(time.ctime(time.time()))
    text = ''
    for i in range(0, index):
        text = text + "CVE ID: {}\n".format(decoded_resp[i]["cve_id"])\
                      + "CVSS Score: {}\n".format(decoded_resp[i]["cvss_score"])\
                      + "Summary: {}\n".format(decoded_resp[i]["summary"])\
                      + "URL: {}\n".format(decoded_resp[i]["url"])\
                      + "--------------------------------------------------------------------------\n"
    server = smtplib.SMTP(_smtp_server, _smtp_port)
    server.ehlo()
    server.starttls()
    server.login(_smtp_username, _smtp_password)
    body = '\r\n'.join(['To: %s' % ','.join(_smtp_recipients), 'From: %s' % _smtp_username, 'Subject: %s' % subject, '', text])
    try:
        server.sendmail(_smtp_username, _smtp_recipients, body)
    except:
        print('[!]{} -  Err - Mails can not be sent'.format(time.ctime(time.time())))
        server.quit()
        write_log('[!]{} -  Err - Mails can not be sent\n'.format(time.ctime(time.time())))
        return -1
    print('[-]{} - Alert mails has been sent'.format(time.ctime(time.time())))
    server.quit()
    write_log('[-]{} - Alert mails has been sent\n'.format(time.ctime(time.time())))
    return 0


def load_config():
    if not os.path.isfile("config.conf"):
        default_conf_file = open('config.conf', 'wb')
        default_conf = "{\n\"_number_entry\": 10,\n"  \
                       "\"cvss_score_min\": 1,\n"  \
                       "\"update_interval\": 10,\n"  \
                       "\"smtp_server\": \"smtp.gmail.com\",\n"  \
                       "\"smtp_port\":587,\n"  \
                       "\"smtp_username\": \"testmailpython3@gmail.com\",\n"  \
                       "\"smtp_password\": \"P@ssw0rd\",\n"  \
                       "\"smtp_recipients\": [\"tuanklnew@gmail.com\",\"13520981@gm.uit.edu.vn\", \"tuannguyentri95@gmail.com\"]\n}"
        default_conf_file.write(default_conf.encode())
        default_conf_file.close()
    conf_file = open('config.conf', 'rb')
    conf_data = conf_file.read()
    conf_file.close()
    try:
        conf_decoded = json.loads(conf_data.decode())
    except (ValueError, KeyError, TypeError):
        print("[!]{} - Parsing config file failed".format(time.ctime(_next_call - 10)))
        return -1

    # Create _url
    try:
        global _number_entry
        _number_entry = int(conf_decoded["number_entry"])
    except:
        _number_entry = 10
    try:
        cvss_score_min = int(conf_decoded["cvss_score_min"])
    except:
        cvss_score_min = 1
    global _url
    _url = 'http://www.cvedetails.com/json-feed.php?numrows={}&vendor_id=0&product_id=0&version_id=0&hasexp=0&opec=0&opov=0&opcsrf=0&opfileinc=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opginf=0&opdos=0&orderby=2&cvssscoremin={}'.format(_number_entry,cvss_score_min)

    # Check _update_interval
    try:
        global _update_interval
        _update_interval = int(conf_decoded["update_interval"])
    except:
        print("[!] _update_interval missing in config file - program will be stopped")
        return -1

    # Check _smtp_server
    try:
        global _smtp_server
        _smtp_server = conf_decoded["smtp_server"]
    except:
        print("[!] _smtp_server missing in config file - program will be stopped")
        return -1

    # Check _smtp_port:
    try:
        global _smtp_port
        _smtp_port = int(conf_decoded["smtp_port"])
    except:
        print("[!] _smtp_port missing in config file - program will be stopped")
        return -1

    # Check _smtp_username
    try:
        global _smtp_username
        _smtp_username = conf_decoded["smtp_username"]
    except:
        print("[!] _smtp_username missing in config file - program will be stopped")
        return -1

    # Check _smtp_password
    try:
        global _smtp_password
        _smtp_password = conf_decoded["smtp_password"]
    except:
        print("[!] _smtp_password missing in config file - program will be stopped")
        return -1

    # Check _smtp_recipients
    try:
        global _smtp_recipients
        _smtp_recipients = conf_decoded["smtp_recipients"]
    except:
        print("[!] _smtp_recipients missing in config file - program will be stopped")
        return -1
    return 0


def main_process():
    _next_call = math.ceil(time.time() / _update_interval) * _update_interval
    while not _exit_event.is_set():
        try:
            respond = requests.get(_url)
        except:
            print("[!] Connection has a problem!")
            break
        try:
            decoded = json.loads(respond.text)
        except (ValueError, KeyError, TypeError):
            print("[!]{} - JSON format error".format(time.ctime(_next_call)))

        else:
            print("[-]{} - Vulnerabilities entries have been updated - {}".format(time.ctime(_next_call),decoded[0]["cve_id"]))
            logThread = threading.Thread(target=write_log, args=["[-]{} - Vulnerabilities entries have been updated\n".format(time.ctime(_next_call))])
            logThread.start()
            if os.path.isfile("data.plk"):
                index = check_new_entry(decoded)
                if index < 0:
                    print("[!] - Error in reading data.plk")
                    os.remove("data.plk")
                    save_respond(decoded)
                    for entry in decoded:
                        print_vuln_entry(entry)
                        print("------------------------")
                    sendMailThread = threading.Thread(target=send_mail, args=[decoded])
                    sendMailThread.start()
                elif index != 0:
                    save_respond(decoded)
                    for i in range(0, index):
                        print_vuln_entry(decoded[i])
                        print("------------------------")
                    sendMailThread = threading.Thread(target=send_mail, args=[decoded, index])
                    sendMailThread.start()
            else:
                save_respond(decoded)
                for entry in decoded:
                    print_vuln_entry(entry)
                    print("------------------------")
                sendMailThread = threading.Thread(target=send_mail, args=[decoded])
                sendMailThread.start()
        _next_call = _next_call + _update_interval
        _exit_event.wait(_next_call - time.time())


def main():
    if load_config() < 0:
        print("[!] Load configuration file error")
        return -1
    timerThread = threading.Thread(target=main_process)
    try:
        timerThread.start()
    except:
        print("[!]{} - Main thread shutting down".format(time.ctime(time.time())))


def quit_program(signo, _frame):
    if signo == signal.SIGINT:
        sig = "Keyboard"
    else:
        sig = "OS"
    print("\n[-] Interrupted by {}, shutting down".format(sig))
    _exit_event.set()


print("  ______   ______  _   __     __           ___   __        __ ")
print(" / ___/ | / / __/ | | / /_ __/ /__  ___   / _ | / /__ ____/ /_")
print("/ /__ | |/ / _/   | |/ / // / / _ \(_-<  / __ |/ / -_) __/ __/")
print("\___/ |___/___/   |___/\_,_/_/_//_/___/ /_/ |_/_/\__/_/  \__/ \n\n")
print("NOTE: Press Ctrl + Break on Windows or Ctrl + C on Linux to stop program !!!\n\n")
for sig in ('SIGTERM', 'SIGINT'):
    signal.signal(getattr(signal, sig), quit_program);
main()
