from django.shortcuts import render
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage
from .forms import MalUrlForm

import urllib.request as urllib
import os
import re
import json
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
import requests, time
import sys
import subprocess
from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseNotFound
import hashlib
import base64, codecs, time
from django.urls import reverse
from .models import Post
import sqlite3

from webapp.forms import *
connection = sqlite3.connect('./db.sqlite3')
BASE_DIR = os.getcwd()

apikey =  os.environ.get('API_KEY')
apikey= "6af39ae43ef096dbac787cdc0208f7669dc604821d417399a379fcd2759151ea"
API_KEY="6af39ae43ef096dbac787cdc0208f7669dc604821d417399a379fcd2759151ea"

def error_500(request,exception=None):
    return render(request, "urlerror.html", {})
    
def error_404(request,exception=None):
    return render(request, "urlerror.html", {})

        

def is_valid_url(url):
    validate = URLValidator()
    try:
        validate(url)
        return True
    except ValidationError:
        return False 

def file_download(request, hash):
    print(request)
    print(hash)
    fs = FileSystemStorage()
    filename = BASE_DIR+'/media/b/'+ hash 
    if fs.exists(filename):
        with fs.open(filename) as pdf:
            response = HttpResponse(pdf, content_type='application/pdf')
            response['Content-Disposition'] = 'attachment; filename='+hash
            return response
    else:
        print("None")
        return HttpResponseRedirect(reverse('index'))

def malurl_form(request):
    return render(request, 'index.html')


def url_upload(request):
    f = open('mal_test.txt','w')
    if request.method == 'POST':
        form = MalUrlForm(request.POST)

        if form.is_valid():
            geturl = request.POST.get("url", "")
            if is_valid_url(geturl)==False:
               return render(request, 'urlerror.html')
            cmd = "curl -s --request GET --url 'https://www.virustotal.com/vtapi/v2/url/report?apikey="+apikey+"&resource="+geturl+"'"
            resp = os.popen(cmd)
            output = resp.read()
            #changing start
            my_apikey = "6af39ae43ef096dbac787cdc0208f7669dc604821d417399a379fcd2759151ea"
            my_url = geturl
            url_scan = 'https://www.virustotal.com/vtapi/v2/url/scan'
            scan_params = {'apikey': my_apikey, 'url': my_url}
            scan_response = requests.post(url_scan, data=scan_params)
 
            print('Virustotal URL SCAN START (60 Seconds Later) : ', my_url, '\n')

            #time.sleep(60)

            url_report = 'https://www.virustotal.com/vtapi/v2/url/report'
            report_params = {'apikey': my_apikey, 'resource': my_url}
            report_response = requests.get(url_report, params=report_params)
            report = report_response.json()
            report_scan_date = report.get('scan_date')
            report_scan_result = report.get('scans')
            report_scan_venders = list(report['scans'].keys())
            num = 1
            print(report.get('verbose_msg','\n'))
            print('scan date: ',report_scan_date)

            try:
                imprint = json.loads(output)['positives']
            except:
                return render(request, 'urlerror.html')
            print(imprint)
            if imprint==1:

               result2="주의가 필요한 사이트입니다."
               result4="<발견된 Malware>"
               result5="해당 사이트로 이동하기"
               re="progress-bar progress-bar-warning progress-bar-striped active" 
               re1="100"
               re2='warning'
               k=0
               for vender in report_scan_venders:
                    outputs=report_scan_result[vender]
                    outputs_keys = report_scan_result[vender].get('result')
                    if(outputs_keys=="malware site" or outputs_keys=="malicious site"):
                        k+=1
                        if (int(imprint) == int(k)) :
                            result3=str(vender)
                            f.write(result3)
                        else:
                            result3=str(vender)+", "
                            f.write(result3)
            elif imprint>1:

               result2="위험한 사이트입니다."
               result4="<발견된 Malware>"
       
               result5=""
               my_url=""
               re="progress-bar progress-bar-danger progress-bar-striped active" 
               re1="100"
               re2='danger'
               #changing start
               #img_color = Image.open('./멀웨어.png')
               #img_co=mpimg.imread('mal')
               #img_ok=plt.imshow(img_co)
               #changing end
               k=0
               for vender in report_scan_venders:
                    outputs=report_scan_result[vender]
                    outputs_keys = report_scan_result[vender].get('result')
                    if(outputs_keys=="malware site" or outputs_keys=="malicious site" or outputs_keys=="phishing site"):
                        k+=1
                        if (int(imprint) == int(k)) :
                            result3=str(vender)
                            f.write(result3)
                        else:
                            result3=str(vender)+", "
                            f.write(result3)

            else:
 
               result2="안전한 사이트입니다."
               result4=""
               result5="해당 사이트로 이동하기"
               re="progress-bar progress-bar-success progress-bar-striped active"
               re1="100"
               re2='safety'

            f = open('mal_test.txt','r')
            line1 = f.read()
            return render(request, 'url_upload.html', 
            {'result2':result2,'line1':line1,'result4':result4,'imprint':imprint,'result5':result5,'my_url':my_url,'re':re,'re1':re1,'re2':re2})
    else:
        form = MalUrlForm()
    f.close()
    return render(request, 'url_upload.html', {'form': form})   

#changing start
def upload(request):
    return render(request,'upload.html')

def upload(request):
    url_check= '123'
    context = {}
    f2 = open('mal_file.txt','w')
    if request.method == 'POST':
        uploaded_file = request.FILES['document']
        fs = FileSystemStorage()
        name = fs.save(uploaded_file.name, uploaded_file)
        context['url'] = fs.url(name)
        file = uploaded_file.name
        files = {'file': (file, open(file, 'rb'))}
        url_scan = 'https://www.virustotal.com/vtapi/v2/file/scan'
        url_scan_params = {'apikey': apikey}
        response_scan = requests.post(url_scan, files=files, params=url_scan_params)
        result_scan = response_scan.json()
        scan_resource = result_scan['resource']
        print('Virustotal FILE SCAN START (60 Seconds Later) : ', file, '\n')
        url_report = 'https://www.virustotal.com/vtapi/v2/file/report'
        url_report_params = {'apikey': apikey, 'resource': scan_resource}
        response_report = requests.get(url_report, params=url_report_params)
        report = response_report.json()
        report_scan_date = report.get('scan_date')
        report_scan_sha256 = report.get('sha256')
        report_scan_md5 = report.get('md5')
        report_scan_result = report.get('scans')
        report_scan_vendors = list(report['scans'].keys())
        report_scan_vendors_cnt = len(report_scan_vendors)
        url_check=file
        num = 1
        print(report.get('verbose_msg'), '\n')
        time.sleep(1)
        print('Scan Date (UTC) : ', report_scan_date)
        print('Scan File SHA256 : ', report_scan_sha256)
        print('Scan File MD5 : ', report_scan_md5)
        print('Scan File Vendor CNT : ', report_scan_vendors_cnt, '\n')

        time.sleep(2)
        k=0
        for vendor in report_scan_vendors:
            outputs = report_scan_result[vendor]
            outputs_result = report_scan_result[vendor].get('result')
            outputs_version = report_scan_result[vendor].get('version')
            outputs_detected = report_scan_result[vendor].get('detected')
            outputs_update = report_scan_result[vendor].get('update')
            #멀웨어 있는 아이를 찾아야 되니깐 True로 바꾸기!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            if(outputs_detected == True):
                k+=1
                if(int(report_scan_vendors_cnt) == int(k)):
                    result3 = str(vendor)
                    f2.write(result3)
                else:
                    result3 = str(vendor)+","
                    f2.write(result3)
            print('No', num,
                'Vendor Name :', vendor,
                ', Vendor Version :', outputs_version,
                ', Scan Detected :', outputs_detected,
                ', Scan Result :', outputs_result)
            num = num + 1
    f2 = open('mal_file.txt','r')
    line2 = f2.read()
    f2.close()

    if(url_check == '123'):
        return render(request,'upload.html',context)
        
    else:
        if line2=='':
            re="progress-bar progress-bar-success progress-bar-striped active"
            re1="100"
            re2='safety'
            line2='탐지된 malware 없음'
        else:
            re="progress-bar progress-bar-danger progress-bar-striped active" 
            re1="100"
            re2='danger'
        return render(request,'upload.html',{'context':uploaded_file.name,'line2':line2,'re':re,'re1':re1,'re2':re2})
  
    #return render(request,'upload.html',context)
#changing end

#아름이가 추가한 코드 잠깐 주석----나중에 풀기
'''
def uploadFile(request):
    context = {}
    if request.method == 'POST':
        uploaded_file = request.FILES['document1']
        fs = FileSystemStorage()
        name = fs.save(uploaded_file.name, uploaded_file)
        context['url'] = fs.url(name)
    return render(request,'upload_f.html',context)
'''

#-------------댄저존을 위한 코드 추가중-------------------------

def uploadFile(request):
    context = {}
    print("Receive File or URL")
    file_sha="a"
    if request.method == 'POST':
        uploaded_file = request.FILES['document1']
        file_name = uploaded_file.name
        media_dir = 'media/suspicious_files'
        file_rm = BASE_DIR + '/' + media_dir + '/' + file_name
        if os.path.isfile(file_rm):
            os.remove(file_rm)
        fs = FileSystemStorage(location=media_dir)
        name = fs.save(file_name, uploaded_file)
        file_sha = 'b'
        # file_id = file_upload(media_dir+'/'+file_name)
        # status = ''
        # cnt = 0
        # while status != 'completed' and cnt != 10:
        #     file_json = file_report(file_id)
        #     status = file_json['data']['attributes']['status']
        #     cnt += 1
        #     print(status, cnt)
        # file_sha = file_json['meta']['file_info']['sha256']
        fileName = file_name.split('.')[0] + '.pdf'
        excute_dangerzone(BASE_DIR+'/'+media_dir+'/'+file_name, file_sha,fileName)
        old_file = os.path.join(BASE_DIR + '/media/'+str(file_sha),'safe-output.pdf')
        
        new_file = os.path.join(BASE_DIR + '/media/'+str(file_sha),fileName)
        os.rename(old_file,new_file)
        #context['request']=file_sha
        context['url'] = BASE_DIR + '/media/'+str(file_sha)+'/'+fileName
        context['hash'] = fileName
        
    # if file_sha=="a":
    #     return render(request,'upload_f.html',context)
    # else:
    #     eun=BASE_DIR + '/' + media_dir + '/' + file_name
    return render(request,'upload_f.html',context)
        
def file_upload(orgfile, timeout=None, proxies=None):
    if not os.path.isfile(orgfile):
        raise Exception('File not found.')
    base_url = 'https://www.virustotal.com/api/v3/files'
    file_size = os.path.getsize(orgfile)
    headers = {
        'x-apikey': API_KEY,
    }
    # 32 MB 기준
    if file_size >= 33554432:
        with open(orgfile, 'rb') as f:
            data = {'file': f.read()}
            try:
                response = requests.get(base_url + '/upload_url',
                                        headers=headers,
                                        proxies=proxies,
                                        timeout=timeout)

                if response.status_code != 200:
                    raise Exception(response)

                upload_url = response.json()['data']
                response = requests.post(upload_url,
                                         headers=headers,
                                         files=data,
                                         proxies=proxies,
                                         timeout=timeout)
                if response.status_code != 200:
                    raise Exception(response)

                return response.json()['data']['id']

            except Exception as e:
                print(e)
                exit(1)
    else:
        with open(orgfile, 'rb') as f:
            data = {'file': f.read()}
            try:
                response = requests.post(base_url,
                                         headers=headers,
                                         files=data,
                                         proxies=proxies,
                                         timeout=timeout)

                if response.status_code != 200:
                    raise Exception(response)

                return response.json()['data']['id']

            except Exception as e:
                print(e)
                exit(1)

def file_report(file_id):
    headers = {
        'x-apikey': API_KEY,
        'Accept': 'application/json',
    }
    response = requests.get(
        'https://www.virustotal.com/api/v3/analyses/{}'.format(file_id), headers=headers)
    return response.json()
def vtchart(request, hash, pk):
    print('-'*10 + 'VirusTotal Malicious Report' + '-'*10)
    print(pk)
    file_path = BASE_DIR + "/media/" + hash + "/report.json"
    with open(file_path, "r") as f:
        file_json = json.load(f)
    file_data = file_json['data']['attributes']
    status = file_json['data']['attributes']['status']
    if file_data['stats']['malicious'] > 0 or file_data['stats']['suspicious'] > 0:
        flag = True
    else:
        flag = False

def excute_dangerzone(path, hash,fileName):
    print('-'*10 + 'Excute Dangerzone' + '-' * 10)
    file_rm = BASE_DIR+'/media/' + hash + fileName
    if os.path.isfile(file_rm):
        os.remove(file_rm)
    
    uploadpath = BASE_DIR + '/media/' + hash
    args = [
        "docker",
        "run",
        "--network",
        "none",
        "-v",
        f"{path}:/tmp/input_file",
        "-v",
        f"{uploadpath}:/safezone",
        "c0natus/cap:0.0",
        "document-to-pdf.sh"
    ]
    try:
        p = subprocess.run(args, timeout=480)
    except subprocess.TimeoutExpired:
        print("Error converting document to PDF, LibreOffice timed out after 60 seconds",flush=True)
        sys.exit(1)

    if p.returncode != 0:
        print(f"Conversion to PDF failed: {p.stdout}",flush=True)
        sys.exit(1)



def adblock(request):
    return render(request,'adblock.html')

# ocr ====================================================================

def excute_ocr(path, hash,fileName):
    print('-'*10 + 'Excute Ocr' + '-' * 10)
    file_rm = BASE_DIR+'/media/' + hash + fileName
    if os.path.isfile(file_rm):
        os.remove(file_rm)
    
    uploadpath = BASE_DIR + '/media/' + hash
    args = [
        "docker",
        "run",
        "--network",
        "none",
        "-v",
        f"{path}:/tmp/input_file",
        "-v",
        f"{uploadpath}:/safezone",
        "-e", 
        "OCR=1", 
        "-e", 
        "OCR_LANGUAGE=Hangul",
        "c0natus/cap:0.0",
        "document-to-pdf.sh"
    ]
    try:
        p = subprocess.run(args, timeout=480)
    except subprocess.TimeoutExpired:
        print("Error converting document to PDF, LibreOffice timed out after 60 seconds",flush=True)
        sys.exit(1)

    if p.returncode != 0:
        print(f"Conversion to PDF failed: {p.stdout}",flush=True)
        sys.exit(1)

def uploadOcr(request):
    return render(request, 'uploadOcr.html')

def uploadOcr(request):
    context = {}
    print("Receive File or URL")
    file_sha="a"
    if request.method == 'POST':
        uploaded_file = request.FILES['dd_2']
        file_name = uploaded_file.name
        media_dir = 'media/ocr_files'
        file_rm = BASE_DIR + '/' + media_dir + '/' + file_name
        if os.path.isfile(file_rm):
            os.remove(file_rm)
        fs = FileSystemStorage(location=media_dir)
        name = fs.save(file_name, uploaded_file)
        file_sha='b'

        fileName = file_name.split('.')[0] + '_OCR.pdf'
        excute_ocr(BASE_DIR+'/'+media_dir+'/'+file_name, file_sha,fileName)
        old_file = os.path.join(BASE_DIR + '/media/'+str(file_sha),'safe-output.pdf')
        
        new_file = os.path.join(BASE_DIR + '/media/'+str(file_sha),fileName)
        os.rename(old_file,new_file)
        #context['request']=file_sha
        context['url'] = BASE_DIR + '/media/'+str(file_sha)+'/'+fileName
        context['hash'] = fileName
        
    # if file_sha=="a":
    #     return render(request,'upload_f.html',context)
    # else:
    #     eun=BASE_DIR + '/' + media_dir + '/' + file_name
    return render(request,'uploadOcr.html',context)
        