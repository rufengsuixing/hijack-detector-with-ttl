'''
author:rufengsuixing
 '''
from scapy3k.all import *
from scapy3k.layers import http
conf.prog.wireshark='C:/Program Files/Wireshark/Wireshark.exe'
import time

def ttl_cul(ps,latitude=4,debug=False):
    ip_arr = {}
    for b in ps:
        ip_src = b.sprintf(r"%IP.src%")
        ip_ttl = int(b.sprintf(r"%IP.ttl%"))
        if ip_src in ip_arr:
            ip_arr[ip_src].add(ip_ttl)
        else:
            ip_arr[ip_src]=set([ip_ttl])
    if debug:
        print(ip_arr)
    ttl_show_time={}
    for b in ip_arr:
        if len(ip_arr[b])<=1:
            continue
        tmp=list(ip_arr[b])
        tmp.sort()
        #基于连续假设,ttl异常出现在同ip中ttl最大值或者最小值并且距离过宽容度，忽略混在中间的，因为难以判断
        if tmp[0]+latitude<tmp[1]:
            try:
                ttl_show_time[tmp[0]]+=1
            except:
                ttl_show_time[tmp[0]]=1
        if tmp[-2]+latitude<tmp[-1]:
            try:
                ttl_show_time[tmp[-1]]+=1
            except:
                ttl_show_time[tmp[-1]]=1
        '''
        #基于相近假设，ttl异常出现在距离超过宽容度处
        c=0
        while 1:
            try:
                if tmp[c]+3>tmp[c+1]:
                    tmp.pop(c)
                    flag=True
                else:
                    c+=1
                    flag=False
            except:
                if flag:
                    tmp.pop[c]
                break
        for b in tmp:
            try:
                ttl_show_time[b]+=1
            except:
                ttl_show_time[b]=1
        '''
    return ttl_show_time
def pkfil_cul(samepk,notsamepk):
    tar=samepk[0].payload.original
    chong=set()
    for b in notsamepk:
        bi=b.payload.original
        for suo in range(0,200):
            if suo in chong:
                continue
            try:
                if bi[suo:suo+4]==tar[suo:suo+4]:
                    chong.add(suo)
            except IndexError:
                pass
    for x in samepk[1:]:
        bi=x.payload.original
        for suo in range(0,200):
            if suo in chong:
                continue
            try:
                if bi[suo:suo+4]!=tar[suo:suo+4]:
                    chong.add(suo)
            except IndexError:
                pass
    for a in range(0,200):
        if a not in chong:
            print(a,' ',tar[a:a+4])
    print('以上为可作为判断准则的字段和值')
def resp_cul(ps,xiangsidu=0.9):
    #用来寻找js劫持，套壳相似度很高
    import Levenshtein
    
    ip_arr = {}
    for b in ps:
        if b[http.HTTPResponse].fields['Status-Line'].find(b'200')==-1:
            continue
        try:
            ct=b[http.HTTPResponse].fields['Content-Type']
            if ct.find(b'text')==-1:
                if ct.find(b'javascript')==-1:
                    continue
            if b[http.HTTPResponse].fields['Content-Length']==b'0':
                continue
        except Exception as e:
            print(e)
            continue
        try:
            if b[http.HTTPResponse].fields['Content-Encoding'].find(b'gzip')!=-1:
                continue
        except:
            pass
        try:    
            charset=re.findall(b'charset=(.*);*',ct)[0].decode()
        except:
            charset='utf-8'
        ip_src = b.sprintf(r"%IP.src%")    
        try:
            ip_resp = b[http.HTTPResponse].original.decode(encoding=charset,errors='strict')
        except Exception as e:
            #print(e)
            try:
                ip_resp = b[http.HTTPResponse].original.decode(encoding='gb2312',errors='strict')
            except:
                continue
        ps[2]
        if ip_src in ip_arr:
            ip_arr[ip_src][ip_resp]=b
        else:
            ip_arr[ip_src]={ip_resp:b}
    xiangsi=[]
    disf=1000
    kz=0
    for b in ip_arr:
        kz+=1
        tmp=kz
        for c in ip_arr:
            if tmp>0:
                tmp-=1
                continue
            for d in ip_arr[b]:
                for e in ip_arr[c]:
                    '''
                    #第一种方法
                    #dis=Levenshtein.distance(d, e)
                    print(dis,end=' ')
                    if dis<150:
                        xiangsi.add(d)
                        xiangsi.add(e)
                    elif disf>dis:
                        disf=dis
                        noxiangsi=[d,e]
                    #第二种方法
                    dis=Levenshtein.jaro(d,e)
                    print(dis,end=' ')
                    if dis>0.8:
                        xiangsi.add(d)
                        xiangsi.add(e)
                    '''
                    #自己的方法
                    lid=d.split('\n')
                    lie=e.split('\n')
                    si=0
                    for a in range(0,len(lid)):
                        try:
                            if lid[a].replace('\r','')==lie[a].replace('\r',''):
                                si+=1
                        except Exception as e:
                            a-=1
                            pass
                    xiang=si/(a+1)
                    #print(xiang)
                    if xiang>xiangsidu:
                        xiangsi.append(ip_arr[b][d])
                        xiangsi.append(ip_arr[c][e])
    #print(xiangsi)
    pkfil_cul(xiangsi,[a for a in ps if a not in xiangsi])

def det_ttl(latitude=4,count=100,debug=False):
    def pcap_fil(p):
        if http.HTTPResponse in p:
            return True
        else:
            return False
    import sys
    conf.verb=0
    print ("ipv4 http responce Hijacking Delector by rufengsuixing with ttl，请关闭可能导致重置ttl的设备，如路由器广告过滤")
    print ("Sniffing .... please open many http pages and i will tell you what ttl most like hijack")
    if debug:
        a=sniff(lfilter=pcap_fil,count=500,offline='respont.pcap')
        #a=sniff(offline='temp.cap')
    else:
        a=sniff( filter="tcp port 80",lfilter=pcap_fil,count=count)
    ttl_show_time=ttl_cul(a,latitude=latitude,debug=debug)
    if not ttl_show_time:
        print('ttl detect failed ,maybe isp modified it')
        return None
    else:
        print('result:',ttl_show_time)
        return a

def creat_ipt(ttl):
    print('''for your router
             iptables -I INPUT -p tcp --sport 80 -m ttl --ttl %d -j DROP
             iptables -I FORWARD -p tcp --sport 80 -m ttl --ttl %d -j DROP'''%(ttl,ttl+1))
if __name__=='__main__':
    a=det_ttl(debug=False)
    resp_cul(a)
