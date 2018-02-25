'''
author:rufengsuixing
'''
from scapy.all import *
from scapy_http import http
conf.prog.wireshark='C:/Program Files/Wireshark/Wireshark.exe'


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

def det_ttl(latitude=4,count=500,debug=False):
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
        a=sniff( filter="tcp port 80",lfilter=pcap_fil,offline='test.pcap')
    else:
        a=sniff( filter="tcp port 80",lfilter=pcap_fil, count=count)
    ttl_show_time=ttl_cul(a,latitude=latitude,debug=debug)

    if not ttl_show_time:
        print('ttl detect failed ,maybe isp modified it')
        return None
    else:
        print('result:',ttl_show_time)
        return a
def det_http_resp(ps):
    for a in ps:
        ip_src = b.sprintf(r"%IP.src%")
        a[http.HTTPResponse]

def creat_ipt(ttl):
    print('''for your router
             iptables -I FORWARD -p tcp --sport 80 -m ttl --ttl %d -j DROP
             iptables -I FORWARD -p tcp --sport 80 -m ttl --ttl %d -j DROP'''%(ttl,ttl+1))
if __name__=='__main__':
    det_ttl(debug=False)