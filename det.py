import sys
from scapy.all import * 


conf.verb=0
print ("TCP Hijacking Delector by rufengsuixing，请关闭可能导致重置ttl的设备，如路由器广告过滤")
print ("Sniffing .... please open many http pages and will tell you what ttl most like hijack")
ip_arr = {}
#可自行修改ttl宽容度
latitude=4
#count=0
while 1:
    a=sniff( filter="tcp and src host not 10.26.234.44", count=50)
    for b in a:
        ip_src = b.sprintf(r"%IP.src%")
        ip_ttl = int(b.sprintf(r"%IP.ttl%"))
        #if ip_ttl==64:
        #    count+=1
        if ip_src in ip_arr:
            ip_arr[ip_src].add(ip_ttl)
        else:
            ip_arr[ip_src]=set([ip_ttl])
    #print(ip_arr)
    ttl_show_time={}
    for a in ip_arr:
        if len(ip_arr[a])<=1:
            continue
        tmp=list(ip_arr[a])
        tmp.sort()
        #基于连续假设
        if tmp[0]+latitude<=tmp[1]:
            try:
                ttl_show_time[tmp[0]]+=1
            except:
                ttl_show_time[tmp[0]]=1
        if tmp[-2]+latitude<=tmp[-1]:
            try:
                ttl_show_time[tmp[-1]]+=1
            except:
                ttl_show_time[tmp[-1]]=1
       
        '''
        #基于相近假设
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

    #if count>100:
    #    print('请关闭广告过滤装置')
    print(ttl_show_time)
