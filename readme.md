<h3>宽带劫持检测,暂基于ttl</h3>
<p>用法<br>
打开py，这时python会监听网卡流量，这时尝试打开很多不同网址的http网页每个几次（考虑到不会每次劫持）<br>
输出值最高的最有可能是劫持的ttl值，打开的不同域名下http网页越多越准确，然后关闭python即可</p>
<p>todo<br>
自动打开http网页进行检测<br>
不仅仅是ttl，基于包的智能分析，比如劫持样板包头特征<br>
生成较为高效的iptables规则u32等 <br>
finally,开发宽带劫持过滤程序<br>
<p>随想<br>
http劫持真烦人，随机替换js套个壳然后先执行广告，再执行原js<br>
投诉无效，真想建立一个宽带劫持ddos小组，一起干他丫的
</p>