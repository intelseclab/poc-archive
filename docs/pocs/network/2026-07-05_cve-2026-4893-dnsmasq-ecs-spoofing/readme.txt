Topology:
https://medium.com/@yanyuyingshu/reproduction-journal-dnsmasq-ecs-validation-and-buffer-overflow-flaws-e0fe0f66f60c

Steps​

1.vi /etc/dnsmasq.conf​

port=5353​

listen-address=xxx.xxx.xxx.x

bind-interfaces​

no-resolv​

no-hosts​

no-poll​

cache-size=1000​

log-queries​

log-facility=-​

server=127.0.0.1#5354​

add-subnet​

(and restart dnsmasq daemon)​

​

2. python3 exp.py​

​
