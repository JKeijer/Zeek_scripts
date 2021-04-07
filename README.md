# Zeek_scripts
Zeek scripts for additional features.
ttls.zeek adds source and destination TTL to conn.log

Installation:

#### 1.
Add the ttls.zeek file to $PREFIX/share/zeek/policy/protocols/conn/

#### 2.
Add the following lines to $PREFIX/share/zeek/site/local.zeek
```
# This line adds source and destination TTLs for TCP traffic, the event is triggered for every SYN packets, so it might impact performance
@load policy/protocols/conn/ttls
```
#### 3.
Redeploy
