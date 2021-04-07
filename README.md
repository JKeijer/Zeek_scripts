# Zeek_scripts
Zeek scripts for additional features

Installation:

Add the ttls.zeek file to $PREFIX/share/zeek/policy/protocols/conn/

Add the following lines to $PREFIX/share/zeek/site/local.zeek
  # This line adds source and destination TTLs for TCP traffic, the event is striggered for every SYN packets, so might impact performance
  @load policy/protocols/conn/ttls
  
Redeploy
