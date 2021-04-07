##! This script adds TTL information to the connection logs

@load base/protocols/conn

module Conn;

redef record Conn::Info += {
        orig_ttl: count &log &optional;
        resp_ttl: count &log &optional;
};

redef record connection += {
        orig_ttl: count &log &optional;
        resp_ttl: count &log &optional;
};

## This event triggers on every TPC SYN packet. This is costly, but the only way to extract TTL information for TCP packets
event connection_SYN_packet(c: connection, pkt: SYN_packet) {
    if ( pkt$is_orig )
            c$orig_ttl = pkt$ttl;

    if ( ! pkt$is_orig )
            c$resp_ttl = pkt$ttl;
    }

## This event triggers once per connection to clean it from memory, to reliably add the ttls to conn.log
event connection_state_remove(c: connection) {
        if ( c ?$ orig_ttl )
                c$conn$orig_ttl = c$orig_ttl;

        if (c ?$ resp_ttl )
                c$conn$resp_ttl = c$resp_ttl;
}
