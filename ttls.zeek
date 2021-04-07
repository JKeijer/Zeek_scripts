##! This script adds TTL information to the connection logs

@load base/protocols/conn

module Conn;

redef record Conn::Info += {
        orig_ttl: count &log &optional;
        resp_ttl: count  &log &optional;
};

redef record connection += {
        orig_ttl: count &log &optional;
        resp_ttl: count  &log &optional;
};


event connection_SYN_packet(c: connection, pkt: SYN_packet) {
    if ( pkt$is_orig )
            c$orig_ttl = pkt$ttl;

    if ( ! pkt$is_orig )
            c$resp_ttl = pkt$ttl;
    }


event connection_state_remove(c: connection) {
        if ( c ?$ orig_ttl )
                c$conn$orig_ttl = c$orig_ttl;

        if (c ?$ resp_ttl )
                c$conn$resp_ttl = c$resp_ttl;
}
