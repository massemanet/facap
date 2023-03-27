-module(facap_pkt).

-export(
   [dll/1,
    dec/2]).

-include_lib("pkt/include/pkt.hrl").

-define(COOKED(PT),
        #linux_cooked{packet_type = PT}).
-define(COOKED2(PT),
        #linux_cooked_v2{packet_type = PT}).
-define(ETHER(),
       #ether{}).
-define(ARP() ,
        #arp{}).
-define(IP4(Saddr, Daddr),
        #ipv4{saddr = Saddr, daddr = Daddr}).
-define(IP6(Saddr, Daddr),
        #ipv6{saddr = Saddr, daddr = Daddr}).
-define(ICMP(),
        #icmp{}).
-define(UDP(Sport, Dport),
        #udp{sport = Sport, dport = Dport}).
-define(TCP(Sport, Dport),
        #tcp{sport = Sport, dport = Dport}).
-define(SCTP(Sport, Dport, Chunks),
        #sctp{sport = Sport, dport = Dport, chunks = Chunks}).

dll(?DLT_EN10MB) -> ether;
dll(?DLT_LINUX_SLL) -> linux_cooked;
dll(?DLT_LINUX_SLL2) -> linux_cooked_v2.

dec(DLL, Payload) ->
    protos(pkt:decapsulate(DLL, Payload), #{}).

protos([], Pkt) ->
    Pkt;
protos([<<>>], Pkt) ->
    Pkt;
protos([H|T], Pkt) ->
    case H of
        ?COOKED(PT) ->
            protos(T, mappend(protos, [{cooked, cooked_dir(PT)}], Pkt));
        ?COOKED2(PT) ->
            protos(T, mappend(protos, [{cooked2, cooked_dir(PT)}], Pkt));
        ?ETHER() ->
            protos(T, mappend(protos, [ether], Pkt));
        ?IP4(Saddr, Daddr) ->
            protos(T, mappend(protos, #{ip => 4, saddr => Saddr, daddr => Daddr}, Pkt));
        ?IP6(Saddr, Daddr) ->
            protos(T, mappend(protos, #{ip => 6, saddr => Saddr, daddr => Daddr}, Pkt));
        ?ARP() ->
            mappend(protos, arp, Pkt);
        ?ICMP() ->
            mappend(protos, icmp, Pkt);
        ?SCTP(Sport, Dport, Chunks) ->
            mappend(payload, facap_sctp:chunks(Chunks), mappend(protos, #{l4 => sctp, sport => Sport, dport => Dport}, Pkt));
        ?TCP(Sport, Dport) ->
            mappend(payload, hd(T), mappend(protos, #{l4 => tcp, sport => Sport, dport => Dport}, Pkt));
        ?UDP(Sport, Dport) ->
            mappend(payload, hd(T), mappend(protos, #{l4 => udp, sport => Sport, dport => Dport}, Pkt));
        _ ->
            error({unrecognized_packet, [H|T]})
    end.

mappend(Key, Val, Map) ->
    maps:update_with(Key, fun(Vals) -> [Val|Vals] end, Val, Map).

cooked_dir(0) -> 'incoming(uni)';
cooked_dir(1) -> 'incoming(broadcast)';
cooked_dir(2) -> 'incoming(multicast)';
cooked_dir(3) -> 'transit';
cooked_dir(4) -> 'outgoing'.
