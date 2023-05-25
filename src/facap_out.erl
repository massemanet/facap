-module(facap_out).

-export(
   [open/1,
    append/2,
    close/1]).

%%%--------------------------------------------------------------------------
%%% construct a cooked binary with `Payload' stuffed in
%%% ipv4/sctp/sctp_chunk/sctp_data_chunk

open(File) when not is_map(File) ->
    open(#{file => File});
open(Opts) ->
    #{file := File} = Opts,
    Magic = 16#a1b2c3d4,
    MinVsn = maps:get(min_vsn, Opts, 666),
    MajVsn = maps:get(maj_vsn, Opts, 666),
    SnapLen = maps:get(snap_len, Opts, 16#ffff0000),
    DllType = maps:get(dll_type, Opts, 113),
    {ok, FD} = file:open(File, [write, raw, binary]),
    ok = file:write(FD, <<Magic:32>>),
    ok = file:write(FD, <<MajVsn:16>>),
    ok = file:write(FD, <<MinVsn:16>>),
    ok = file:write(FD, <<0:64>>),
    ok = file:write(FD, <<SnapLen:32>>),
    ok = file:write(FD, <<DllType:32>>),
    #{file => File, fd => FD}.

close(#{fd := FD}) ->
    ok = file:close(FD).

append(Layers, #{fd := FD} = S) ->
    Pkt = encode(Layers),
    ok = file:write(FD, Pkt),
    S.

encode([PCAP|Layers]) ->
    #{headers := H, payload := P} = expand(Layers),
    pcap_encode(PCAP, pkt:encode(H), P).

pcap_encode(PCAP, Headers, Payload) ->
    TS = maps:get(ts, PCAP),
    TSsec = trunc(TS),
    TSusec = round((TS-TSsec)*1000_000),
    Len = byte_size(Payload)+byte_size(Headers),
    <<TSsec:32, TSusec:32, Len:32, Len:32, Headers/bytes, Payload/bytes>>.

-include_lib("pkt/include/pkt.hrl").
expand(Layers) ->
    lists:foldr(fun expand/2, #{}, Layers).

expand(#{type := cooked}, Acc) ->
    MAC = <<"amacaddr">>,
    Cooked = #linux_cooked{packet_type = 4, ll_bytes = MAC, ll_len = 6},
    Hs = maps:get(headers, Acc, []),
    Acc#{headers => [Cooked|Hs]};
expand(#{type := ipv4} = IPV4, Acc) ->
    Saddr = maps:get(saddr, IPV4, {127,0,0,1}),
    Daddr = maps:get(daddr, IPV4, {127,0,0,1}),
    Len = 20+maps:get(length, Acc, 0),
    Proto = maps:get(proto, Acc, ?IPPROTO_IP),
    IP4 = #ipv4{len = Len, p = Proto, saddr = Saddr, daddr = Daddr},
    Hs = [IP4|maps:get(headers, Acc, [])],
    Acc#{length => Len, headers => Hs};
expand(#{type := tcp} = TCP, Acc) ->
    Sport = maps:get(sport, TCP, 0),
    Dport = maps:get(dport, TCP, 0),
    Tcp = #tcp{sport = Sport, dport = Dport},
    Len = 5*4+maps:get(length, Acc, 0),
    Hs = [Tcp|maps:get(headers, Acc, [])],
    Acc#{length => Len, headers => Hs, proto => ?IPPROTO_TCP};
expand(#{type := sctp} = SCTP, Acc) ->
    Sport = maps:get(sport, SCTP, 0),
    Dport = maps:get(dport, SCTP, 0),
    PPI = maps:get(ppi, SCTP, 3),
    Data = maps:get(payload, Acc, <<>>),
    ChunkData = #sctp_chunk_data{ppi = PPI, data = Data},
    Chunk = #sctp_chunk{type = ?SCTP_CHUNK_DATA,
                        b = 1,     % first segment
                        e = 1,     % last segment
                        payload = ChunkData},
    Sctp = #sctp{sport = Sport, dport = Dport, chunks = [Chunk]},
    Len = 12+4+12+maps:get(length, Acc, 0),
    Hs = [Sctp|maps:get(headers, Acc, [])],
    Acc#{length => Len, headers => Hs, payload => <<>>, proto => ?IPPROTO_SCTP};
expand(#{type := payload, data := Data}, Acc) ->
    Acc#{length => byte_size(Data), payload => Data}.
