-module(facap_out).

-export(
   [open/1,
    append/2,
    close/1]).

%%%--------------------------------------------------------------------------
%%% construct a cooked binary with `Payload' stuffed in
%%% ipv4/sctp/sctp_chunk/sctp_data_chunk

open(#{file := File} = S) ->
    Magic = 16#a1b2c3d4,
    MinVsn = maps:get(min_vsn, S, 666),
    MajVsn = maps:get(maj_vsn, S, 666),
    SnapLen = maps:get(snap_len, S, 16#ffff0000),
    DllType = maps:get(dll_type, S, 113),
    {ok, FD} = file:open(File, [write, raw, binary]),
    ok = file:write(FD, <<Magic:32>>),
    ok = file:write(FD, <<MajVsn:16>>),
    ok = file:write(FD, <<MinVsn:16>>),
    ok = file:write(FD, <<0:64>>),
    ok = file:write(FD, <<SnapLen:32>>),
    ok = file:write(FD, <<DllType:32>>),
    FD.

close(#{fd := FD}) ->
    ok = file:close(FD).

append(#{time_stamp := TS, payload := Payload}, #{fd := FD} = S) ->
    Pkt = encode(Payload),
    TSsec = trunc(TS),
    TSusec = round((TS-TSsec)*1000_000),
    Len = byte_size(Payload),
    ok = file:write(FD, <<TSsec:32>>),
    ok = file:write(FD, <<TSusec:32>>),
    ok = file:write(FD, <<Len:32>>),
    ok = file:write(FD, <<Len:32>>),
    ok = file:write(FD, <<Pkt/binary>>),
    S.

encode(_) ->
    <<>>.

%%% encode(Layers) ->
%%%     pkt:encode(expand(Layers)).
%%% 
%%% expand(Layers) ->
%%%     S0 = #{global => #{}, out => []},
%%%     maps:get(out, lists:foldr(fun expand/2, S0, Layers)).
%%% 
%%% expand(#{type := cooked}, Acc) ->
%%%     #{global := Global, out := Out} = Acc,
%%%     MAC = <<"amacaddr">>,
%%%     Packet = #linux_cooked{packet_type = 4, ll_bytes = MAC, ll_len = 6},
%%%     #{global => Global, out => [Packet|Out]};
%%% expand(#{type := ipv4} = IPV4, Acc) ->
%%%     #{global := Global, out := Out} = Acc,
%%%     Saddr = maps:get(saddr, IPV4, {127,0,0,1}),
%%%     Daddr = maps:get(daddr, IPV4, {127,0,0,1}),
%%%     PayloadLen = maps:get(ip_payload_length, Global, 0),
%%%     PayloadProto = maps:get(ip_payload_proto, Global, '_IP'),
%%%     Len = 20+PayloadLen,
%%%     Packet = #ipv4{len = Len, p = PayloadProto, saddr = Saddr, daddr = Daddr},
%%%     #{global => Global, out => [Packet|Out]};
%%% expand(#{type := sctp} = SCTP, Acc) ->
%%%     #{global := Global, out := Out} = Acc,
%%%     Sport = maps:get(sport, SCTP, 0),
%%%     Dport = maps:get(dport, SCTP, 0),
%%%     Data = maps:get(data, SCTP, <<>>),
%%%     PPI = maps:get(ppi, SCTP, 3),
%%%     Len = 12+4+12+byte_size(Data),
%%%     ChunkData = #sctp_chunk_data{ppi = PPI, data = Data},
%%%     Chunk = #sctp_chunk{type = '_SCTP_CHUNK_DATA',
%%%                         b = 1,     % first segment
%%%                         e = 1,     % last segment
%%%                         payload = ChunkData},
%%%     Packet = #sctp{sport = Sport, dport = Dport, chunks = [Chunk]},
%%%     Glob = Global#{ip_payload_length => Len, ip_payload_proto => '_IPPROTO_SCTP'},
%%%     #{global => Glob, out => [Packet|Out]}.
%%% 
%%% lift(ok, eof) ->
%%%     exit(eof);
%%% lift(Tag, {Tag, Val}) ->
%%%     Val.
%%% 
%%% to_map(Tuple) ->
%%%     [Name|Fields] = tuple_to_list(Tuple),
%%%     maps:from_list(lists:zip(fields(Name), Fields)).
%%% 
%%% fields(file_header) ->
%%%     record_info(fields, file_header).
%%% 
