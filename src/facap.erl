%% -*- mode: erlang; erlang-indent-level: 4 -*-
-module(facap).

%% reading
-export(
   [header/1,
    list/1,
    fold/3,
    fold/4]).

%% writing
-export(
   [open_file/1,
    close_file/1,
    write_packet/3,
    encode/1]).

-include_lib("kernel/include/file.hrl").
-include_lib("kernel/include/inet_sctp.hrl").
-include_lib("kernel/include/logger.hrl").
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

-record(file_header,
        {maj_vsn,
         min_vsn,
         snap_length,
         time_resolution,
         dll_type}).

-record(packet,
        {ts_sec,
         captured_len,
         original_len,
         payload}).

header(File) ->
    {ok, FD} = file:open(File, [read, raw, binary, read_ahead]),
    try to_map(file_header(FD))
    after file:close(FD)
    end.

list(File) ->
    lists:reverse(fold(fun(P, O) -> [P|O] end, [], File)).

fold(Fun, Acc0, File) ->
    fold(Fun, Acc0, File, #{max_count => inf}).

fold(Fun, Acc0, File, Opts) ->
    case file:read_file_info(File) of
        {error, enoent} ->
            {error, {no_such_file, File}};
        {ok, #file_info{type = directory}} ->
            folder(Fun, Acc0, Opts, files(File));
        {ok, #file_info{type = regular}} ->
            folder(Fun, Acc0, Opts, [File])
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

files(Dir) ->
    {ok, Fs}  = file:list_dir(Dir),
    [filename:join(Dir, F) || F <- Fs].

folder(Fun, Acc0, Opts, Files) ->
    lists:foldl(mk_folder(Fun, Opts), Acc0, Files).

mk_folder(Fun, Opts) ->
    fun(F, A) -> do_fold(Fun, A, F, Opts) end.

do_fold(Fun, Acc0, File, Opts0) ->
    {ok, FD} = file:open(File, [read, raw, binary, read_ahead]),
    Opts = opts(FD, Opts0),
    try fold_loop(Fun, Acc0, Opts)
    catch throw:Acc -> Acc
    after file:close(FD)
    end.

opts(FD, Opts) ->
    FH = file_header(FD),
    maps:merge(#{'_count' => 0, fd => FD, ptr => 24, file_header => FH}, Opts).

file_header(FD) ->
    case hex(lift(ok, file:pread(FD, 0, 4))) of
        "0a0d0d0a" -> file_header(ng, ng, FD);
        "a1b23c4d" -> file_header(big, nano, FD);
        "a1b2c3d4" -> file_header(big, micro, FD);
        "4d3cb2a1" -> file_header(little, nano, FD);
        "d4c3b2a1" -> file_header(little, micro, FD)
    end.

hex(X) ->
    [case N<10 of true -> N+$0; false-> N+$W end || <<N:4>> <= X].

file_header(ng, ng, _FD) ->
    error({pcap_ng, not_yet_implemented});
file_header(Endian, TimeRes, FD) ->
    {Maj, Min, Snap, DLL} = file_header(Endian, FD),
    #file_header{
       maj_vsn = Maj,
       min_vsn = Min,
       time_resolution = timeres(TimeRes),
       snap_length = Snap,
       dll_type = dll(DLL)}.

file_header(Endian, FD) ->
    {ok, H} = file:pread(FD, 4, 20),
    fh(Endian, H).

fh(big, <<A:16/big, B:16/big, _:8/bytes, C:32/big, D:32/big>>) ->
    {A, B, C, D};
fh(little, <<A:16/little, B:16/little, _:8/bytes, C:32/little, D:32/little>>) ->
    {A, B, C, D}.

timeres(micro) -> 1_000_000;
timeres(nano) -> 1_000_000_000.

dll(?DLT_EN10MB) -> ether;
dll(?DLT_LINUX_SLL) -> linux_cooked;
dll(?DLT_LINUX_SLL2) -> linux_cooked_v2.

fold_loop(Fun, Acc, Opts0) ->
    Opts = try packet(Opts0) catch error:{badmatch,eof} -> throw(Acc) end,
    Pkt = decapsulate(Opts),
    fold_loop(Fun, Fun(Pkt, Acc), Opts).

packet(Opts0) ->
    #{fd := FD, ptr := Ptr, file_header := FH} = Opts = maybe_done(Opts0),
    {ok, PH} = file:pread(FD, Ptr, 16),
    <<TSsec:32/little, TSfrac:32/little, Cap:32/little, Orig:32/little>> = PH,
    {ok, Payload} = file:pread(FD, Ptr+16, Cap),
    Opts#{ptr => Ptr+16+Cap,
          packet => #packet{
                       ts_sec = TSsec+TSfrac/FH#file_header.time_resolution,
                       captured_len = Cap,
                       original_len = Orig,
                       payload = Payload}}.

decapsulate(#{'_count' := Count, packet := Packet, file_header := FH}) ->
    Protos = pkt:decapsulate(FH#file_header.dll_type, Packet#packet.payload),
    dec(Protos, #{ts => Packet#packet.ts_sec, count => Count, protos => []}).

-define(CM(C, M), #{'_count' := C, max_count := M}).
-define(IS_DONE(Count, Max), is_integer(Max), Max < Count).
maybe_done(?CM(Count, Max)) when ?IS_DONE(Count, Max) -> error({badmatch, eof});
maybe_done(Opts) -> maps:update_with('_count', fun plus1/1, Opts).

plus1(I) -> I+1.

dec([], Pkt) ->
    Pkt;
dec([<<>>], Pkt) ->
    Pkt;
dec([H|T], Pkt) ->
    case H of
        ?COOKED(PT) ->
            dec(T, mappend(protos, {cooked, cooked_dir(PT)}, Pkt));
        ?COOKED2(PT) ->
            dec(T, mappend(protos, {cooked2, cooked_dir(PT)}, Pkt));
        ?ETHER() ->
            dec(T, mappend(protos, ether, Pkt));
        ?ARP() ->
            dec(T, mappend(protos, arp, Pkt));
        ?IP4(Saddr, Daddr) ->
            dec(T, mappend(protos, #{ip => 4, saddr => Saddr, daddr => Daddr}, Pkt));
        ?IP6(Saddr, Daddr) ->
            dec(T, mappend(protos, #{ip => 6, saddr => Saddr, daddr => Daddr}, Pkt));
        ?ICMP() ->
            mappend(protos, icmp, Pkt);
        ?SCTP(Sport, Dport, Chunks) ->
            mappend(payload, chunks(Chunks), mappend(protos, #{l4 => sctp, sport => Sport, dport => Dport}, Pkt));
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

-define(DATA(P, D),          #sctp_chunk{type = ?SCTP_CHUNK_DATA, payload = #sctp_chunk_data{ppi = P, data = D}}).
-define(INIT(),              #sctp_chunk{type = ?SCTP_CHUNK_INIT}).
-define(INIT_ACK(),          #sctp_chunk{type = ?SCTP_CHUNK_INIT_ACK}).
-define(SACK(),              #sctp_chunk{type = ?SCTP_CHUNK_SACK}).
-define(HEARTBEAT(),         #sctp_chunk{type = ?SCTP_CHUNK_HEARTBEAT}).
-define(HEARTBEAT_ACK(),     #sctp_chunk{type = ?SCTP_CHUNK_HEARTBEAT_ACK}).
-define(ABORT(),             #sctp_chunk{type = ?SCTP_CHUNK_ABORT}).
-define(SHUTDOWN(),          #sctp_chunk{type = ?SCTP_CHUNK_SHUTDOWN}).
-define(SHUTDOWN_ACK(),      #sctp_chunk{type = ?SCTP_CHUNK_SHUTDOWN_ACK}).
-define(ERROR(),             #sctp_chunk{type = ?SCTP_CHUNK_ERROR}).
-define(COOKIE_ECHO(),       #sctp_chunk{type = ?SCTP_CHUNK_COOKIE_ECHO}).
-define(COOKIE_ACK(),        #sctp_chunk{type = ?SCTP_CHUNK_COOKIE_ACK}).
-define(SHUTDOWN_COMPLETE(), #sctp_chunk{type = ?SCTP_CHUNK_SHUTDOWN_COMPLETE}).

chunks(Chunks) ->
    lists:map(fun chunk/1, Chunks).

chunk(Chunk) ->
    case Chunk of
        ?DATA(PPI, Data)     -> #{chunk_type => data, ppi => PPI, chunk_data => Data};
        ?INIT()              -> #{chunk_type => init};
        ?INIT_ACK()          -> #{chunk_type => init_ack};
        ?SACK()              -> #{chunk_type => sack};
        ?HEARTBEAT()         -> #{chunk_type => heartbeat};
        ?HEARTBEAT_ACK()     -> #{chunk_type => heartbeat_ack};
        ?ABORT()             -> #{chunk_type => abort};
        ?SHUTDOWN()          -> #{chunk_type => shutdown};
        ?SHUTDOWN_ACK()      -> #{chunk_type => shutdown_ack};
        ?ERROR()             -> #{chunk_type => error};
        ?COOKIE_ECHO()       -> #{chunk_type => cookie_echo};
        ?COOKIE_ACK()        -> #{chunk_type => cookie_ack};
        ?SHUTDOWN_COMPLETE() -> #{chunk_type => shutdown_complete}
    end.

%%%--------------------------------------------------------------------------
%%% construct a cooked binary with `Payload' stuffed in
%%% ipv4/sctp/sctp_chunk/sctp_data_chunk

open_file(Filename) ->
    open_file(Filename, #{}).
open_file(Filename, Opts) ->
    Magic = 16#a1b2c3d4,
    MinVsn = maps:get(min_vsn, Opts, 666),
    MajVsn = maps:get(maj_vsn, Opts, 666),
    SnapLen = maps:get(snap_len, Opts, 16#ffff0000),
    DllType = maps:get(dll_type, Opts, 113),
    {ok, FD} = file:open(Filename, [write, raw, binary]),
    ok = file:write(FD, <<Magic:32>>),
    ok = file:write(FD, <<MajVsn:16>>),
    ok = file:write(FD, <<MinVsn:16>>),
    ok = file:write(FD, <<0:64>>),
    ok = file:write(FD, <<SnapLen:32>>),
    ok = file:write(FD, <<DllType:32>>),
    FD.

close_file(FD) ->
    ok = file:close(FD).

write_packet(FD, TS, Payload) ->
    TSsec = trunc(TS),
    TSusec = round((TS-TSsec)*1000_000),
    Len = byte_size(Payload),
    ok = file:write(FD, <<TSsec:32>>),
    ok = file:write(FD, <<TSusec:32>>),
    ok = file:write(FD, <<Len:32>>),
    ok = file:write(FD, <<Len:32>>),
    ok = file:write(FD, <<Payload/binary>>).

encode(Layers) ->
    pkt:encode(expand(Layers)).

expand(Layers) ->
    S0 = #{global => #{}, out => []},
    maps:get(out, lists:foldr(fun expand/2, S0, Layers)).

expand(#{type := cooked}, Acc) ->
    #{global := Global, out := Out} = Acc,
    MAC = <<"amacaddr">>,
    Packet = #linux_cooked{packet_type = 4, ll_bytes = MAC, ll_len = 6},
    #{global => Global, out => [Packet|Out]};
expand(#{type := ipv4} = IPV4, Acc) ->
    #{global := Global, out := Out} = Acc,
    Saddr = maps:get(saddr, IPV4, {127,0,0,1}),
    Daddr = maps:get(daddr, IPV4, {127,0,0,1}),
    PayloadLen = maps:get(ip_payload_length, Global, 0),
    PayloadProto = maps:get(ip_payload_proto, Global, ?IPPROTO_TCP),
    Len = 20+PayloadLen,
    Packet = #ipv4{len = Len, p = PayloadProto, saddr = Saddr, daddr = Daddr},
    #{global => Global, out => [Packet|Out]};
expand(#{type := sctp} = SCTP, Acc) ->
    #{global := Global, out := Out} = Acc,
    Sport = maps:get(sport, SCTP, 0),
    Dport = maps:get(dport, SCTP, 0),
    Data = maps:get(data, SCTP, <<>>),
    PPI = maps:get(ppi, SCTP, 3),
    Len = 12+4+12+byte_size(Data),
    ChunkData = #sctp_chunk_data{ppi = PPI, data = Data},
    Chunk = #sctp_chunk{type = ?SCTP_CHUNK_DATA,
                        b = 1,     % first segment
                        e = 1,     % last segment
                        payload = ChunkData},
    Packet = #sctp{sport = Sport, dport = Dport, chunks = [Chunk]},
    Glob = Global#{ip_payload_length => Len, ip_payload_proto => ?IPPROTO_SCTP},
    #{global => Glob, out => [Packet|Out]}.

lift(ok, eof) ->
    exit(eof);
lift(Tag, {Tag, Val}) ->
    Val.

to_map(Tuple) ->
    [Name|Fields] = tuple_to_list(Tuple),
    maps:from_list(lists:zip(fields(Name), Fields)).

fields(file_header) ->
    record_info(fields, file_header).
