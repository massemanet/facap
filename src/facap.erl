%% -*- mode: erlang; erlang-indent-level: 4 -*-
-module(facap).

-export(
   [fold/3,
    fold/4,
    open_file/1,
    close_file/1,
    write_packet/3,
    encode/1]).

-include_lib("kernel/include/file.hrl").
-include_lib("kernel/include/inet_sctp.hrl").
-include_lib("kernel/include/logger.hrl").
-include_lib("pkt/include/pkt.hrl").

little(X) ->
    binary:decode_unsigned(X, little).
big(X) ->
    binary:decode_unsigned(X, big).
hex(X) ->
    [case N<10 of true -> N+$0; false-> N+$W end || <<N:4>> <= X].

-define(COOKED(Pro),
        #linux_cooked{pro = Pro}).
-define(ETHER(),
       #ether{}).
-define(IP(Saddr, Daddr, Proto),
        #ipv4{saddr = Saddr, daddr = Daddr, p = Proto}).
-define(ICMP(),
        #icmp{}).
-define(TCP(Sport, Dport),
        #tcp{sport = Sport, dport = Dport}).
-define(SCTP(Sport, Dport, Chunks),
        #sctp{sport = Sport, dport = Dport, chunks = Chunks}).

-record(file_header,
        {maj_vsn,
         min_vsn,
         snap_length,
         dll_type}).

-record(packet_header,
        {ts_sec,
         ts_usec,
         captured_len,
         original_len,
         payload}).

fold(Fun, Acc0, File) ->
    fold(Fun, Acc0, File, #{}).
fold(Fun, Acc0, File, Opts) ->
    case file:read_file_info(File) of
        {error, enoent} -> {error, {no_such_file, File}};
        {ok, #file_info{type = directory}} -> lists:foldl(fun(F, A) -> do_fold(Fun, A, F, Opts) end, Acc0, files(File));
        {ok, #file_info{type = regular}} -> do_fold(Fun, Acc0, File, Opts)
    end.

files(Dir) ->
    {ok, Fs}  = file:list_dir(Dir),
    [filename:join(Dir, F) || F <- Fs].

do_fold(Fun, Acc0, File, Opts) ->
    {ok, FD} = file:open(File, [read, raw, binary, read_ahead]),
    H = file_header(FD),
    try fold_loop(Fun, Acc0, Opts#{'_count' => 0, fd => FD, ptr => 24, file_header => H})
    catch throw:Acc -> Acc
    after file:close(FD)
    end.

file_header(FD) ->
    case hex(lift(ok, file:pread(FD, 0, 4))) of
        "d4c3b2a1" -> file_header_little(FD);
        "a1b2c3d4" -> file_header_big(FD)
    end.

file_header_little(FD) ->
    #file_header{
       maj_vsn = little(lift(ok, file:pread(FD, 4, 2))),
       min_vsn = little(lift(ok, file:pread(FD, 6, 2))),
       %% _ = hex(lift(ok, file:pread(FD, 8, 8))),
       snap_length = little(lift(ok, file:pread(FD, 16, 4))),
       dll_type = dll(little(lift(ok, file:pread(FD, 20, 4))))}.

file_header_big(FD) ->
    #file_header{
       maj_vsn = big(lift(ok, file:pread(FD, 4, 2))),
       min_vsn = big(lift(ok, file:pread(FD, 6, 2))),
       %% _ = hex(lift(ok, file:pread(FD, 8, 8))),
       snap_length = big(lift(ok, file:pread(FD, 16, 4))),
       dll_type = dll(big(lift(ok, file:pread(FD, 20, 4))))}.


dll(?DLT_EN10MB) -> ether;
dll(?DLT_LINUX_SLL) -> linux_cooked;
dll(?DLT_LINUX_SLL2) -> linux_cooked_v2.

fold_loop(Fun, Acc, #{fd := FD, ptr := Ptr0, file_header := #file_header{dll_type = DLLT}} = Opts) ->
    PC = try packet_header(FD, Ptr0) catch exit:eof -> throw(Acc) end,
    Ptr = Ptr0+16+PC#packet_header.captured_len,
    TS = (PC#packet_header.ts_sec)+(PC#packet_header.ts_usec)/1000_000,
    Pkt = decapsulated(pkt:decapsulate(DLLT, PC#packet_header.payload), TS, Opts),
    A = lists:foldl(fun(P, A) -> Fun(P, A) end, Acc, mk_pkts(Pkt, Opts)),
    fold_loop(Fun, A, maybe_done(Opts#{ptr => Ptr}, A)).

decapsulated(Dec, TS, #{'_count' := Count}) ->
    dec(Dec, #{ts => TS, count => Count}).

dec([<<>>], Pkt) ->
    Pkt;
dec([Extra], Pkt) when is_binary(Extra) ->
    Pkt#{extra => Extra};
dec([H|T], Pkt) ->
    case H of
        ?SCTP(Sport, Dport, Chunks) ->
            dec(T, Pkt#{proto => sctp, sport => Sport, dport => Dport, chunks => Chunks});
        ?TCP(Sport, Dport) ->
            dec(T, Pkt#{proto => tcp, sport => Sport, dport => Dport});
        ?ICMP() ->
            dec(T, Pkt#{proto => icmp});
        ?IP(Saddr, Daddr, Proto) ->
            dec(T, Pkt#{proto => ip, saddr => Saddr, daddr => Daddr, protocol1 => Proto});
        ?COOKED(Proto) ->
            dec(T, Pkt#{proto => cooked, protocol0 => Proto});
        ?ETHER() ->
            dec(T, Pkt#{proto => ether});
        _ ->
            error({unrecognized_packet, [H|T]})
    end.

packet_header(FD, P) ->
    PC = #packet_header{
            ts_sec = little(lift(ok, file:pread(FD, P+0, 4))),
            ts_usec = little(lift(ok, file:pread(FD, P+4, 4))),
            captured_len = little(lift(ok, file:pread(FD, P+8, 4))),
            original_len = little(lift(ok, file:pread(FD, P+12, 4)))},
    PC#packet_header{payload = lift(ok, file:pread(FD, P+16, PC#packet_header.captured_len))}.


mk_pkts(Pkt, _Opts) ->
    case Pkt of
        #{proto := sctp, chunks := Chunks} -> [chunk(Pkt, C) || C <- Chunks];
        #{proto := _} -> [Pkt]
    end.

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

chunk(Pkt, Chunk) ->
    case Chunk of
        ?DATA(PPI, Data)     -> Pkt#{chunk_type => data, ppi => PPI, chunk_data => Data};
        ?INIT()              -> Pkt#{chunk_type => init};
        ?INIT_ACK()          -> Pkt#{chunk_type => init_ack};
        ?SACK()              -> Pkt#{chunk_type => sack};
        ?HEARTBEAT()         -> Pkt#{chunk_type => heartbeat};
        ?HEARTBEAT_ACK()     -> Pkt#{chunk_type => heartbeat_ack};
        ?ABORT()             -> Pkt#{chunk_type => abort};
        ?SHUTDOWN()          -> Pkt#{chunk_type => shutdown};
        ?SHUTDOWN_ACK()      -> Pkt#{chunk_type => shutdown_ack};
        ?ERROR()             -> Pkt#{chunk_type => error};
        ?COOKIE_ECHO()       -> Pkt#{chunk_type => cookie_echo};
        ?COOKIE_ACK()        -> Pkt#{chunk_type => cookie_ack};
        ?SHUTDOWN_COMPLETE() -> Pkt#{chunk_type => shutdown_complete}
    end.

-define(COUNTS(C, M), #{'_count' := C, max_count := M}).
maybe_done(?COUNTS(Count, Max), Acc) when 0 < Max, Max < Count -> throw(Acc);
maybe_done(#{'_count' := C} = Opts, _) -> Opts#{'_count' => C+1}.

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
