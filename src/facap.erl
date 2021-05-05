%% -*- mode: erlang; erlang-indent-level: 4 -*-
-module(facap).

-export(
   [fold/3,
    fold/4,
    encode/3]).

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

-define(LIFT(_X), (fun() -> case begin _X end of {ok, X} -> X; X -> exit(X) end end)()).

-define(COOKED(Pro),
        [#linux_cooked{pro = Pro},
         <<>>]).
-define(IP(Saddr, Daddr, Proto),
        [#linux_cooked{},
         #ipv4{saddr = Saddr, daddr = Daddr, p = Proto},
         <<>>]).
-define(SCTP(Saddr, Daddr, Sport, Dport, Chunks),
        [#linux_cooked{},
         #ipv4{saddr = Saddr, daddr = Daddr},
         #sctp{sport = Sport, dport = Dport, chunks = Chunks},
         <<>>]).

-record(pcap_file,
        {maj_vsn,
         min_vsn,
         snap_length,
         dll_type}).

-record(pcap_packet,
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
    case hex(?LIFT(file:pread(FD, 0, 4))) of
        "d4c3b2a1" -> #pcap_file{dll_type = 113} = file_header_little(FD);
        "a1b2c3d4" -> #pcap_file{dll_type = 113} = file_header_big(FD)
    end,
    try fold_loop(FD, 24, Fun, Acc0, Opts#{'_count' => 0})
    catch throw:Acc -> Acc
    after file:close(FD)
    end.

fold_loop(FD, Pos, Fun, Acc, Opts) ->
    PC = try pcap_packet(FD, Pos) catch exit:eof -> throw(Acc) end,
    NP = Pos+16+PC#pcap_packet.captured_len,
    TS = (PC#pcap_packet.ts_sec)+(PC#pcap_packet.ts_usec)/1000_000,
    case pkt:decapsulate(linux_sll, PC#pcap_packet.payload) of
        ?SCTP(Saddr, Daddr, Sport, Dport, Chunks) ->
            Pkt = #{proto => sctp, ts => TS, count => maps:get('_count', Opts),
                    saddr => Saddr, sport => Sport,
                    daddr => Daddr, dport => Dport},
            A = lists:foldl(fun(C, A) -> Fun(mk_pkt(Pkt, C, Opts), A) end, Acc, Chunks),
            fold_loop(FD, NP, Fun, A, maybe_done(Opts, A));
        ?IP(Saddr, Daddr, Proto) ->
            erlang:display({not_sctp, Saddr, Daddr, Proto}),
            fold_loop(FD, NP, Fun, Acc, maybe_done(Opts, Acc));
        ?COOKED(Proto) ->
            erlang:display({not_ip, Proto}),
            fold_loop(FD, NP, Fun, Acc, maybe_done(Opts, Acc));
        X ->
            error({unrecognized_packet, X})
    end.

file_header_little(FD) ->
    #pcap_file{
       maj_vsn = little(?LIFT(file:pread(FD, 4, 2))),
       min_vsn = little(?LIFT(file:pread(FD, 6, 2))),
       %% _ = hex(?LIFT(file:pread(FD, 8, 8))),
       snap_length = little(?LIFT(file:pread(FD, 16, 4))),
       dll_type = little(?LIFT(file:pread(FD, 20, 4)))}.

file_header_big(FD) ->
    #pcap_file{
       maj_vsn = big(?LIFT(file:pread(FD, 4, 2))),
       min_vsn = big(?LIFT(file:pread(FD, 6, 2))),
       %% _ = hex(?LIFT(file:pread(FD, 8, 8))),
       snap_length = big(?LIFT(file:pread(FD, 16, 4))),
       dll_type = big(?LIFT(file:pread(FD, 20, 4)))}.

pcap_packet(FD, P) ->
    PC = #pcap_packet{
            ts_sec = little(?LIFT(file:pread(FD, P+0, 4))),
            ts_usec = little(?LIFT(file:pread(FD, P+4, 4))),
            captured_len = little(?LIFT(file:pread(FD, P+8, 4))),
            original_len = little(?LIFT(file:pread(FD, P+12, 4)))},
    PC#pcap_packet{payload = ?LIFT(file:pread(FD, P+16, PC#pcap_packet.captured_len))}.

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
mk_pkt(Pkt, Chunk, _Opts) ->
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

encode(Framing, PPI, Data) ->
    Saddr = maps:get(saddr, Framing, {127,0,0,1}),
    Daddr = maps:get(daddr, Framing, {127,0,0,1}),
    Sport = maps:get(sport, Framing, 0),
    Dport = maps:get(dport, Framing, 0),
    Chunk = #sctp_chunk{payload = #sctp_chunk_data{ppi = PPI, data = Data}},
    SctpLen = 12+4+12+byte_size(Data),
    IpLen = 20+SctpLen,
    pkt:encode([#linux_cooked{packet_type = 0,
                              ll_len = 6},
                #ipv4{len = IpLen,
                      p = ?IPPROTO_SCTP,
                      sum = 0,
                      saddr = Saddr,
                      daddr = Daddr},
                #sctp{sport = Sport,
                      dport = Dport,
                      chunks = [Chunk]}]).
