%% -*- mode: erlang; erlang-indent-level: 4 -*-
-module(facap).

-export(
   [fold/3,
    encode/3]).

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

-define(SCTP(_Saddr, _Daddr, _Sport, _Dport, _Chunks),
        [#linux_cooked{},
         #ipv4{saddr = _Saddr, daddr = _Daddr},
         #sctp{sport = _Sport, dport = _Dport, chunks = _Chunks},
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
    {ok, FD} = file:open(File, [read, raw, binary, read_ahead]),
    case hex(?LIFT(file:pread(FD, 0, 4))) of
        "d4c3b2a1" -> #pcap_file{dll_type = 113} = file_header_little(FD);
        "a1b2c3d4" -> #pcap_file{dll_type = 113} = file_header_big(FD)
    end,
    try fold_loop(FD, 24, Fun, Acc0, Opts#{'_count' => 0})
    catch throw:Acc -> Acc
    after file:close(FD)
    end.

fold_loop(FD, P, Fun, Acc, Opts) ->
    PC = try pcap_packet(FD, P) catch exit:eof -> throw(Acc) end,
    NP = P+16+PC#pcap_packet.captured_len,
    TS = (PC#pcap_packet.ts_sec)+(PC#pcap_packet.ts_usec)/1000_000,
    case pkt:decapsulate(linux_sll, PC#pcap_packet.payload) of
        ?SCTP(Saddr, Daddr, Sport, Dport, Chunks) ->
            Pkt = #{proto => sctp, ts => TS, count => maps:get('_count', Opts),
                    saddr => Saddr, sport => Sport,
                    daddr => Daddr, dport => Dport},
            A = lists:foldl(fun(C, A) -> Fun(mk_pkt(Pkt, C, Opts), A) end, Acc, Chunks),
            fold_loop(FD, NP, Fun, A, maybe_done(Opts, A));
        _NotSctp ->
            fold_loop(FD, NP, Fun, Acc, maybe_done(Opts, Acc))
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

mk_pkt(Pkt, Chunk, Opts) ->
    case Chunk of
        #sctp_chunk{payload = #sctp_chunk_data{ppi = PPI, data = Data}} ->
            case maps:get(level, Opts, raw) of
                raw ->
                    Pkt#{ppi => PPI, chunk_data => Data}
              end;
        _ ->
            Pkt
    end.

maybe_done(#{'_count' := C, max_count := M}, Acc) when 0 < M, M < C -> throw(Acc);
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
