-module(facap_in).

-export(
   [header/1,
    list/1,
    fold/3]).

-include_lib("kernel/include/file.hrl").

header(File) ->
    {ok, FD} = file:open(File, [read, raw, binary, read_ahead]),
    try state0(FD, File, #{})
    after file:close(FD)
    end.

list(S) ->
    lists:reverse(fold(fun(P, O) -> [P|O] end, [], S)).

fold(Fun, Acc0, #{file := File} = S) ->
    case file:read_file_info(File) of
        {error, enoent} ->
            {error, {no_such_file, File}};
        {ok, #file_info{type = directory}} ->
            folder(Fun, Acc0, S, files(File));
        {ok, #file_info{type = regular}} ->
            folder(Fun, Acc0, S, [File])
    end.

files(Dir) ->
    {ok, Fs}  = file:list_dir(Dir),
    [filename:join(Dir, F) || F <- Fs].

folder(Fun, Acc0, State, Files) ->
    lists:foldl(mk_folder(Fun, State), Acc0, Files).

mk_folder(Fun, State) ->
    fun(F, A) -> do_fold(Fun, A, F, State) end.

do_fold(Fun, Acc0, File, Opts) ->
    {ok, FD} = file:open(File, [read, raw, binary, read_ahead]),
    State = state0(FD, File, Opts),
    try fold_loop(Fun, Acc0, State)
    catch throw:Acc -> Acc
    after file:close(FD)
    end.

state0(FD, File, State) ->
    State0 = #{seqno => 0, fd => FD, filename => File, fmod => fmod(FD)},
    file_header(maps:merge(State0, State)).

fmod(FD) ->
    case magic(FD) of
        ng -> facap_ng;
        og -> facap_og
    end.

magic(FD) ->
    case file:pread(FD, 0, 4) of
        {ok, <<16#0a0d0d0a:32>>} -> ng;
        {ok, <<16#a1b23c4d:32>>} -> og;
        {ok, <<16#a1b2c3d4:32>>} -> og;
        {ok, <<16#4d3cb2a1:32>>} -> og;
        {ok, <<16#d4c3b2a1:32>>} -> og;
        {ok, W} -> error({bad_magic, W});
        Err -> error(Err)
    end.

file_header(#{fd := FD, fmod := FMod} = S) ->
    S#{fstate => FMod:file_header(FD)}.

fold_loop(Fun, Acc, State0) ->
    case packet(State0) of
        {eof, _State} ->
            Acc;
        {Packet, State} ->
            fold_loop(Fun, Fun(dec(Packet, State), Acc), State)
    end.

packet(State) ->
    case maybe_done(State) of
        eof -> {eof, State};
        S -> get_packet(S)
    end.

-define(SC(S, C), #{seqno := S, count := C}).
-define(IS_DONE(Seqno, Count), is_integer(Count), Count =< Seqno).
maybe_done(?SC(Seqno, Count)) when ?IS_DONE(Seqno, Count) -> eof;
maybe_done(State) -> maps:update_with(seqno, fun plus1/1, State).

plus1(I) -> I+1.

get_packet(#{fd := FD, fstate := FS0, fmod := FM} = S) ->
    case FM:packet(FD, FS0) of
        {FS, Packet} -> {Packet, S#{fstate => FS}};
        eof -> {eof, S}
    end.

dec(#{payload := Payload}, #{fstate := #{dll_type := DLL}}) ->
    facap_pkt:dec(DLL, Payload).
