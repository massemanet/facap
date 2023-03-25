%% -*- mode: erlang; erlang-indent-level: 4 -*-
-module(facap_iter).

-export(
   [iterate/2]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% iterator internals, user side

iterate(init, File) ->
    spawn(fun() -> init(File) end);
iterate(next, Pid) ->
    irecv(isend(Pid, next));
iterate(state, Pid) ->
    irecv(isend(Pid, state));
iterate(finalize, Pid) ->
    irecv(isend(Pid, quit)).

isend(Pid, Msg) ->
    case erlang:is_process_alive(Pid) of
        true -> Pid ! {self(), erlang:make_ref(), Msg};
        false -> {error, dead}
    end.

irecv({error, Err}) ->
    {error, Err};
irecv({_, _, quit}) ->
    ok;
irecv({_, Ref, _}) ->
    receive {Ref, X} -> X
    after 1000 -> {error, timeout}
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% runs in iterator process

init(File) ->
    iloop(iinit(File)).

iinit(File) ->
    Files = iopen(File),
    Tree = gb_trees:from_orddict(lists:sort(lists:filtermap(fun ikv/1, Files))),
    #{tree => Tree}.

ikv(F) ->
    F ! (R = erlang:make_ref()),
    receive {R, Pkt} -> {true, {its(Pkt), {F, Pkt}}}
    after 100 -> false
    end.

its(#{ts := TS}) ->
    TS.

iloop(State) ->
    receive
        {P, Ref, state} -> iloop(istate(P, Ref, State));
        {P, Ref, next} -> iloop(inext(P, Ref, State));
        {_, _, quit} -> ifinal(State)
    end.

iopen(File) ->
    Fs = filelib:wildcard(File),
    Self = self(),
    Fun = fun(Pkt, A) -> receive R -> Self ! {R, Pkt}, A end end,
    [spawn(fun() -> facap_in:fold(Fun, #{}, #{file => F}) end) || F <- Fs].


istate(P, Ref, State) ->
    P ! {Ref, istate(State)},
    State.

istate(#{tree := Tree}) ->
    iiter(gb_trees:iterator(Tree), []).

iiter(Iter, Acc) ->
    case gb_trees:next(Iter) of
        none -> lists:reverse(Acc);
        {_TS, {_F, S}, I} -> iiter(I, [S|Acc])
    end.

inext(P, Ref, State0) ->
    {Pkt, State} = inext(State0),
    P ! {Ref, Pkt},
    State.

inext(#{tree := Tree} = State) ->
    case catch gb_trees:take_smallest(Tree) of
        {_, {F, Pkt}, T} -> {Pkt, State#{tree => iinsert(F, T)}};
        {'EXIT', _} -> {eof, State}
    end.

iinsert(F, Tree) ->
    case ikv(F) of
        {true, {K, V}} -> gb_trees:insert(K, V, Tree);
        false -> Tree
    end.

ifinal(State) ->
    State.
