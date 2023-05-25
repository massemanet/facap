-module(facap).

%% reading
-export(
   [header/1,
    list/1,
    list/2,
    fold/3,
    fold/4]).

%% iterator
-export(
   [iterator/1,
    next/1,
    finalize/1,
    inspect/1]).

%% writing
-export(
   [open_file/1,
    open_file/2,
    close_file/1,
    append_file/2]).

open_file(File) ->
    open_file(File, #{}).

open_file(File, Opts) ->
    facap_out:open(Opts#{file => File}).

close_file(S) ->
    facap_out:close(S).

append_file(S, Pkt) ->
    facap_out:append(Pkt, S).

iterator(File) ->
    facap_iter:iterate(init, File).

next(Iter) ->
    facap_iter:iterate(next, Iter).

inspect(Iter) ->
    facap_iter:iterate(state, Iter).

finalize(Iter) ->
    facap_iter:iterate(finalize, Iter).

list(File) ->
    facap_in:list(#{file => File}).

header(File) ->
    facap_in:header(File).

list(File, Opts) ->
    facap_in:list(Opts#{file => File}).

fold(Fun, Acc, File) ->
    facap_in:fold(Fun, Acc, #{file => File}).

fold(Fun, Acc, File, Opts) ->
    facap_in:fold(Fun, Acc, Opts#{file => File}).
