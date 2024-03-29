-module(facap_test).

-include_lib("eunit/include/eunit.hrl").

t_0_test() ->
    S = facap:open_file("/tmp/foo.fcap"),
    facap:append_file(
      S,
      [#{type => pcap, ts => 10101010101},
       #{type => cooked},
       #{type => ipv4, saddr => {1,2,3,4}, daddr => {6,7,8,9}},
       #{type => tcp, sport => 666, dport => 999},
       #{type => payload, data => text()}]),
    facap:close_file(S).

text() ->
    <<"hello Vint!">>.

%% SCTP encoding not yet implemented in pkt.
%% t_1_test() ->
%%     S = facap:open_file("/tmp/foo.fcap"),
%%     facap:append_file(
%%       S,
%%       [#{type => pcap, ts => 10101010101},
%%        #{type => cooked},
%%        #{type => ipv4, saddr => {1,2,3,4}, daddr => {6,7,8,9}},
%%        #{type => sctp, sport => 666, dport => 999},
%%        #{type => payload, data => m3ua()}]),
%%     facap:close_file(S).
%%
%% m3ua() ->
%%     <<1,0,1,1,0,0,0,80,2,16,0,72,0,0,5,4,0,0,53,167,3,3,0,8,
%%       17,128,15,4,15,26,0,11,18,6,0,17,4,100,39,147,0,16,0,11,
%%       18,149,0,17,4,100,7,8,0,3,2,24,101,22,72,4,76,203,172,0,
%%       73,4,8,50,96,162,108,8,161,6,2,1,2,2,1,56>>.
