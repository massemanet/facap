-module(facap_ng).

-export([file_header/1]).

%%% Section Header Block
%% Block Type (4 bytes) = 0x0a0d0d0a
%% Block Length (4 bytes)
%% Byte-Order Magic (4 bytes) = 0x1a2b3c4d
%% Major Version (2 bytes) = 0x0001
%% Minor Version (2 bytes) = 0x0000
%% Section Length (8 bytes) = 0xffffffffffffffff
%% Options (variable length)
%% Block Length (redundant 4 byte value)
file_header(FD) ->
    {ok, FH} = file:pread(FD, 4, 20),
    Endian = endian(FH),
    {Len, Maj, Min} = fh(Endian, FH),
    #{ptr => Len,
      endian => Endian,
      major_version => Maj,
      minor_version => Min}.

endian(<<_:4/bytes, 16#4d3c2b1a:32/little, _:12/bytes>>) ->
    little;
endian(<<_:4/bytes, 16#4d3c2b1a:32/big, _:12/bytes>>) ->
    big.

fh(big, <<Len:32/big, _:4/bytes, Maj:16/big, Min:16/big, _:8/bytes>>) ->
    {Len, Maj, Min};
fh(little, <<Len:32/little, _:4/bytes, Maj:16/little, Min:16/little, _:8/bytes>>) ->
    {Len, Maj, Min}.

%%% Interface Description Block
%% Block Type (4 bytes) = 0x00000001
%% Block Total Length (4 bytes)
%% Link Type (2 bytes)
%% Reserved (2 bytes) = 0x0000
%% Snap Length (4 bytes)
%% Options (variable length)
%% Block Total Length (redundant 4 byte value)
