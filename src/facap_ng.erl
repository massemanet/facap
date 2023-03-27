-module(facap_ng).

-export(
   [file_header/1,
    packet/2]).

file_header(FD) ->
    {ok, Magic} = file:pread(FD, 8, 4),
    case block(FD, #{ptr => 0, endian => endian(Magic)}) of
        eof -> eof;
        {meta, S} -> S;
        Err -> error({bad_header, Err})
    end.

packet(FD, S0) ->
    case block(FD, S0) of
        eof -> eof;
        {meta, S} -> packet(FD, S);
        {P, S} -> {P, S}
    end.

endian(<<16#1a2b3c4d:32/little>>) ->
    little;
endian(<<16#1a2b3c4d:32/big>>) ->
    big.

-define(MAGIC, 16#1a2b3c4d).

%% block types
-define(SHB, 16#0a0d0d0a). % section header
-define(IDB, 16#00000001). % interface description
-define(SPB, 16#00000003). % simple packet
-define(NRB, 16#00000004). % name resolution
-define(ISB, 16#00000005). % interface statistics
-define(DSB, 16#0000000a). % decryption secrets
-define(EPB, 16#00000006). % enhanced packet


%% since we can get new sections whenever, the file can change
%% endianess(!).
-define(SECTION_BIG(L), <<?SHB:32, L:32/big, ?MAGIC:32/big>>).
-define(SECTION_LITTLE(L), <<?SHB:32, L:32/little, ?MAGIC:32/little>>).
-define(IS_BIG(S), map_get(endian, S) =:= big).
-define(IS_LITTLE(S), map_get(endian, S) =:= little).
-define(IS_VENDOR(T), (T band 16#c0000000) =/= 0).
-define(BLOCK_BIG(T, L), <<T:32/big, L:32/big, _:4/bytes>>).
-define(BLOCK_LITTLE(T, L), <<T:32/little, L:32/little, _:4/bytes>>).
block(FD, #{ptr := Ptr} = S) ->
    case file:pread(FD, Ptr, 12) of
        eof ->
            eof;
        {ok, ?SECTION_BIG(Len)} ->
            block(?SHB, file:pread(FD, Ptr+8, Len-12), #{ptr => Ptr+Len});
        {ok, ?SECTION_LITTLE(Len)} ->
            block(?SHB, file:pread(FD, Ptr+8, Len-12), #{ptr => Ptr+Len});
        {ok, ?BLOCK_LITTLE(Type, Len)} when ?IS_LITTLE(S) ->
            block(Type, file:pread(FD, Ptr+8, Len-12), S#{ptr => Ptr+Len});
        {ok, ?BLOCK_BIG(Type, Len)} when ?IS_BIG(S) ->
            block(Type, file:pread(FD, Ptr+8, Len-12), S#{ptr => Ptr+Len})
    end.

%% handle all block types

block(_, eof, _) ->
    eof;

%%% Section Header Block
%% Block Type (4 bytes) = 0x0a0d0d0a
%% Block Length (4 bytes)
%% Byte-Order Magic (4 bytes) = 0x1a2b3c4d
%% Major Version (2 bytes) = 0x0001
%% Minor Version (2 bytes) = 0x0000
%% Section Length (8 bytes) = <should be ignored>
%% Options (variable length)
%% Block Length (redundant 4 byte value)

block(?SHB, {ok, Bytes}, S) ->
    <<Magic:4/bytes, Maj:2/bytes, Min:2/bytes, _:8/bytes, Os/bytes>> = Bytes,
    E = endian(Magic),
    {meta,
     S#{major_version => swp(E, Maj),
        minor_version => swp(E, Min),
        endian => E,
        options => byte_size(Os)}};

%%% Interface Description Block
%% Block Type (4 bytes) = 0x00000001
%% Block Total Length (4 bytes)
%% Link Type (2 bytes)
%% Reserved (2 bytes) = 0x0000
%% Snap Length (4 bytes)
%% Options (variable length)
%% Block Total Length (redundant 4 byte value)

block(?IDB, {ok, Bytes}, #{endian := E} = S) ->
    <<LinkType:2/bytes, _:2/bytes, SnapLen:4/bytes, Os/bytes>> = Bytes,
    IF = #{dll_type => swp(E, LinkType),
           snap_length => swp(E, SnapLen),
           options => byte_size(Os)},
    {meta,
     add_if(IF, S)};

%% Enhanced Packet Block
%% Block Type (4 bytes) = 0x00000006
%% Block Total Length (4 bytes)
%% Interface ID (4 bytes)
%% Timestamp Upper (4 bytes)
%% Timestamp Lower (4 bytes)
%% Captured Packet Length (4 bytes)
%% Original Packet Length (4 bytes)
%% Packet Data (variable length)
%% Options (variable length)
%% Block Total Length (redundant 4 byte value)

block(?EPB, {ok, Bytes}, #{endian := E} = S) ->
    <<I:4/bytes, TS:8/bytes, C:4/bytes, L:4/bytes, X/bytes>> = Bytes,
    Iid = swp(E, I),
    Captured = swp(E, C),
    OLen = swp(E, L),
    #{dll_type := DLL} = Interface = get_if(Iid, S),
    <<Payload:Captured/bytes, Os/bytes>> = X,
    {#{iid => Iid,
       interface => Interface,
       dll_type => DLL,
       ts => TS,
       captured_len => Captured,
       original_len => OLen,
       payload => Payload,
       options => byte_size(Os)},
    S};

%% Vendor Specific Block
%% ...local use number codes (the block or option type code numbers
%% with the Most Significant Bit set).

block(Type, {ok, _Bytes}, #{endian := _E} = S) when ?IS_VENDOR(Type) ->
    {meta, S};

%% simple packet block
%%
%%  8 |                    Original Packet Length                     |
%%    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% 12 /                          Packet Data                          /
%%    /              variable length, padded to 32 bits               /
%%
%% has no timestamp
%
%% it MUST be assumed that all the Simple Packet Blocks have been
%% captured on the interface previously specified in the first
%% Interface Description Block.
%%
%% if the packet has been truncated by the capture process, the
%% SnapLen value in Section 4.2 will be less than the Original Packet
%% Length value, and the SnapLen value MUST be used to determine the
%% size of the Packet Data field length.

block(?SPB, {ok, Bytes}, #{endian := E} = S) ->
    <<L:4/bytes, X/bytes>> = Bytes,
    OLen = swp(E, L),
    #{dll_type := DLL, snap_length := Snap} = get_if(0, S),
    Captured = max(Snap, OLen),
    <<Payload:Captured/bytes, Os/bytes>> = X,
    {#{dll_type => DLL,
       captured_len => Captured,
       original_len => OLen,
       payload => Payload,
       options => byte_size(Os)}};

%% name resolution block
%%
%% 8 |      Record Type              |      Record Value Length      |
%%   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%12 /                       Record Value                            /
%%   /              variable length, padded to 32 bits               /
%%   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%   .                  . . . other records . . .                    .
%%   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%   |  Record Type = nrb_record_end |   Record Value Length = 0     |
%%   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%   /                      Options (variable)                       /

block(?NRB, {ok, _Bytes}, #{endian := _E} = S) ->
    {meta, S};

%% interface statistics block
%%
%%  8 |                         Interface ID                          |
%%    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% 12 |                        Timestamp (High)                       |
%%    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% 16 |                        Timestamp (Low)                        |
%%    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% 20 /                      Options (variable)                       /

block(?ISB, {ok, _Bytes}, #{endian := _E} = S) ->
    {meta, S};

%% decryption secrets block
%%
%%  8 |                          Secrets Type                         |
%%    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% 12 |                         Secrets Length                        |
%%    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%% 16 /                          Secrets Data                         /
%%    /              (variable length, padded to 32 bits)             /
%%    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
%%    /                       Options (variable)                      /

block(?DSB, {ok, _Bytes}, #{endian := _E} = S) ->
    {meta, S};

%% unknown block type, read error, etc.

block(Type, Read, S) ->
    error({read_error, Type, Read, S}).

swp(big, <<I:16/big>>) -> I;
swp(little, <<I:16/little>>) -> I;
swp(big, <<I:32/big>>) -> I;
swp(little, <<I:32/little>>) -> I.

add_if(IF, #{ifs := #{ifs := I}} = S) ->
    S#{ifs => #{ifs => I+1, I => IF}};
add_if(IF, S) ->
    S#{ifs => #{ifs => 0, 0 => IF}}.

get_if(I, #{ifs := IFS}) ->
    maps:get(I, IFS, undefined);
get_if(_, _) ->
    undefined.
