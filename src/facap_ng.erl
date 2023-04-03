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
        options => opts(shb, Os, #{endian => E})}};

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
           options => opts(idb, Os, S)},
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
    Interface = get_if(Iid, S),
    Pad = pad(Captured),
    <<Payload:Captured/bytes, _:Pad/bytes, Os/bytes>> = X,
    {#{iid => Iid,
       interface => Interface,
       dll_type => dll(Interface),
       ts => TS,
       captured_len => Captured,
       original_len => OLen,
       payload => Payload,
       options => opts(epb, Os, S)},
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
    <<Payload:Captured/bytes, _/bytes>> = X,
    {#{dll_type => DLL,
       captured_len => Captured,
       original_len => OLen,
       payload => Payload}};

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

opts(_, <<>>, _) -> [];
opts(S, O, #{endian := E}) -> opts(E, S, O, []).

opts(E, S, O, [{eoc, _}|Os]) ->
    opts(E, S, O, Os);
opts(_, _, O, Os) when byte_size(O) < 4 ->
    Os;
opts(E, S, <<Type:2/bytes, L:2/bytes, X/bytes>>, Os) ->
    Len = swp(E, L),
    Pad = pad(Len),
    <<Val:Len/bytes, _:Pad/bytes, Y/bytes>> = X,
    opts(E, S, Y, [opt(opt_key(S, swp(E, Type)), E, Val)|Os]).

opt_key(_, 0) -> eoc;
opt_key(_, 1) -> comment;

opt_key(shb, 2) -> hw;
opt_key(shb, 3) -> os;
opt_key(shb, 4) -> appl;

opt_key(idb,  2) -> if_name;
opt_key(idb,  3) -> if_description;
opt_key(idb,  4) -> if_ipv4addr;
opt_key(idb,  5) -> if_ipv6addr;
opt_key(idb,  6) -> if_macaddr;
opt_key(idb,  7) -> if_euiaddr;
opt_key(idb,  8) -> if_speed;
opt_key(idb,  9) -> if_tsresol;
opt_key(idb, 10) -> if_tzone;
opt_key(idb, 11) -> if_filter;
opt_key(idb, 12) -> if_os;
opt_key(idb, 13) -> if_fcslen;
opt_key(idb, 14) -> if_tsoffset;
opt_key(idb, 15) -> if_hardware;
opt_key(idb, 16) -> if_txspeed;
opt_key(idb, 17) -> if_rxspeed;

opt_key(epb, 2) -> flags;
opt_key(epb, 3) -> hash;
opt_key(epb, 4) -> dropcount;
opt_key(epb, 5) -> packetid;
opt_key(epb, 6) -> queue;
opt_key(epb, 7) -> verdict;

opt_key(nrb, 2) -> dnsname;
opt_key(nrb, 3) -> dnsIP4addr;
opt_key(nrb, 4) -> dnsIP6addr;

opt_key(isb, 2) -> starttime;
opt_key(isb, 3) -> endtime;
opt_key(isb, 4) -> ifrecv;
opt_key(isb, 5) -> ifdrop;
opt_key(isb, 6) -> filteraccept;
opt_key(isb, 7) -> osdrop;
opt_key(isb, 8) -> usrdeliv;

opt_key(_, I) -> I.

%%  EPB flag
%%   0-1 Inbound / Outbound packet (00 = information not available, 01 = inbound, 10 = outbound)
%%   2-4 Reception type (000 = not specified, 001 = unicast, 010 = multicast, 011 = broadcast, 100 = promiscuous).
%%   5-8 Frame Check Sequence length, in octets (0000 if this information is not available).
%%   9-15 Reserved (MUST be set to zero).
%%  16-31 link-layer-dependent errors
%%         Bit 31 = symbol error,
%%         Bit 30 = preamble error
%%         Bit 29 = Start Frame Delimiter error
%%         Bit 28 = unaligned frame error
%%         Bit 27 = wrong Inter Frame Gap error
%%         Bit 26 = packet too short error
%%         Bit 25 = packet too long error
%%         Bit 24 = CRC error
opt(flags, End, Val) ->
    IVal = swp(End, Val),
    <<Esym:1,
      Epre:1,
      Esfd:1,
      Euna:1,
      Eifg:1,
      Ep2s:1,
      Ep2l:1,
      Ecrc:1,
      _:8,
      0:7,
      FCS:4,
      Cast:3,
      Dir:2>> = <<IVal:32>>,
    {flags,
     lists:foldl(
       fun({_, 0}, O) -> O; ({K, V}, O) -> O#{K => V} end,
       #{},
       [{error_symbol, Esym},
        {error_preamble, Epre},
        {error_sfd, Esfd},
        {error_unaligned, Euna},
        {error_ifg, Eifg},
        {error_p2s, Ep2s},
        {error_p2l, Ep2l},
        {error_crc, Ecrc},
        {fcs_len, FCS},
        {cast, opt_flag_cast(Cast)},
        {dir, opt_flag_dir(Dir)}])};
opt(K, _E, V) ->
    {K, V}.

opt_flag_dir(0) -> 0;
opt_flag_dir(1) -> in;
opt_flag_dir(2) -> out.

opt_flag_cast(0) -> 0;
opt_flag_cast(1) -> uni;
opt_flag_cast(2) -> multi;
opt_flag_cast(3) -> broad;
opt_flag_cast(4) -> promiscuous.

%% lookup table
pad(I) ->
    element((I band 3)+1, {0, 3, 2, 1}).

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

dll(undefined) -> 0;
dll(#{dll_type := DLL}) -> DLL.
