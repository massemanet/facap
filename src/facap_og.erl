-module(facap_og).
-export(
   [file_header/1,
    packet/2]).

file_header(FD) ->
    get_file_header(FD).

packet(FD, S) ->
    get_packet(FD, S).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% file header

get_file_header(FD) ->
    case file:pread(FD, 0, 4) of
        {ok, <<16#a1b23c4d:32>>} -> file_header(big, nano, FD);
        {ok, <<16#a1b2c3d4:32>>} -> file_header(big, micro, FD);
        {ok, <<16#4d3cb2a1:32>>} -> file_header(little, nano, FD);
        {ok, <<16#d4c3b2a1:32>>} -> file_header(little, micro, FD);
        Err -> error({bad_magic, Err})
    end.

file_header(Endian, TimeRes, FD) ->
    {Maj, Min, Snap, DLL} = get_fh(Endian, FD),
    #{maj_vsn => Maj,
      min_vsn => Min,
      endian => Endian,
      time_resolution => timeres(TimeRes),
      snap_length => Snap,
      dll_type => DLL,
      ptr => 24}.

get_fh(Endian, FD) ->
    {ok, H} = file:pread(FD, 4, 20),
    fh(Endian, H).

fh(big, <<J:16/big, N:16/big, _:8/bytes, S:32/big, D:32/big>>) ->
    {J, N, S, D};
fh(little, <<J:16/little, N:16/little, _:8/bytes, S:32/little, D:32/little>>) ->
    {J, N, S, D}.

timeres(micro) -> 1_000_000;
timeres(nano) -> 1_000_000_000.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% packet

get_packet(FD, #{ptr := Ptr, endian := Endian} = S) ->
    case file:pread(FD, Ptr, 16) of
        {ok, PH} ->
            {TSsec, TSfrac, Cap, Orig} = ph(Endian, PH),
            case file:pread(FD, Ptr+16, Cap) of
                {ok, Payload} ->
                    #{dll_type := DLL, time_resolution := TimeRes} = S,
                    {#{ts_sec => TSsec+(TSfrac/TimeRes),
                       captured_len => Cap,
                       original_len => Orig,
                       dll_type => DLL,
                       payload => Payload},
                     S#{ptr => Ptr+16+Cap}};
                eof -> eof
            end;
        eof -> eof
    end.

ph(little, <<TSsec:32/little, TSfrac:32/little, Cap:32/little, Orig:32/little>>) ->
    {TSsec, TSfrac, Cap, Orig};
ph(big, <<TSsec:32/big, TSfrac:32/big, Cap:32/big, Orig:32/big>>) ->
    {TSsec, TSfrac, Cap, Orig}.
