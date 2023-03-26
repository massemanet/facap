-module(facap_sctp).

-export([chunks/1]).

-include_lib("pkt/include/pkt.hrl").
-include_lib("kernel/include/inet_sctp.hrl").

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

chunks(Chunks) ->
    lists:map(fun chunk/1, Chunks).

chunk(Chunk) ->
    case Chunk of
        ?DATA(PPI, Data)     -> #{chunk_type => data, ppi => PPI, chunk_data => Data};
        ?INIT()              -> #{chunk_type => init};
        ?INIT_ACK()          -> #{chunk_type => init_ack};
        ?SACK()              -> #{chunk_type => sack};
        ?HEARTBEAT()         -> #{chunk_type => heartbeat};
        ?HEARTBEAT_ACK()     -> #{chunk_type => heartbeat_ack};
        ?ABORT()             -> #{chunk_type => abort};
        ?SHUTDOWN()          -> #{chunk_type => shutdown};
        ?SHUTDOWN_ACK()      -> #{chunk_type => shutdown_ack};
        ?ERROR()             -> #{chunk_type => error};
        ?COOKIE_ECHO()       -> #{chunk_type => cookie_echo};
        ?COOKIE_ACK()        -> #{chunk_type => cookie_ack};
        ?SHUTDOWN_COMPLETE() -> #{chunk_type => shutdown_complete}
    end.
