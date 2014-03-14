#!/usr/bin/env escript
%% -*- erlang -*-
%%! -smp disable
-module(gen_rtp_header).

% -mode(compile).

-define(VERSION, "0.1").

-export([main/1]).

-record(rtp_packet,
        {
          version = 2,
          padding = 0,
          marker = 0,
          payload_type = 0,
          seqno = 0,
          timestamp = 0,
          ssrc = 0,
          csrcs = [],
          extension = <<>>,
          payload = <<>>,
	  realtime
        }).


main(Args) ->
    DefaultOpts = [{format, state},
                   {ssrc, 16#11223344},
                   {rate, 8000},
                   {pt, 98}],
    {PosArgs, Opts} = getopts_checked(Args, DefaultOpts),
    log(debug, fun (Dev) ->
            io:format(Dev, "Initial options:~n", []),
	    dump_opts(Dev, Opts),
	    io:format(Dev, "~s: ~p~n", ["Args", PosArgs])
        end, [], Opts),
    main(PosArgs, Opts).

main([First | RemArgs], Opts) ->
    try
        F = list_to_integer(First),
	Format = proplists:get_value(format, Opts, state),
	PayloadData = proplists:get_value(payload, Opts, undef),
	InFile = proplists:get_value(file, Opts, undef),

        Payload = case {PayloadData, InFile} of
	    {undef, undef} ->
		% use default value
		#rtp_packet{}#rtp_packet.payload;
	    {P, undef} -> P;
	    {_, File} ->
		log(info, "Loading file '~s'~n", [File], Opts),
		{ok, InDev} = file:open(File, [read]),
		DS = [ Pl#rtp_packet.payload || {_T, Pl} <- read_packets(InDev, Opts)],
		file:close(InDev),
		log(debug, "File '~s' closed, ~w packets read.~n", [File, length(DS)], Opts),
		DS
	end,
        Dev = standard_io,
	write_packet_pre(Dev, Format),
        do_groups(Dev, Payload, F, RemArgs, Opts),
	write_packet_post(Dev, Format),
	0
    catch
        _:_ ->
            log(debug, "~p~n", [hd(erlang:get_stacktrace())], Opts),
            usage(),
            halt(1)
    end
    ;

main(_, _Opts) ->
    usage(),
    halt(1).

%%% group (count + offset) handling %%%

do_groups(_Dev, _Pl, _F, [], _Opts) ->
    ok;

do_groups(Dev, Pl, F, [L], Opts) ->
    do_groups(Dev, Pl, F, [L, 0], Opts);

do_groups(Dev, Pl, First, [L, O | Args], Opts) ->
    Ssrc = proplists:get_value(ssrc, Opts, #rtp_packet.ssrc),
    PT   = proplists:get_value(pt, Opts, #rtp_packet.payload_type),
    Len  = list_to_num(L),
    Offs = list_to_num(O),
    log(info, "Starting group: Ssrc=~.16B, PT=~B, First=~B, Len=~B, Offs=~B~n",
        [Ssrc, PT, First, Len, Offs], Opts),
    Pkg = #rtp_packet{ssrc = Ssrc, payload_type = PT},
    Pl2 = write_packets(Dev, Pl, Pkg, First, Len, Offs, Opts),
    {Args2, Opts2} = getopts_checked(Args, Opts),
    log(debug, fun (Io) ->
            io:format(Io, "Changed options:~n", []),
	    dump_opts(Io, Opts2 -- Opts)
        end, [], Opts),
    do_groups(Dev, Pl2, First+Len, Args2, Opts2).

%%% error handling helpers %%%

getopts_checked(Args, Opts) ->
    try
        getopts(Args, Opts)
    catch
        C:R ->
            log(error, "~s~n",
                [explain_error(C, R, erlang:get_stacktrace(), Opts)], Opts),
            usage(),
            halt(1)
    end.

explain_error(error, badarg, [{erlang,list_to_integer,[S,B]} | _ ], _Opts) ->
    io_lib:format("Invalid number '~s' (base ~B)", [S, B]);
explain_error(error, badarg, [{erlang,list_to_integer,[S]} | _ ], _Opts) ->
    io_lib:format("Invalid decimal number '~s'", [S]);
explain_error(C, R, [Hd | _ ], _Opts) ->
    io_lib:format("~p, ~p:~p", [Hd, C, R]);
explain_error(_, _, [], _Opts) ->
    "".

%%% usage and options %%%

myname() ->
    filename:basename(escript:script_name()).

usage(Text) ->
    io:format(standard_error, "~s: ~s~n", [myname(), Text]),
    usage().

usage() ->
    io:format(standard_error,
              "Usage: ~s [Options] Start Count1 Offs1 [[Options] Count2 Offs2 ...]~n",
              [myname()]).

show_version() ->
    io:format(standard_io,
              "~s ~s~n", [myname(), ?VERSION]).

show_help() ->
    io:format(standard_io,
              "Usage: ~s [Options] Start Count1 Offs1 [[Options] Count2 Offs2 ...]~n~n" ++
              "Options:~n" ++
	      "  -h, --help             this text~n" ++
	      "      --version          show version info~n" ++
	      "  -i, --file=FILE        reads payload from file (state format by default)~n" ++
	      "  -f, --frame-size=N     read payload as binary frames of size N instead~n" ++
	      "  -p, --payload=HEX      set constant payload~n" ++
	      "      --verbose=N        set verbosity~n" ++
	      "  -v                     increase verbosity~n" ++
	      "      --format=state     use state format for output (default)~n" ++
	      "  -C, --format=c         use simple C lines for output~n" ++
	      "      --format=carray    use a C array for output~n" ++
	      "  -s, --ssrc=SSRC        set the SSRC~n" ++
	      "  -t, --type=N           set the payload type~n" ++
	      "  -r, --rate=N           set the RTP rate [8000]~n" ++
	      "  -D, --duration=N       set the packet duration in RTP time units [160]~n" ++
	      "  -d, --delay=FLOAT      add offset to playout timestamp~n" ++
	      "~n" ++
	      "Arguments:~n" ++
	      "  Start              initial packet (sequence) number~n" ++
	      "  Count              number of packets~n" ++
	      "  Offs               timestamp offset (in RTP units)~n" ++
	      "", [myname()]).

getopts([ "--file=" ++ File | R], Opts) ->
        getopts(R, [{file, File} | Opts]);
getopts([ "-i" ++ T | R], Opts) ->
        getopts_alias_arg("--file", T, R, Opts);
getopts([ "--frame-size=" ++ N | R], Opts) ->
        Size = list_to_integer(N),
        getopts(R, [{frame_size, Size}, {in_format, bin} | Opts]);
getopts([ "-f" ++ T | R], Opts) ->
        getopts_alias_arg("--frame-size", T, R, Opts);
getopts([ "--duration=" ++ N | R], Opts) ->
        Duration = list_to_integer(N),
        getopts(R, [{duration, Duration} | Opts]);
getopts([ "-D" ++ T | R], Opts) ->
        getopts_alias_arg("--duration", T, R, Opts);
getopts([ "--rate=" ++ N | R], Opts) ->
        Rate = list_to_integer(N),
        getopts(R, [{rate, Rate} | Opts]);
getopts([ "-r" ++ T | R], Opts) ->
        getopts_alias_arg("--rate", T, R, Opts);
getopts([ "--version" | _], _Opts) ->
	show_version(),
        halt(0);
getopts([ "--help" | _], _Opts) ->
	show_help(),
        halt(0);
getopts([ "-h" ++ T | R], Opts) ->
        getopts_alias_no_arg("--help", T, R, Opts);
getopts([ "--verbose=" ++ V | R], Opts) ->
        Verbose = list_to_integer(V),
        getopts(R, [{verbose, Verbose} | Opts]);
getopts([ "-v" ++ T | R], Opts) ->
        Verbose = proplists:get_value(verbose, Opts, 0),
        getopts_short_no_arg(T, R, [ {verbose, Verbose+1} | Opts]);
getopts([ "--format=state" | R], Opts) ->
        getopts(R, [{format, state} | Opts]);
getopts([ "--format=c" | R], Opts) ->
        getopts(R, [{format, c} | Opts]);
getopts([ "-C" ++ T | R], Opts) ->
        getopts_alias_no_arg("--format=c", T, R, Opts);
getopts([ "--format=carray" | R], Opts) ->
        getopts(R, [{format, carray} | Opts]);
getopts([ "--payload=" ++ Hex | R], Opts) ->
        getopts(R, [{payload, hex_to_bin(Hex)} | Opts]);
getopts([ "--ssrc=" ++ Num | R], Opts) ->
        getopts(R, [{ssrc, list_to_num(Num)} | Opts]);
getopts([ "-s" ++ T | R], Opts) ->
        getopts_alias_arg("--ssrc", T, R, Opts);
getopts([ "--type=" ++ Num | R], Opts) ->
        getopts(R, [{pt, list_to_num(Num)} | Opts]);
getopts([ "-t" ++ T | R], Opts) ->
        getopts_alias_arg("--type", T, R, Opts);
getopts([ "--delay=" ++ Num | R], Opts) ->
        getopts(R, [{delay, list_to_float(Num)} | Opts]);
getopts([ "-d" ++ T | R], Opts) ->
        getopts_alias_arg("--delay", T, R, Opts);

% parsing helpers
getopts([ "--" | R], Opts) ->
        {R, normalize_opts(Opts)};
getopts([ O = "--" ++ _ | _], _Opts) ->
        usage("Invalid option: " ++ O),
        halt(1);
getopts([ [ $-, C | _] | _], _Opts) when C < $0; C > $9 ->
        usage("Invalid option: -" ++ [C]),
        halt(1);

getopts(R, Opts) ->
        {R, normalize_opts(Opts)}.

getopts_short_no_arg([], R, Opts) -> getopts(R, Opts);
getopts_short_no_arg(T, R, Opts)  -> getopts([ "-" ++ T | R], Opts).

getopts_alias_no_arg(A, [], R, Opts) -> getopts([A | R], Opts);
getopts_alias_no_arg(A, T, R, Opts)  -> getopts([A, "-" ++ T | R], Opts).

getopts_alias_arg(A, [], [T | R], Opts) -> getopts([A ++ "=" ++ T | R], Opts);
getopts_alias_arg(A, T, R, Opts)        -> getopts([A ++ "=" ++ T | R], Opts).

normalize_opts(Opts) ->
       [ proplists:lookup(E, Opts) || E <- proplists:get_keys(Opts) ].

%%% conversions %%%

bin_to_hex(Bin) -> [hd(integer_to_list(N,16)) || <<N:4>> <= Bin].
hex_to_bin(Hex) -> << <<(list_to_integer([Nib],16)):4>> || Nib <- Hex>>.

list_to_num("-" ++ Str) -> -list_to_num(Str);
list_to_num("0x" ++ Str) -> list_to_integer(Str, 16);
list_to_num("0b" ++ Str) -> list_to_integer(Str, 2);
list_to_num(Str = [ $0 | _ ])  -> list_to_integer(Str, 8);
list_to_num(Str)         -> list_to_integer(Str, 10).

%%% dumping data %%%

dump_opts(Dev, Opts) ->
        dump_opts2(Dev, Opts, proplists:get_keys(Opts)).

dump_opts2(Dev, Opts, [OptName | R]) ->
        io:format(Dev, "  ~-10s: ~p~n",
                  [OptName, proplists:get_value(OptName, Opts)]),
        dump_opts2(Dev, Opts, R);
dump_opts2(_Dev, _Opts, []) -> ok.

%%% logging %%%

log(L, Fmt, Args, Opts) when is_list(Opts) ->
    log(L, Fmt, Args, proplists:get_value(verbose, Opts, 0), Opts).

log(debug,  Fmt, Args, V, Opts) when V > 2 -> log2("DEBUG", Fmt, Args, Opts);
log(info,   Fmt, Args, V, Opts) when V > 1 -> log2("INFO", Fmt, Args, Opts);
log(notice, Fmt, Args, V, Opts) when V > 0 -> log2("NOTICE", Fmt, Args, Opts);
log(warn,   Fmt, Args, _V, Opts)           -> log2("WARNING", Fmt, Args, Opts);
log(error,  Fmt, Args, _V, Opts)           -> log2("ERROR", Fmt, Args, Opts);

log(Lvl,  Fmt, Args, V, Opts) when V >= Lvl -> log2("", Fmt, Args, Opts);

log(_, _, _, _i, _) -> ok.

log2(Type, Fmt, Args, _Opts) when is_list(Fmt) ->
    io:format(standard_error, "~s: " ++ Fmt, [Type | Args]);
log2("", Fmt, Args, _Opts) when is_list(Fmt) ->
    io:format(standard_error, Fmt, Args);
log2(_Type, Fun, _Args, _Opts) when is_function(Fun, 1) ->
    Fun(standard_error).

%%% RTP packets %%%

make_rtp_packet(P = #rtp_packet{version = 2}) ->
    << (P#rtp_packet.version):2,
       0:1, % P
       0:1, % X
       0:4, % CC
       (P#rtp_packet.marker):1,
       (P#rtp_packet.payload_type):7,
       (P#rtp_packet.seqno):16,
       (P#rtp_packet.timestamp):32,
       (P#rtp_packet.ssrc):32,
       (P#rtp_packet.payload)/bytes
    >>.

parse_rtp_packet(
    << 2:2, % Version 2
       0:1, % P (not supported yet)
       0:1, % X (not supported yet)
       0:4, % CC (not supported yet)
       M:1,
       PT:7,
       SeqNo: 16,
       TS:32,
       Ssrc:32,
       Payload/bytes >>) ->
    #rtp_packet{
        version = 0,
	marker = M,
	payload_type = PT,
	seqno = SeqNo,
	timestamp = TS,
	ssrc = Ssrc,
	payload = Payload}.

%%% payload generation %%%

next_payload(F) when is_function(F) ->
    {F(), F};
next_payload({F, D}) when is_function(F) ->
    {P, D2} = F(D),
    {P, {F, D2}};
next_payload([P | R]) ->
    {P, R};
next_payload([]) ->
    undef;
next_payload(Bin = <<_/bytes>>) ->
    {Bin, Bin}.

%%% real writing work %%%

write_packets(_Dev, DS, _P, _F, 0, _O, _Opts) ->
    DS;
write_packets(Dev, DataSource, P = #rtp_packet{}, F, L, O, Opts) ->
    Format = proplists:get_value(format, Opts, state),
    Ptime = proplists:get_value(duration, Opts, 160),
    Delay = proplists:get_value(delay, Opts, 0),
    Rate = proplists:get_value(rate, Opts, 8000),
    case next_payload(DataSource) of
        {Payload, DataSource2} ->
            write_packet(Dev, Ptime * F / Rate + Delay,
                         P#rtp_packet{seqno = F, timestamp = F*Ptime+O,
			              payload = Payload},
                         Format),
            write_packets(Dev, DataSource2, P, F+1, L-1, O, Opts);
	Other -> Other
    end.

write_packet(Dev, Time, P = #rtp_packet{}, Format) ->
    Bin = make_rtp_packet(P),

    write_packet_line(Dev, Time, P, Bin, Format).

write_packet_pre(Dev, carray) ->
    io:format(Dev,
              "struct {float t; int len; char *data;} packets[] = {~n", []);

write_packet_pre(_Dev, _) -> ok.

write_packet_post(Dev, carray) ->
    io:format(Dev, "};~n", []);

write_packet_post(_Dev, _) -> ok.

write_packet_line(Dev, Time, _P, Bin, state) ->
    io:format(Dev, "~f ~s~n", [Time, bin_to_hex(Bin)]);

write_packet_line(Dev, Time, #rtp_packet{seqno = N, timestamp = TS}, Bin, c) ->
    ByteList = [ [ $0, $x | integer_to_list(Byte, 16) ] || <<Byte:8>> <= Bin ],
    ByteStr = string:join(ByteList, ", "),
    io:format(Dev, "/* time=~f, SeqNo=~B, TS=~B */ {~s}~n", [Time, N, TS, ByteStr]);

write_packet_line(Dev, Time, #rtp_packet{seqno = N, timestamp = TS}, Bin, carray) ->
    io:format(Dev, "  /* RTP: SeqNo=~B, TS=~B */~n", [N, TS]),
    io:format(Dev, "  {~f, ~B, \"", [Time, size(Bin)]),
    [ io:format(Dev, "\\x~2.16.0B", [Byte]) || <<Byte:8>> <= Bin ],
    io:format(Dev, "\"},~n", []).

%%% real reading work %%%

read_packets(Dev, Opts) ->
    Format = proplists:get_value(in_format, Opts, state),

    read_packets(Dev, Opts, Format).

read_packets(Dev, Opts, Format) ->
    case read_packet(Dev, Opts, Format) of
        eof -> [];
        Tuple -> [Tuple | read_packets(Dev, Opts, Format)]
    end.

read_packet(Dev, Opts, bin) ->
    Size = proplists:get_value(frame_size, Opts),
    case file:read(Dev, Size) of
        {ok, Data} -> {0, #rtp_packet{payload = iolist_to_binary(Data)}};
	eof -> eof
    end;
read_packet(Dev, _Opts, Format) ->
    case read_packet_line(Dev, Format) of
        {Time, Bin} -> {Time, parse_rtp_packet(Bin)};
	eof -> eof
    end.

read_packet_line(Dev, state) ->
    case io:fread(Dev, "", "~f ~s") of
        {ok, [Time, Hex]} -> {Time, hex_to_bin(Hex)};
	eof -> eof
    end.
