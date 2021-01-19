%%==========================================================================================
%% ISO8583 / BIC ISO Parser Hex Utils
%%------------------------------------------------------------------------------------------
%% Artur Stefanowicz (C)
%% 2018-2020
%%==========================================================================================
-module(hex).
-export([bin_to_hex/1,hex_to_bin/1,int_to_hex/1,int_to_hex/2]).

bin_to_hex(B) when is_binary(B)->
    lists:flatten([io_lib:format("~2.16.0B",[X]) || X <- binary_to_list(B)]);

bin_to_hex(L) when is_list(L)->
    lists:flatten([io_lib:format("~2.16.0B",[X]) || X <- L]).

int_to_hex(N)->
    lists:flatten([io_lib:format("~2.16.0B",[X]) || 
		      X <- binary_to_list(binary:encode_unsigned(N))]).

int_to_hex(N,LEN) when LEN rem 2 =:= 0 ->
    X=lists:flatten([io_lib:format("~2.16.0B",[X]) || 
			X <- binary_to_list(binary:encode_unsigned(N))]),
    lists:flatten(lists:duplicate((LEN-length(X)) div 2,"00"),X).

hex_to_bin(S) when is_binary(S)->
    S1=binary_to_list(S),
    hex_to_bin(S1,[]);
hex_to_bin(S) when is_list(S)->
    hex_to_bin(S,[]).
hex_to_bin([],Acc) ->
	list_to_binary(lists:reverse(Acc));
hex_to_bin([X,Y|T],Acc) ->
	{ok,[V],[]} = io_lib:fread("~16u",[X,Y]),
	hex_to_bin(T,[V|Acc]);
hex_to_bin([X|T],Acc) ->
	{ok,[V],[]} = io_lib:fread("~16u",lists:flatten([X,"0"])),
	hex_to_bin(T,[V|Acc]).
