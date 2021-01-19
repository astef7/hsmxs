%%==============================================================================
%% Copyright 2020,2021 Artur Stefanowicz <artur.stefanowicz7@gmail.com>.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%====================================================================================

%%====================================================================================
%% hsmxs some common utils
%%------------------------------------------------------------------------------------
%% 2018-2021
%%====================================================================================
-module(utils).
-compile(export_all).

%%-------------------------------------------------------------------------------------
-spec format_integer(N::integer(),LEN::integer())->binary().
format_integer(N,LEN)->
    list_to_binary(lists:flatten([io_lib:format("~"++integer_to_list(LEN)++"..0B",[N])])).
%%-------------------------------------------------------------------------------------
-spec to_binary(X::binary() | list() | atom())->binary().
to_binary(X) when is_binary(X) ->
    X;
to_binary(X) when is_list(X) ->
    list_to_binary(X);
to_binary(X) when is_atom(X) ->
    atom_to_binary(X).
%%-------------------------------------------------------------------------------------
-spec to_binary_and_length(TXT::string() | binary())->{binary(),integer()}.
to_binary_and_length(TXT)->
    case is_list(TXT) of
	true -> {list_to_binary(TXT),length(TXT)};
	_ -> {TXT,byte_size(TXT)}
    end.
%%-------------------------------------------------------------------------------------
-spec lmk_to_binary(LMK::kblk|variant)->binary().
lmk_to_binary(LMK)->
    case LMK of
	kblk -> <<"01">>;
	variant -> <<"00">>;
	_ -> error(bad_lmk)
    end.
%%------------------------------------------------------------------------------------
-spec shorten_appid(APPID::string())->binary().
shorten_appid(APPID) when is_list(APPID)->
    <<PAN:13/bytes,_Rest/binary>> = list_to_binary(APPID),
    PAN.
%%------------------------------------------------------------------------------------

