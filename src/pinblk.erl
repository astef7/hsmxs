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
%% hsmxs pinblock library
%%------------------------------------------------------------------------------------
%% 2018-2021
%%====================================================================================
-module(pinblk).
-export([create/3]).

-define(PIN_LEN,4).

-type hex_string() :: string().
-type pinblk_type() :: 01 | 05 | 47.

%%------------------------------------------------------------------------------------
% uniform random over LEN digits
-spec rand(LEN::integer())->integer().
rand(LEN)->
    rand:uniform(trunc(math:pow(10,LEN))).
%%------------------------------------------------------------------------------------
% fill binary on LEN with char CHR
-spec fill(CHR::char(),LEN::integer())->binary().
fill(CHR,LEN)->
    list_to_binary(lists:flatten(string:pad("",LEN,leading,CHR))).
%%------------------------------------------------------------------------------------
-spec create(TYPE,PIN,PAN)-> string() when
      TYPE::pinblk_type(),
      PIN::binary() | string(),
      PAN::binary() | string() | none .
create(01,PIN,PAN)-> %% ISO 9564-1 Format 0 / ANSI X9.8
    {PIN1,PLEN}=utils:to_binary_and_length(PIN),
    if
	PLEN =:= ?PIN_LEN -> ok;
	true -> error(bad_pin_length)
    end,
	
    PAN1=commands:extract_pan(PAN),
    FILLER=fill($F,16-(2+?PIN_LEN)),
    PINLEN=utils:format_integer(?PIN_LEN,1),

    P1 = <<"0",PINLEN/binary,PIN1/binary,FILLER/binary>>,
    P2 = <<"0000",PAN1/binary>>,

    % na calej wartosci...
    P1N = binary_to_integer(P1,16),
    P2N = binary_to_integer(P2,16),    
    RES0 = integer_to_list(P1N bxor P2N,16),
    RES00=string:right(RES0,16,$0),
    io:format("RES0=~p~n",[RES00]),

    RES00;

create(05,PIN,none)-> %% ISO 9564-1 Format 1
    {PIN1,PLEN} = case is_list(PIN) of
		      true -> {list_to_binary(PIN),length(PIN)};
		      _ -> {PIN,length(binary_to_list(PIN))}
		  end,
    if
	PLEN =:= ?PIN_LEN -> ok;
	true -> error(bad_pin_length)
    end,

    PLENB=utils:format_integer(?PIN_LEN,1),
    RANDLEN=16-(2+?PIN_LEN),
    RAND=utils:format_integer(rand(RANDLEN),RANDLEN),
    binary_to_list(<<"1",PLENB/binary,PIN1/binary,RAND/binary>>);

create(47,PIN,PAN)-> %% ISO 9564-1 Format 3
    {PIN1,PLEN} = utils:to_binary_and_length(PIN),
    if
	PLEN =:= ?PIN_LEN -> ok;
	true -> error(bad_pin_length)
    end,
	
    PAN1 = commands:extract_pan(PAN),
    FILLER=fill($F,16-(2+?PIN_LEN)), % should be randomized : 1010-1111
    PLENB = integer_to_binary(?PIN_LEN,16),

    P1 = <<"3",PLENB/binary,PIN1/binary,FILLER/binary>>,
    P2 = <<"0000",PAN1/binary>>,

    P1N = binary_to_integer(P1,16),
    P2N = binary_to_integer(P2,16),
    
    integer_to_list((P1N + P2N) div 2,16).
