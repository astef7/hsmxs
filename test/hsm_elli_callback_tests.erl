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
%%==============================================================================

%%==============================================================================
%% Thales 9000 REST Interface  / Testing utilities
%%------------------------------------------------------------------------------
%% rebar3 eunit --dir="test" --cover
%%------------------------------------------------------------------------------
%% 2018-2021
%%==============================================================================
-module(hsm_elli_callback_tests).

-include_lib("eunit/include/eunit.hrl").

-compile(export_all).

%% ---------------- Testy  -----------------------------------------------------
start()->
    ?debugFmt("Starting hsmxs",[]),
    application:start(hsmxs),
    receive
    after 1000 -> ok %% zsynchronizowanie z inicjalizajca RCV...
    end.

stop(_SetupData)->
    ?debugFmt("Stopping hsmxs",[]),
    application:stop(hsmxs).

rest_performance_test_() ->
    {setup,
     fun() ->
	     start(),
	     N=10,
	     TS1 = erlang:timestamp(),
	     {N,TS1}
     end,
     fun({N,TS1}) ->
	     TS2 = erlang:timestamp(),
	     ?debugFmt("REST Performance test, TS2=~p",[TS2]),
	     ?debugFmt("REST Performance test, TS1=~p",[TS1]),
	     Diff = timer:now_diff(TS2,TS1),
	     ?debugFmt("REST Performance test, time diff=~pms, tx/s=~p",
		       [Diff/1000,N/(Diff/1000000)]),
	     stop(TS1)
     end,
     fun({N,_})->
	     {inparallel,50,
	      test_generator(N)
	     }
     end}.

test_generator(N) ->
    {generator,
     fun () ->
	     if N > 0 ->
		     %% PVV check...
		     RESP=rest_client:test(pvv_check),
		     [
		      ?_assertEqual({ok},RESP)
		     | test_generator(N-1)];
		true ->
		     []
	     end
     end}.
