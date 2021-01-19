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
%% Thales 9000 Hsm GenServer / Testing utilities
%%------------------------------------------------------------------------------
%% rebar3 eunit --dir="test" --cover
%%------------------------------------------------------------------------------
%% 2018-2021
%%==============================================================================
-module(hsm_tests).

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

hsm_regular_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     {inorder,
	      [
	       hsm_buff_overflow_tester(),
	       hsm_exec_timeout_tester(),
	       hsm_port_exit_tester(),
	       hsm_tcp_closed_tester(),
	       hsm_tcp_error_tester(),
	       hsm_unknown_message_tester(),
	       hsm_udp_response_tester(),
	       hsm_tcp_uncorrelated_response_tester(),
	       hsm_connect_retry_tester(),
	       hsm_big_buff_size_tester()
	      ]
	     }
     end}.

hsm_buff_overflow_tester() ->
    Size=33000*8,
    DummyMegaMessage = <<1:Size>>,
    ?debugFmt("*** Hsm buffer overflow test ***",[]),
    RESP=commands:execute({DummyMegaMessage,fun(X)->ok end}),
    ?_assertEqual({error,buff_overflow},RESP).

%% Test for covering exec timeout error...
hsm_exec_timeout_tester() ->
    ?debugFmt("*** Hsm exec timeout test ***",[]),
    Cmd = commands:build_cmd_N0(kblk,3),
    Tmt=1, %% timeout 1ms
    RESP=commands:execute(tcp,Cmd,Tmt),
    ?_assertMatch({error,timeout},RESP).

%% Test for covering {'EXIT',port,Reason} for RCV
hsm_port_exit_tester() ->
    receive
    after 2000 -> ok %% zsynchronizowanie z inicjalizajca RCV...
    end,
    ?debugFmt("*** Hsm port exit test ***",[]),
    CL=supervisor:which_children(hsm_sup),
    ?debugFmt("Children=~p",[CL]),
    {_,RCV,_,_}=lists:keyfind('HsmReceiverTcp',1,CL),
    PL=lists:map(fun(PORT)-> 
			 [_,_,{id,ID},{_,PID}|_] = erlang:port_info(PORT),
			 {PID,ID,PORT}
		 end,erlang:ports()),
    [PX] = [PORT || {PID,ID,PORT} <- PL, PID =:= RCV],
    erlang:port_close(PX), %% results in {'EXIT',port, ... }

     %% Dummy...
    ?_assertEqual(1,1).

%% Test for covering {tcp_closed,SCK} for RCV
hsm_tcp_closed_tester() ->
    receive
    after 2000 -> ok %% zsynchronizowanie z inicjalizajca RCV...
    end,
    ?debugFmt("*** Hsm tcp_closed test ***",[]),
    CL=supervisor:which_children(hsm_sup),
    ?debugFmt("Children=~p",[CL]),
    {_,RCV,_,_}=lists:keyfind('HsmReceiverTcp',1,CL),
    PL=lists:map(fun(PORT)-> 
			 [_,_,{id,ID},{_,PID}|_] = erlang:port_info(PORT),
			 {PID,ID,PORT}
		 end,erlang:ports()),
    [{PIDX,PORTX}] = [{PID,PORT} || {PID,ID,PORT} <- PL, PID =:= RCV],
    
    RCV ! {tcp_closed,PORTX},
    
    %% Dummy...
    ?_assertEqual(1,1).

%% Test for covering {tcp_error,SCK,test} for RCV
hsm_tcp_error_tester() ->
    receive
    after 2000 -> ok %% zsynchronizowanie z inicjalizajca RCV...
    end,
    ?debugFmt("*** Hsm tcp_error test ***",[]),
    CL=supervisor:which_children(hsm_sup),
    ?debugFmt("Children=~p",[CL]),
    {_,RCV,_,_}=lists:keyfind('HsmReceiverTcp',1,CL),
    PL=lists:map(fun(PORT)-> 
			 [_,_,{id,ID},{_,PID}|_] = erlang:port_info(PORT),
			 {PID,ID,PORT}
		 end,erlang:ports()),
    [{PIDX,PORTX}] = [{PID,PORT} || {PID,ID,PORT} <- PL, PID =:= RCV],
    
    RCV ! {tcp_error,PORTX,test},
    
    %% Dummy...
    ?_assertEqual(1,1).

%% Test for covering {unknown-message} for RCV
hsm_unknown_message_tester() ->
    receive
    after 2000 -> ok %% zsynchronizowanie z inicjalizajca RCV...
    end,
    ?debugFmt("*** Hsm unknown message test ***",[]),
    CL=supervisor:which_children(hsm_sup),
    ?debugFmt("Children=~p",[CL]),
    {_,RCV,_,_}=lists:keyfind('HsmReceiverTcp',1,CL),
    PL=lists:map(fun(PORT)-> 
			 [_,_,{id,ID},{_,PID}|_] = erlang:port_info(PORT),
			 {PID,ID,PORT}
		 end,erlang:ports()),
    [{PIDX,PORTX}] = [{PID,PORT} || {PID,ID,PORT} <- PL, PID =:= RCV],
    
    RCV ! {'unknown-message-test'},
    
    %% Dummy...
    ?_assertEqual(1,1).

%% Test for covering {udp,sck,ip,port,response} for RCV
hsm_udp_response_tester() ->
    receive
    after 2000 -> ok %% zsynchronizowanie z inicjalizajca RCV...
    end,
    ?debugFmt("*** Hsm udp response test ***",[]),
    CL=supervisor:which_children(hsm_sup),
    ?debugFmt("Children=~p",[CL]),
    {_,RCV,_,_}=lists:keyfind('HsmReceiverUdp',1,CL),
    PL=lists:map(fun(PORT)-> 
			 [_,_,{id,ID},{_,PID}|_] = erlang:port_info(PORT),
			 {PID,ID,PORT}
		 end,erlang:ports()),
    [{PIDX,PORTX}] = [{PID,PORT} || {PID,ID,PORT} <- PL, PID =:= RCV],
    
    RCV ! {udp,PORTX,{10,10,104,25},1500,<<9:16,"0001N1123">>},
    
    %% Dummy...
    ?_assertEqual(1,1).

%% Test for covering uncorrelated {tcp,sck,response} for RCV
hsm_tcp_uncorrelated_response_tester() ->
    receive
    after 2000 -> ok %% zsynchronizowanie z inicjalizajca RCV...
    end,
    ?debugFmt("*** Hsm tcp uncorrelated message test ***",[]),
    CL=supervisor:which_children(hsm_sup),
    ?debugFmt("Children=~p",[CL]),
    {_,RCV,_,_}=lists:keyfind('HsmReceiverTcp',1,CL),
    PL=lists:map(fun(PORT)-> 
			 [_,_,{id,ID},{_,PID}|_] = erlang:port_info(PORT),
			 {PID,ID,PORT}
		 end,erlang:ports()),
    [{PIDX,PORTX}] = [{PID,PORT} || {PID,ID,PORT} <- PL, PID =:= RCV],
    
    %% Length prefix is dropped ... <<9:16,"0001N1123">>
    RCV ! {tcp,PORTX,<<"0001N1123">>},
    
    %% Dummy...
    ?_assertEqual(1,1).
    

%% Test for covering connect retry
hsm_connect_retry_tester() ->
    ?debugFmt("*** HSM reconnect test ***",[]),
    TIMEOUT=10000,
    
    stop(dummy),
    ?cmd("cp config/sys.config.reconnect_test config/sys.config"),
    start(),

    ?debugFmt("*** Hsm reconnect test - not_connected ***",[]),
    Cmd = commands:build_cmd_N0(kblk,3),
    RESP=commands:execute(tcp,Cmd),
    
    receive
    after TIMEOUT ->
	    ok
    end,
    
    stop(dummy),
    ?cmd("cp config/sys.config.normal config/sys.config"),
    
    %% Dummy...
    ?_assertMatch({error,not_connected},RESP).

%% Test for covering buffer size configuration exceeding limit
hsm_big_buff_size_tester() ->
    ?debugFmt("*** HSM bad buffer size config test ***",[]),
    TIMEOUT=10000,
    
    stop(dummy),
    ?cmd("cp config/sys.config.buffer_exceeding_test config/sys.config"),
    start(),

    Cmd = commands:build_cmd_N0(kblk,3),
    RESP=commands:execute(tcp,Cmd),
    
    receive
    after TIMEOUT ->
	    ok
    end,
    
    stop(dummy),
    ?cmd("cp config/sys.config.normal config/sys.config"),
    
    %% Dummy...
    ?_assertMatch({ok,_},RESP).

