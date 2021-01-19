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
%% Thales 9000 Commands / Testing utilities
%%------------------------------------------------------------------------------
%% rebar3 eunit --dir="test"
%%------------------------------------------------------------------------------
%% 2018-2021
%%==============================================================================
-module(rest_tests).

-include_lib("eunit/include/eunit.hrl").

-include("HsmPubKeySpec.hrl").
-include_lib("public_key/include/public_key.hrl"). 

-compile(export_all).

%% ---------------- Testy  -----------------------------------------------------------------
start()->
    ?debugFmt("Starting hsmxs",[]),
    application:start(hsmxs),
    receive
    after 1000 -> ok %% zsynchronizowanie z inicjalizajca RCV...
    end.

stop(_SetupData)->
    ?debugFmt("Stopping hsmxs",[]),
    application:stop(hsmxs).

rest_pvv_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** rest_pvv regular tests ***",[]),
	     RESP1=rest_client:test(pvv_generate),
	     RESP2=rest_client:test(pvv_check),
	     RESP3=rest_client:test(pvv_check,bad_pvv),
	     [
	      ?_assertMatch({ok,"9839"},RESP1),
	      ?_assertMatch({ok},RESP2),
	      ?_assertMatch({error,"bad pvv"},RESP3)
	     ]
     end}.

rest_pvv_bad_params_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** rest_pvv_bad_params_test ***",[]),
	     RESP1=rest_client:test(pvv_generate,bad_params),
	     RESP2=rest_client:test(pvv_check,bad_params),
	     [
	      ?_assertMatch({error,"bad input"},RESP1),
	      ?_assertMatch({error,"bad input"},RESP2)
	     ]
     end}.

rest_dcvv_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** rest_dcvv regular tests ***",[]),
	     {ok,DCVV}=RESP1=rest_client:test(dcvv_generate),
	     RESP2=rest_client:test(dcvv_check,DCVV),
	     RESP3=rest_client:test(dcvv_check,bad_pvv),
	     [
	      ?_assertMatch({ok,_},RESP1),
	      ?_assertMatch({ok},RESP2),
	      ?_assertMatch({error,"bad dcvv"},RESP3)
	     ]
     end}.

rest_dcvv_bad_params_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** rest_dcvv bad params tests ***",[]),
	     RESP1=rest_client:test(dcvv_generate,bad_params),
	     RESP2=rest_client:test(dcvv_check,bad_params),
	     [
	      ?_assertMatch({error,"bad input"},RESP1),
	      ?_assertMatch({error,"bad input"},RESP2)
	     ]
     end}.

rest_encr_decr_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** encr/decr regular tests ***",[]),
	     TEXT="plain-text",
	     {ok,ENCRYPTED}=rest_client:test(encrypt,TEXT),
	     RESP=rest_client:test(decrypt,ENCRYPTED),
	     [
	      ?_assertMatch({ok,TEXT},RESP)
	     ]
     end}.

rest_encr_decr_bad_params_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** rest_encr_decr_bad_params_test ***",[]),
	     TEXT="plain-text",
	     {ok,ENCRYPTED}=rest_client:test(encrypt,TEXT),
	     RESP2=rest_client:test(decrypt,ENCRYPTED,bad_params),
	     RESP3=rest_client:test(encrypt,TEXT,bad_params),
	     [
	      ?_assertMatch({error,"bad input"},RESP2),
	      ?_assertMatch({error,"bad input"},RESP3)
	     ]
     end}.

rest_decr_error_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** rest_decr_error_test ***",[]),
	     RESP=rest_client:test(decrypt,<<1:32>>),
	     [
	      ?_assertMatch({error,_},RESP)
	     ]
     end}.

rest_decr_bad_key_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** rest_decr_bad_key_test ***",[]),
	     TEXT="plain-text",
	     {ok,ENCRYPTED}=rest_client:test(encrypt,TEXT),
	     RESP=rest_client:test(decrypt,ENCRYPTED,bad_key),
	     [
	      ?_assertMatch({error,"decryption error: B2"},RESP)
	     ]
     end}.

rest_encr_bad_key_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** rest_encr_bad_key_test ***",[]),
	     TEXT="plain-text",
	     RESP=rest_client:test(encrypt,TEXT,bad_key),
	     [
	      ?_assertMatch({error,"encryption error: B2"},RESP)
	     ]
     end}.

rest_set_skey_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** rest_set_skey_test ***",[]),
	     RESP1=rest_client:test(set_skey,des3,false),
	     RESP2=rest_client:test(set_skey,aes128,false),
	     RESP3=rest_client:test(set_skey,aes256,false),
	     [
	      ?_assertMatch({ok,_},RESP1),
	      ?_assertMatch({ok,_},RESP2),
	      ?_assertMatch({ok,_},RESP3)
	     ]
     end}.

rest_set_skey_bad_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** rest_set_skey_bad_test ***",[]),
	     RESP1=rest_client:test(set_skey,des3,bad_params),
	     RESP2=rest_client:test(set_skey,aes128,bad_params),
	     RESP3=rest_client:test(set_skey,aes256,bad_params),
	     [
	      ?_assertMatch({error,"bad input"},RESP1),
	      ?_assertMatch({error,"bad input"},RESP2),
	      ?_assertMatch({error,"bad input"},RESP3)
	     ]
     end}.

rest_set_skey_and_use_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** rest_set_skey_and_use_test ***",[]),
	     RESP1=rest_client:test(set_and_use_skey,ignored,false),
	     [
	      ?_assertMatch({ok,_},RESP1)
	     ]
     end}.

rest_set_skey_and_use_bad_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** rest_set_skey_and_use_bad_test ***",[]),
	     RESP1=rest_client:test(set_and_use_skey,ignore,bad_params),
	     [
	      ?_assertMatch({error,"bad input"},RESP1)
	     ]
     end}.

rest_generate_bkey_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** rest_generate_bkey_test ***",[]),
	     RESP1=rest_client:test(generate_bkey,des3,false),
	     RESP2=rest_client:test(generate_bkey,aes128,false),
	     RESP3=rest_client:test(generate_bkey,aes256,false),
	     [
	      ?_assertMatch({ok,_},RESP1),
	      ?_assertMatch({ok,_},RESP2),
	      ?_assertMatch({ok,_},RESP3)
	     ]
     end}.

rest_generate_bkey_bad_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** rest_generate_bkey_bad_test ***",[]),
	     RESP1=rest_client:test(generate_bkey,des3,bad_params),
	     RESP2=rest_client:test(generate_bkey,aes128,bad_params),
	     RESP3=rest_client:test(generate_bkey,aes256,bad_params),
	     [
	      ?_assertMatch({error,"bad input"},RESP1),
	      ?_assertMatch({error,"bad input"},RESP2),
	      ?_assertMatch({error,"bad input"},RESP3)
	     ]
     end}.

rest_bad_url_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** rest_bad_url_test ***",[]),
	     RESP=rest_client:test(bad_url),
	     [
	      ?_assertMatch({error,"Not Found..."},RESP)
	     ]
     end}.
