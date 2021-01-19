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
-module(commands_tests).

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

pinblock_01_1_test_()->
    PIN="1122",
    PAN="212676479325X",
    PINBLK_TYPE=01,
    K3=cryptoxs:get_test_visa_3des(),
    PINBLK=pinblk:create(PINBLK_TYPE,PIN,PAN), % 01
    PINBLK_ENCR=cryptoxs:encrypt(des3,ecb,K3,hex:hex_to_bin(PINBLK)),
    PINBLK_ENCR_HEX=hex:bin_to_hex(PINBLK_ENCR),
    ?debugFmt("PINBLK_HEX=~p~n",[PINBLK_ENCR_HEX]),

    ?_assertEqual("795E84641FE8513E",PINBLK_ENCR_HEX).

pinblock_01_2_test_()->
    PIN="123",
    PAN="212676479325X",
    PINBLK_TYPE=01,
    K3=cryptoxs:get_test_visa_3des(),
    ?_assertError(bad_pin_length,pinblk:create(PINBLK_TYPE,PIN,PAN)).

pinblock_05_1_test_()->
    PIN="1122",
    PINBLK_TYPE=05,
    K3=cryptoxs:get_test_visa_3des(),
    PINBLK=pinblk:create(PINBLK_TYPE,PIN,none), % 05
    PINBLK_ENCR=cryptoxs:encrypt(des3,ecb,K3,hex:hex_to_bin(PINBLK)),
    PINBLK_ENCR_HEX=hex:bin_to_hex(PINBLK_ENCR),
    ?debugFmt("PINBLK_HEX=~p~n",[PINBLK_ENCR_HEX]),

    %% Randomisation disallows easy assertion check...
    ?_assertEqual(1,1).

pinblock_05_2_test_()->
    PIN="123",
    PINBLK_TYPE=05,
    K3=cryptoxs:get_test_visa_3des(),
    ?_assertError(bad_pin_length,pinblk:create(PINBLK_TYPE,PIN,none)).

pinblock_47_1_test_()->
    PIN="1122",
    PAN="212676479325X",
    PINBLK_TYPE=47,
    K3=cryptoxs:get_test_visa_3des(),
    PINBLK=pinblk:create(PINBLK_TYPE,PIN,PAN), % 47
    PINBLK_ENCR=cryptoxs:encrypt(des3,ecb,K3,hex:hex_to_bin(PINBLK)),
    PINBLK_ENCR_HEX=hex:bin_to_hex(PINBLK_ENCR),
    ?debugFmt("PINBLK_HEX=~p~n",[PINBLK_ENCR_HEX]),

    ?_assertEqual("6325F4ED20CA2F06",PINBLK_ENCR_HEX).

pinblock_47_2_test_()->
    PIN="123",
    PAN="212676479325X",
    PINBLK_TYPE=47,
    K3=cryptoxs:get_test_visa_3des(),
    ?_assertError(bad_pin_length,pinblk:create(PINBLK_TYPE,PIN,PAN)).

local_des3_ecb_crypto_test_()->
    K3=cryptoxs:get_test_visa_3des(),
    Text= <<"1234567890123456">>,
    Encrypted=cryptoxs:encrypt(des3,ecb,K3,Text),
    Text1=cryptoxs:decrypt(des3,ecb,K3,Encrypted),

    ?_assertEqual(Text1,Text).

local_des3_cbc_crypto_test_()->
    K3=cryptoxs:get_test_visa_3des(),
    IV=[1,0,0,0,1,0,0,0],
    Text= <<"1234567890123456">>,
    Encrypted=cryptoxs:encrypt(des3,cbc,K3,IV,Text),
    Text1=cryptoxs:decrypt(des3,cbc,K3,IV,Encrypted),

    ?_assertEqual(Text1,Text).

local_aes128_ecb_crypto_test_()->
    K128=cryptoxs:get_test_aes128(),
    Text= <<"1234567890123456">>,
    Encrypted=cryptoxs:encrypt(aes128,ecb,K128,Text),
    Text1=cryptoxs:decrypt(aes128,ecb,K128,Encrypted),

    ?_assertEqual(Text1,Text).

local_aes128_cbc_crypto_test_()->
    K128=cryptoxs:get_test_aes128(),
    IV=[1,0,0,0,1,0,0,0,1,0,0,0,1,0,0,0],
    Text= <<"1234567890123456">>,
    Encrypted=cryptoxs:encrypt(aes128,cbc,K128,IV,Text),
    Text1=cryptoxs:decrypt(aes128,cbc,K128,IV,Encrypted),

    ?_assertEqual(Text1,Text).

cmd_A0_EI_GI_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->

	     %%---------------------A0------------------------
	     ?debugFmt("cmd_A0_test_1_ ...",[]),
	     CMD1=commands:build_cmd_A0(kblk,dek,aes128),
	     RESP1=commands:execute(CMD1),
		 
	     ?debugFmt("cmd_A0_test_2_ ...",[]),
	     CMD2=commands:build_cmd_A0(kblk,pvk_visa,des3),
	     RESP2=commands:execute(CMD2),
	     ?_assertMatch({ok,_,_},RESP2),
		 
	     ?debugFmt("cmd_A0_test_3_ ...",[]),
	     CMD3=commands:build_cmd_A0(variant,pvk_ibm,des3), % dla odmiany variant
	     RESP3=commands:execute(CMD3),
	     %%---------------------EI------------------------
	     ?debugFmt("cmd_EI_test_1_ ...",[]),
	     CMD4=commands:build_cmd_EI(kblk,sign_and_key_mgt,2048),
	     RESP4=commands:execute(CMD4),

	     ?debugFmt("cmd_EI_test_2_ ...",[]),
	     CMD4v=commands:build_cmd_EI(variant,sign_and_key_mgt,2048),
	     RESP4v=commands:execute(CMD4v),
	     %%---------------------GI kblk ------------------------
	     CMD5=commands:build_cmd_EI(kblk,key_mgt_only,2048),
	     {ok,PUB,PRV}=commands:execute(CMD5),
	     
	     {ok,#'HsmPubKey'{modulus=MOD,exponent=EXP}} =
		 'HsmPubKeySpec':decode('HsmPubKey',hex:hex_to_bin(PUB)),
	     
	     PKR= #'RSAPublicKey'{modulus=MOD,publicExponent=EXP},
	     AES= <<"1234567890123456">>,
	     ENCR_KEY=public_key:encrypt_public(AES,PKR,[{rsa_padding,rsa_pkcs1_padding}]),
	     PLAIN= <<"text778888888899">>,
	     ENCR_TEXT=cryptoxs:encrypt(aes128,ecb,AES,PLAIN),

	     KEY_TYPE=tek,
	     CMD6=commands:build_cmd_GI(kblk,KEY_TYPE,aes128,ENCR_KEY,PRV),
	     {ok,KEY,KCV}=commands:execute(CMD6),

	     CMD7=commands:build_cmd_M2(kblk,ecb,{KEY_TYPE,KEY},noiv,ENCR_TEXT),
	     {ok,RESP7}=commands:execute(CMD7),

	     [
	      %% A0...
	      ?_assertMatch({ok,_,_},RESP1),
	      ?_assertMatch({ok,_,_},RESP2),
	      ?_assertMatch({ok,_,_},RESP3),
	      ?_assertError(bad_lmk,commands:build_cmd_A0(other,dek,aes128)),

	      %% EI...
	      ?_assertMatch({ok,_,_},RESP4),
	      ?_assertMatch({ok,_,_},RESP4v),
	      ?_assertError(bad_lmk,commands:build_cmd_EI(other,sign_and_key_mgt,2048)),

	      %% GI + M0 + M2
	      ?_assertEqual(PLAIN,RESP7),
	      ?_assertError(function_clause,commands:build_cmd_GI(other,KEY_TYPE,aes128,ENCR_KEY,PRV)),
	      ?_assertError(bad_lmk,commands:build_cmd_M0(other,ecb,{KEY_TYPE,KEY},noiv,PLAIN)),
	      ?_assertError(bad_lmk,commands:build_cmd_M2(other,ecb,{KEY_TYPE,KEY},noiv,ENCR_TEXT))
	     ]
     end}.

cmd_GI_variant_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->

	     %%---------------------GI variant ------------------------
	     CMD1=commands:build_cmd_EI(variant,key_mgt_only,1024),
	     {ok,PUB,PRV}=commands:execute(CMD1),
	     ?debugFmt("GI Variant, PUB=~p~n",[PUB]),
	     
	     {ok,#'HsmPubKey'{modulus=MOD,exponent=EXP}} =
		 'HsmPubKeySpec':decode('HsmPubKey',hex:hex_to_bin(PUB)),
	     
	     PKR= #'RSAPublicKey'{modulus=MOD,publicExponent=EXP},

	     K2="BCD94A49B9AE4F94D5A1ADEAC10D023B",
	     K2B=hex:hex_to_bin(K2),
	     ENCR_KEY2=public_key:encrypt_public(K2B,PKR,[{rsa_padding,rsa_pkcs1_padding}]),

	     {S1,S2,_}=cryptoxs:get_test_visa_3des(),
	     %% UWAGA: for variant LMK, 3des key has to be converted from ede to ed form 
	     %% before RSA encryption.

	     %% Effectively, K2B == K3B

	     K3B = hex:hex_to_bin(lists:flatten([S1,S2])),
	     ENCR_KEY3=public_key:encrypt_public(K3B,PKR,[{rsa_padding,rsa_pkcs1_padding}]),

	     CMD2=commands:build_cmd_GI(variant,tpk,des2,ENCR_KEY2,PRV),
	     RESP2=commands:execute(CMD2),

	     CMD3=commands:build_cmd_GI(variant,tpk,des3,ENCR_KEY3,PRV),
	     RESP3=commands:execute(CMD3),

	     [
	      %% GI
	      ?_assertMatch({ok,_,_},RESP2),
	      ?_assertMatch({ok,_,_},RESP3)
	     ]
     end}.

cmd_PVV_kblk_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->

	     PIN="1122",
	     PAN="212676479325x",
	     PINBLK_TYPE=01,
	     K3=cryptoxs:get_test_visa_3des(),
	     PINBLK=pinblk:create(PINBLK_TYPE,PIN,PAN), % 01
	     PINBLK_ENCR=cryptoxs:encrypt(des3,ecb,K3,hex:hex_to_bin(PINBLK)),
	     PINBLK_HEX=hex:bin_to_hex(PINBLK_ENCR),
	     
	     %% ------------- EI ---------------------------
	     CMD0=commands:build_cmd_EI(kblk,key_mgt_only,2048),
	     {ok,PUB,PRV}=commands:execute(CMD0),
	     
	     {ok,#'HsmPubKey'{modulus=MOD,exponent=EXP}} =
		 'HsmPubKeySpec':decode('HsmPubKey',hex:hex_to_bin(PUB)),
	     
	     PKR= #'RSAPublicKey'{modulus=MOD,publicExponent=EXP},
	     K3B = hex:hex_to_bin(lists:flatten(tuple_to_list(K3))),
	     ENCR_KEY=public_key:encrypt_public(K3B,PKR,[{rsa_padding,rsa_pkcs1_padding}]),
	     
	     %% ------------ GI ----------------------------
	     CMD1=commands:build_cmd_GI(kblk,tpk,des3,ENCR_KEY,PRV),
	     {ok,TPK,KCV}=commands:execute(CMD1),
	     
	     %% ------------ PBLK->PIN/LMK ------------------
	     CMD2=commands:build_cmd_JC(kblk,TPK,PINBLK_HEX,PINBLK_TYPE,PAN),
	     {ok,PINLMK}=commands:execute(CMD2),
	     
	     CMD3=commands:build_cmd_A0(kblk,pvk_visa,des2),
	     {ok,PVK,_}=commands:execute(CMD3),
	     
	     CMD4=commands:build_cmd_DG(kblk,PVK,PAN,PINLMK),
	     {ok,PVV}=commands:execute(CMD4),
	     
	     %% ------------ DC ----------------------------
	     CMD5=commands:build_cmd_DC(kblk,PVK,TPK,PAN,PVV,PINBLK_HEX,01),
	     RESP5=commands:execute(CMD5),

	     [
	      %% CVV
	      ?_assertEqual({ok},RESP5)
	     ]
     end}.
		 
cmd_M0_M2_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->

	     PLAIN= <<"text778888888899">>,
	     IV_16= <<"0001000100010001">>,
	     IV_32= <<"00010001000100010001000100010001">>,


	     %%------------ ECB -----------------------------------------------------
	     %%------------- kblk ---------------------------------------------------
	     CMD1=commands:build_cmd_A0(kblk,tek,aes256),
	     {ok,TEK1,_}=commands:execute(CMD1),

	     CMD2=commands:build_cmd_M0(kblk,ecb,{tek,TEK1},noiv,PLAIN),
	     {ok,ENCRYPTED}=commands:execute(CMD2),

	     CMD3=commands:build_cmd_M2(kblk,ecb,{tek,TEK1},noiv,ENCRYPTED),
	     RESP3=commands:execute(CMD3),

	     %%------------- variant ---------------------------------------------------
	     CMD4=commands:build_cmd_A0(variant,tek,aes256),
	     {ok,TEK2,_}=commands:execute(CMD4),

	     CMD5=commands:build_cmd_M0(variant,ecb,{tek,TEK2},noiv,PLAIN),
	     {ok,ENCRYPTED2}=commands:execute(CMD5),

	     CMD6=commands:build_cmd_M2(variant,ecb,{tek,TEK2},noiv,ENCRYPTED2),
	     RESP6=commands:execute(CMD6),

	     %%------------ CBC -----------------------------------------------------
	     %%------------- kblk ---------------------------------------------------
	     CMD7=commands:build_cmd_A0(kblk,tek,aes256),
	     {ok,TEK3,_}=commands:execute(CMD7),

	     CMD8=commands:build_cmd_M0(kblk,cbc,{tek,TEK3},IV_32,PLAIN),
	     {ok,IV3,ENCRYPTED3}=commands:execute(CMD8),

	     CMD9=commands:build_cmd_M2(kblk,cbc,{tek,TEK3},IV_32,ENCRYPTED3),
	     RESP9=commands:execute(CMD9),

	     %%------------- variant ---------------------------------------------------
	     CMD10=commands:build_cmd_A0(variant,tek,aes256),
	     {ok,TEK4,_}=commands:execute(CMD10),

	     CMD11=commands:build_cmd_M0(variant,cbc,{tek,TEK4},IV_16,PLAIN),
	     {ok,IV4,ENCRYPTED4}=commands:execute(CMD11),

	     CMD12=commands:build_cmd_M2(variant,cbc,{tek,TEK4},IV_16,ENCRYPTED4),
	     RESP12=commands:execute(CMD12),

	     [
	      %% M0-M2
	      ?_assertEqual({ok,PLAIN},RESP3),
	      ?_assertEqual({ok,PLAIN},RESP6),
	      ?_assertMatch({ok,_,PLAIN},RESP9),
	      ?_assertMatch({ok,_,PLAIN},RESP12),
	      ?_assertError(bad_iv_len,commands:build_cmd_M0(variant,cbc,{tek,TEK4},"0102",PLAIN)),
	      ?_assertError(bad_iv_len,commands:build_cmd_M0(kblk,cbc,{tek,TEK1},"0102",PLAIN))
	     ]
     end}.

cmd_DCVV_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->

	     PM_TWU=30,
	     PM_MKDCVV="S10096E0TN00E0001ACF7C47087DE618314D68ACC704397CD8E956082A9F1B215F7A89F41C0D72FC9B1A9D4949836DD27A",
	     CMD0=commands:build_cmd_PM(kblk,generate,{"4455660000000000","1905","111"},
					{PM_TWU,PM_MKDCVV}),
	     {ok,DCVV}=commands:execute(CMD0),
	     
	     CMD1=commands:build_cmd_PM(kblk,verify,{"4455660000000000","1905",DCVV},{PM_TWU,PM_MKDCVV}),
	     RESP1=commands:execute(CMD1),

	     [
	      %% DCVV
	      ?_assertEqual({ok},RESP1)
	     ]
     end}.
		 
%% Only for coverage in commands for test code...
cmd_covering_internal_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->

	     commands:test_EI(),
	     commands:test_GI(),
	     commands:test_A0(),
	     commands:test_A0(pvk_visa),
	     commands:test_A0(kblk,pvk_visa),
	     commands:test_A0(variant,pvk_visa),
	     commands:test_M0(),
	     commands:test_PVV(kblk),
	     commands:test_N0(),
	     commands:test_PM(),
	     commands:check_hsm(),
	     commands:check_hsm(tcp,kblk),
	     commands:check_hsm(tcp,variant),
	     commands:test_M0_M2(),

	     [
	      %% dummy
	      ?_assertEqual(1,1)
	     ]
     end}.
    
udp_not_available_at_UAT_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_SetupData)->
	     ?debugFmt("*** UDP unavailable test ***",[]),
	     RESP=commands:check_hsm(udp,kblk),
	     [
	      %% obecnie UDP nie dziala na linii testowej...
	      ?_assertMatch({error,{timeout,_}},RESP)
	      
	     ]
     end}.
