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
%% Thales 9000 REST Interface : elli callback module
%%------------------------------------------------------------------------------
%% 2018-2021
%%==============================================================================
-module(hsm_elli_callback).
-export([handle/2,handle_event/3]).
-export([get_rsa_offset/1,get_pvk/0]).

-include_lib("elli/include/elli.hrl").
-behaviour(elli_handler).

handle(Req,_Args)->
    handle(Req#req.method,elli_request:path(Req),Req).

%%----------------------------------------------------------------------------
%% Set-PVV
%%----------------------------------------------------------------------------
handle('POST',[<<"hsmrt">>,<<"set-pin-pvv">>],#req{body=Body}=_Req)->
    logger:info("hsm_elli_callback: set-pin-pvv",[]),
    try
	Json = jsx:decode(Body),
	{ok,Appid}=maps:find(<<"appId">>,Json),
	{ok,MPinBlkMap}=maps:find(<<"mpinBlock">>,Json),
	{ok,MKeyBlk}=maps:find(<<"mkeyBlock">>,MPinBlkMap),
	{ok,MPinBlk}=maps:find(<<"mpinBlock">>,MPinBlkMap),
	{ok,RsaOffset}=maps:find(<<"rsaOffset">>,Json),
	{ok,Pvk}=maps:find(<<"pvk">>,Json),
	
	logger:info("hsm_elli_callback: mkeyBlk=~p, mpinBlk=~p",[MKeyBlk,MPinBlk]),
	{_PUB,PRV,_PKR}=get_rsa_offset(RsaOffset),
	
	%% ------------ Import TPK ------------------------------
	CMD1=commands:build_cmd_GI(kblk,tpk,des3,hex:hex_to_bin(MKeyBlk),PRV),
	{ok,TPK,_KCV}=commands:execute(CMD1),

	PAN=utils:shorten_appid(Appid),

	%% ------------ PBLK->PIN/LMK ---------------------------
	CMD2=commands:build_cmd_JC(kblk,TPK,MPinBlk,01,PAN),
	{ok,PINLMK}=commands:execute(CMD2),

	%% ------------ Generate PVV ----------------------------
	CMD3=commands:build_cmd_DG(kblk,Pvk,PAN,PINLMK),
	{ok,PVV}=commands:execute(CMD3),

	RespMap = #{ <<"pvv">> => PVV},
	{ok,[],jsx:encode(RespMap,[{space,2},{indent,4}])}
    catch _:{badmatch,error} ->
	    logger:error("Hsm-callback: bad input data",[]),
	    {404,[],<<"bad input">>};
	_:E ->
	    logger:error("Hsm-callback: error=~p",[E]),
	    {404,[],utils:to_binary(E)}
    end;

%%----------------------------------------------------------------------------
%% Check-PVV
%%----------------------------------------------------------------------------
handle('POST',[<<"hsmrt">>,<<"check-pin-pvv">>],#req{body=Body}=_Req)->
    logger:info("hsm_elli_callback: check-pin-pvv",[]),
    try
	Json = jsx:decode(Body),
	{ok,Appid}=maps:find(<<"appId">>,Json),
	{ok,MPinBlkMap}=maps:find(<<"mpinBlock">>,Json),
	{ok,MKeyBlk}=maps:find(<<"mkeyBlock">>,MPinBlkMap),
	{ok,MPinBlk}=maps:find(<<"mpinBlock">>,MPinBlkMap),
	{ok,RsaOffset}=maps:find(<<"rsaOffset">>,Json),
	{ok,Pvk}=maps:find(<<"pvk">>,Json),
	{ok,Pvv}=maps:find(<<"pvv">>,Json),
	
	logger:info("hsm_elli_callback: mkeyBlk=~p, mpinBlk=~p",[MKeyBlk,MPinBlk]),
	{_PUB,PRV,_PKR}=get_rsa_offset(RsaOffset),
	
	%% ------------ Import TPK ------------------------------
	CMD1=commands:build_cmd_GI(kblk,tpk,des3,hex:hex_to_bin(MKeyBlk),PRV),
	{ok,TPK,_KCV}=commands:execute(CMD1),

	PAN=utils:shorten_appid(Appid),
	%% ------------ PBLK->PIN/LMK ---------------------------
	%% CMD2=commands:build_cmd_JC(kblk,TPK,MPinBlk,01,PAN),
	%% {ok,PINLMK}=commands:execute(CMD2),
	%% io:format("JC PINLMK=[~p]~n",[PINLMK]),

	%% ------------ Check PVV ----------------------------
	CMD3=commands:build_cmd_DC(kblk,Pvk,TPK,PAN,Pvv,MPinBlk,01),
	case commands:execute(CMD3) of
	    {ok} ->
		logger:debug("DC Sucess~n",[]),
		{ok,[],[]};
	    {error,_ER} ->
		{404,[],<<"bad pvv">>}
	end
    catch _:{badmatch,error} ->
	    logger:error("Hsm-callback: bad input data",[]),
	    {404,[],<<"bad input">>};
	_:E ->
	    logger:error("Hsm-callback: error=~p",[E]),
	    {404,[],utils:to_binary(E)}
    end;

%%----------------------------------------------------------------------------
%% Encrypt
%%----------------------------------------------------------------------------
handle('POST',[<<"hsmrt">>,<<"encrypt-dek">>],#req{body=Body}=_Req)->
    logger:info("hsm_elli_callback: encrypt-dek",[]),
    try
	Json = jsx:decode(Body),
	{ok,_Appid}=maps:find(<<"appId">>,Json),
	{ok,Text}=maps:find(<<"text">>,Json),
	{ok,Dek}=maps:find(<<"dek">>,Json),
	
	%% ------------ Encrypt ----------------------------
	IV= hex:bin_to_hex(<<13:128>>), %% default IV
	Text1 = cryptoxs:pad(Text,16),
	CMD=commands:build_cmd_M0(kblk,cbc,{dek,Dek},IV,Text1),
	case commands:execute(CMD) of
	    {ok,_,Encrypted} ->
		RespMap = #{ <<"encrypted">> => list_to_binary(hex:bin_to_hex(Encrypted)),
			     <<"iv">> => list_to_binary(IV)
			   },
		{ok,[],jsx:encode(RespMap,[{space,2},{indent,4}])};
	    {error,ER} ->
		ERB=list_to_binary(ER),
		{404,[],<<"encryption error: ",ERB/binary>>}
	end
    catch _:{badmatch,error} ->
	    logger:error("Hsm-callback: bad input data",[]),
	    {404,[],<<"bad input">>};
	_:E ->
	    logger:error("Hsm-callback: error=~p",[E]),
	    {404,[],utils:to_binary(E)}
    end;

%%----------------------------------------------------------------------------
%% Decrypt
%%----------------------------------------------------------------------------
handle('POST',[<<"hsmrt">>,<<"decrypt-dek">>],#req{body=Body}=_Req)->
    logger:info("hsm_elli_callback: encrypt-dek",[]),
    try
	Json = jsx:decode(Body),
	{ok,_Appid}=maps:find(<<"appId">>,Json),
	{ok,Encrypted}=maps:find(<<"encrypted">>,Json),
	Iv= case maps:find(<<"iv">>,Json) of
		{ok,Iv0} -> Iv0;
		_ -> hex:bin_to_hex(<<13:128>>) %% default IV
	    end,
	{ok,Dek}=maps:find(<<"dek">>,Json),

	%% ------------ Decrypt ----------------------------
	CMD=commands:build_cmd_M2(kblk,cbc,{dek,Dek},Iv,hex:hex_to_bin(Encrypted)),
	case commands:execute(CMD) of
	    {ok,_,Text} ->
		RespMap = #{ 
			     <<"text">> => cryptoxs:unpad(Text)
			   },
		{ok,[],jsx:encode(RespMap,[{space,2},{indent,4}])};
	    {error,ER} ->
		ERB=list_to_binary(ER),
		{404,[],<<"decryption error: ",ERB/binary>>}
	end
    catch _:{badmatch,error} ->
	    logger:error("Hsm-callback: bad input data",[]),
	    {404,[],<<"bad input">>};
	_:E:Strc ->
	    logger:error("Hsm-callback: error=~p",[E]),
	    logger:error("Hsm-callback: Stacktrace=~p",[Strc]),
	    {404,[],utils:to_binary(E)}
    end;

%%----------------------------------------------------------------------------
%% Generate-DCVV
%%----------------------------------------------------------------------------
handle('POST',[<<"hsmrt">>,<<"generate-dcvv">>],#req{body=Body}=_Req)->
    logger:info("hsm_elli_callback: generate-dcvv",[]),
    try
	Json = jsx:decode(Body),
	{ok,_Appid}=maps:find(<<"appId">>,Json),
	{ok,Pan}=maps:find(<<"pan">>,Json),
	{ok,Expdt}=maps:find(<<"expdt">>,Json),

	{TwuDefault,MkdcvvDefault}=get_dcvv_config(),
	Mkdcvv = case maps:find(<<"mkdcvv">>,Json) of
		     {ok,Mkdcvv0} -> Mkdcvv0;
		     _ -> MkdcvvDefault
		 end,

	%% ------------ Generate DCVV ----------------------------
	CMD=commands:build_cmd_PM(kblk,generate,{Pan,Expdt,"111"},{TwuDefault,Mkdcvv}),
	{ok,DCVV}=commands:execute(CMD),

	RespMap = #{ <<"dcvv">> => DCVV},
	{ok,[],jsx:encode(RespMap,[{space,2},{indent,4}])}

    catch _:{badmatch,error} ->
	    logger:error("Hsm-callback: bad input data",[]),
	    {404,[],<<"bad input">>};
	_:E ->
	    logger:error("Hsm-callback: error=~p",[E]),
	    {404,[],utils:to_binary(E)}
    end;

%%----------------------------------------------------------------------------
%% Check-DCVV
%%----------------------------------------------------------------------------
handle('POST',[<<"hsmrt">>,<<"check-dcvv">>],#req{body=Body}=_Req)->
    logger:info("hsm_elli_callback: check-dcvv",[]),
    try
	Json = jsx:decode(Body),
	{ok,_Appid}=maps:find(<<"appId">>,Json),
	{ok,Pan}=maps:find(<<"pan">>,Json),
	{ok,Expdt}=maps:find(<<"expdt">>,Json),
	{ok,Dcvv}=maps:find(<<"dcvv">>,Json),

	{TwuDefault,MkdcvvDefault}=get_dcvv_config(),
	Mkdcvv = case maps:find(<<"mkdcvv">>,Json) of
		     {ok,Mkdcvv0} -> Mkdcvv0;
		     _ -> MkdcvvDefault
		 end,

	%% ------------ Check DCVV ----------------------------
	CMD=commands:build_cmd_PM(kblk,verify,{Pan,Expdt,Dcvv},{TwuDefault,Mkdcvv}),
	case commands:execute(CMD) of
	    {ok} ->
		logger:debug("PM Sucess~n",[]),
		{ok,[],[]};
	    {error,_ER} ->
		{404,[],<<"bad dcvv">>}
	end
    catch _:{badmatch,error} ->
	    logger:error("Hsm-callback: bad input data",[]),
	    {404,[],<<"bad input">>};
	_:E ->
	    logger:error("Hsm-callback: error=~p",[E]),
	    {404,[],utils:to_binary(E)}
    end;


%%----------------------------------------------------------------------------
%% Set-Session-Key
%%----------------------------------------------------------------------------
handle('POST',[<<"hsmrt">>,<<"set-session-key">>],#req{body=Body}=_Req)->
    logger:info("hsm_elli_callback: set-session-key",[]),
    try
	Json = jsx:decode(Body),
	{ok,_Appid}=maps:find(<<"appId">>,Json),
	{ok,SKeyBlk}=maps:find(<<"sessionKeyBlock">>,Json),
	{ok,_SKeyGuid}=maps:find(<<"sessionKeyGuid">>,Json),
	{ok,KeyType0}=maps:find(<<"keyType">>,Json),
	{ok,RsaOffset}=maps:find(<<"rsaOffset">>,Json),
	
	KeyType = case KeyType0 of
		      <<"des3">> -> des3;
		      <<"aes128">> -> aes128;
		      <<"aes256">> -> aes256;
		      _ -> error(bad_key_type)
		  end,
	
	logger:info("hsm_elli_callback: mkeyBlk=~p",[SKeyBlk]),
	{_PUB,PRV,_PKR}=get_rsa_offset(RsaOffset),
	
	%% ------------ Import DEK ------------------------------
	CMD=commands:build_cmd_GI(kblk,dek,KeyType,hex:hex_to_bin(SKeyBlk),PRV),
	{ok,DEK,_KCV}=commands:execute(CMD),

	RespMap = #{ <<"skey">> => DEK},
	{ok,[],jsx:encode(RespMap,[{space,2},{indent,4}])}

    catch _:{badmatch,error} ->
	    logger:error("Hsm-callback: bad input data",[]),
	    {404,[],<<"bad input">>};
	_:E ->
	    logger:error("Hsm-callback: error=~p",[E]),
	    {404,[],utils:to_binary(E)}
    end;

%%----------------------------------------------------------------------------
%% Generate-B-Key
%%----------------------------------------------------------------------------
handle('POST',[<<"hsmrt">>,<<"generate-bkey">>],#req{body=Body}=_Req)->
    logger:info("hsm_elli_callback: generate-bkey",[]),
    try
	Json = jsx:decode(Body),
	{ok,_Appid}=maps:find(<<"appId">>,Json),
	{ok,KeyType0}=maps:find(<<"keyType">>,Json),
	{ok,SKey}=maps:find(<<"sessionKey">>,Json),

	
	{KeyType,Key} = case KeyType0 of
			    <<"des3">> -> 
				%% ------- Generate 2-K  ----------
				CMD1=commands:build_cmd_N0(kblk,16),
				{ok,RAND}=commands:execute(CMD1),
				logger:info("N0=~p",[RAND]),
				<<K1:8/bytes,K2:8/bytes>> = binary:encode_unsigned(RAND),
				K2B = <<K1/binary,K2/binary>>,
				{des3,K2B};
			    <<"aes128">> -> 
				%% ------- Generate 128  ----------
				CMD1=commands:build_cmd_N0(kblk,16),
				{ok,RAND}=commands:execute(CMD1),
				{aes128,binary:encode_unsigned(RAND)};			    
			    <<"aes256">> -> 
				%% ------- Generate 256  ----------
				CMD1=commands:build_cmd_N0(kblk,32),
				{ok,RAND}=commands:execute(CMD1),
				{aes256,binary:encode_unsigned(RAND)};
			    _ -> error(bad_key_type)
			end,
	
	{_PUB,PRV,PKR}=get_rsa_offset(0),
	ENCR_KEY=public_key:encrypt_public(Key,PKR,[{rsa_padding,rsa_pkcs1_padding}]),
	
	%% ------------ Import DEK (B-KEY)  ------------------------------
	CMD2=commands:build_cmd_GI(kblk,dek,KeyType,ENCR_KEY,PRV),
	{ok,DEK,_KCV}=commands:execute(CMD2),

	%% ------------ Encrypt DEK (B-KEY)------------------------------
	CMD3=commands:build_cmd_M0(kblk,ecb,{dek,SKey},noiv,Key),
	{ok,KeyEncrypted}=commands:execute(CMD3),

	RespMap = #{ 
		     <<"bkey">> => hex:bin_to_hex(KeyEncrypted), %% under session-key 
		     <<"dek">> => DEK %% under LMK
		   },
	{ok,[],jsx:encode(RespMap,[{space,2},{indent,4}])}

    catch _:{badmatch,error} ->
	    logger:error("Hsm-callback: bad input data",[]),
	    {404,[],<<"bad input">>};
	_:E ->
	    logger:error("Hsm-callback: error=~p",[E]),
	    {404,[],utils:to_binary(E)}
    end;

handle(_,_,_Req) ->
    {404,[],<<"Not Found...">>}.

handle_event(_Event,_Data,_Args)->
    %%logger:info("hsm_elli_callback: handle_event:~p, data:~p",[Event,Data]),
    ok.

%%===============================================================================
%% Test data
%%===============================================================================
get_rsa_offset(0)->
    PRV="5331303730343033524430304E3030303162067068FC70293CB6D3933FEEF951A33C0071D80907A80F90BBF809BC4FE5F5D2F5B6311D2750D550E56F12BF6A2154C562CFBCB4DE6B56E1345EBA66E328FBB137BBA5ECEC11BE273408B912D5B2C383A5B44B84B190E10D9BFB4D3605DDD4A513B2CB709D0454FD2A8D622C102D4013BD0CE891704443C0BFEED187BF5D180DA33F4FB57961DCE94C8E263ACBC5FF6C839FD0F3CF02FC1B2C3F3D3BCE3C917A69D3AC69AAC33707AB548DEC373CC4548427AB76D6053296A6AE1D0D42F3E46486DDDA47EFC8A6E3F1AAA9659288F41BEE758FE740F5FCC040966B161C3AB504E82E0937383DF11F89CFAC5AE356584658BCB01CC6966C86DA36B3DC7B2568CB69FBEE23F13E58429941AA7BD780A787DE34CF6D950D637D8B47F6675A4A6BF80A5184109AC482C074311A3C936859266AA27F322F21029D51F5132A1263269F4141C4158D402B333998A91F227FC554021F42CFDDA2E4F3571205BB3C2EDC1A790ADDADF0A88743941756FA057BF14B373E70753C1DD246EBF375C80DBB0EF1E323C7DF36451AC6614A888E8E05DCE0D1488AA24088D827E7C72531CAF67E9472DFA3E8ECCD5A703A1F0C06B6B86E81C95E1C032B6131F568EAF35CD5FCE7818787D5303497D3B3A53D20B417C44BC3C9B923ED6489B2C03D1D97FC103FA45C747D1E9B247F71BB9513536A499E36B0BD86A0A9B2919F3839D8DF1F56608BE1C250B05BC66C939509B5CB9FDA4EE473047194FF34C9C2A27128C8158659638E1C2EE7C6B4531F20236CFEC8573844355322F4E0B41B73AA91F285148E90693B702282FB806D6543A01084CA7414010034C8B11A47FD0A7C7B14F906B570319288E0BF98AF0AEED27729ADCD51DE58784B297DC723B9E8DB1013AFE3320586EEDCC809960BA9A58CDCF1DBD35399350E6D0461F5AEFB411DF6F1F0646AEFD843463043333046433838363939353831",
    PUB="308201090282010094ED829E0EB7AAFBE99D34807ED05B1B55247008124DB775D044FF590EFF482A2DAF166B46EAD30D9802308082BE7431D4668D42A3546E7986AAFEBCEE003CF1A4C8C8997410DE62A58F989D84167EB38D99F9E963A612D23436EEC06CCFFCC94D08FB380411F7F1FEE9E61D4641DE2BB10C5A74D04EDEC97DEAAC74EABC6787AE7E6951F0DE3CC9317B7E7775EF57A1BA5857902A994B0F5F1188A26D98F8C00EDC020E6DE4644C7CC8C8B2A4B12D4BF96DE774A83BB5F935AF46070AE79AEC026B7B43458AB2CDF1C8CB164E0DA8560A8E3165D50B85A168F2CA81DC067E1E554B0C980B9FE75B1A76E057EADED23C40C6BCC8B4769EAB25582A0D5A105EF70203010001",
    PKR={'RSAPublicKey',-13516616279602160447486537391273793897235139708584631550309555281331816511128122316768699144073797480995644212289505767050862526766651809966528027213011978539180130282658738379582614472867119780581661609340466329980645098058044365447245506815555458689228889831379787709504311253146281206325822283445295911407830793751759856410544787116798836162265518922563992914548294452412011154400881798348938986601601924845594315124087271391377104547144456899263495801731693565492554166936744804635159806618362976922968044029301624595264324811543749672543032390360996233426883198414253511740382528243332324634535030613560915894537,65537},

    {PUB,PRV,PKR}.

get_pvk()->
    "S10096V2TN00N0001D30BFE6007215E29B99D03CA5D05F9A944F27A707E807E0B109CF45971BDFCACE3F53218F62FA8D0".

get_dcvv_config()->
    PM_TWU=30,
    PM_MKDCVV="S10096E0TN00E0001ACF7C47087DE618314D68ACC704397CD8E956082A9F1B215F7A89F41C0D72FC9B1A9D4949836DD27A",
    {PM_TWU,PM_MKDCVV}.



