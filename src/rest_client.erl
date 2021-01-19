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
%% Thales 9000 REST client : tests and examples 
%%------------------------------------------------------------------------------------
%% 2018-2021
%%====================================================================================
-module(rest_client).
-compile(export_all).

%% Good-params tests...
test(pvv_generate)->
    test(pvv_generate,false);
test(pvv_check) ->
    test(pvv_check,false);
test(encrypt)->
    TEXT="plain-text-0000000000-1111111111-2222222222-3333333333-444444444-55555",
    test(encrypt,TEXT,false);
test(dcvv_generate)->
    test(dcvv_generate,false);
test(dcvv_check) ->
    test(dcvv_check,false);
test(set_skey) ->
    test(set_skey,aes128,false);
%% Bad URL test...
test(bad_url)->
    inets:start(),

    RESP=httpc:request(post,{"http://127.0.0.1:8087/hsmrt/bad-url",
    			    [],
    			    "application/json",
			     jsx:encode(#{},[{space,2},{indent,4}])},[],[]),
    case RESP of
	{ok,{{_,200,_},_,M}} ->
	    io:format("Unexpected M=~p~n",[M]),
	    {ok,M};
	{ok,{{_,_,_},_,E}} ->
	    {error,E}
    end.


%% Generate PVV
test(pvv_generate,BAD_PARAM_TEST)->
    inets:start(),

    {_,_,PKR}=hsm_elli_callback:get_rsa_offset(0),
    PVK=hsm_elli_callback:get_pvk(),

    %% Pinblock
    PIN="1122",
    APPID="123456789012345678901234567890FF",
    PAN= utils:shorten_appid(APPID),
    K3=cryptoxs:get_test_visa_3des(),
    PINBLK=pinblk:create(01,PIN,PAN),
    PINBLK_ENCR=cryptoxs:encrypt(des3,ecb,K3,hex:hex_to_bin(PINBLK)),
    PINBLK_HEX=hex:bin_to_hex(PINBLK_ENCR),

    %% Keyblock
    K3B = hex:hex_to_bin(lists:flatten(tuple_to_list(K3))),
    ENCR_KEY=public_key:encrypt_public(K3B,PKR,[{rsa_padding,rsa_pkcs1_padding}]),
    ENCR_KEY_HEX=hex:bin_to_hex(ENCR_KEY),

    quickrand:seed(),
    UUID=uuid:uuid_to_string(uuid:get_v4()),

    io:format("UUID=~p~n",[UUID]),
    
    ReqMap = #{ <<"appId">> => APPID,
		<<"mpinBlock">> => #{ <<"mpinBlock">> => PINBLK_HEX,
				      <<"mkeyGuid">> => UUID,
				      <<"mkeyBlock">> => ENCR_KEY_HEX},
		<<"rsaOffset">> => 0,
		<<"pvk">> => PVK},

    %% Damage to data ...
    ReqMap1 = case BAD_PARAM_TEST of
		  bad_params ->
		      maps:remove(<<"mpinBlock">>,ReqMap);
		  false ->
		      ReqMap
	      end,
    
    io:format("JSON=~p~n",[jsx:format(jsx:encode(ReqMap1,[{space,2},{indent,4}]))]),
    
    %% RESP=httpc:request(get,{"http://127.0.0.1:8087/hello/world",
    %% 			    [{"Content-Type","application/json"},
    %% 			     {"Accept","application/json"}],
    %% 			    "application/json",
    %% 			    REQ},[],[]).


    RESP=httpc:request(post,{"http://127.0.0.1:8087/hsmrt/set-pin-pvv",
    			    [],
    			    "application/json",
			     jsx:encode(ReqMap1,[{space,2},{indent,4}])},[],[]),
    case RESP of
	{ok,{{_,200,_},_,M}} ->
	    io:format("M=~p~n",[M]),
	    RespMap = jsx:decode(list_to_binary(M)),
	    {ok,Text0}=maps:find(<<"pvv">>,RespMap),
	    {ok,binary_to_list(Text0)};
	{ok,{{_,_,_},_,E}} ->
	    {error,E}
    end;

%% Check PVV, ADDITIONAL_PARAM can be either bad_params | bad_pvv or "pvv value as list"
test(pvv_check,ADDITIONAL_PARAM)->
    inets:start(),

    {_,_,PKR}=hsm_elli_callback:get_rsa_offset(0),
    PVK=hsm_elli_callback:get_pvk(),

    %% Pinblock
    PIN="1122",
    APPID="123456789012345678901234567890FF",
    PAN= utils:shorten_appid(APPID),
    K3=cryptoxs:get_test_visa_3des(),
    PINBLK=pinblk:create(01,PIN,PAN),
    PINBLK_ENCR=cryptoxs:encrypt(des3,ecb,K3,hex:hex_to_bin(PINBLK)),
    PINBLK_HEX=hex:bin_to_hex(PINBLK_ENCR),

    %% Keyblock
    K3B = hex:hex_to_bin(lists:flatten(tuple_to_list(K3))),
    ENCR_KEY=public_key:encrypt_public(K3B,PKR,[{rsa_padding,rsa_pkcs1_padding}]),
    ENCR_KEY_HEX=hex:bin_to_hex(ENCR_KEY),

    quickrand:seed(),
    UUID=uuid:uuid_to_string(uuid:get_v4()),

    io:format("UUID=~p~n",[UUID]),
    
    ReqMap = #{ <<"appId">> => APPID,
		<<"mpinBlock">> => #{ <<"mpinBlock">> => PINBLK_HEX,
				      <<"mkeyGuid">> => UUID,
				      <<"mkeyBlock">> => ENCR_KEY_HEX},
		<<"rsaOffset">> => 0,
		<<"pvk">> => PVK,
		<<"pvv">> => <<"9839">>},

    %% Damage to data ...
    ReqMap1 = case ADDITIONAL_PARAM of
		  bad_params ->
		      maps:remove(<<"mpinBlock">>,ReqMap);
		  bad_pvv ->
		      maps:put(<<"pvv">>,<<"0000">>,ReqMap);
		  PVV when is_list(PVV) ->
		      maps:put(<<"pvv">>,list_to_binary(PVV),ReqMap);
		  _ ->
		      ReqMap
	      end,
    
    io:format("JSON=~p~n",[jsx:format(jsx:encode(ReqMap1,[{space,2},{indent,4}]))]),    
    RESP=httpc:request(post,{"http://127.0.0.1:8087/hsmrt/check-pin-pvv",
    			    [],
    			    "application/json",
    			    jsx:encode(ReqMap1,[{space,2},{indent,4}])},[],[]),

    case RESP of
	{ok,{{_,200,_},_,_}} ->
	    {ok};
	{ok,{{_,_,_},_,E}} ->
	    {error,E}
    end;

%% Generate DCVV
test(dcvv_generate,BAD_PARAM_TEST)->
    inets:start(),

    APPID="123456789012345678901234567890FF",
    PAN="4455660000000000",
    EXPDT="1905",
    
    ReqMap = #{ <<"appId">> => APPID,
		<<"pan">> => PAN,
		<<"expdt">> => EXPDT},

    %% Damage to data ...
    ReqMap1 = case BAD_PARAM_TEST of
		  bad_params ->
		      maps:remove(<<"pan">>,ReqMap);
		  false ->
		      ReqMap
	      end,
    
    io:format("JSON=~p~n",[jsx:format(jsx:encode(ReqMap1,[{space,2},{indent,4}]))]),
    RESP=httpc:request(post,{"http://127.0.0.1:8087/hsmrt/generate-dcvv",
    			    [],
    			    "application/json",
			     jsx:encode(ReqMap1,[{space,2},{indent,4}])},[],[]),
    case RESP of
	{ok,{{_,200,_},_,M}} ->
	    io:format("M=~p~n",[M]),
	    RespMap = jsx:decode(list_to_binary(M)),
	    {ok,Text0}=maps:find(<<"dcvv">>,RespMap),
	    {ok,Text0};
	{ok,{{_,_,_},_,E}} ->
	    {error,E}
    end;

%% Check PVV, ADDITIONAL_PARAM can be either bad_params | bad_pvv or "pvv value as list"
test(dcvv_check,ADDITIONAL_PARAM)->
    inets:start(),

    APPID="123456789012345678901234567890FF",
    PAN="4455660000000000",
    EXPDT="1905",
    DCVV_DEFAULT="000",

    ReqMap = #{ <<"appId">> => APPID,
		<<"pan">> => PAN,
		<<"expdt">> => EXPDT,
		<<"dcvv">> => DCVV_DEFAULT},

    %% Damage to data ...
    ReqMap1 = case ADDITIONAL_PARAM of
		  bad_params ->
		      maps:remove(<<"pan">>,ReqMap);
		  bad_dcvv ->
		      maps:put(<<"dcvv">>,DCVV_DEFAULT,ReqMap);
		  DCVV when is_list(DCVV) ->
		      maps:put(<<"dcvv">>,list_to_binary(DCVV),ReqMap);
		  _ ->
		      ReqMap
	      end,
    
    io:format("JSON=~p~n",[jsx:format(jsx:encode(ReqMap1,[{space,2},{indent,4}]))]),    
    RESP=httpc:request(post,{"http://127.0.0.1:8087/hsmrt/check-dcvv",
    			    [],
    			    "application/json",
    			    jsx:encode(ReqMap1,[{space,2},{indent,4}])},[],[]),

    case RESP of
	{ok,{{_,200,_},_,_}} ->
	    {ok};
	{ok,{{_,_,_},_,E}} ->
	    {error,E}
    end;


%% Encrypt
test(encrypt,TEXT)->
    test(encrypt,TEXT,false);
test(decrypt,TEXT)->
    test(decrypt,TEXT,false).

test(encrypt,TEXT,BAD_PARAM_TEST)->
    inets:start(),

    APPID="123456789012345678901234567890FF",
    DEK="S1009623AN00N00016AA097E57249F447A3C3EFDE6D73846204C9ACC085B8533D3BB17D74011C302D78D27A07A55E33AE", %% Key is AES ...

    ReqMap = #{ <<"appId">> => APPID,
		<<"text">> => TEXT,
		<<"dek">> => DEK},

    %% Damage to data ...
    ReqMap1 = case BAD_PARAM_TEST of
		  bad_params ->
		      maps:remove(<<"text">>,ReqMap);
		  bad_key ->
		      maps:put(<<"dek">>,"S1009623AN00N",ReqMap);
		  false ->
		      ReqMap
	      end,
    
    io:format("JSON=~p~n",[jsx:format(jsx:encode(ReqMap1,[{space,2},{indent,4}]))]),

    RESP=httpc:request(post,{"http://127.0.0.1:8087/hsmrt/encrypt-dek",
    			    [],
    			    "application/json",
    			    jsx:encode(ReqMap1,[{space,2},{indent,4}])},[],[]),

    case RESP of
	{ok,{{_,200,_},_,M}} ->
	    io:format("M=~p~n",[M]),
	    RespMap = jsx:decode(list_to_binary(M)),
	    {ok,Text0}=maps:find(<<"encrypted">>,RespMap),
	    {ok,binary_to_list(Text0)};
	{ok,{{_,_,_},_,E}} ->
	    {error,E}
    end;

%% Encrypt
test(decrypt,ENCRYPTED,BAD_PARAM_TEST)->
    inets:start(),

    APPID="123456789012345678901234567890FF",
    DEK="S1009623AN00N00016AA097E57249F447A3C3EFDE6D73846204C9ACC085B8533D3BB17D74011C302D78D27A07A55E33AE",
    
    ReqMap = #{ <<"appId">> => APPID,
		<<"encrypted">> => ENCRYPTED,
		<<"dek">> => DEK},
    
    %% Damage to data ...
    ReqMap1 = case BAD_PARAM_TEST of
		  bad_params ->
		      maps:remove(<<"encrypted">>,ReqMap);
		  bad_key ->
		      maps:put(<<"dek">>,"S1009623AN00N",ReqMap);
		  false ->
		      ReqMap
	      end,

    io:format("JSON=~p~n",[jsx:format(jsx:encode(ReqMap1,[{space,2},{indent,4}]))]),

    RESP=httpc:request(post,{"http://127.0.0.1:8087/hsmrt/decrypt-dek",
    			    [],
    			    "application/json",
    			    jsx:encode(ReqMap1,[{space,2},{indent,4}])},[],[]),

    case RESP of
	{ok,{{_,200,_},_,M}} ->
	    io:format("M=~p~n",[M]),
	    RespMap = jsx:decode(list_to_binary(M)),
	    {ok,Text0}=maps:find(<<"text">>,RespMap),
	    {ok,binary_to_list(Text0)};
	{ok,{{_,_,_},_,E}} ->
	    {error,E}
    end;


%% Set Session-Key
test(set_skey,KEY_TYPE,ADDITIONAL_PARAM)->
    inets:start(),

    {_,_,PKR}=hsm_elli_callback:get_rsa_offset(0),

    APPID="123456789012345678901234567890FF",
    %% Keyblock
    Key = case KEY_TYPE of
	      des3 ->
		  K3=cryptoxs:get_test_visa_3des(),
		  _K3B = hex:hex_to_bin(lists:flatten(tuple_to_list(K3)));
	      aes128 ->
		  _K128=cryptoxs:get_test_aes128();
	      aes256 ->
		  _K256=cryptoxs:get_test_aes256()
	  end,
    ENCR_KEY=public_key:encrypt_public(Key,PKR,[{rsa_padding,rsa_pkcs1_padding}]),
    ENCR_KEY_HEX=hex:bin_to_hex(ENCR_KEY),

    quickrand:seed(),
    UUID=uuid:uuid_to_string(uuid:get_v4()),
    
    ReqMap = #{ <<"appId">> => APPID,
		<<"sessionKeyGuid">> => UUID,
		<<"sessionKeyBlock">> => ENCR_KEY_HEX,
		<<"keyType">> => atom_to_binary(KEY_TYPE),
		<<"rsaOffset">> => 0},

    %% Damage to data ...
    ReqMap1 = case ADDITIONAL_PARAM of
		  bad_params ->
		      maps:remove(<<"sessionKeyBlock">>,ReqMap);
		  _ ->
		      ReqMap
	      end,
    
    io:format("JSON=~p~n",[jsx:format(jsx:encode(ReqMap1,[{space,2},{indent,4}]))]),    
    RESP=httpc:request(post,{"http://127.0.0.1:8087/hsmrt/set-session-key",
    			    [],
    			    "application/json",
    			    jsx:encode(ReqMap1,[{space,2},{indent,4}])},[],[]),

    case RESP of
	{ok,{{_,200,_},_,M}} ->
	    io:format("M=~p~n",[M]),
	    RespMap = jsx:decode(list_to_binary(M)),
	    {ok,Text0}=maps:find(<<"skey">>,RespMap),
	    {ok,binary_to_list(Text0)};
	{ok,{{_,_,_},_,E}} ->
	    {error,E}
    end;

%% Set Session-Key
test(set_and_use_skey,_KEY_TYPE,ADDITIONAL_PARAM)->
    inets:start(),

    APPID="123456789012345678901234567890FF",
    K128 = cryptoxs:get_test_aes128(),
    {ok,SKEY}=test(set_skey,aes128,none), %% uses the same aes128 test key

    IV=[1,0,0,0,1,0,0,0,1,0,0,0,1,0,0,0],
    Text= cryptoxs:pad(<<"1234567890123456aaaabbbbccccddddeeeeffffgggg">>,16),
    Encrypted=cryptoxs:encrypt(aes128,cbc,K128,IV,Text),
    Text1=cryptoxs:decrypt(aes128,cbc,K128,IV,Encrypted),
io:format("Descrypted cryptoxs=~p~n",[Text1]),
io:format("IV HEX=~p~n",[hex:bin_to_hex(IV)]),
    ReqMap = #{ <<"appId">> => APPID,
		<<"encrypted">> => hex:bin_to_hex(Encrypted),
		<<"iv">> => hex:bin_to_hex(IV),
		<<"dek">> => SKEY},

    %% Damage to data ...
    ReqMap1 = case ADDITIONAL_PARAM of
		  bad_params ->
		      maps:remove(<<"encrypted">>,ReqMap);
		  _ ->
		      ReqMap
	      end,
    
    io:format("JSON=~p~n",[jsx:format(jsx:encode(ReqMap1,[{space,2},{indent,4}]))]),    
    RESP=httpc:request(post,{"http://127.0.0.1:8087/hsmrt/decrypt-dek",
    			    [],
    			    "application/json",
    			    jsx:encode(ReqMap1,[{space,2},{indent,4}])},[],[]),

    case RESP of
	{ok,{{_,200,_},_,M}} ->
	    io:format("M=~p~n",[M]),
	    RespMap = jsx:decode(list_to_binary(M)),
	    {ok,Text0}=maps:find(<<"text">>,RespMap),
	    {ok,binary_to_list(Text0)};
	{ok,{{_,_,_},_,E}} ->
	    {error,E}
    end;



%% Generate B-Key / KTYPE = des3 | aes128 | aes256
test(generate_bkey,KEY_TYPE,ADDITIONAL_PARAM)->
    inets:start(),

    APPID="123456789012345678901234567890FF",
    DEK="S1009623AN00N00016AA097E57249F447A3C3EFDE6D73846204C9ACC085B8533D3BB17D74011C302D78D27A07A55E33AE", %% Key is AES ...

    ReqMap = #{ <<"appId">> => APPID,
		<<"keyType">> => atom_to_binary(KEY_TYPE),
		<<"sessionKey">> => DEK},

    %% Damage to data ...
    ReqMap1 = case ADDITIONAL_PARAM of
		  bad_params ->
		      maps:remove(<<"sessionKey">>,ReqMap);
		  _ ->
		      ReqMap
	      end,
    
    io:format("JSON=~p~n",[jsx:format(jsx:encode(ReqMap1,[{space,2},{indent,4}]))]),    
    RESP=httpc:request(post,{"http://127.0.0.1:8087/hsmrt/generate-bkey",
    			    [],
    			    "application/json",
    			    jsx:encode(ReqMap1,[{space,2},{indent,4}])},[],[]),

    case RESP of
	{ok,{{_,200,_},_,M}} ->
	    RespMap = jsx:decode(list_to_binary(M)),
	    {ok,Text0}=maps:find(<<"bkey">>,RespMap),
	    {ok,Text0};
	{ok,{{_,_,_},_,E}} ->
	    {error,E}
    end.

