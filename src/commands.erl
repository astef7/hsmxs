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
%% Thales 9000 Commands / API
%%------------------------------------------------------------------------------
%% 2018-2021
%%==============================================================================
-module(commands).
-compile([export_all]).

-define(LOG_PFX,"HSMXS").

-define(PM_TWU,30).
-define(PM_MKDCVV,"S10096E0TN00E0001ACF7C47087DE618314D68ACC704397CD8E956082A9F1B215F7A89F41C0D72FC9B1A9D4949836DD27A").

-define(PIN_LEN,4).

-include_lib("public_key/include/public_key.hrl"). 
-include("HsmPubKeySpec.hrl").

-type hex_string() :: string().
-type lmk_type() :: kblk | variant.
-type key_type() :: hmac_sha1 | hmac_sha256 | pvk_gen | pvk_ibm | pvk_visa |
		    rsa_prv | rsa_pub | cvv | dek | zek | tek | dcvv |
		    tmk | zmk | kek | tpk | zpk.
-type key_type_rsa() :: sign_only | key_mgt_only | sign_and_key_mgt | data_encr_decr |
			pin_encr_decr.

-type alg_type() :: aes128 | aes256 | des2 | des3 | hmac |rsa.

%%------------------------------------------------------------------------------------
%% extract 12-right-most excluding Luhna...
%%------------------------------------------------------------------------------------
-spec extract_pan(PAN::binary()|list())->binary().
extract_pan(PAN)->
    {PAN1,PLEN1} = case is_binary(PAN) of
		       true -> {PAN,length(binary_to_list(PAN))};
		       _ -> {list_to_binary(PAN),length(PAN)}
		   end,
    % 12-right-most excluding Luhna...
    PFX_LEN=PLEN1-13,
    <<_PFX:PFX_LEN/bytes,PAN2:12/bytes,_LUHN:1/bytes>> = PAN1,
    PAN2.
%%------------------------------------------------------------------------------------
-spec get_key_table()-> #{KEY_TYPE::key_type() := {string(),string(),string()}}.
get_key_table()->
    #{
      hmac_sha1 => {"61","10C","3401"},
      hmac_sha256 => {"63","10C","3401"},
      pvk_gen => {"V0","002","1400"},
      pvk_ibm => {"V1","002","1400"},
      pvk_visa => {"V2","002","1400"},
      rsa_prv => {"03","00C","3400"},
      rsa_pub => {"02","00D","3600"},

      cvv => {"13","402","1404"},
      dek => {"21","00B","3200"},
      zek => {"22","00A","3000"},
      tek => {"23","30B","3203"},
      dcvv => {"32","000","0000"},

      tmk => {"51","002","1400"} , % for separated: {"51","80D","3608"}
      zmk => {"52","000","0400"},
      kek => {"54","107","2401"},
      tpk => {"71","002","1400"}, % for separated: {"71","70D","3607"}
      zpk => {"72","001","0600"}
     }.

-spec get_alg_table()-> #{ALG_TYPE::alg_type() := {string()|none,string(),string()|none}}.
get_alg_table()->
    #{
      aes128 => {"1","A","A1"},
      aes256 => {"1","A","A3"},
      des2 => {"0","T","T2"},
      des3 => {"0","T","T3"},
      hmac => {none,"H",none},
      rsa => {none,"R",none}
     }.

-spec get_rsa_key_type()-> #{RSA_KEY_TYPE::key_type_rsa() := binary()}.
get_rsa_key_type()->
    #{
      sign_only => <<"0">>,
      key_mgt_only => <<"1">>,
      sign_and_key_mgt => <<"2">>,
      data_encr_decr => <<"4">>,
      pin_encr_decr => <<"5">>
     }.
%%-------------------------------------------------------------------------
get_pub_len(1024)-> 139;
get_pub_len(2048)-> 269.
%%-------------------------------------------------------------------------
%-------------------------------------------------------------------------------------
% Do testow VISA ApplePay:
% UC35E81DE357027195B4EB9AD4B290709 / KCV=F7D5A0
% Jawnie: 2315 208C 9110 AD40 2315 208C 9110 AD40
%-------------------------------------------------------------------------------------
%%------------------------------------------------------------------------------------------
%% dek()->
%%     {<<"U01833D376C0D6602D5B0556AFCA93DF4">>,<<"00B">>,<<"3477C9">>}.
%% zek()->
%%     {<<"U840E00405378BE60311B85FA438EE77E">>,<<"00A">>,<<"D99DC8">>}.
%% tek()->
%%     {<<"UE1B940BE595F6F8901957FB5F672095F">>,<<"30B">>,<<"63774A">>}.
%% pvk(variant)->
%%     {<<"U656C5DCBDF7B103BD896BE836168DE32">>,<<"002">>,<<"D58DC1">>};
%% pvk(keyblk) ->
%%     {<<"S10096V1TN00E000119C453C86E7A851BF8361AEA6721387FCC5ED38A0F6D1A5DC1AA66A28A3D5D22A1BF06D381F90DCEBEDF9E">>,<<"FFF">>,none}.
%%------------------------------------------------------------------------------------------

-spec build_cmd_EI(LMK,KEY_TYPE_RSA,KEY_LEN) -> {binary(),fun()} when
      LMK::lmk_type(),
      KEY_TYPE_RSA::key_type_rsa(),
      KEY_LEN::integer().
build_cmd_EI(LMK,KEY_TYPE_RSA,KEY_LEN) ->
    KEY_TYPE_IND_TAB = get_rsa_key_type(),
    {ok,KEY_TYPE_IND} = maps:find(KEY_TYPE_RSA,KEY_TYPE_IND_TAB),
    KEY_LEN1 = utils:format_integer(KEY_LEN,4),
    {LMK1,KEY_SPEC_KBLK} = case LMK of
	    kblk -> {<<"01">>,<<"#","00","00">>};
	    variant -> {<<"00">>,<<"">>};
	    _ -> error(bad_lmk)
	end,

    CMD = <<"EI",
	    KEY_TYPE_IND/binary,
	    KEY_LEN1/binary,
	    "01",
	    "%",
	    LMK1/binary,
	    KEY_SPEC_KBLK/binary
	  >>,
    {CMD,fun(R)-> parse_EI_response(LMK,R,KEY_LEN) end}.

-spec parse_EI_response(LMK::lmk_type(),RESP::binary(),KEY_LEN::integer())->
	  {ok,PUB::hex_string(),PRV::hex_string()} |
	  {error,CD::string()}.
parse_EI_response(kblk,RESP,KEY_LEN)->
    PUB_LEN=get_pub_len(KEY_LEN),
    <<"EJ",CD:2/bytes,PUB:PUB_LEN/bytes,"FFFF",REST/binary>> = RESP,
    case CD of
	<<"00">> ->
	    {ok,hex:bin_to_hex(PUB),hex:bin_to_hex(REST)};
	_ -> 
	    {error,CD}
    end;
parse_EI_response(variant,RESP,KEY_LEN)->
    PUB_LEN=get_pub_len(KEY_LEN),
    <<"EJ",CD:2/bytes,PUB:PUB_LEN/bytes,_PRV_LEN:4/bytes,REST/binary>> = RESP,
    case CD of
	<<"00">> ->
	    %%PRV_LEN1=binary_to_integer(PRV_LEN),
	    %%ACTUAL_LEN=length(binary_to_list(REST)),
	    {ok,hex:bin_to_hex(PUB),hex:bin_to_hex(REST)};
	_ -> 
	    {error,CD}
    end.

test_EI()->
    CMD=build_cmd_EI(kblk,sign_and_key_mgt,2048),
    {ok,PUB,PRV}=execute(CMD),
    logger:debug("EI PUB=~p~n~nPRV=~p~n",[PUB,PRV]).

%%-------------------------------------------------------------------------
-spec build_cmd_GI(LMK,KEY_TYPE,KEY_ALG,KEY_ENCRYPTED,PRV) -> {binary(),fun()} when
      LMK::lmk_type(),
      KEY_TYPE::key_type(),
      KEY_ALG::alg_type(),
      KEY_ENCRYPTED::string()|binary(),
      PRV::hex_string()|binary().
build_cmd_GI(kblk,KEY_TYPE,KEY_ALG,KEY_ENCRYPTED,PRV) ->
    KTAB=get_key_table(),
    ATAB=get_alg_table(),
    {ok,{U,_,_}}=maps:find(KEY_TYPE,KTAB),
    USAGE=list_to_binary(U),
    {KEY1,KLEN1} = utils:to_binary_and_length(KEY_ENCRYPTED),
    KLEN2=utils:format_integer(KLEN1,4),
    {ok,{A,_,_}}=maps:find(KEY_ALG,ATAB),
    IMPORT_KEY_TYPE=list_to_binary(A),

    % uwaga: tym razem to musi byc LIST...
    PRV1 = case is_binary(PRV) of
	       true -> binary_to_list(PRV);
	       _ -> PRV
	   end,
    PRV2 = hex:hex_to_bin(PRV1),

    CMD = <<"GI",
	    "01",
	    "01",
	    "FFFF",
	    KLEN2/binary,
	    KEY1/binary,
	    ";",
	    "99"
	    "FFFF",
	    PRV2/binary,
	    ";",
	    IMPORT_KEY_TYPE/binary,
	    "S",
	    "1", % KCV=6
	    "=",
	    "03",
	    "%",
	    "01", % LMK
	    "#",
	    USAGE/binary,
	    "N",
	    "00",
	    "N",
	    "00"
	  >>,
    {CMD,fun(R)-> parse_GI_response(kblk,R) end};

build_cmd_GI(variant,KEY_TYPE,KEY_ALG,KEY_ENCRYPTED,PRV) ->
    KTAB=get_key_table(),
    ATAB=get_alg_table(),
    {ok,{_,_,U}}=maps:find(KEY_TYPE,KTAB),
    USAGE=list_to_binary(U),
    {KEY1,KLEN1} = utils:to_binary_and_length(KEY_ENCRYPTED),
    KLEN2=utils:format_integer(KLEN1,4),
    {ok,{A,_,_}}=maps:find(KEY_ALG,ATAB),
    IMPORT_KEY_TYPE=list_to_binary(A),

    % uwaga: tym razem to musi byc LIST...
    PRV1 = hex:hex_to_bin(PRV),
    PRV1_LEN_FMT=utils:format_integer(byte_size(PRV1),4),

    CMD = <<"GI",
	    "01",
	    "01",
	    USAGE/binary,
	    KLEN2/binary,
	    KEY1/binary,
	    ";",
	    "99",
	    PRV1_LEN_FMT/binary,
	    PRV1/binary,
	    ";",
	    IMPORT_KEY_TYPE/binary,
	    "U",
	    "1", % KCV=6
	    "=",
	    "03",
	    "%",
	    "00" % LMK
	  >>,
    {CMD,fun(R)-> parse_GI_response(variant,R) end}.

-spec parse_GI_response(LMK::lmk_type(),RESP::binary())->
	  {ok,KEY::binary(),KCV::binary()} |
	  {error,CD::string()}.
parse_GI_response(_LMK,RESP)->
    <<"GJ",CD:2/bytes,REST/binary>> = RESP,
    KLEN=length(binary_to_list(REST))-6,
    case CD of
	<<"00">> ->
	    <<KEY:KLEN/bytes,KCV:6/bytes>> = REST,
	    {ok,KEY,KCV};
	ER ->
	    {error,ER}
	end.

test_GI()->
    % ------------- EI ---------------------------
    CMD0=build_cmd_EI(kblk,key_mgt_only,2048),
    {ok,PUB,PRV}=execute(CMD0),

    {ok,#'HsmPubKey'{modulus=MOD1,exponent=EXP1}} =
	'HsmPubKeySpec':decode('HsmPubKey',hex:hex_to_bin(PUB)),

    PKR= #'RSAPublicKey'{modulus=MOD1,publicExponent=EXP1},
    AES= <<"1234567890123456">>,
    ENCR_KEY=public_key:encrypt_public(AES,PKR,[{rsa_padding,rsa_pkcs1_padding}]),
    ENCR_TEXT=cryptoxs:encrypt(aes128,ecb,AES,<<"text778888888899">>),

    % ------------ GI ----------------------------
    KEY_TYPE=tek,
    CMD1=build_cmd_GI(kblk,KEY_TYPE,aes128,ENCR_KEY,PRV),
    {ok,KEY,KCV}=execute(CMD1),
    logger:debug("GI KEY=[~p],KCV=[~p]~n",[KEY,KCV]),

    % ------------ M2 ----------------------------
    CMD2=build_cmd_M2(kblk,ecb,{KEY_TYPE,KEY},noiv,ENCR_TEXT),
    {ok,RESP2}=execute(CMD2),
    logger:debug("M2 RESP=[~p]~n",[RESP2]).

%%-------------------------------------------------------------------------
-spec build_cmd_A0(LMK,KEY_TYPE,ALG) -> {binary(),fun()} when
      LMK::lmk_type(),
      KEY_TYPE::key_type(),
      ALG::alg_type().
build_cmd_A0(LMK,KEY_TYPE,ALG) ->
    KTAB = get_key_table(),
    ATAB = get_alg_table(),
    {LMK1,KEY_TYPE1,KEY_SPEC_KBLK,KEY_SCHEME1} = 
	case LMK of
	    kblk ->
		{ok,{U,_,_}}=maps:find(KEY_TYPE,KTAB),
		U2=list_to_binary(U),
		{ok,{_,_,A}}=maps:find(ALG,ATAB),
		A2=list_to_binary(A),
		{<<"01">>,<<"FFF">>,<<"#",U2/binary,A2/binary,"N","00","N","00">>,<<"S">>};
	    variant ->
		{ok,{_,U,_}}=maps:find(KEY_TYPE,KTAB),
		U2=list_to_binary(U),
		{<<"00">>,U2,<<"">>,<<"U">>};
	    _ -> error(bad_lmk)
	end,
    CMD= <<"A0",
	   "0",
	   KEY_TYPE1/binary,
	   KEY_SCHEME1/binary,
	   "%",
	   LMK1/binary,
	   KEY_SPEC_KBLK/binary
	 >>,
    {CMD,fun(R)-> parse_A0_response(LMK,R) end}.

-spec parse_A0_response(LMK::lmk_type(),RESP::binary())->
	  {ok,KEY::hex_string(),KCV::hex_string()} | 
	  {error, CD::string()}.
parse_A0_response(_LMK,RESP)->
    <<"A1",CD:2/bytes,REST/binary>> = RESP,
    KLEN=length(binary_to_list(REST))-6,
    case CD of
	<<"00">> ->
	    <<KEY:KLEN/bytes,KCV:6/bytes>> = REST,
	    {ok,binary_to_list(KEY),binary_to_list(KCV)};
	ER ->
	    {error,binary_to_list(ER)}
	end.

test_A0()->
    CMD=build_cmd_A0(kblk,dek,aes128),
    {ok,_KEY,_KCV}=execute(CMD).

test_A0(PVK)->
    CMD=build_cmd_A0(kblk,PVK,des3),
    {ok,_KEY,_KCV}=execute(CMD).

test_A0(LMK,PVK)->
    CMD=build_cmd_A0(LMK,PVK,des3),
    {ok,_KEY,_KCV}=execute(CMD).

%%-----------------------------------------------------------------------------
%% For variant/3DES or AES IV is 16H
%% For kblk/3DES IV is 16H
%% For kblk/AES IV is 32H
%%-----------------------------------------------------------------------------
-spec build_cmd_M0(LMK,MODE,{KEY_TYPE,KEY},IV,PLAIN) -> {binary(),fun()} when
      LMK::lmk_type(),
      MODE::ecb | cbc,
      KEY_TYPE::key_type(),
      KEY::string() | binary(),
      IV::hex_string() | binary() | noiv,
      PLAIN::string() | binary().
build_cmd_M0(LMK,MODE,{KEY_TYPE,KEY},IV,PLAIN) when (MODE =:= ecb) or (MODE =:= cbc) ->
    {LMK1,KEY_TYPE1} = case LMK of
			   kblk -> {<<"01">>,<<"FFF">>};
			   variant ->
			       KTAB=get_key_table(),
			       {ok,{_,KT,_}}=maps:find(KEY_TYPE,KTAB),
			       {<<"00">>,list_to_binary(KT)};
			   _ -> error(bad_lmk)
		       end,
    {PLAIN1,LEN1} = case is_list(PLAIN) of
			true -> {list_to_binary(PLAIN),length(PLAIN)};
		 _ -> {PLAIN,length(binary_to_list(PLAIN))}
	     end,
    if 
	LEN1 > 65535 -> error(plain_length);
	true -> ok
    end,

    if 
	LEN1 rem 16 =:= 0 ->
	    ok;
	true ->
	    error(no_padding)
    end,

    LEN1HEX=list_to_binary(hex:int_to_hex(LEN1,4)),
    KEY1 = case is_list(KEY) of
	       true -> list_to_binary(KEY);
	       _ -> KEY
	   end,
    {MODE1,IV1} = case MODE of
		      ecb -> {<<"00">>,<<"">>};
		      cbc -> 
			  IVx = case is_list(IV) of
				    true -> list_to_binary(IV);
				    _ -> IV
				end,

			  case LMK of
			      kblk ->
				  <<_KPfx:8/bytes,A:1/bytes,_KRest/binary>> = KEY1,
				  %% IV is in HEX ...
				  case {A, byte_size(IVx) == 32} of
				      {<<"A">>,false}->
					  error(bad_iv_len);
				      {<<"A">>,true}->
					  if byte_size(PLAIN1) rem 16 == 0 ->
						  ok;
					     true -> error(bad_padding_16)
					  end;
				      _ -> ok
				  end;
			      variant ->
				  if byte_size(IVx) /= 16 ->
					  error(bad_iv_len);
				     true -> ok
				  end,
				  if byte_size(PLAIN1) rem 8 == 0 ->
					  ok;
				     true -> error(bad_padding_8)
				  end
			  end,
			  
			  {<<"01">>,IVx}
		  end,

    CMD = <<"M0",
	    MODE1/binary,
	    "0",
	    "0",
	    KEY_TYPE1/binary,
	    KEY1/binary,
	    IV1/binary,
	    LEN1HEX/binary,
	    PLAIN1/binary,
	    "%",
	    LMK1/binary
	  >>,
    {CMD,fun(R)-> parse_M0_response(LMK,MODE,R) end}.

-spec parse_M0_response(LMK::lmk_type(),MODE::ecb|cbc,RESP::binary())-> 
	  {ok,IV::hex_string(),ENCR::hex_string()} |
	  {ok,ENCR::hex_string()} |
	  {error,CD::string()}.
parse_M0_response(_LMK,MODE,RESP)->
    <<"M1",CD:2/bytes,REST/binary>> = RESP,
    case {CD,MODE} of
	{<<"00">>,ecb} ->
	    <<_LENHEX:4/bytes,ENCR/binary>> = REST,
	    {ok,ENCR};
	{<<"00">>,cbc} ->
	    % if KEY was AES - IV is 32H, if it was TDES - IV is 16H
	    <<IV1H:16/bytes,LEN1H:4/bytes,ENCR1/binary>> = REST,
	    LEN1 = binary_to_integer(LEN1H,16),
	    LEN1ACTUAL = byte_size(ENCR1),
	    if
		LEN1 =:= LEN1ACTUAL ->
		    {ok,IV1H,ENCR1};
		true ->
		    %% guess was wrong...
		    <<IV2H:32/bytes,LEN2H:4/bytes,ENCR2/binary>> = REST,
		    LEN2 = binary_to_integer(LEN2H,16),
		    LEN2ACTUAL = byte_size(ENCR2),
		    if
			LEN2 =:= LEN2ACTUAL ->
			     {ok,IV2H,ENCR2};
			true ->
			    error(m1_len_decoding)
		    end
	    end;
	{ER,_} ->
	    {error,binary_to_list(ER)}
	end.

test_M0()->
    KEY="S1009623AN00N00016AA097E57249F447A3C3EFDE6D73846204C9ACC085B8533D3BB17D74011C302D78D27A07A55E33AE",
    PLAIN = <<"text555555555555">>,

    CMD1 = build_cmd_M0(kblk,ecb,{tek,KEY},noiv,PLAIN),
    {ok,ENCR}=execute(CMD1),

    CMD2 = build_cmd_M2(kblk,ecb,{tek,KEY},noiv,ENCR),
    {ok,PLAIN1}=execute(CMD2),
    logger:debug("M2=[~p]~n",[PLAIN1]).

%%-------------------------------------------------------------------------
%% For variant/3DES or AES IV is 16H
%% For kblk/3DES IV is 16H
%% For kblk/AES IV is 32H
%%-----------------------------------------------------------------------------
-spec build_cmd_M2(LMK,MODE,{KEY_TYPE,KEY},IV,ENCRYPTED) -> {binary(),fun()} when
      LMK::lmk_type(),
      MODE::ecb | cbc,
      KEY_TYPE::key_type(),
      KEY::string() | binary(),
      IV::string() | binary() | noiv,
      ENCRYPTED::string()|binary().
build_cmd_M2(LMK,MODE,{KEY_TYPE,KEY},IV,ENCRYPTED) when (MODE =:= ecb) or (MODE =:= cbc) ->
    {LMK1,KEY_TYPE1} = case LMK of
			   kblk -> {<<"01">>,<<"FFF">>};
			   variant ->
			       KTAB=get_key_table(),
			       {ok,{_,KT,_}}=maps:find(KEY_TYPE,KTAB),
			       {<<"00">>,list_to_binary(KT)};
			   _ -> error(bad_lmk)
		       end,
    {ENCRYPTED1,LEN1} = utils:to_binary_and_length(ENCRYPTED),
    if 
	LEN1 > 65535 -> error(encrypted_length);
	true -> ok
    end,
    LEN1HEX=list_to_binary(hex:int_to_hex(LEN1,4)),
    KEY1 = case is_list(KEY) of
	       true -> list_to_binary(KEY);
	       _ -> KEY
	   end,
    {MODE1,IV1} = case MODE of
		      ecb -> {<<"00">>,<<"">>};
		      cbc -> 
			  IVx = case is_list(IV) of
				    true -> list_to_binary(IV);
				    _ -> IV
				end,

			  case LMK of
			      kblk ->
				  <<_KPfx:8/bytes,A:1/bytes,_KRest/binary>> = KEY1,
				  case {A, byte_size(IVx) == 32} of
				      {<<"A">>,false}->
					  error(bad_iv_len);
				      _ -> ok
				  end;
			      variant ->
				  if byte_size(IVx) /= 16 ->
					error(bad_iv_len);
				     true -> ok
				  end
			  end,
			  {<<"01">>,IVx}
		  end,

    CMD = <<"M2",
	    MODE1/binary,
	    "0",
	    "0",
	    KEY_TYPE1/binary,
	    KEY1/binary,
	    IV1/binary,
	    LEN1HEX/binary,
	    ENCRYPTED1/binary,
	    "%",
	    LMK1/binary
	  >>,
    {CMD,fun(R)-> parse_M2_response(LMK,MODE,R) end}.

-spec parse_M2_response(LMK::lmk_type(),MODE::ecb|cbc,RESP::binary())-> 
	  {ok,IV::hex_string(),PLAIN::hex_string()} |
	  {ok,PLAIN::hex_string()} |
	  {error,CD::string()}.
parse_M2_response(_LMK,MODE,RESP)->
    <<"M3",CD:2/bytes,REST/binary>> = RESP,
    case {CD,MODE} of
	{<<"00">>,ecb} ->
	    <<_LENHEX:4/bytes,PLAIN/binary>> = REST,
	    {ok,PLAIN};
	{<<"00">>,cbc} ->
	    % if KEY was AES - IV is 32H, if it was TDES - IV is 16H
	    <<IV1H:16/bytes,LEN1H:4/bytes,PLAIN1/binary>> = REST,
	    LEN1 = binary_to_integer(LEN1H,16),
	    LEN1ACTUAL = byte_size(PLAIN1),
	    if
		LEN1 =:= LEN1ACTUAL ->
		    {ok,IV1H,PLAIN1};
		true ->
		    %% guess was wrong...
		    <<IV2H:32/bytes,LEN2H:4/bytes,PLAIN2/binary>> = REST,
		    LEN2 = binary_to_integer(LEN2H,16),
		    LEN2ACTUAL = byte_size(PLAIN2),
		    if
			LEN2 =:= LEN2ACTUAL ->
			     {ok,IV2H,PLAIN2};
			true ->
			    error(m1_len_decoding)
		    end
	    end;
	{ER,_} ->
	    {error,binary_to_list(ER)}
	end.

test_M0_M2()->
    IV16= <<"0001000100010001">>,
    IV32= <<"00010001000100010001000100010001">>,

    PLAIN= <<"text778888888899">>,

    CMD7=commands:build_cmd_A0(kblk,dek,des3),
    {ok,TEK3,_}=commands:execute(CMD7),
    
    %% kblk/des3 -> IV16
    CMD8=commands:build_cmd_M0(kblk,cbc,{dek,TEK3},IV16,PLAIN),
    {ok,_IV3,ENCRYPTED3}=commands:execute(CMD8),
    
    CMD9=commands:build_cmd_M2(kblk,cbc,{dek,TEK3},IV16,ENCRYPTED3),
    {ok,_,_RESP9}=commands:execute(CMD9),
    
    %%------------- variant ---------------------------------------------------
    CMD10=commands:build_cmd_A0(variant,tek,des3),
    {ok,TEK4,_}=commands:execute(CMD10),

    %% variant/des3 -> IV16
    CMD11=commands:build_cmd_M0(variant,cbc,{tek,TEK4},IV16,PLAIN),
    {ok,_IV4,ENCRYPTED4}=commands:execute(CMD11),
    
    CMD12=commands:build_cmd_M2(variant,cbc,{tek,TEK4},IV16,ENCRYPTED4),
    {ok,_,_RESP12}=commands:execute(CMD12),

    %%------------- variant AES ------------------------------------------------
    CMD13=commands:build_cmd_A0(variant,tek,aes256),
    {ok,TEK5,_}=commands:execute(CMD13),

    %% variant/aes256 -> IV16
    CMD14=commands:build_cmd_M0(variant,cbc,{tek,TEK5},IV16,PLAIN),
    {ok,_IV5,ENCRYPTED5}=commands:execute(CMD14),
    
    CMD15=commands:build_cmd_M2(variant,cbc,{tek,TEK5},IV16,ENCRYPTED5),
    {ok,_,_RESP15}=commands:execute(CMD15),

    %%------------- kblk AES 128 ---------------------------------------------
    CMD16=commands:build_cmd_A0(kblk,tek,aes128),
    {ok,TEK6,_}=commands:execute(CMD16),

    %% kblk/aes128 -> IV32
    CMD17=commands:build_cmd_M0(kblk,cbc,{tek,TEK6},IV32,PLAIN),
    {ok,_IV6,ENCRYPTED6}=commands:execute(CMD17),
    
    CMD18=commands:build_cmd_M2(kblk,cbc,{tek,TEK6},IV32,ENCRYPTED6),
    {ok,_,_RESP18}=commands:execute(CMD18),

    %%------------- kblk AES 256 ---------------------------------------------
    CMD19=commands:build_cmd_A0(kblk,tek,aes256),
    {ok,TEK7,_}=commands:execute(CMD19),

    %% kblk/aes256 -> IV32
    CMD20=commands:build_cmd_M0(kblk,cbc,{tek,TEK7},IV32,PLAIN),
    {ok,_IV7,ENCRYPTED7}=commands:execute(CMD20),
    
    CMD21=commands:build_cmd_M2(kblk,cbc,{tek,TEK7},IV32,ENCRYPTED7),
    {ok,_,_RESP19}=commands:execute(CMD21).

%%-------------------------------------------------------------------------
%% Pinblok/TPK -> PIN/LMK
%%-------------------------------------------------------------------------
-spec build_cmd_JC(LMK,TPK,PINBLK,PINBLK_TYPE,PAN) -> {binary(),fun()} when
      LMK::lmk_type(),
      TPK::binary() | hex_string(),
      PINBLK::binary() | hex_string(),
      PINBLK_TYPE::integer(),
      PAN::binary() | string().
build_cmd_JC(LMK,TPK,PINBLK,PINBLK_TYPE,PAN)->
    LMK1 = utils:lmk_to_binary(LMK),
    TPK1 = utils:to_binary(TPK),
    PINBLK1 = utils:to_binary(PINBLK),
    PAN1 = extract_pan(PAN),
    PINBLK_TYPE1 = utils:format_integer(PINBLK_TYPE,2),

    CMD = <<"JC",
	    TPK1/binary,
	    PINBLK1/binary,
	    PINBLK_TYPE1/binary,
	    PAN1/binary,
	    "%",
	    LMK1/binary
	  >>,
    {CMD,fun(R)-> parse_JC_response(LMK,R) end}.

-spec parse_JC_response(LMK::lmk_type(),RESP::binary())-> 
	  {ok,PINLMK::binary()} |
	  {error,CD::binary()}.
parse_JC_response(_LMK,RESP)->
    <<"JD",CD:2/bytes,REST/binary>> = RESP,
    case CD of
	<<"00">> -> {ok,REST};
	ER -> {error,ER}
    end.

%%-------------------------------------------------------------------------
%% Generate ABA PVV
%%-------------------------------------------------------------------------
-spec build_cmd_DG(LMK,PVK,PAN,PIN_LMK) -> {binary(),fun()} when
      LMK::lmk_type(),
      PVK::binary() | string(), % Usage = V2 !
      PAN::binary() | string(),
      PIN_LMK::binary().
build_cmd_DG(LMK,PVK,PAN,PIN_LMK)->
    LMK1 = utils:lmk_to_binary(LMK),
    PVK1 = utils:to_binary(PVK),
    PIN_LMK1 = utils:to_binary(PIN_LMK),

    PAN2 = extract_pan(PAN),

    CMD = <<"DG",
	    PVK1/binary, % PVK pair
	    PIN_LMK1/binary,
	    PAN2/binary,
	    "3", % PVKI
	    "%",
	    LMK1/binary
	  >>,
    {CMD,fun(R)-> parse_DG_response(LMK,R) end}.	 

-spec parse_DG_response(LMK::lmk_type(),RESP::binary())-> 
	  {ok,PVV::binary()} |
	  {error,CD::binary()}.
parse_DG_response(_LMK,RESP)->
    <<"DH",CD:2/bytes,REST/binary>> = RESP,
    case CD of
	<<"00">> -> {ok,REST};
	ER -> {error,ER}
    end.

%%-------------------------------------------------------------------------
%% Verify ABA PVV
%%-------------------------------------------------------------------------
-spec build_cmd_DC(LMK,PVK,TPK,PAN,PVV,PINBLK_HEX,PINBLK_TYPE) -> {binary(),fun()} when
      LMK::lmk_type(),
      PVK::binary() | string(),
      TPK::binary() | string(),
      PAN::binary() | string(),
      PVV::binary() | string(),
      PINBLK_HEX::hex_string(),
      PINBLK_TYPE::integer().
build_cmd_DC(LMK,PVK,TPK,PAN,PVV,PINBLK_HEX,PINBLK_TYPE)->
    LMK1 = utils:lmk_to_binary(LMK),
    PVK1 = utils:to_binary(PVK),
    TPK1 = utils:to_binary(TPK),
    PINBLK1 = utils:to_binary(PINBLK_HEX),
    PVV2 = utils:to_binary(PVV),

    PAN2 = extract_pan(PAN),
    PINBLK_CD1 = utils:format_integer(PINBLK_TYPE,2),

    CMD = <<"DC",
	    TPK1/binary,
	    PVK1/binary, % PVK pair
	    PINBLK1/binary,
	    PINBLK_CD1/binary,
	    PAN2/binary,
	    "3", % PVKI
	    PVV2/binary,
	    "%",
	    LMK1/binary>>,
    {CMD,fun(R)-> parse_DC_response(LMK,R) end}.

-spec parse_DC_response(LMK::lmk_type(),RESP::binary())-> 
	  {ok,PVV::binary()} |
	  {error,CD::binary()}.
parse_DC_response(_LMK,RESP)->
    <<"DD",CD:2/bytes,_REST/binary>> = RESP,
    case CD of
	<<"00">> -> {ok};
	ER -> {error,ER}
    end.

test_PVV(kblk)->
    PIN="1122",
    PAN="212676479325x",
    PINBLK_TYPE=1,
    K3=cryptoxs:get_test_visa_3des(),
    PINBLK=pinblk:create(PINBLK_TYPE,PIN,PAN), % 01
    logger:debug("PINBLK_2=~p~n",[PINBLK]),
    PINBLK_ENCR=cryptoxs:encrypt(des3,ecb,K3,hex:hex_to_bin(PINBLK)),
    logger:debug("PINBLK_ENCR_2=~p~n",[PINBLK_ENCR]),
    PINBLK_HEX=hex:bin_to_hex(PINBLK_ENCR),
    logger:debug("PINBLK_HEX_2=~p~n",[PINBLK_HEX]),

    % ------------- EI ---------------------------
    CMD0=build_cmd_EI(kblk,key_mgt_only,2048),
    {ok,PUB,PRV}=execute(CMD0),
    logger:debug("EI PRV=~p~n",[PRV]),
    logger:debug("EI PUB=~p~n",[PUB]),

    {ok,#'HsmPubKey'{modulus=MOD,exponent=EXP}} =
	'HsmPubKeySpec':decode('HsmPubKey',hex:hex_to_bin(PUB)),

    PKR= #'RSAPublicKey'{modulus=MOD,publicExponent=EXP},
    logger:debug("EI PUB/PKR=~p~n",[PKR]),
    K3B = hex:hex_to_bin(lists:flatten(tuple_to_list(K3))),
    ENCR_KEY=public_key:encrypt_public(K3B,PKR,[{rsa_padding,rsa_pkcs1_padding}]),

    % ------------ GI ----------------------------
    CMD1=build_cmd_GI(kblk,tpk,des3,ENCR_KEY,PRV),
    {ok,TPK,KCV}=execute(CMD1),
    logger:debug("GI TPK=[~p],KCV=[~p]~n",[TPK,KCV]),

    % ------------ PBLK->PIN/LMK ------------------
    CMD2=build_cmd_JC(kblk,TPK,PINBLK_HEX,PINBLK_TYPE,PAN),
    {ok,PINLMK}=execute(CMD2),
    logger:debug("JC PINLMK=[~p]~n",[PINLMK]),

    CMD3=build_cmd_A0(kblk,pvk_visa,des2),
    {ok,PVK,_}=execute(CMD3),
    logger:debug("PVK=[~p]~n",[PVK]),

    CMD4=build_cmd_DG(kblk,PVK,PAN,PINLMK),
    {ok,PVV}=execute(CMD4),
    logger:debug("DG PVV=[~p]~n",[PVV]),

    % ------------ DC ----------------------------
    CMD5=build_cmd_DC(kblk,PVK,TPK,PAN,PVV,PINBLK_HEX,01),
    {ok}=execute(CMD5),
    logger:debug("DC Sucess~n",[]).
    
%%-------------------------------------------------------------------------
-spec build_cmd_N0(LMK,LEN)-> {binary(),fun()} when
      LMK::kblk|variant,
      LEN::integer().
build_cmd_N0(LMK,LEN) ->
    LMK1 = utils:lmk_to_binary(LMK),
    LEN1 = utils:format_integer(LEN,3),
    CMD = <<"N0",
	    LEN1/binary,
	    "%",
	    LMK1/binary
	  >>,
    {CMD,fun(R)-> parse_N0_response(LMK,R) end}.

-spec parse_N0_response(LMK,RESPONSE) -> {ok,RAND::integer()} | {error, CD::string()} when
      LMK::lmk_type(),
      RESPONSE::binary().
parse_N0_response(_LMK,RESPONSE)->
    <<"N1",CD:2/bytes,REST/binary>> = RESPONSE,
    case CD of
	<<"00">> ->
	    {ok,binary:decode_unsigned(REST)};
	CD -> {error,binary_to_list(CD)}
    end.
test_N0() ->
    CMD=build_cmd_N0(kblk,3),
    {ok,RAND}=execute(CMD),
    logger:debug("N0 RAND=[~p]~n",[RAND]).
    
%%------------------------------------------------------------------------
-spec build_cmd_PM(LMK,ACTION,{PAN,EXPDT,DCVV},{TWU,MKDCVV})-> {binary(),fun()} when
      LMK::lmk_type(),
      ACTION::generate|verify,
      PAN::string(),
      EXPDT::string(),
      DCVV::string(),
      TWU::integer(),
      MKDCVV::string().
build_cmd_PM(LMK,ACTION,{PAN,EXPDT,DCVV},{TWU,MKDCVV})->
    LMK1 = utils:lmk_to_binary(LMK),
    SchemeID = <<"5">>,
    Version = <<"0">>,
    TWU1 = erlang:list_to_binary(lists:flatten(
				   io_lib:format("~6..0s",[integer_to_list(TWU,10)]))),

    %% %% TODO -> migracja na erlang:timestamp(), :now() jest DEPPRECATED
    %% {Mega,Sec0,_}=erlang:now(),
    %% Sec = Mega*1000000+Sec0,
    %% TIME=erlang:list_to_binary(lists:flatten(
    %% 				 io_lib:format("~8..0s",[integer_to_list(Sec,16)]))),

    Julian = erlang:system_time(second),
    TIME=erlang:list_to_binary(lists:flatten(
				 io_lib:format("~8..0s",[integer_to_list(Julian,16)]))),
    
    PAN1 = utils:to_binary(PAN),
    EXPDT1 = utils:to_binary(EXPDT),
    DCVV1 = utils:to_binary(DCVV),
    MKDCVV1 = utils:to_binary(MKDCVV),

    CMD = <<"PM",
	    SchemeID/binary,
	    Version/binary,
	    MKDCVV1/binary,
	    PAN1/binary,
	    ";",
	    EXPDT1/binary,
	    TWU1/binary,
	    TIME/binary,
	    DCVV1/binary,
	    "%",
	    LMK1/binary>>,
    {CMD,fun(R)-> parse_PM_response(LMK,ACTION,R) end}.

-spec parse_PM_response(LMK,ACTION,RESP)-> {ok} | {ok,DCVV} | {error,ER} when
      LMK::lmk_type(),
      ACTION::generate|verify,
      RESP::binary(),
      DCVV::string(),
      ER::string().
parse_PM_response(_LMK,ACTION,RESP)->
    <<"PN",CD:2/bytes,REST/binary>> = RESP,
    case {CD,ACTION} of
	{<<"00">>,verify} -> {ok};
	{<<"01">>,generate} -> {ok,binary_to_list(REST)};
	{_,_} -> {error,binary_to_list(CD)}
    end.     

test_PM()->
    CMD0=build_cmd_PM(kblk,generate,{"4455660000000000","1905","111"},{?PM_TWU,?PM_MKDCVV}),
    {ok,DCVV}=execute(CMD0),
    logger:info("PM done. DCVV=~p",[hex:bin_to_hex(DCVV)]),

    CMD1=build_cmd_PM(kblk,verify,{"4455660000000000","1905",DCVV},{?PM_TWU,?PM_MKDCVV}),
    {ok}=execute(CMD1),
    logger:info("PM done. sukces").

%%------------------------------------------------------------------------------------------
check_hsm()->
    check_hsm(tcp,variant).

check_hsm(udp)->
    check_hsm(udp,variant).

check_hsm(Transport,LMK) ->
    CMD = build_cmd_N0(LMK,3),
    execute(Transport,CMD).

%%--------------------------------------------------------------------------
-spec execute(Transport::tcp|udp, {Cmd::binary(),RespProc::fun()}) ->
	  term() | %% as returned by "parse_XX_response"
	  {error,Err::string()}.
execute(Transport,{Cmd,RespProc})->
    case hsm:exec(Transport,Cmd) of
	{ok,Resp} ->
	    RespProc(Resp);
	{error,Error}=ER ->
	    logger:error("HSM returned error=~p",[Error]),
	    ER
    end.

-spec execute(Transport::tcp|udp, {Cmd::binary(),RespProc::fun()}, Timeout :: integer()) ->
	  term() | %% as returned by "parse_XX_response"
	  {error,Err::string()}.
execute(Transport,{Cmd,RespProc}, Timeout)->
    case hsm:exec(Transport,Cmd,Timeout) of
	{ok,Resp} ->
	    RespProc(Resp);
	{error,Error}=ER ->
	    logger:error("HSM returned error=~p",[Error]),
	    ER
    end.
%%--------------------------------------------------------------------------
%% default transport is tcp...
execute({Cmd,RespProc})->
    execute(tcp,{Cmd,RespProc}).

