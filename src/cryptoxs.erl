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
%% Xtra Small Crypto Lib, for pinblock encryption and mobile application simulation
%%------------------------------------------------------------------------------------
%% 2018-2021
%%====================================================================================
-module(cryptoxs).
-compile(export_all).

get_test_visa_3des()->
    {"BCD94A49B9AE4F94","D5A1ADEAC10D023B","BCD94A49B9AE4F94"}.

get_test_aes128()->
    <<"1234567890123456">>.

get_test_aes256()->
    <<"12345678901234561234567890123456">>.
     
encrypt(des3,ecb,{_K1,_K2,_K3}=T,Text) ->
    KL = tuple_to_list(T),
    KLX = lists:map(fun(X) -> hex:hex_to_bin(X) end,KL),
    IV= <<0:64>>,
    Text1=utils:to_binary(Text),
    crypto:crypto_one_time(des_ede3_cbc,KLX,IV,Text1,true);

encrypt(aes128,ecb,K,Text)->
    IV= <<0:128>>,
    Text1=utils:to_binary(Text),
    crypto:crypto_one_time(aes_128_cbc,[K],IV,Text1,true).

encrypt(des3,cbc,{_K1,_K2,_K3}=T,IV,Text) ->
    KL = tuple_to_list(T),
    KLX = lists:map(fun(X) -> hex:hex_to_bin(X) end,KL),
    IV1=utils:to_binary(IV),
    Text1=utils:to_binary(Text),
    crypto:crypto_one_time(des_ede3_cbc,KLX,IV1,Text1,true);

encrypt(aes128,cbc,K,IV,Text)->
    IV1=utils:to_binary(IV),
    Text1=utils:to_binary(Text),
    crypto:crypto_one_time(aes_128_cbc,[K],IV1,Text1,true).

decrypt(des3,ecb,{_K1,_K2,_K3}=T,Encrypted) ->
    KL = tuple_to_list(T),
    KLX = lists:map(fun(X) -> hex:hex_to_bin(X) end,KL),
    IV= <<0:64>>,
    crypto:crypto_one_time(des_ede3_cbc,KLX,IV,Encrypted,false);

decrypt(aes128,ecb,K,Encrypted)->
    IV= <<0:128>>,
    crypto:crypto_one_time(aes_128_ecb,[K],IV,Encrypted,false).

decrypt(des3,cbc,{_K1,_K2,_K3}=T,IV,Encrypted) ->
    KL=tuple_to_list(T),
    KLX=lists:map(fun(X) -> hex:hex_to_bin(X) end,KL),
    IV1=utils:to_binary(IV),
    crypto:crypto_one_time(des_ede3_cbc,KLX,IV1,Encrypted,false);

decrypt(aes128,cbc,K,IV,Text)->
    Text1=utils:to_binary(Text),
    IV1=utils:to_binary(IV),
    crypto:crypto_one_time(aes_128_cbc,[K],IV1,Text1,false).

pad(T,LEN)->
    T1 = if is_list(T) ->
		 list_to_binary(T);
	    true -> T
	 end,
    PAD_LEN= case (byte_size(T1) rem LEN) of
		 0 -> 0;
		 N -> LEN-N
	     end,
    PAD_LEN_BITS=PAD_LEN*8,
    <<T1/binary,0:PAD_LEN_BITS>>.

unpad(X)->
    case binary:match(X,<<0>>) of
	nomatch -> X;
	{P,_} -> binary:part(X,{0,P})
    end.
