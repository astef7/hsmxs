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
%% Thales 9000 Communication Interface / Configuration utils
%%------------------------------------------------------------------------------
%% 2018-2021
%%==============================================================================

-module(config_utils).
-compile([export_all]).

-spec get_sysconfig(SYS::atom())-> {ok,Cfg0::list()}.
get_sysconfig(SYS)->
    {ok,[All]}=file:consult("config/sys.config"),
    {SYS,Cfg0}=lists:keyfind(SYS,1,All),
    {ok,Cfg0}.

-spec get_param(Key::atom(),List::list(tuple()),Defult::term())-> term().
get_param(Key,List,Default)->
    case lists:keyfind(Key,1,List) of
	{Key,Value} -> Value;
	_ -> Default
    end.
