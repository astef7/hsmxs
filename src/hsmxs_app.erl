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
%% hsmxs application : simple Thales 9000 REST Interface and command library
%%------------------------------------------------------------------------------------
%% 2018-2021
%%====================================================================================
-module(hsmxs_app).
-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    logger:set_primary_config(level,info),
    logger:set_handler_config(default,
			      formatter,
			      {logger_formatter, 
			       #{
				 legacy_header => false,
				 single_line => true,
				 template => [time," ",level,"[",pid,"]",file," ",msg,"\n"]}}),
    hsmxs_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
