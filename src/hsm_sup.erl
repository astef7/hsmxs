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
%% Thales 9000 Communication Interface / Hsm Comm Srv Supervisor
%%------------------------------------------------------------------------------
%% 2018-2021
%%==============================================================================
-module(hsm_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the supervisor
%% @end
%%--------------------------------------------------------------------
-spec start_link() -> {ok, Pid :: pid()} |
	  {error, {already_started, Pid :: pid()}} |
	  {error, {shutdown, term()}} |
	  {error, term()} |
	  ignore.
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a supervisor is started using supervisor:start_link/[2,3],
%% this function is called by the new process to find out about
%% restart strategy, maximum restart intensity, and child
%% specifications.
%% @end
%%--------------------------------------------------------------------
-spec init(Args :: term()) ->
	  {ok, {SupFlags :: supervisor:sup_flags(),
		[ChildSpec :: supervisor:child_spec()]}} |
	  ignore.
init([]) ->

    SupFlags = #{strategy => one_for_one,
		 intensity => 1,
		 period => 5},

    SenderChildTcp = #{id => 'HsmSenderTcp',
		       start => {hsm, start_link, [snd,{'hsm-port-tcp',
							tcp,
							self()}]},
		       restart => transient,
		       shutdown => 5000,
		       type => worker,
		       modules => [hsm]},

    SenderChildUdp = #{id => 'HsmSenderUdp',
		       start => {hsm, start_link, [snd,{'hsm-port-udp',
							udp,
							self()}]},
		       restart => transient,
		       shutdown => 5000,
		       type => worker,
		       modules => [hsm]},

    %% 
    %% Used in hsm.erl at snd initialization :
    %%
    %% ReceiverChild = #{id => 'HsmReceiver',
    %% 	       start => {hsm, start_link, [...]},
    %% 	       restart => transieng,
    %% 	       shutdown => 5000,
    %% 	       type => worker,
    %% 	       modules => [hsm]},

    {ok, {SupFlags, [SenderChildTcp,SenderChildUdp]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
