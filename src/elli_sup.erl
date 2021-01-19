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
%% Thales 9000 Communication Interface / REST Interface (Elli) Sup
%%------------------------------------------------------------------------------
%% 2018-2021
%%==============================================================================
-module(elli_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

-define(DEFAULT_REST_PORT,8087).

-ifdef(EUNIT).
-define(get_config(),config_utils:get_sysconfig(rest)).
-else.
-define(get_config(),{ok,application:get_all_env(rest)}).
-endif.

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
-spec init(Args :: term()) ->
	  {ok, {SupFlags :: supervisor:sup_flags(),
		[ChildSpec :: supervisor:child_spec()]}} |
	  ignore.
init([]) ->

    SupFlags = #{strategy => one_for_all,
		 intensity => 1,
		 period => 5},

    %% Config...
    {ok,Cfg}=?get_config(),
    logger:info("REST/Elli, Cfg=~p",[Cfg]),
    Port = config_utils:get_param(port,Cfg,?DEFAULT_REST_PORT),

    ElliChild = #{id => 'Elli-Web-Srv',
	       start => {elli, start_link, [[{callback,hsm_elli_callback},{port,Port}]]},
	       restart => permanent,
	       shutdown => 5000,
	       type => worker,
	       modules => [elli]},

    {ok, {SupFlags, [ElliChild]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
