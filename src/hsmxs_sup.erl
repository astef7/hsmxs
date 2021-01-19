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
%% hsmxs main supervisor
%%------------------------------------------------------------------------------------
%% 2018-2021
%%====================================================================================
-module(hsmxs_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% sup_flags() = #{strategy => strategy(),         % optional
%%                 intensity => non_neg_integer(), % optional
%%                 period => pos_integer()}        % optional

%% child_spec() = #{id => child_id(),       % mandatory
%%                  start => mfargs(),      % mandatory
%%                  restart => restart(),   % optional
%%                  shutdown => shutdown(), % optional
%%                  type => worker(),       % optional
%%                  modules => modules()}   % optional

init([]) ->
    SupFlags = #{strategy => one_for_all,
                 intensity => 1,
                 period => 5},

    HsmSupChild = #{id => 'HsmPortSup',
		    start => {hsm_sup, start_link, []},
		    restart => permanent,
		    shutdown => 5000,
		    type => supervisor,
		    modules => [hsm_sup]},

    ElliWebSupChild = #{id => 'ElliWebSup',
		    start => {elli_sup, start_link, []},
		    restart => permanent,
		    shutdown => 5000,
		    type => supervisor,
		    modules => [elli_sup]},

    ChildSpecs = [HsmSupChild,ElliWebSupChild],
    {ok, {SupFlags, ChildSpecs}}.

%% internal functions
