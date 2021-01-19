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
%% Thales 9000 Communication Interface / Hsm Comm Server [TCP | UDP]
%%------------------------------------------------------------------------------
%% 2018-2021
%%==============================================================================
-module(hsm).

-behaviour(gen_server).

%% API for Sup
-export([start_link/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_info/2,
	 terminate/2, code_change/3, format_status/2]). %% handle_cast/2 not used.

%% API Calls
-export([exec/2,exec/3]).

-define(SERVER, ?MODULE).
-define(CALL_TIMEOUT,7000).
-define(CONN_TIMEOUT,2000).
-define(RECONNECT_OFFSET,3000).
-define(BUFF_MAX,32000).
-define(PFX_LEN,4).
-define(PFX_MOD,10000).

-define(DEFAULT_BUFF_MAX,32000).
-define(DEFAULT_HSM_ADDRESS,{10,10,104,25}).
-define(DEFAULT_HSM_PORT,1500).
-define(DEFAULT_UDP_PORT,1234).

-ifdef(EUNIT).
-define(get_config(),config_utils:get_sysconfig(hsm)).
-else.
-define(get_config(),{ok,application:get_all_env(hsm)}).
-endif.

%% role : snd | rcv
%% sup : supervisor PID
%% transport : tcp | udp
%% ip : hsm ip
%% port : hsm port
%% sck : working socket
%% snd : sender PID
%% rcv : receiver PID
%% reqs : requests ETS Tid
%% cnt : current counter modulo 10^?PFX_LEN
%% avl : predicted bytes available in HSM buffer (max is ?BUFF_MAX)
%% send : send fun (curried) (depends on transport tcp|udp)
%% close : close SCK fun (curried) (depends on transport tcp|udp)
-record(state, {role :: snd | rcv,
		sup :: pid() | undefined,
		transport :: tcp | udp,
		ip :: tuple() | undefined,
		port :: integer() | undefined,
		sck :: port() | undefined,
		snd :: pid() | undefined,
		rcv :: pid() | undefined,
		reqs :: ets:tid() | undefined,
		cnt = 0 :: integer(),
		avl :: term() | undefined,
		send :: fun((binary())-> ok | {error,term()}) | undefined,
		close :: fun(()-> ok) | undefined}).
-record(req,{id,from,len}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%% @end
%%--------------------------------------------------------------------
-spec start_link(Role,Args) -> 
	  {ok, Pid :: pid()} |
	  {error, Error :: {already_started, pid()}} |
	  {error, Error :: term()} |
	  ignore 
	      when
      Role::snd|rcv,
      Args::{Name::atom(),
	     Transport::tcp|udp,
	     Sup::pid()} | 
	    {Snd::pid(),
	     Sck::port(),
	     Reqs::map(),
	     AvRef::term(),
	     Transport::tcp|udp,
	     CloseFun::fun(()->ok)
	    }.
start_link(snd,{Name,Transport,Sup}) ->
    gen_server:start_link({local, Name}, ?MODULE, {snd,Name,Transport,Sup}, []);
start_link(rcv,{Snd,Sck,Reqs,AvlRef,Transport,CloseFun}) ->
    gen_server:start_link(?MODULE, {rcv,Snd,Sck,Reqs,AvlRef,Transport,CloseFun}, []).

%%--------------------------------------------------------------------
%% Call HSM Command
%%--------------------------------------------------------------------
-spec exec(Transport, CMD, Timeout)-> 
	  {ok,Resp::binary()} | 
	  {error, ER::string()} when 
      Transport :: tcp | udp,
      CMD :: binary(),
      Timeout :: integer().
exec(tcp,CMD,Timeout)->
    try gen_server:call('hsm-port-tcp',{execute,CMD},Timeout)
    catch _C:ER ->
	    logger:error("Error on hsm:exec/tcp, ER=~p",[ER]),
	    case ER of
		{timeout,_} ->
		    {error,timeout};
		_ ->
		    {error,ER}
	    end
    end.

%% Implicit timeout...
-spec exec(Transport, CMD)-> 
	  {ok,Resp::binary()} | 
	  {error, ER::string()} when 
      Transport :: tcp | udp,
      CMD :: binary().
exec(tcp,CMD)->
    exec(tcp,CMD,?CALL_TIMEOUT);

exec(udp,CMD)->
    try gen_server:call('hsm-port-udp',{execute,CMD},?CALL_TIMEOUT)
    catch _C:ER ->
	    logger:error("Error on hsm:exec/udp, ER=~p",[ER]),
	    {error,ER}
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%% @end
%%--------------------------------------------------------------------
-spec init(Args :: term()) -> {ok, State :: term()} |
	  {ok, State :: term(), Timeout :: timeout()} |
	  {ok, State :: term(), hibernate} |
	  {stop, Reason :: term()} |
	  ignore.
init({snd,_Name,Trans,Sup}) ->
    logger:info("Hsm init as snd/~p for SUP=~p",[Trans,Sup]),
    process_flag(trap_exit, true),
    {ok, #state{role=snd,sup=Sup,transport=Trans},0};
init({rcv,Snd,Sck,Reqs,AvlRef,Trans,CloseFun}) ->
    logger:info("Hsm init as rcv/~p with SND=~p,SCK=~p",[Trans,Snd,Sck]),
    process_flag(trap_exit, true),
    {ok, #state{role=rcv,snd=Snd,sck=Sck,reqs=Reqs,avl=AvlRef,close=CloseFun,
		transport=Trans},0}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%% @end
%%--------------------------------------------------------------------
-spec handle_call(Request :: term(), From :: {pid(), term()}, State :: term()) ->
	  {reply, Reply :: term(), NewState :: term()} |
	  {reply, Reply :: term(), NewState :: term(), Timeout :: timeout()} |
	  {reply, Reply :: term(), NewState :: term(), hibernate} |
	  {noreply, NewState :: term()} |
	  {noreply, NewState :: term(), Timeout :: timeout()} |
	  {noreply, NewState :: term(), hibernate} |
	  {stop, Reason :: term(), Reply :: term(), NewState :: term()} |
	  {stop, Reason :: term(), NewState :: term()}.
handle_call({execute,_}, _From, #state{reqs=undefined}=State) ->
    {reply,{error,not_connected},State};
handle_call({execute,CMD}, From, #state{reqs=Reqs,cnt=Cnt,avl=Avl,send=SendFun}=State) ->
    Id = utils:format_integer(Cnt+1,?PFX_LEN),
    Msg = <<Id/binary,CMD/binary>>,
    Len = byte_size(Msg),
    Req = #req{id=Id,from=From,len=Len},
    true = ets:insert(Reqs,Req),
    case counters:get(Avl,1)-Len >0 of
	true -> 
	    ok=counters:sub(Avl,1,Len),
	    %% SendFun = gen_tcp:send(Sck,Msg) | gen_udp:send(Sck,Ip,Port,Msg) ...
	    case SendFun(Msg) of
		ok -> 
		    logger:info("Hsm: snd send TCP message=[~p]",[Id]),
		    {noreply, State#state{cnt = (Cnt+1) rem ?PFX_MOD}};
		{error,Reason} ->
		    logger:error("Hsm snd: error on send, Err=~p",[Reason]),
		    {stop,Reason,State}
	    end;
	_ -> {reply,{error,buff_overflow},State}
    end.

%% handle_call(_Request, _From, State) ->
%%     Reply = ok,
%%     {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%% @end
%%--------------------------------------------------------------------
%% -spec handle_cast(Request :: term(), State :: term()) ->
%% 	  {noreply, NewState :: term()} |
%% 	  {noreply, NewState :: term(), Timeout :: timeout()} |
%% 	  {noreply, NewState :: term(), hibernate} |
%% 	  {stop, Reason :: term(), NewState :: term()}.
%% handle_cast(Request, State) ->
%%     logger:error("Hsm: cast mode unsupported, request=~p",[Request]),
%%     {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%% @end
%%--------------------------------------------------------------------
-spec handle_info(Info :: timeout() | term(), State :: term()) ->
	  {noreply, NewState :: term()} |
	  {noreply, NewState :: term(), Timeout :: timeout()} |
	  {noreply, NewState :: term(), hibernate} |
	  {stop, Reason :: normal | term(), NewState :: term()}.

handle_info(timeout, #state{role=Role,sup=Sup,transport=Trans}=State) when Role == snd ->
    logger:info("Hsm: init (timeout) info for role=snd and transport=~p",[Trans]),

    %% Config...
    {ok,Cfg}=?get_config(),
    logger:info("Hsm: for role=snd/~p, Cfg=~p",[Trans,Cfg]),
    BuffMax0 = config_utils:get_param(buff_max,Cfg,?DEFAULT_BUFF_MAX),
    BuffMax = if
		  BuffMax0 > ?DEFAULT_BUFF_MAX -> ?DEFAULT_BUFF_MAX;
		  true -> BuffMax0
	      end, 
    Ip = config_utils:get_param(ip,Cfg,?DEFAULT_HSM_ADDRESS),
    Port = config_utils:get_param(port,Cfg,?DEFAULT_HSM_PORT),
    PortUdp = config_utils:get_param(port_udp,Cfg,?DEFAULT_UDP_PORT),

    Resp = case Trans of
	       tcp ->
		   gen_tcp:connect(Ip,Port,
				   [binary,
				    {active,true},
				    {packet,2},
				    {nodelay,true}],
				   ?CONN_TIMEOUT);
	       udp ->
		   gen_udp:open(PortUdp,
				[binary,
				 {active,true}])
	   end,

    case Resp of
    	{ok,Sck} ->

	    ReqsTab = ets:new('hsm-reqs',[public,set,{keypos,2}]),
	    AvlRef=counters:new(1,[]),	    
	    counters:put(AvlRef,1,BuffMax),

	    {SendFun,CloseFun} = 
		case Trans of
		    tcp ->
			{fun(Msg)->gen_tcp:send(Sck,Msg) end,
			 fun()->gen_tcp:close(Sck) end};
		    udp ->
			logger:info("Snd: curring send to ip=~p,port=~p,Sck=~p",
				    [Ip,Port,Sck]),
			{fun(Msg)->
				 Len=byte_size(Msg),
				 Msg1 = <<Len:16/big,Msg/binary>>,
				 gen_udp:send(Sck,Ip,Port,Msg1) end,
			 fun()->gen_udp:close(Sck) end}
		end,
	    
	    ReceiverChild = #{id => void,
			      start => {hsm, start_link, 
					[rcv,
					 {self(),Sck,ReqsTab,AvlRef,Trans,CloseFun}]},
			      restart => temporary,
			      shutdown => 5000,
			      type => worker,
			      modules => [hsm]},

	    ReceiverChild1 = %% only different id...
		case Trans of
		    tcp ->
			ReceiverChild#{id => 'HsmReceiverTcp'};
		    udp ->
			ReceiverChild#{id => 'HsmReceiverUdp'}
		end,	    
	    {ok,Pid} = supervisor:start_child(Sup,ReceiverChild1),
	    _Ref=erlang:monitor(process,Pid),
	    case Trans of
		tcp ->
		    ok = gen_tcp:controlling_process(Sck,Pid);
		udp ->
		    ok = gen_udp:controlling_process(Sck,Pid)
	    end,
	    
	    {noreply, State#state{rcv=Pid,sck=Sck,reqs=ReqsTab,avl=AvlRef,
				  ip=Ip,port=Port,
				  send=SendFun,close=CloseFun}};

	{error,Reason}->
	    logger:error("Hsm Snd: error connecting HSM=~p, Err=~p",[Ip,Reason]),
	    {noreply, State, ?RECONNECT_OFFSET}
    end;

handle_info(timeout, #state{role=Role,sck=Sck,transport=Trans}=State) when Role == rcv->
    logger:info("Hsm: init (timeout) info for role=rcv and transport=~p",[Trans]),
    %% Does not depend on transport...
    ok=inet:setopts(Sck,[{active,true}]),
    {noreply, State};

handle_info({'DOWN',_Ref,process,Pid,Reason}, #state{role=Role,rcv=Pid}=State) when Role == snd->
    logger:info("Hsm: snd : got DOWN message for Pid=~p",[Pid]),
    case Reason of
	shutdown ->
	    {stop, normal, State};
	_ ->
	    {stop, rcv_down, State}
    end;

handle_info({'EXIT',Port,Reason}, #state{role=Role}=State) when Role == rcv->
    logger:info("Hsm: rcv : got EXIT message for Port=~p, reason=~p",[Port,Reason]),
    case Reason of
	shutdown ->
	    {stop, normal, State};
	_ ->
	    {stop, port_down, State}
    end;

handle_info({tcp,Sck,Response},#state{role=Role,sck=Sck,reqs=Reqs,avl=Avl}=State) when Role == rcv->
    case handle_response(Response,Reqs,Avl) of
	{ok,Id} ->
	    logger:info("Hsm: rcv got TCP response=[~p]",[Id]);
	{error,Id} ->
	    logger:error("Hsm: rcv got TCP *uncorrelated* response=[~p]",[Id])
    end,
    {noreply, State};

handle_info({udp,Sck,_Ip,_Port,Response},#state{role=Role,sck=Sck,reqs=Reqs,avl=Avl}=State) when Role == rcv->
    case handle_response(Response,Reqs,Avl) of
	{ok,Id} ->
	    logger:info("Hsm: rcv got UDP response=[~p]",[Id]);
	{error,Id} ->
	    logger:error("Hsm: rcv got UDP *uncorrelated* response=[~p]",[Id])
    end,
    {noreply, State};

handle_info({tcp_closed,Sck},#state{role=Role,sck=Sck}=State) when Role == rcv->
    logger:error("Hsm: rcv got tcp_closed. Exiting.",[]),
    {stop, tcp_closed, State};

handle_info({tcp_error,Sck,Reason},#state{role=Role,sck=Sck}=State) when Role == rcv->
    logger:error("Hsm: rcv got tcp_error, Reason=~p.",[Reason]),
    {stop, {tcp_error,Reason}, State};

handle_info(Info, #state{role=R,sck=Sck}=State) ->
    logger:error("Hsm: ~p/sck=~p unknown info=~p",[R,Sck,Info]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%% @end
%%--------------------------------------------------------------------
-spec terminate(Reason :: normal | shutdown | {shutdown, term()} | term(),
		State :: term()) -> any().
terminate(Reason, #state{role=Role,sck=Sck,close=CloseFun}=_State) when Role == rcv ->
    logger:info("Hsm: rcv, terminate called, Reason=~p, closing Sck=~p",[Reason,Sck]),
    ok=CloseFun(),
    ok;
terminate(Reason, #state{role=Role}=_State) when Role == snd ->
    logger:info("Hsm: snd, terminate called, Reason=~p",[Reason]),
    %% Sck is closed by rcv...
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%% @end
%%--------------------------------------------------------------------
-spec code_change(OldVsn :: term() | {down, term()},
		  State :: term(),
		  Extra :: term()) -> {ok, NewState :: term()} |
	  {error, Reason :: term()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called for changing the form and appearance
%% of gen_server status when it is returned from sys:get_status/1,2
%% or when it appears in termination error logs.
%% @end
%%--------------------------------------------------------------------
-spec format_status(Opt :: normal | terminate,
		    Status :: list()) -> Status :: term().
format_status(_Opt, Status) ->
    Status.

%%%===================================================================
%%% Internal functions
%%%===================================================================
-spec handle_response(Respone::binary(),Reqs::ets:tid(),Avl::term())->
	  {ok,Id::binary()} |
	  {error,Id::binary()}.
handle_response(Response,Reqs,Avl)->
    <<Id:?PFX_LEN/bytes,CmdResp/binary>> = Response,
    case ets:lookup(Reqs,Id) of
	[#req{from=From,len=Len}] ->
	    counters:add(Avl,1,Len),
	    %%logger:info("Hsm: rcv, avl after resp processed =~p",[counters:get(Avl,1)]),
	    ok=gen_server:reply(From,{ok,CmdResp}),
	    {ok,Id};
	[] ->
	    {error,Id}
    end.    

