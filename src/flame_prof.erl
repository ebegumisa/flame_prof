%%
%%      Copyright 2020 Medical-Objects Pty Ltd.
%% 
%%      Licensed under the Apache License, Version 2.0 (the "License");
%%      you may not use this file except in compliance with the License.
%%      You may obtain a copy of the License at
%% 
%%          http://www.apache.org/licenses/LICENSE-2.0
%% 
%%      Unless required by applicable law or agreed to in writing, software
%%      distributed under the License is distributed on an "AS IS" BASIS,
%%      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%      See the License for the specific language governing permissions and
%%      limitations under the License.
%%

%%% ============================================================================
%%% @doc Erlang profiler which generates Linux perf_events output (even on
%%%      Windows/MacOS).
%%%
%%%      This is a general-purpose erlang profiler a little like OTP's `fprof',
%%%      except...
%%%
%%%      <li>It generates Linux perf_events [1] script output [2] (even on 
%%%          Win/macOS) intended to be consumed by, and analysed with, a fork of
%%%          Netflix's Flamescope [3].</li>
%%%      <li>It uses a call-stack sampling approach rather than attempting to
%%%          measure each individual call. So it does not need to use Erlang
%%%          tracing (though it may use tracing for certain optional features).
%%%          </li>
%%%      <li>It retains calling process information including process status,
%%%          memory usage, message queue lengths and garbage collection info.
%%%         </li>
%%%      <li>Provides control over output file writing (e.g. sample flush 
%%%          frequency, output file rotation).</li>
%%%      <li>It provides means to automatically select processes to be profiled
%%%          (e.g. top 100 by reductions). Automatically triggering profiling in
%%%          in a controlled manner is coming soon.</li>
%%%
%%%      [1] [https://en.wikipedia.org/wiki/Perf_(Linux)]<br />
%%%      [2] [https://linux.die.net/man/1/perf-script]<br />
%%%      [3] [https://github.com/ebegumisa/flamescope]<br />
%%% @end
%%% ============================================================================
-module(flame_prof).

%%% -- Public Control --
-export([start/0, start/1, start/2,
         start_link/0, start_link/1, start_link/2,
         stop/0, stop/1, stop/2]).

%%% -- Public Interface --
-export([apply/1, apply/2,
         profile_start/0, profile_start/1,
         profile_stop/0]).
-type process_status_t() ::
        exiting | garbage_collecting | waiting | running | runnable | suspended.
-type viral_mode_t() ::
        true | false | spawn | spawn_and_send | send | self_only.
-type process_opts_t() ::
        #{viral => undefined | viral_mode_t(),
          status => undefined | all | process_status_t()}.
-type start_opts_t() ::
        #{basename => undefined | file:filename(),
          flatten_recursive => undefined | boolean(),
          sample_interval => undefined | pos_integer(),
          flush_interval => undefined | pos_integer(),
          flush_close_max => undefined | infinity | pos_integer(),
          files_max => undefined | infinity | pos_integer(),
          auto_select =>
            undefined
            | {top,ProcessCount :: pos_integer()}
            | {top,ProcessCount :: pos_integer(),Interval :: pos_integer()},
          auto_process_opts => process_opts_t()}.
-export_type([start_opts_t/0,
              process_status_t/0, viral_mode_t/0,
              process_opts_t/0]).

%%% -- Private Interface  --
-export([sampler/3]).
-export([system_continue/3, system_terminate/4, system_get_state/1]).

-type perf_counter_t() :: integer().
-type millisecs_t() :: non_neg_integer().
-type stack_initial_item_t() ::
        {Mod :: module(), Func :: atom(), Arity :: non_neg_integer()}.
-type stack_item_t() ::
        {Mod :: module(), Func :: atom(), Arity :: non_neg_integer(),
         [{file,string()} | {line,non_neg_integer()}]}.
-type stack_t() :: [stack_initial_item_t() | stack_item_t()].
-type stacks_t() :: #{pid() => stack_t()}.
-type process_metrics_t() ::
        [{atom(),pos_integer()} | {atom(),[{atom(),pos_integer()}]}].
-type process_metrics_delta_t() ::
        [{atom(),pos_integer(),integer()} |
         {atom(),[{atom(),pos_integer(),integer()}]}].
-type processes_t() ::
        #{pid() =>
            {StatusFilter :: all | process_status_t(),
             Metrics :: undefined | process_metrics_t()}}.
-type process_grp_t() :: pos_integer().
-type sample_t() :: {TS :: perf_counter_t(),
                     MetricsDelta :: process_metrics_delta_t(),
                     Stacks :: stacks_t(),
                     InitialCalls :: [stack_initial_item_t()]}.
-type reg_names_t() :: #{pid() => 0 | atom()}.

%%% -- Private Preprocess --
-define(DFLT_SAMPLE_INTERVAL, 9).     % 99 hz (combined for all processes)
-define(DFLT_FLUSH_INTERVAL,  15000). % 15 secs
-define(DFLT_FLUSH_CLOSE_MAX, 8).     % 2 mins worth
-define(DFLT_FILES_MAX, 15).          % 30 mins worth (30 / 2).
-define(DFLT_TOP_INTERVAL, 10000).    % 10 secs (etop's default).

-define(DELAY_SIZE,     10*1024*1024).   % 10 MiB
-define(DELAY_INTERVAL, 5*60*1000).      % 5 mins

-define(BACKTRACE_DEPTH, 255).

-record(st_r,
    {flush_tout :: perf_counter_t(),
     flush_close_max :: non_neg_integer(),
     flush_count=0 :: non_neg_integer(),
     sample_tout :: perf_counter_t(),
     sample_tout_ms :: millisecs_t(),
     prev_sample_ts :: undefined | perf_counter_t(),
     prev_flush_ts :: undefined | perf_counter_t(),
     ps_grps=#{} :: #{process_grp_t() => processes_t()},
     expl_ps=#{} :: #{pid() => process_grp_t()},
     auto_ps=#{} :: #{pid() => process_grp_t()},
     auto_ts :: undefined | perf_counter_t(),
     reg_names=#{} :: reg_names_t(),
     samples=[] :: [sample_t()],
     file :: undefined | file:io_device(),
     paths :: undefined | {non_neg_integer(),queue:queue(file:filename())},
     auto_selector :: undefined | pid(),
     auto_status :: process_status_t(),
     auto_traceopts :: [set_on_spawn|send]}).

-include_lib("kernel/include/file.hrl").

%%% -- Control -----------------------------------------------------------------

-spec start() -> pid() | {error,{already_started,pid()}}.
        
start() ->
    start(#{}).
    

-spec start(start_opts_t() | non_neg_integer() | infinity) ->
        pid() | {error,{already_started,pid()}}.

start(#{}=Opts) ->
    do_start(false, Opts, 5000);
start(TOut) ->
    do_start(false, #{}, TOut).


-spec start(start_opts_t(), non_neg_integer() | infinity) ->
    pid() | {error,{already_started,pid()}}.

start(#{}=Opts, TOut) ->
    do_start(false, Opts, TOut).
    

-spec start_link() -> pid() | {error,{already_started,pid()}}.

start_link() ->
    start_link(#{}).


-spec start_link(start_opts_t() | non_neg_integer() | infinity) ->
        pid() | {error,{already_started,pid()}}.

start_link(#{}=Opts) ->
    do_start(true, Opts, 5000);
start_link(TOut) ->
    do_start(true, #{}, TOut).
    

-spec start_link(start_opts_t(), non_neg_integer() | infinity) ->
    pid() | {error,{already_started,pid()}}.

start_link(#{}=Opts, TOut) ->
    do_start(true, Opts, TOut).


do_start(ShouldLnk, #{}=Opts, TOut)
        when is_boolean(ShouldLnk), is_integer(TOut) orelse TOut=:=infinity
    ->
    A = [self(),chk_start_opts(Opts),TOut],
    case whereis(?MODULE) of
        undefined when ShouldLnk ->
            proc_lib:start_link(?MODULE, sampler, A, TOut, [{priority,max}]);
        undefined ->
            proc_lib:start(?MODULE, sampler, A, TOut, [{priority,max}]);
        P ->
            {error,{already_started,P}}
    end.
    

stop() ->
    stop(?MODULE).

stop(TOut) when is_integer(TOut); TOut=:=infinity ->
    stop(?MODULE, TOut);
stop(P) ->
    stop(P, 5000).
    
stop(P, TOut) when is_pid(P) orelse is_atom(P),
                   is_integer(TOut) orelse TOut=:=infinity
    ->
    try proc_lib:stop(P, normal, TOut)
    catch exit:noproc -> ok
    end.
    
        
%%% -- Interface ---------------------------------------------------------------

-spec apply(fun(() -> term())) -> term().
%%
%% @doc Same as calling {@link apply/2} with empty profiling process options
%%      (i.e. default process options).
%% 
apply(Fn) ->
    ?MODULE:apply(Fn, #{}).


-spec apply(fun(() -> term()), process_opts_t()) -> term().
%%
%% @doc Profile the evaluation of a given function in the context of the calling
%%      process using the given profiling process options.
%%
apply(Fn, Opts) ->
    profile_start(Opts),
    try Fn()
    after profile_stop()
    end.


-spec profile_start() -> non_neg_integer().
%%
%% @doc Same as calling {@link profile_start/1} with emtpy profiling process
%%      options (i.e. default process options).
%% 
profile_start() ->
    profile_start(#{}).
    

-spec profile_start(process_opts_t()) -> non_neg_integer().
%%
%% @doc Start profiling the calling process using the given profiling process
%%      options.
%%
profile_start(Opts) ->
    profile_start1(chk_p_opts(Opts, spawn)).
    
profile_start1(#{viral:=Viral,status:=Status}) ->
    Sampler = whereis(?MODULE),
    true = is_pid(Sampler) orelse error({not_started,?MODULE}),
    ViralTraceOpts = viral_to_traceopts(Viral),
    % Notify sampler about this process by briefly tracing a single call to
    % explicit/1.
    erlang:trace_pattern({?MODULE,explicit,1}, true, [local]),
    erlang:trace(self(), true, [{tracer,Sampler},'call']),
    try Status = explicit(Status)
    after
        erlang:trace(self(), false, [all]),
        erlang:trace_pattern({?MODULE,process,1}, false, [local])
    end,
    % Now that the sampler knows to sample us, profile without tracing any
    % calls.
    erlang:system_flag(backtrace_depth, ?BACKTRACE_DEPTH),
    maybe_trace_send_on(ViralTraceOpts),
    trace_p_on(self(), Sampler, ViralTraceOpts).


-spec profile_stop() -> non_neg_integer().
    
profile_stop() ->
    trace_p_off(self()).
    
%%% -- sampler proc_lib impl --

explicit(Status) -> Status.

sampler(Parent,
        #{sample_interval:=SampleMs,flush_interval:=FlushMs,
          flush_close_max:=CloseMax,auto_select:=AutoSel,
          auto_process_opts:=#{status:=AutoStatus,viral:=AutoViral}}=Opts,
        TOut) when is_pid(Parent)
    ->
    process_flag(trap_exit, true),
    try register(?MODULE, self()) of
        true ->
            S = #st_r{sample_tout_ms=SampleMs,
                      sample_tout=pc_from_millisecs(SampleMs),
                      flush_tout=pc_from_millisecs(FlushMs),
                      flush_close_max=CloseMax,
                      paths=del_excess_files(Opts),
                      auto_status=AutoStatus,
                      auto_traceopts=viral_to_traceopts(AutoViral),
                      auto_selector=
                        case undefined=:=AutoSel 
                                orelse
                             seltor@flame_prof:start_link(
                                AutoSel, [{timeout,TOut}])
                        of
                            {ok,P} -> P;
                            true   -> undefined
                        end},
            ok = proc_lib:init_ack(Parent, {ok,self()}),
            sampler_loop(Parent, nil, S, Opts)
    catch error:badarg ->
        {error,{already_started,erlang:whereis(?MODULE)}}
    end.

sampler_loop(Parent, nil, #st_r{}=S, Opts)
        when map_size(S#st_r.expl_ps)=:=0, map_size(S#st_r.auto_ps)=:=0
    ->
    % Nothing to sample as yet, so wait here until there is.
    receive Msg -> sampler_loop(Parent, Msg, S, Opts) end;
sampler_loop(Parent, nil, #st_r{}=S0, Opts) ->
    % Figure out if it's time to sample and/or flush the stacks.
    TS = os:perf_counter(),
    S1 = sampler_maybe_sample(TS, S0, Opts),
    % Wait for more profile events, otherwise check if we need to sample roughly
    % after the sample interval.
    receive Msg -> sampler_loop(Parent, Msg, S1, Opts) 
    after S1#st_r.sample_tout_ms -> sampler_loop(Parent, nil, S1, Opts)
    end;
sampler_loop(Parent, {auto_selected,[_|_]=Ps}, #st_r{}=S, Opts) ->
    % seltor@flame_prof has sent the set of processes to automatically
    % profile. Replace the ones we have.
    TS = os:perf_counter(),
    erlang:system_flag(backtrace_depth, ?BACKTRACE_DEPTH),
    maybe_trace_send_on(S#st_r.auto_traceopts),
    sampler_loop(
        Parent, nil, sampler_ps_add_auto(Ps, S#st_r{auto_ts=TS}), Opts);
sampler_loop(Parent, {trace,P,call,{?MODULE,explicit,[Status]}},
             #st_r{}=S, Opts) 
    ->
    % Add calling process to map of processes to explicitly sample
    % (call is as result of an external call to apply/N or profile_start/N).
    sampler_loop(Parent, nil, sampler_p_add_expl(P, Status, S), Opts);
sampler_loop(Parent, {trace,_,call,_}, #st_r{}=S, Opts) ->
    sampler_loop(Parent, nil, S, Opts);
sampler_loop(Parent, {trace,_,send,_,_}, #st_r{}=S, Opts)
        when map_size(S#st_r.expl_ps)=:=0, map_size(S#st_r.auto_ps)=:=0
    ->
    trace_send_off(),
    sampler_loop(Parent, nil, S, Opts);
sampler_loop(Parent, {trace,_,send,_,{NmeOrP,Nd}}=Ev, #st_r{}=S, Opts) ->
    case Nd=:=node() andalso (is_pid(NmeOrP) orelse whereis(NmeOrP)) of
        true ->
            sampler_loop(Parent, setelement(5, Ev, NmeOrP), S, Opts);
        false ->
            sampler_loop(Parent, nil, S, Opts);
        undefined ->
            sampler_loop(Parent, nil, S, Opts);
        P when is_pid(P) ->
            sampler_loop(Parent, setelement(5, Ev, P), S, Opts)
    end;
sampler_loop(Parent, {trace,Frm,send,_,To}, #st_r{}=S0, Opts)
        when is_pid(Frm), is_pid(To)
    ->
    % Add local recipient process to map of processes to explicitly sample
    % if the sending process is being explicitly sampled (i.e. send is as result
    % of an exernal call to apply/N or profile_start/N)
    S1 = case node(To)=:=node() andalso S0#st_r.expl_ps of
            #{Frm:=ExplGrp} ->
                case S0#st_r.ps_grps of
                    #{ExplGrp:=#{Frm:=ExplStatus}} ->
                        sampler_p_add_expl(To, ExplStatus, S0);
                    #{} ->
                        local
                end;
            #{} ->
                local;
            false ->
                remote
         end,
    S2 = case S1=:=local andalso S1#st_r.auto_ps of
            #{Frm:=AutoGrp} ->
                % Add local recipient process to map of processes to auto sample
                % if sending process is being auto sampled.
                case S1#st_r.ps_grps of
                    #{AutoGrp:=#{Frm:=AutoStatus}} ->
                        sampler_p_add_auto(To, AutoStatus, S1);
                    #{} ->
                        S0
                end;
            #{} ->
                S1;
            false ->
                S0
         end,
    sampler_loop(Parent, nil, S2, Opts);
sampler_loop(Parent, {trace,Frm,send,_,_}=Ev, #st_r{}=S, Opts) when is_atom(Frm)
    ->
    case whereis(Frm) of
        undefined ->
            sampler_loop(Parent, nil, S, Opts);
        P ->
            sampler_loop(Parent, setelement(2, Ev, P), S, Opts)
    end;
sampler_loop(Parent, {trace,_,send,_,To}=Ev, #st_r{}=S, Opts) when is_atom(To) ->
    case whereis(To) of
        undefined ->
            sampler_loop(Parent, nil, S, Opts);
        P ->
            sampler_loop(Parent, setelement(5, Ev, P), S, Opts)
    end;
sampler_loop(Parent, {trace,_,send,_,To}, #st_r{}=S, Opts) when is_port(To) ->
    sampler_loop(Parent, nil, S, Opts);
sampler_loop(Parent, {trace,_,send_to_non_existing_process,_,_}, #st_r{}=S, 
             Opts)
    ->
    map_size(S#st_r.expl_ps)=:=0 andalso map_size(S#st_r.auto_ps)=:=0 andalso
        trace_send_off(),
    sampler_loop(Parent, nil, S, Opts);
sampler_loop(Parent, {trace,P,exit,_}, #st_r{}=S, Opts) ->
    sampler_loop(Parent, nil, sampler_p_remove(P, S), Opts);
sampler_loop(Parent, {trace,P,register,Nme}, #st_r{reg_names=Nmes}=S, Opts) ->
    sampler_loop(Parent, nil, S#st_r{reg_names=Nmes#{P=>Nme}}, Opts);
sampler_loop(Parent, {trace,P,unregister,_}, #st_r{reg_names=Nmes}=S, Opts) ->
    sampler_loop(Parent, nil, S#st_r{reg_names=Nmes#{P=>0}}, Opts);
sampler_loop(Parent, {trace,_,spawn,_,_}, #st_r{}=S, Opts) ->
    sampler_loop(Parent, nil, S, Opts);
sampler_loop(Parent, {trace,_,spawned,_,_}, #st_r{}=S, Opts) ->
    sampler_loop(Parent, nil, S, Opts);
sampler_loop(Parent, {trace,_,link,_}, #st_r{}=S, Opts) ->
    sampler_loop(Parent, nil, S, Opts);
sampler_loop(Parent, {trace,_,unlink,_}, #st_r{}=S, Opts) ->
    sampler_loop(Parent, nil, S, Opts);
sampler_loop(Parent, {trace,_,getting_linked,_}, #st_r{}=S, Opts) ->
    sampler_loop(Parent, nil, S, Opts);
sampler_loop(Parent, {trace,_,getting_unlinked,_}, #st_r{}=S, Opts) ->
    sampler_loop(Parent, nil, S, Opts);
sampler_loop(Parent, Other, #st_r{auto_selector=AutoSeltor}=S, Opts) ->
    % Handle 'EXIT' messages, sys messages and unexpected trace events.
    case Other of
        {'EXIT',Parent,Reason} ->
            system_terminate(Reason, Parent, undefined, {S,Opts});
        {'EXIT',AutoSeltor,Reason} ->
            case is_terminate_crash(Reason) of
                true  -> system_terminate(Reason, Parent, undefined, {S,Opts});
                false -> sampler_loop(Parent, nil, S, Opts)
            end;
        {system,Frm,Rq} ->
            sys:handle_system_msg(
                Rq, Frm, Parent, ?MODULE, undefined, {S,Opts});
        Other when Other=/=nil ->
            system_terminate({unexpected,Other}, Parent, undefined, {S,Opts})
    end.

sampler_p_remove(P, #st_r{ps_grps=PsGrps}=S) ->
    case S#st_r.expl_ps of
        #{P:=Grp} ->
            #{Grp:=Ps} = PsGrps,
            false = maps:is_key(P, S#st_r.auto_ps),
            S#st_r{ps_grps=PsGrps#{Grp:=maps:remove(P, Ps)},
                   expl_ps=maps:remove(P, S#st_r.expl_ps),
                   reg_names=maps:remove(P, S#st_r.reg_names)};
        #{} ->
            case S#st_r.auto_ps of
                #{P:=Grp} ->
                    #{Grp:=Ps} = PsGrps,
                    false = maps:is_key(P, S#st_r.expl_ps),
                    S#st_r{ps_grps=PsGrps#{Grp:=maps:remove(P, Ps)},
                           reg_names=maps:remove(P, S#st_r.reg_names)};
                #{} ->
                    false = maps:is_key(P, S#st_r.reg_names),
                    S
            end
     end.

sampler_p_add_grp(P, Status, PsGrps, Ps) ->
    Grp = case maps:is_key(P, Ps) of
              true -> maps:get(P, Ps);
              false -> rand:uniform(11)
          end,
    {case PsGrps of
        #{Grp:=#{P:=X}=PsGrp} ->
            {_,Metrics} = X,
            PsGrps#{Grp:=PsGrp#{P=>{Status,Metrics}}};
        #{Grp:=PsGrp} ->
            PsGrps#{Grp:=PsGrp#{P=>{Status,undefined}}};
        #{} ->
            PsGrps#{Grp=>#{P=>{Status,undefined}}}
     end,
     Ps#{P=>Grp}}.
                        
sampler_p_add_expl(P, Status, S) ->
    {PsGrps,ExplPs} =
        sampler_p_add_grp(P, Status, S#st_r.ps_grps, S#st_r.expl_ps),
    S#st_r{ps_grps=PsGrps,
           expl_ps=ExplPs,
           auto_ps=maps:remove(P, S#st_r.auto_ps)}.

sampler_p_add_auto(P, Status, S) ->
    case maps:is_key(P, S#st_r.expl_ps) of
        false ->
            {PsGrps,AutoPs} =
                sampler_p_add_grp(P, Status, S#st_r.ps_grps, S#st_r.auto_ps),
            S#st_r{ps_grps=PsGrps,auto_ps=AutoPs};
        true ->
            S
    end.

sampler_ps_add_auto(Ps, S) ->
    sampler_ps_add_auto1(Ps, S#st_r.auto_ps, [], S).
        
sampler_ps_add_auto1([H|T], OrigAutoPs, AccPs, S) ->
    case S of
        #st_r{expl_ps=#{H:=_}} ->
            sampler_ps_add_auto1(T, OrigAutoPs, AccPs, S);
        #st_r{auto_status=AutoStatus} ->
            % Ensure we're tracing proccess if it's to be virally profiled.
            S#st_r.auto_traceopts=/=[] andalso
                trace_p_on(H, self(), S#st_r.auto_traceopts),
            sampler_ps_add_auto1(
                T, OrigAutoPs, [H|AccPs], sampler_p_add_auto(H, AutoStatus, S))
    end;
sampler_ps_add_auto1([], #{}=OrigAutoPs, [_|_]=AccPs, S0) ->
    if
        map_size(OrigAutoPs)=:=0 ->
            #st_r{}=S0;
        true ->
            % Stop profiling processes that were, but are no longer, in auto
            % profiled set.
            maps:fold(
                fun(P, _, S1) ->
                    S0#st_r.auto_traceopts=/=[] andalso
                        trace_p_off(P), % Stop tracing virally profiled process
                    sampler_p_remove(P, S1)
                end, S0, maps:without(AccPs, OrigAutoPs))
    end;
sampler_ps_add_auto1([], #{}, [], S) ->
    S.
        
sampler_maybe_sample(TS, #st_r{prev_flush_ts=undefined}=S, _) ->
    % First loop 
    S#st_r{prev_sample_ts=TS,prev_flush_ts=TS};
sampler_maybe_sample(TS, S, Opts) ->
    if
        TS - S#st_r.prev_flush_ts >= S#st_r.flush_tout ->
            % Sample once more, flush all samples then possibly close.
            FileS =
                if
                    S#st_r.file=:=undefined ->
                        TS - S#st_r.prev_flush_ts;
                    S#st_r.flush_count >= S#st_r.flush_close_max ->
                        close;
                    true ->
                        opened
                end,
            flush_samples(
                FileS,
                sampler_maybe_sample1(
                    TS, S#st_r{prev_sample_ts=TS,prev_flush_ts=TS}),
                Opts);
        TS - S#st_r.prev_sample_ts >= S#st_r.sample_tout ->
            % Sample and accumulate
            sampler_maybe_sample1(TS, S#st_r{prev_sample_ts=TS});
        true ->
            S
    end.

sampler_maybe_sample1(TS, #st_r{ps_grps=PsGrps}=S) ->
    Grp = rand:uniform(11),
    case PsGrps of
        #{Grp:=Ps0} ->
            case maps:fold(fun sample_p/3, {undefined,Ps0}, Ps0) of
                {#{}=Stks,#{}=Ps1} ->
                    Samples = [{TS,Stks}|S#st_r.samples],
                    S#st_r{samples=Samples,ps_grps=PsGrps#{Grp:=Ps1}};
                {undefined,_} ->
                    S
            end;
        #{} -> 
            S
    end.
    
system_continue(Parent, _, {S,Opts}) ->
    sampler_loop(Parent, nil, S, Opts).

system_get_state({S,Opts}) ->
    {ok,{{'$hidden',erts_debug:size(S)},Opts}}.
    
system_terminate(Reason, _, _, {S,Opts}) ->
    try flush_samples(close, S, Opts)
    after trace_send_off()
    end,
    exit(Reason).
               
%%% -- Helpers -----------------------------------------------------------------

chk_start_opts(#{}=Opts0) ->
    Opts1 = 
        lists:foldl(
            fun(K, Acc) ->
                Acc#{K=>chk_start_opt(K, maps:get(K, Acc, undefined))}
            end, Opts0, [basename,sample_interval,flush_interval,
                         flush_close_max,flatten_recursive,files_max,
                         auto_select,auto_process_opts]),
    #{flush_interval:=FlushMs,sample_interval:=SampleMs} = Opts1,
    (FlushMs - 1000) < SampleMs andalso error({badarg,flush_interval}),
    Opts1.
    
chk_start_opt(basename, V) when is_list(V); is_binary(V) ->
    V;
chk_start_opt(flatten_recursive, V) when is_boolean(V) ->
    V;
chk_start_opt(sample_interval, V) when is_integer(V), V>0 ->
    V;
chk_start_opt(flush_interval, V) when is_integer(V), V>0 ->
    V;
chk_start_opt(flush_close_max, V) when is_integer(V), V>=0 ->
    V;
chk_start_opt(flush_close_max, infinity) ->
    0;
chk_start_opt(files_max, infinity) ->
    infinity;
chk_start_opt(files_max, V) when is_integer(V), V>0 ->
    V;
chk_start_opt(auto_select, {top,0}) ->
    undefined;
chk_start_opt(auto_select, {top,0,Ival}) when is_integer(Ival), Ival>0 ->
    undefined;
chk_start_opt(auto_select, {top,N}) ->
    chk_start_opt(auto_select, {top,N,?DFLT_TOP_INTERVAL});
chk_start_opt(auto_select, {top,N,Ival}=V)
        when is_integer(N), N>0, is_integer(Ival), Ival>0
    ->
    V;
chk_start_opt(auto_process_opts, undefined) ->
    chk_start_opt(auto_process_opts, #{});
chk_start_opt(auto_process_opts, V) ->
    chk_p_opts(V, self_only);
                % ^^^ Default for auto sampled processes as opposed to 'spawn'
                %     which is the default for explicitly sampled processes.
    
chk_start_opt(K, undefined) ->
    dflt_start_opt(K);
chk_start_opt(K, V) when is_boolean(V) ->
    error({badarg,{K,V}}).
    
dflt_start_opt(basename) ->
    {home,Home} = lists:keyfind(home, 1, init:get_arguments()),
    filename:join(Home, ?MODULE);
dflt_start_opt(flatten_recursive) ->
    true;
dflt_start_opt(sample_interval) ->
    ?DFLT_SAMPLE_INTERVAL;
dflt_start_opt(flush_interval) ->
    ?DFLT_FLUSH_INTERVAL;
dflt_start_opt(flush_close_max) ->
    ?DFLT_FLUSH_CLOSE_MAX;
dflt_start_opt(files_max) ->
    ?DFLT_FILES_MAX;
dflt_start_opt(auto_select) ->
    undefined.

chk_p_opts(#{}=Opts, DfltViral) ->
    lists:foldl(
        fun
            (viral, Acc) ->
                case chk_p_opt(viral, maps:get(viral, Acc, undefined)) of
                    undefined ->
                        Acc#{viral=>DfltViral};
                    V ->
                        Acc#{viral=>V}
                end;
            (K, Acc) ->
                Acc#{K=>chk_p_opt(K, maps:get(K, Acc, undefined))}
        end, Opts, [viral,status]).
                        
chk_p_opt(viral, true) ->
    spawn_and_send;
chk_p_opt(viral, false) ->
    self_only;
chk_p_opt(viral, V)
        when V=:=spawn; V=:=spawn_and_send; V=:=send; V=:=self_only
    ->
    V;
chk_p_opt(status, V)
        when V=:=all; V=:=exiting; V=:=garbage_collecting; V=:=waiting;
             V=:=running; V=:=runnable; V=:=suspended
    ->
    V;
chk_p_opt(viral, undefined) ->
    undefined; % Intentional. See chk_p_opts/2.
chk_p_opt(status, undefined) ->
    all;
chk_p_opt(K, V) ->
    error({badarg,{K,V}}).

viral_to_traceopts(self_only) ->
    [];
viral_to_traceopts(spawn) ->
    [set_on_spawn];
viral_to_traceopts(spawn_and_send) ->
    [send,set_on_spawn]; % NB: We rely on 'send' always being at head.
viral_to_traceopts(send) ->
    [send]. % Ditto NB above.

sample_p(P, {Filter,PrevMetrics}, {Stks,Ps}) ->
    case erlang:process_info(P, [status]) of
        [{status,Status}] when Filter=:=all; Status=:=Filter ->
            case erlang:process_info(
                    P, [current_function,current_stacktrace,initial_call,
                        dictionary,reductions,message_queue_len,
                        memory,total_heap_size,garbage_collection_info,
                        garbage_collection])
            of
                [{current_function,CurrMFA0},{current_stacktrace,Stk},
                 {initial_call,Init},{dictionary,Dict}|CurrMetrics]
                ->
                    % TODO: Confirm that this may be different from head of 
                    %       current_stacktrace. If not, remove it.
                    CurrMFA1 =
                        case CurrMFA0 of
                            undefined -> native;
                            _         -> CurrMFA0
                        end,
                    Inits =
                        case lists:keyfind('$initial_call', 1, Dict) of
                            {'$initial_call',{M,F,N}}=GenInit
                            when is_atom(M), is_atom(F), is_integer(N)
                            ->
                                [Init,GenInit];
                            _ ->
                                [Init]
                        end,
                    MetricsDelta = metrics_delta(PrevMetrics, CurrMetrics),
                    Sample = {Status,MetricsDelta,[CurrMFA1|Stk],Inits},
                    if
                        undefined=:=Stks ->
                            {#{P=>Sample},Ps#{P:={Filter,CurrMetrics}}};
                        true ->
                            {Stks#{P=>Sample},Ps#{P:={Filter,CurrMetrics}}}
                    end;
                undefined ->
                    {Stks,Ps} % TODO: Remove P for st_r.ps so we don't have to trace exits
            end;
        [{status,_}] ->
            {Stks,Ps};
        undefined ->
            {Stks,Ps} % TODO: Ditto above.
    end.

metrics_delta(undefined, [{_,[]}=PairB|TB]) ->
    [PairB|metrics_delta(undefined, TB)];
metrics_delta([{K,[]}|TA], [{K,[]}=PairB|TB]) ->
    [PairB|metrics_delta(TA, TB)];
metrics_delta(undefined, [{garbage_collection,LB}|TB]) ->
    [{garbage_collection,[{K,V,0} || {K,V} <- LB, K=:=minor_gcs]}
      |metrics_delta(undefined, TB)];
metrics_delta([{garbage_collection,LA}|TA],
                [{garbage_collection,LB}|TB])
    ->
    {_,VA} = lists:keyfind(minor_gcs, 1, LA),
    {_,VB} = lists:keyfind(minor_gcs, 1, LB),
    VDelta = if VB>VA -> VB-VA; true -> VB end,
    % NB: VB-VA ^^^ doesn't make sense if there's been one or more full sweeps 
    %     between samples [1]. If VB<VA, then we're sure there's been a full
    %     sweep, and we handle it above by taking VB as the delta (ignoring
    %     the case where there have been many full sweeps). HOWEVER...
    % FIXME: If VA>VB, we need to somehow find detect if there's been a full 
    %        sweep and similarly take VB as the delta. This case we're currently
    %        not handling.
    % [1] https://github.com/erlang/otp/blob/de00be8f6723dededcbcff6f635394167b609367/erts/emulator/beam/erl_bif_info.c#L1812
    %     https://github.com/erlang/otp/blob/a67f636bcf14dd5eebea9b1bf1e7b89b38895b22/erts/emulator/beam/erl_gc.c#L1855
    [{garbage_collection,[{minor_gcs,VB,VDelta}]}|metrics_delta(TA, TB)];
metrics_delta(undefined, [{garbage_collection_info,LB}|TB]) ->
    [{garbage_collection_info,[{K,VB,0} || {K,VB} <- LB]}
     |metrics_delta(undefined, TB)];
metrics_delta([{garbage_collection_info,LA}|TA],
              [{garbage_collection_info,LB}|TB])
    ->
    [{garbage_collection_info,
      fun
        Delta([{K,VA}|TAInner], [{K,VB}|TBInner]) ->
            [{K,VB,VB-VA}|Delta(TAInner, TBInner)];
        Delta([], []) ->
            []
      end(LA, LB)} | metrics_delta(TA, TB)];
metrics_delta(undefined, [{reductions,VB}|TB]) ->
    [{reductions,VB,1}|metrics_delta(undefined, TB)];
metrics_delta(undefined, [{K,VB}|TB]) ->
    [{K,VB,0}|metrics_delta(undefined, TB)];
metrics_delta([{reductions,VA}|TA], [{reductions,VB}|TB]) ->
    [{reductions,VB,case VB-VA of X when X>=0 -> X+1; X -> -X end}
                               % XXX: Negative does happen ^
                               %      (maybe due to a scheduler race?)
     |metrics_delta(TA, TB)];
metrics_delta([{K,VA}|TA], [{K,VB}|TB]) ->
    [{K,VB,VB-VA}|metrics_delta(TA, TB)];
metrics_delta(undefined, []) ->    
    [];
metrics_delta([], []) ->    
    [].

flush_samples(Dur, #st_r{file=undefined,samples=[]}=S, #{}) when is_integer(Dur)
    ->
    S;
flush_samples(Dur, #st_r{file=undefined}=S, #{basename:=BseNme,
                                              files_max:=Max}=Opts)
        when is_integer(Dur)
    ->
    StartSysTm = erlang:system_time(perf_counter) - Dur,
    {{Yy,Mn,Dd},{Hh,Mm,Ss}} =
        calendar:system_time_to_local_time(StartSysTm, perf_counter),
    Leaf = io_lib:format(
                "~4..0w-~2..0w-~2..0w@~2..0w~2..0w.~2..0w.erl_perf.log",
                [Yy,Mn,Dd,Hh,Mm,Ss]),
    Path = filename:join(BseNme, Leaf),
    _ = filelib:ensure_dir(Path),
    {ok,Fd} = file:open(Path, [append,read,
                               {delayed_write,?DELAY_SIZE,?DELAY_INTERVAL}]),
    flush_samples1(Fd, S#st_r.samples, S#st_r.reg_names, Opts),
    file_flush_delayed(Fd),
    Paths =
        case S#st_r.paths of
            undefined when Max=:=undefined ->
                undefined;
            {N,Q0} when N=:=Max ->
                {{value,FPath},Q1} = queue:out(Q0),
                _ = file:delete(FPath),
                {Max,queue:in(Path, Q1)};
            {N,Q} when N>=0, N<Max ->
                {N+1,queue:in(Path, Q)}
        end,
    S#st_r{samples=[],flush_count=0,paths=Paths,file=Fd};
flush_samples(close, #st_r{file=undefined,samples=[]}=S, #{}) ->
    S;
flush_samples(close, #st_r{file=undefined,samples=[_|_]}=S, #{}=Opts) ->
    flush_samples(close, flush_samples(0, S, Opts), Opts);
flush_samples(close, #st_r{}=S, Opts) ->
    Fd = flush_samples1(S#st_r.file, S#st_r.samples, S#st_r.reg_names, Opts),
    file_flush_delayed(Fd),
    _ = file:close(Fd),
    S#st_r{samples=[],flush_count=0,file=undefined};
flush_samples(opened, #st_r{samples=[]}=S, #{}) ->
    S;
flush_samples(opened, #st_r{flush_count=FlushCount}=S, #{}=Opts) ->
    S#st_r{samples=[],flush_count=FlushCount+1,
           file=flush_samples1(
                    S#st_r.file, S#st_r.samples, S#st_r.reg_names, Opts)}.
            
flush_samples1(Fd, [], #{}, #{}) ->
    Fd;
flush_samples1(Fd, [_|_]=Samples, Nmes, #{flatten_recursive:=Flatten}) ->
    flush_samples2(Fd, lists:reverse(Samples), Nmes, Flatten).
                     % TODO: ^^^ Does the order really matter to FlameScope or
                     %           flamegraph.pl? If not, no need to bother with
                     %           reverse. Mabye a start op to retain order?
                     
flush_samples2(Fd, [], _, _) ->
    Fd;
flush_samples2(Fd, [{TS,#{}=Ps}|TSamples], Nmes, Flatten) ->
    % For format, see...
    %   https://github.com/Netflix/flamescope/blob/141238b4f69feee1d026c2156951eb78857e3953/app/perf/regexp.py#L24
    %   https://github.com/Netflix/flamescope/blob/141238b4f69feee1d026c2156951eb78857e3953/app/perf/flame_graph.py#L185
    %   https://github.com/Netflix/flamescope/blob/141238b4f69feee1d026c2156951eb78857e3953/app/common/fileutil.py#L45
    maps:fold(
        fun
            Fold(P, {Status,Metrics,Stk,[_|_]=Inits}, sample) ->
                PStr = pid_str(P),
                %Nme = case maps:get(P, Nmes, 0) of
                %        0 -> PStr;
                %        X -> atom_to_list(X)
                %      end,
                Us = pc_to_microsecs(TS),
                io:put_chars(
                    Fd, [atom_to_list(Status),$\t,PStr," [000] ",
                         microsecs_to_secs_str(Us),": cpu-clock:"]),
                flush_metrics(Fd, Metrics),
                io:put_chars(Fd, "\n"),
                Fold(P, Stk, Inits);
            Fold(P, [{M,F,N,_}]=Stk, [{M,F,N}|TNext]) ->
                Fold(P, Stk, TNext);
            Fold(P, [{M,F,N}]=Stk, [{M,F,N}|TNext]) ->
                Fold(P, Stk, TNext);
            Fold(P, [{M,F,N,_}]=Stk, [{'$initial_call',{M,F,N}}]) ->
                Fold(P, Stk, []);
            Fold(P, [{M,F,N}]=Stk, [{'$initial_call',{M,F,N}}]) ->
                Fold(P, Stk, []);
            Fold(P, [{M,F,N},{M,F,N,_}=Second|TStk], Next) ->
                Fold(P, [Second|TStk], Next);
            Fold(P, [{M,F,N}|TStk], Next) ->
                Fold(P, [{M,F,N,[]}|TStk], Next);
            Fold(P, [{M,F,N,_},{M,F,N,_}=Recursive|TStk], Next)
                    when Flatten
                ->
                Fold(P, [Recursive|TStk], Next);
            Fold(P, [{M,F,N,[{file,File},{line,Ln}|_]}|TStk], Next) ->
                io:put_chars(Fd, ["\tffffffff ",atom_to_list(M),$:,
                                  atom_to_list(F),$/,integer_to_list(N),$;,
                                  integer_to_list(Ln)," (",File,")\n"]),
                Fold(P, TStk, Next);
            Fold(P, [{M,F,N,[]}|TStk], Next) ->
                MStr = atom_to_list(M),
                io:put_chars(Fd, ["\tffffffff ",MStr,$:,atom_to_list(F),$/,
                                  integer_to_list(N)," (",MStr,".erl)\n"]),
                Fold(P, TStk, Next);
            Fold(P, [{'$initial_call',{M,F,N}}|TStk], Next) ->
                MStr = atom_to_list(M),
                io:put_chars(Fd, ["\tffffffff (",MStr,$:,atom_to_list(F),$/,
                                  integer_to_list(N),") (",MStr,".erl)\n"]),
                Fold(P, TStk, Next);
            Fold(P, [native|TStk], Next) ->
                io:put_chars(Fd, ["\tffffffff native ()\n"]),
                Fold(P, TStk, Next);
            Fold(P, [], [_|_]=Inits) ->
                Fold(P, Inits, sample);
            Fold(P, [], []) ->
                Fold(P, [], sample);
            Fold(_, [], sample) ->
                io:put_chars(Fd, "\n"),
                sample
        end, sample, Ps),
    flush_samples2(Fd, TSamples, Nmes, Flatten).

flush_metrics(Fd, [{_,[]}|T]) ->
    flush_metrics(Fd, T);
flush_metrics(Fd, [{_,[_|_]=L}|T]) ->
    io:put_chars(
        Fd, [["\tmetric_erlang_",atom_to_list(K),": ",integer_to_list(V),", ",
              integer_to_list(Delta)] || {K,V,Delta} <- L]),
    flush_metrics(Fd, T);
flush_metrics(Fd, [{K,V,Delta}|T]) ->
    io:put_chars(
        Fd, ["\tmetric_erlang_",atom_to_list(K),": ",integer_to_list(V),", ",
             integer_to_list(Delta)]),
    flush_metrics(Fd, T);
flush_metrics(_, []) ->
    ok.

%%%
%% Delete all but the lexicographically last `files_max' *.erl_perf.log files in
%% the basename dir, returning their count and paths.
%%
del_excess_files(#{files_max:=infinity}) ->
    undefined;
del_excess_files(#{files_max:=Max,basename:=BseNme}) when Max>=0 ->
    Paths = filelib:wildcard(filename:join(BseNme,"*.erl_perf.log")),
    lists:foldr(
        fun
            (Path, {N,_}=Acc) when N=:=Max ->
                _ = file:delete(Path),
                Acc;
            (Path, {N,Q}=Acc) when N<Max ->
                case file_del_if_zero(Path) of
                    true ->
                        _ = file:delete(Path),
                        Acc;
                    false ->
                        {N+1,queue:in_r(Path, Q)}
                end
        end, {0,queue:new()}, Paths).

file_del_if_zero(Path) ->
    case file:read_file_info(Path) of
        {ok,#file_info{size=0}} ->
            _ = file:delete(Path),
            true;
        {ok,#file_info{}} ->
            false;
        {error,_} ->
            false
    end.

file_flush_delayed(Fd) ->
    case file:read(Fd, 1) of
        {ok,_}          -> ok;
        eof             -> ok;
        {error,enoent}  -> ok;
        {error,enotdir} -> ok
    end.

%%%
%% Flamescope and flamegraph.pl don't like the "<" and ">" in the process name
%% and PID columns of the output file, so strip them from the erlang process
%% pid.
%%
pid_str(P) when is_pid(P) ->
    pid_str(pid_to_list(P));
pid_str([$>]) ->
    [];
pid_str([$<|T]) ->
    pid_str(T);
pid_str([C|T]) ->
    [C|pid_str(T)].

maybe_trace_send_on([send|_]) ->
    erlang:trace_pattern(send, true, []);
maybe_trace_send_on([_|_]) ->
    0;
maybe_trace_send_on([]) ->
    0.
     
trace_send_off() ->
    erlang:trace_pattern(send, false, []).
     
trace_p_on(P, Sampler, [_|_]=ViralTraceOpts) ->
    TraceOpts = [{tracer,Sampler},procs|ViralTraceOpts],
    if
        P=:=self() ->
            erlang:trace(P, true, TraceOpts);
        true ->
            try erlang:trace(P, true, TraceOpts)
            catch error:badarg ->
                case is_process_alive(P) of
                    false -> 0;
                    true  -> error(badarg)
                end
            end
    end.

trace_p_off(P) when P=:=self() ->
    erlang:trace(P, false, [all]);
trace_p_off(P) ->
    try erlang:trace(P, false, [all])
    catch error:badarg ->
        case is_process_alive(P) of
            false -> 0;
            true  -> error(badarg)
        end
    end.

pc_from_millisecs(Ms) ->
    erlang:convert_time_unit(Ms, millisecond, perf_counter).
    
pc_to_microsecs(Pc) ->
    erlang:convert_time_unit(Pc, perf_counter, microsecond).

microsecs_to_secs_str(Us) ->
    SubSecs = Us rem 1000000,
    [integer_to_list(Us div 1000000),$.|
     if
         SubSecs>99999 -> integer_to_list(SubSecs);
         SubSecs>9999 ->  [$0|integer_to_list(SubSecs)];
         SubSecs>999 ->   [$0,$0|integer_to_list(SubSecs)];
         SubSecs>99 ->    [$0,$0,$0|integer_to_list(SubSecs)];
         SubSecs>9 ->     [$0,$0,$0,$0|integer_to_list(SubSecs)];
         SubSecs>0 ->     [$0,$0,$0,$0,$0|integer_to_list(SubSecs)];
         SubSecs=:=0 ->   "000000"
     end].
     
is_terminate_crash(normal)       -> false;
is_terminate_crash(shutdown)     -> false;
is_terminate_crash({shutdown,_}) -> false;
is_terminate_crash(killed)       -> false;
is_terminate_crash(_)            -> true.
