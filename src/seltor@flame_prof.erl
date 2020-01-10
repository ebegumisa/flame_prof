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
%%% @doc Process selector for `flame_prof'
%%%
%%%      This process auto selects processes to be profiled by `flame_prof' on a
%%%      timer and sends them to `flame_prof'.
%%% @end
%%% ============================================================================
-module(seltor@flame_prof).

%%% -- Public Control --
-export([start_link/2]).

%%% -- Private Interface --
-behaviour(gen_server).
-export([init/1, handle_continue/2,
         handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3, format_status/2]).

-record(st_r,
    {sampler      :: pid(),
     auto_select  :: {top,ProcessCount :: pos_integer(),
                         IntervalMillisecs :: pos_integer(),
                         IntervalPc :: integer()},
     snapshot=#{} :: #{pid() => {ReductionsDelta :: integer(),
                       Reductions :: non_neg_integer()}}}).
                                 
%%% -- Public Control ----------------------------------------------------------

start_link({top,_,_}=AutoSel, SysOpts) when is_list(SysOpts) ->
    gen_server:start_link({local,?MODULE}, ?MODULE, {AutoSel,self()}, SysOpts).

%%% -- Public Interface --------------------------------------------------------

%%% -- 'gen_server' callbacks ---

init({AutoSel,Sampler}) ->
    process_flag(trap_exit, true),
    S = #st_r{sampler=Sampler,auto_select=AutoSel},
    {ok,S,{continue,init}}.

handle_continue(init, #st_r{auto_select={top,PCount,Ival}}=S) ->
    {Ps,Snap} = auto_select_top(PCount, get_reductions_new()),
    []=/=Ps andalso (S#st_r.sampler ! {auto_selected,Ps}),
    {noreply,S#st_r{snapshot=Snap},Ival}.

handle_call(never_match, _, S) ->
    {stop,never_match,S}.

handle_cast(never_match, S) ->
    {stop,never_match,S}.

handle_info(timeout, #st_r{auto_select={top,PCount,Ival}}=S) ->
    {Ps,Snap} = auto_select_top(PCount, get_reductions_delta(S#st_r.snapshot)),
    []=/=Ps andalso (S#st_r.sampler ! {auto_selected,Ps}),
    {noreply,S#st_r{snapshot=Snap},Ival};
handle_info({'EXIT',Sampler,Reason}, #st_r{sampler=Sampler}=S) ->
    {stop,Reason,S};
handle_info({'EXIT',SamplerParent,Reason}, #st_r{}=S) ->
    [_,SamplerParent] = get('$ancestors'),
    {stop,Reason,S}.

terminate(_, _) ->
    ok.
    
code_change(_, #st_r{auto_select={top,_,_},snapshot=#{}}=S, _) ->
    {ok,S}.

format_status(_, [_,#st_r{snapshot=Snap}=S]) ->
    [{data, [{"State",S#st_r{snapshot={'$hidden',erts_debug:size(Snap)}}}]}].

%%% -- Helpers -----------------------------------------------------------------

%%%
%% @doc Get the top N processes by reductions.
%%
auto_select_top(N, {RedPairs,Snap}) when is_integer(N), N>0 ->
    % See {@link observer_backend:etop_collect/1} [https://github.com/erlang/otp/blob/a67f636bcf14dd5eebea9b1bf1e7b89b38895b22/lib/runtime_tools/src/observer_backend.erl#L325]
    % See {@link observer_backend:etop_collect/2} [https://github.com/erlang/otp/blob/a67f636bcf14dd5eebea9b1bf1e7b89b38895b22/lib/runtime_tools/src/observer_backend.erl#L371]
    Decc = lists:sort( % <<< TODO: Use more efficient partial sort instead.
                fun({_,{_,_}=PairA}, {_,{_,_}=PairB}) -> PairA>PairB end,
                RedPairs),
    {auto_select_top1(N, Decc), Snap}.

auto_select_top1(0, Decc) when is_list(Decc) ->
    [];
auto_select_top1(N, [{P,{_,_}}|T]) ->
    [P|auto_select_top1(N-1, T)];
auto_select_top1(_, []) ->
    [].

get_reductions_new() ->
    do_get_reductions(processes(), #{}, #{}, [], true).

get_reductions_delta(PrevSnap) ->
    do_get_reductions(processes(), PrevSnap, #{}, [], true).
    
do_get_reductions([H|T], PrevSnap, CurrSnap, Acc, WantDelta) ->
    case process_info(H, reductions) of
        {_,CurrReds} when WantDelta ->
            CurrPair = 
                case PrevSnap of
                    #{H:=PrevPair} ->
                        {_,PrevReds} = PrevPair,
                        {CurrReds-PrevReds,CurrReds};
                    #{} ->
                        {0,CurrReds}
                end,
            do_get_reductions(
                T, maps:remove(H, PrevSnap), CurrSnap#{H=>CurrPair},
                [{H,CurrPair}|Acc], true);
        {_,CurrReds} ->
            CurrPair = {0,CurrReds},
            do_get_reductions(
                T, maps:remove(H, PrevSnap), CurrSnap#{H=>CurrPair},
                [{H,CurrPair}|Acc], false);
        undefined ->
            do_get_reductions(
                T, maps:remove(H, PrevSnap), CurrSnap, Acc, WantDelta)
    end;
do_get_reductions([], #{}, #{}=CurrSnap, Acc, _) ->
    {Acc,CurrSnap}.
    
