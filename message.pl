% Distributed SOFI

:- module(message, [
    check_authority/1,
    check_agent/1,
    check_message/1,
    export/5,
    export/4,
    import/4,
    empty_message/1
]).

:- use_module(entity).
:- use_module(integrity).
:- use_module(operation).
:- use_module(util).

% check_authority(+A)
% Checks that A is a valid authority identifier.
check_authority(A) :- check_(atom(A)).

% check_agent(+AG)
% Checks that AG is a valid agent specification.
check_agent([]).
check_agent([A|T]) :- check_authority(A), check_agent(T).

% check_message(+M)
% Checks that M is a valid message
check_message(M) :-
    check_(is_dict(M, message)),
    dict_pairs(M, message, P),
    check_message_pairs(P).

check_message_pairs([]).
check_message_pairs([H|T]) :-
    check_(H = A-E), check_authority(A), check_entity(E), check_(E.get(sig)),
    check_message_pairs(T).

% export(+AG, +F, +E, +M, -EM)
% Exports entity E from agent AG using function F and a stored message M,
% yielding message EM.
export(AG, F, E, M, EM) :-
    check_agent(AG), check_entity(E), check_message(M),
    check_(current_predicate(F/4)),
    export_ag(AG, F, E, M, EA),
    dict_pairs(EA, message, P),
    export_not_ag(AG, F, E, P, EP),
    dict_pairs(EM, message, EP).

export_ag([], _, _, M, M).
export_ag([A|T], F, E, M, EM) :-
    export_ag(T, F, E, M, EM1),
    export_keys(EK),
    (
        fcall(F, A, E, EK, EE) ->
            ES = EE.put(sig, valid), EM = EM1.put(A, ES)
        ;
            EM = EM1
    ).

export_not_ag(_, _, _, [], []).
export_not_ag(AG, F, E, [A-EE|T], [A-EE|EP]) :-
    member(A, AG), !, export_not_ag(AG, F, E, T, EP).
export_not_ag(AG, F, E, [A-E0|T], [A-ES|T1]) :-
    export_not_ag(AG, F, E, T, T1),
    export_keys(EK),
    (
        fcall(F, A, E, EK, EE) ->
            (EE == E -> SIG = valid; SIG = invalid), ES = EE.put(sig, SIG)
        ;
            ES = E0
    ).

fcall(_, _, _, [], entity{}).
fcall(F, A, E, [K|T], EE) :-
    fcall(F, A, E, T, EE1),
    FCALL =.. [F, A, E, K, V], FCALL, EE = EE1.put(K, V).

export_keys([i, mi, t, p, r, data, acl]).

% export(+AG, +F, +E, -EM)
% Exports entity E from agent AG using export function F, yielding message EM.
export(AG, F, E, EM) :- empty_message(M), export(AG, F, E, M, EM).

% import(+AG, +F, +M, +E)
% Imports entity E from message M by agent AG using import function F.
import(AG, F, M, E) :-
    check_agent(AG), check_message(M), check_(current_predicate(F/4)),
    export_keys(EK), import_lists(AG, F, M, EK, E),
    
import_lists(_, _, _, [], entity{}).
import_lists(AG, F, M, [K|T], E) :-
    import_lists(AG, F, M, T, E1),
    import_list(AG, M, K, VL),
    (
        VL = [_|_] ->
            FCALL =.. [F, AG, K, VL, V], FCALL, E = E1.put(K, V)
        ;
            E = E1
    ).

import_list([], _, _, _, []).
import_list([A|AG], M, K, ILK) :-
    import_list(AG, M, K, ILK1),
    (
        E = M.get(A), del_dict(sig, E, valid, V) ->
            ILK = [A-V|ILK1]
        ;
            ILK = ILK1
    ).

% empty_message(?M)
% Creates an empty message.
empty_message(message{}).
