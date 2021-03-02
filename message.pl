% Distributed SOFI

:- module(message, [
    check_authority/1,
    check_agent/1,
    check_message/1,
    export/5,
    export/4,
    import/3,
    empty_message/1
]).

:- use_module(entity).
:- use_module(integrity).
:- use_module(operation).
:- use_module(util).

check_authority(A) :- check_(atom(A)).

check_agent([]).
check_agent([A|T]) :- check_authority(A), check_agent(T).

check_message(M) :-
    check_(is_dict(M, message)),
    dict_pairs(M, message, P),
    check_message_pairs(P).

check_message_pairs([]).
check_message_pairs([H|T]) :-
    check_(H = A-E), check_authority(A), check_entity(E), check_(E.get(sig)),
    check_message_pairs(T).

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
    FCALL =.. [F, A, E, EE],
    (FCALL -> ES = EE.put(sig, valid), EM = EM1.put(A, ES); EM = EM1).

export_not_ag(AG, _, _, [], []).
export_not_ag(AG, F, E, [A:EE|T], [A:EE|EP]) :-
    member(A, AG), !, export_not_ag(AG, F, E, T, EP).
export_not_ag(AG, F, E, [A:E0|T], [A:ES|T1]) :-
    export_not_ag(AG, F, E, T, T1),
    FCALL =.. [F, A, E, EE],
    (
        FCALL ->
            (EE == E -> SIG = valid; SIG = invalid), ES = EE.put(sig, SIG)
        ;
            ES = E0
    ).

export(F, E, EM) :- empty_message(M), export(AG, F, E, M, EM).

import(F, M, E) :-
    check_agent(AG), check_message(M), check_(current_predicate(F/4)),
    import_a(F, M, entity{}, E).

import_a(_, [], E, E).

empty_message(message{}).
