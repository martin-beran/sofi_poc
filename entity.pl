% Entity, ACL, functions

:- module(entity, [
    check_entity/1,
    check_subject/1,
    check_object/1,
    check_acl/1,
    test_acl/3,
    acl_empty/1,
    acl_allow/3,
    acl_deny/3,
    test_id/4,
    prov_none/4,
    prov_id/4,
    recv_none/4,
    recv_all/4
]).

:- use_module(integrity).
:- use_module(util).

% check_entity(+E)
% Checks that E is a valid entity
check_entity(E) :-
    check_(entity{i:I, mi:MI, t:T, p:P, r:R, data:_} :< E),
    check_integrity(I), check_integrity(MI),
    check_test(T), check_prov(P), check_recv(R).

% check_test(+T)
% where T is T(+F, +S.i, +O.i, -I), checks that T is a valid "test" predicate
check_test(T) :- check_(current_predicate(T, 4)).

% check_prov(+P)
% where P is P(+F, +O.i, +S.i, -I), checks that P is a valid "prov" predicate
check_prov(P) :- check_(current_predicate(P, 4)).

% check_recv(+R)
% where R is R(+F, +S.i, +PI, -I), checks that R is a valid "recv" predicate
check_recv(R) :- check_(current_predicate(R, 4)).

% check_subject(+E)
% Checks that E is a valid subject entity.
check_subject(E) :- check_entity(E).

% check_object(+E)
% Checks that E is a valid object entity.
check_object(E) :-
    check_entity(E),
    check_(ACL = E.get(acl)),
    check_acl(ACL).

% check_acl(+ACL)
% Check that ACL is a valid ACL.
check_acl(ACL) :-
    check_(is_dict(ACL)), dict_pairs(ACL, acl, A), check_acl_list(A).

check_acl_list([]).
check_acl_list([H|T]) :-
    check_(H = F-A), check_(atom(F)), check_acl_list2(A), check_acl_list(T).

check_acl_list2([]).
check_acl_list2([H|T]) :- check_integrity(H), check_acl_list2(T).

test_acl(I, F, ACL) :-
    check_integrity(I), check_acl(ACL), A = ACL.get(F), test_acl2(I, A).

test_acl2(I, [A|_]) :- I #>= A.
test_acl2(I, [_|T]) :- test_acl2(I, T).

% acl_empty(?A)
% An empty ACL, not allowing any access
acl_empty(acl{}).

% acl_allow(+A1, +F, ?A2)
% Allows all to access operation F in an ACL.
acl_allow(ACL1, F, ACL2) :-
    check_acl(ACL1), integrity_min(I), ACL2 = ACL1.put([F:[I]]).

% acl_deny(+A1, +F, ?A2)
% Denies all from accessing operation F in an ACL.
acl_deny(ACL1, F, ACL2) :- check_acl(ACL1), ACL2 = ACL1.put([F:[]]).

% test_id(+F, +R, +W, ?I)
% Identity test integrity function
test_id(_F, _R, W, W).

% prov_none(+F, +W, +R, ?I)
% Integrity providing function that provides nothing
prov_none(_F, _W, _R, integrity_min).

% prov_none(+F, +W, +R, ?I)
% Integrity providing function that provides the integrity of the writer
prov_id(_F, W, _R, W).

% recv_none(+F, +R, +W, ?I)
% Integrity receiving function that accepts nothing
recv_none(_F, _R, _W, integrity_min).

% recv_all(+F, +R, +W, ?I)
% Integrity receiving function that accepts anything
recv_all(_F, _R, _W, integrity_max).
