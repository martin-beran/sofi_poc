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
    test_id/3,
    prov_none/3,
    prov_id/3,
    recv_none/3,
    recv_all/3
]).

:- use_module(integrity).
:- use_module(util).

check_entity(entity{i:I, mi:MI, t:T, p:P, r:R, data:_}) :-
    check_integrity(I), check_integrity(MI),
    check_test(T), check_prov(P), check_recv(R).

check_test(T) :- check_(current_predicate(T, 3)).

check_prov(P) :- check_(current_predicate(P, 3)).

check_recv(R) :- check_(current_predicate(R, 3)).

check_subject(E) :- check_entity(E).

check_object(E) :-
    check_entity(E),
    check_(ACL = E.get(acl)),
    check_acl(ACL).

check_acl(ACL) :-
    check_(is_dict(ACL)), dict_pairs(ACL, acl, A), check_acl_list(A).

check_acl_list([]).
check_acl_list([F-A|T]) :-
    check_(atom(F)), check_acl_list2(A), check_acl_list(T).

check_acl_list2([]).
check_acl_list2([H|T]) :- check_integrity(H), check_acl_list2(T).

test_acl(I, F, ACL) :-
    check_integrity(I), check_acl(ACL), A = ACL.get(F), test_acl2(I, A).

test_acl2(I, [A|_]) :- I #>= A.
test_acl2(I, [_|T]) :- test_acl2(I, T).

acl_empty(acl{}).

acl_allow(ACL1, F, ACL2) :-
    check_acl(ACL1), integrity_min(I), ACL2 = ACL1.put([F:[I]]).

acl_deny(ACL1, F, ACL2) :- check_acl(ACL1), ACL2 = ACL1.put([F:[]]).

test_id(_R, W, W).

prov_none(_W, _R, integrity_min).

prov_id(W, _R, W).

recv_none(_R, _W, integrity_min).

recv_all(_R, _W, integrity_max).
