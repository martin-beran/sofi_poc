% Entity, ACL, functions

:- module(entity, [
    is_entity/1,
    is_subject/1,
    is_object/1,
    is_acl/1,
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

is_entity(entity{i:I, mi:MI, t:T, p:P, r:R}) :-
    is_integrity(I), is_integrity(MI), is_test(T), is_prov(P), is_recv(R).

is_test(T) :- current_predicate(T, 3).

is_prov(P) :- current_predicate(P, 3).

is_recv(R) :- current_predicate(R, 3).

is_subject(E) :- is_entity(E).

is_object(E) :-
    is_entity(E),
    ACL = E.acl,
    is_acl(ACL).

is_acl(ACL) :-
    is_dict(ACL), dict_pairs(ACL, acl, A), is_acl_list(A).

is_acl_list([]).
is_acl_list([F-A|T]) :- atom(F), is_acl_list2(A), is_acl_list(T).

is_acl_list2([]).
is_acl_list2([H|T]) :- is_integrity(H), is_acl_list2(T).

test_acl(I, F, ACL) :-
    is_integrity(I), is_acl(ACL), A = ACL.get(F), test_acl2(I, A).

test_acl2(I, [A|_]) :- I #>= A.
test_acl2(I, [_|T]) :- test_acl2(I, T).

acl_empty(acl{}).

acl_allow(ACL1, F, ACL2) :-
    is_acl(ACL1), integrity_min(I), ACL2 = ACL1.put([F-[I]]).

acl_deny(ACL1, F, ACL2) :- is_acl(ACL1), ACL2 = ACL1.put([F-[]]).

test_id(_R, W, W).

prov_none(_W, _R, integrity_min).

prov_id(W, _R, W).

recv_none(_R, _W, integrity_min).

recv_all(_R, _W, integrity_max).
