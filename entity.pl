% Entity, ACL, functions

:- module(entity, [
    is_entity/1,
    is_subject/1,
    is_object/1,
    is_acl/1,
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

is_acl([]).
is_acl([H|T]) :- is_integrity(H), is_acl(T).

test_id(_R, W, W).

prov_none(_W, _R, integrity_min).

prov_id(W, _R, W).

recv_none(_R, _W, integrity_min).

recv_all(_R, _W, integrity_max).
