% Integrity, confidentiality, and integrity attributes

:- module(integrity, [
    op(990, xfx, #:=),
    (#:=)/2,
    op(700, xfx, #==),
    (#==)/2,
    op(700, xfx, #\=),
    (#\=)/2,
    op(700, xfx, #=<),
    (#=<)/2,
    op(700, xfx, #<),
    (#<)/2,
    op(700, xfx, #>=),
    (#>=)/2,
    op(700, xfx, #>),
    (#>)/2,
    op(500, yfx, #+),
    op(400, yfx, #*),
    check_integrity/1,
    make_integrity/3,
    integrity_min/1,
    integrity_max/1
]).

:- use_module(util).

% Compares integrities I1 and I2 for equality.
I1 #== I2 :-
    check_integrity(I1), check_integrity(I2),
    I1 = integrity{ia:IA1, ca:CA1}, I2 = integrity{ia:IA2, ca:CA2},
    ia_eq(IA1, IA2), ca_eq(CA1, CA2).

ia_eq(root, root).
ia_eq(A, B) :- eq(A, B).

ca_eq(top_secret, top_secret).
ca_eq(A, B) :- eq(A, B).

eq(A, B) :-
    is_list(A), is_list(B), list_to_ord_set(A, OA), list_to_ord_set(B, OB),
    ord_seteq(OA, OB).

% Compares integrities I1 and I2 for inequality.
I1 #\= I2 :-
    check_integrity(I1), check_integrity(I2),
    I1 = integrity{ia:_, ca:_}, I2 = integrity{ia:_, ca:_},
    \+ I1 #== I2.

% Tests if integrity I1 is less or equal to I2.
I1 #=< I2 :-
    check_integrity(I1), check_integrity(I2),
    I1 = integrity{ia:IA1, ca:CA1}, I2 = integrity{ia:IA2, ca:CA2},
    ia_le(IA1, IA2), ca_le(CA1, CA2).

ia_le(_, root).
ia_le(A, B) :- le(A, B).

ca_le(top_secret, _).
ca_le(A, B) :- le(B, A).

le(A, B) :-
    is_list(A), is_list(B), list_to_ord_set(A, OA), list_to_ord_set(B, OB),
    ord_subset(OA, OB).

% Tests if integrity I1 is less than I2.
I1 #< I2 :- I1 #=< I2, I1 #\= I2.

% Tests if integrity I1 is greater or equal to I2.
I1 #>= I2 :- I2 #=< I1.

% Tests if integrity I1 is greater than I2.
I1 #> I2 :- I2 #< I1.

% Assigns union of integrities I1 and I2 to I.
I #:= I1 #+ I2 :-
    I = integrity{ia:IA, ca:CA},
    I1 = integrity{ia:IA1, ca:CA1}, I2 = integrity{ia:IA2, ca:CA2},
    ia_union(IA1, IA2, IA), ca_union(CA1, CA2, CA).

% Assigns intersection of integrities I1 and I2 to I.
I #:= I1 #* I2 :-
    I = integrity{ia:IA, ca:CA},
    I1 = integrity{ia:IA1, ca:CA1}, I2 = integrity{ia:IA2, ca:CA2},
    ia_intersection(IA1, IA2, IA), ca_intersection(CA1, CA2, CA).

ia_union(root, root, root).
ia_union(root, B, root) :- is_list(B).
ia_union(A, root, root) :- is_list(A).
ia_union(A, B, AB) :- a_union(A, B, AB).

ca_union(top_secret, top_secret, top_secret).
ca_union(top_secret, B, OB) :- is_list(B), list_to_ord_set(B, OB).
ca_union(A, top_secret, OA) :- is_list(A), list_to_ord_set(A, OA).
ca_union(A, B, AB) :- a_intersection(A, B, AB).

ia_intersection(root, root, root).
ia_intersection(root, B, OB) :-  is_list(B), list_to_ord_set(B, OB).
ia_intersection(A, root, OA) :- is_list(A), list_to_ord_set(A, OA).
ia_intersection(A, B, AB) :- a_intersection(A, B, AB).

ca_intersection(top_secret, top_secret, top_secret).
ca_intersection(top_secret, B, top_secret) :- is_list(B).
ca_intersection(A, top_secret, top_secret) :- is_list(A).
ca_intersection(A, B, AB) :- a_union(A, B, AB).

a_union(A, B, AB) :-
    is_list(A), is_list(B), list_to_ord_set(A, OA), list_to_ord_set(B, OB),
    ord_union(OA, OB, AB).

a_intersection(A, B, AB) :-
    is_list(A), is_list(B), list_to_ord_set(A, OA), list_to_ord_set(B, OB),
    ord_intersection(OA, OB, AB).

% check_integrity(+I)
% Checks that I is a valid integrity.
check_integrity(I) :-
    check_(I = integrity{ia:IA, ca:CA}),
    check_(ia_list(IA)), check_(ca_list(CA)).

ia_list(root).
ia_list(L) :- is_list(L), list_to_ord_set(L, L).

ca_list(top_secret).
ca_list(L) :- is_list(L), list_to_ord_set(L, L).

% make_integrity(+IA, +CA, ?I)
% Combines integrity and confidentiality attributes into an integrity.
make_integrity(IA, CA, integrity{ia:IL, ca:CL}) :-
    make_ia_list(IA, IL), make_ca_list(CA, CL).

make_ia_list(root, root).
make_ia_list(IA, IL) :- is_list(IA), list_to_ord_set(IA, IL).

make_ca_list(top_secret, top_secret).
make_ca_list(CA, CL) :- is_list(CA), list_to_ord_set(CA, CL).

% Creates a minimum integrity.
integrity_min(integrity{ia:[], ca:top_secret}).

% Creates a maximum integrity.
integrity_max(integrity{ia:root, ca:[]}).
