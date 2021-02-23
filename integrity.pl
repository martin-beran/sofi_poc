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
    is_integrity/1,
    make_integrity/3,
    integrity_min/1,
    integrity_max/1
]).

I1 #== I2 :-
    I1 = integrity{ia:IA1, ca:CA1}, I2 = integrity{ia:IA2, ca:CA2},
    ia_eq(IA1, IA2), ca_eq(CA1, CA2).

ia_eq(root, root).
ia_eq(A, B) :- eq(A, B).

ca_eq(top_secret, top_secret).
ca_eq(A, B) :- eq(A, B).

eq(A, B) :-
    is_list(A), is_list(B), list_to_ord_set(A, OA), list_to_ord_set(B, OB),
    ord_seteq(OA, OB).

I1 #\= I2 :-
    I1 = integrity{ia:_, ca:_}, I2 = integrity{ia:_, ca:_},
    \+ I1 #== I2.

I1 #=< I2 :-
    I1 = integrity{ia:IA1, ca:CA1}, I2 = integrity{ia:IA2, ca:CA2},
    ia_le(IA1, IA2), ca_le(CA1, CA2).

ia_le(_, root).
ia_le(A, B) :- le(A, B).

ca_le(top_secret, _).
ca_le(A, B) :- le(B, A).

le(A, B) :-
    is_list(A), is_list(B), list_to_ord_set(A, OA), list_to_ord_set(B, OB),
    ord_subset(OA, OB).

I1 #< I2 :- I1 #=< I2, I1 #\= I2.

I1 #>= I2 :- I2 #=< I1.

I1 #> I2 :- I2 #< I1.

I #:= I1 #+ I2 :-
    I = integrity{ia:IA, ca:CA},
    I1 = integrity{ia:IA1, ca:CA1}, I2 = integrity{ia:IA2, ca:CA2},
    ia_union(IA1, IA2, IA), ca_union(CA1, CA2, CA).
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

is_integrity(integrity{ia:IA, ca:CA}) :- ia_list(IA), ca_list(CA).

ia_list(root).
ia_list(L) :- is_list(L), list_to_ord_set(L, L).

ca_list(top_secret).
ca_list(L) :- is_list(L), list_to_ord_set(L, L).

make_integrity(IA, CA, integrity{ia:IL, ca:CL}) :-
    make_ia_list(IA, IL), make_ca_list(CA, CL).

make_ia_list(root, root).
make_ia_list(IA, IL) :- is_list(IA), list_to_ord_set(IA, IL).

make_ca_list(top_secret, top_secret).
make_ca_list(CA, CL) :- is_list(CA), list_to_ord_set(CA, CL).

integrity_min(integrity{ia:[], ca:top_secret}).

integrity_max(integrity{ia:root, ca:[]}).
