% SOFI example: World Wide Web (implementation module)

:- module(examples_www, [
    server/3,
    init_browser/0,
    browser_stat/0,
    browser_goto/3,
    browser_load/3
]).

:- use_module(sofi).

% op_type(?O, ?T)
% Defines type T (read/write/read-write) of a SOFI operation O.
op_type(www_goto, r). % Go to another page
op_type(www_load, r). % Load a resource from a server into the current page

% server(+H, +P, ?E)
% An entity (WWW resource) E available on a WWW server host H at path P.
server(H, P, E) :-
    H = 'www.company.example', P = '/',
    E = entity{
        data: server(H, P, "Company WWW presentation"),
        i: I, mi: MI, t: test_id, p: prov_id, r: recv_none, acl: A
    },
    make_integrity([H, main], [], I), make_integrity([H], [], AI),
    integrity_min(MI), make_gl_acl(MI, AI, A),
    check_entity(E).
server(H, P, E) :-
    H = 'www.company.example', P = '/public_data',
    E = entity{
        data: server(H, P, "Data that can be accessed by anyone"),
        i: I, mi: MI, t: test_id, p: prov_id, r: recv_none, acl: A
    },
    make_integrity([H], [], I), integrity_min(MI), make_gl_acl(MI, I, A),
    check_entity(E).
server(H, P, E) :-
    H = 'www.company.example', P = '/private_data',
    E = entity{
        data: server(H, P, "Data accessible from www.company.example only"),
        i: I, mi: MI, t: test_id, p: prov_id, r: recv_none, acl: A
    },
    make_integrity([H], [], I), integrity_min(MI), make_gl_acl(I, I, A),
    check_entity(E).
server(H, P, E) :-
    H = 'www.company.example', P = '/restricted',
    E = entity{
        data: server(H, P, "Accessible from browser or main page"),
        i: I, mi: MI, t: test_id, p: prov_id, r: recv_none, acl: A
    },
    make_integrity([H, main], [], I), make_integrity([browser], [], B),
    integrity_min(MI), A = acl{www_goto:[I, B], www_load:[I, B]},
    check_entity(E).
server(H, P, E) :-
    H = 'www.other.example', P = '/',
    E = entity{
        data: server(H, P, "Another WWW presentation"),
        i: I, mi: MI, t: test_id, p: prov_id, r: recv_none, acl: A
    },
    make_integrity([H, main], [], I), make_integrity([H], [], AI),
    integrity_min(MI), make_gl_acl(MI, AI, A),
    check_entity(E).

% make_acl(+I, ?A)
% Create an ACL A such that all operations require integrity I.
make_acl(I, A) :-
    findall(O, op_type(O, _), L),
    make_acl(L, I, A).

make_acl([], _, acl{}).
make_acl([O|T], I, A) :- make_acl(T, I, A0), A = A0.put(O, [I]).

% make_gl_acl(+G, +L, ?A)
% Creates ACL A such that operation 'goto' requires integrity G and operation
% 'load' requires integrity L.
make_gl_acl(G, L, acl{www_goto:[G], www_load:[L]}).

% browser(+P)
% The current state of the browser. P is the current page represented as a SOFI
% subject.
:- dynamic browser/1.

% init_browser
% Initialize the browser.
init_browser :-
    E = entity{
        data: "",
        i: I, mi: MI, t: test_id, p: prov_none, r: recv_all, acl: A
    },
    make_integrity([browser], [], I), integrity_min(MI), make_acl(MI, A),
    update_browser(E).

update_browser(P) :-
    retractall(browser(_)), assertz(browser(P)).

% browser_stat
% Displays the current state of the browser.
browser_stat :-
    browser(P),
    write_entity(P).

% browser_goto(+H, +P, -R)
% Performs a goto operation for host H and path P, returning the SOFI result R.
browser_goto(H, P, R) :- browser_op(H, P, R, www_goto).

% browser_load(+H, +P, -R)
% Performs a load operation for host H and path P, returning the SOFI result R.
browser_load(H, P, R) :- browser_op(H, P, R, www_load).

browser_op(H, P, R, F) :-
    server(H, P, ES),
    export([H], server_export, ES, M), import([browser], browser_import, M, EB),
    op_type(F, T), browser(E1),
    f_execute(E1, EB, _, F, T, E2, _, _, R),
    update_browser(E2), !.

server_export(A, E, K, V) :-
    E.data = server(A, _, _), member(K, [t, p, r, data]), V = E.K.
server_export(A, E, K, V) :-
    E.data = server(A, _, _), member(K, [i, mi]), prefix_integrity(A, E.K, V).
server_export(A, E, K, V) :-
    E.data = server(A, _, _), member(K, [acl]), prefix_acl(A, E.K, V).

prefix_integrity(A, I, P) :-
    I = integrity{ia:IA, ca:CA},
    prefix_i(A, root, IA, PIA), prefix_i(A, top_secret, CA, PCA),
    make_integrity(PIA, PCA, P).

prefix_i(A, root, root, [AR]) :- cond_concat(A, root, AR).
prefix_i(_, top_secret, top_secret, top_secret).
prefix_i(_, _, [], []).
prefix_i(A, _, [H|T], [AH|AT]) :-
    cond_concat(A, H, AH), prefix_i(A, _, T, AT).

cond_concat(P, V, PV) :-
    (V == browser; atom_chars(V, A), member(':', A)) -> PV = V;
        atomic_list_concat([P, ':', V], PV).

prefix_acl(A, ACL, PACL) :-
    dict_pairs(ACL, acl, L),
    prefix_acl_list(A, L, PL),
    dict_pairs(PACL, acl, PL).

prefix_acl_list(_, [], []).
prefix_acl_list(A, [F-H|T], [F-PH|PT]) :-
    prefix_acl_list2(A, H, PH), prefix_acl_list(A, T, PT).

prefix_acl_list2(_, [], []).
prefix_acl_list2(A, [H|T], [PH|PT]) :-
    prefix_integrity(A, H, PH), prefix_acl_list2(A, T, PT).

browser_import(_, K, [_-V|_], V) :- member(K, [t, p, r, data]).
browser_import(_, K, VL, V) :- member(K, [i, mi]), join_integrity(VL, V).
browser_import(_, K, VL, V) :- member(K, [acl]), join_acl(VL, V).

join_integrity([_-I], I).
join_integrity([_-A,_-B|T], I) :- AB #:= A #+ B, join_integrity([_-AB|T], I).

join_acl([_-A], A).
join_acl([_-X,_-Y|T], A) :-
    dict_pairs(X, acl, XL), dict_pairs(Y, acl, YL),
    pairs_keys(XL, XK), pairs_keys(YL, YK),
    list_to_ord_set(XK, XS), list_to_ord_set(YK, YS),
    ord_union(XS, YS, S),
    join_acl2(X, Y, S, XY),
    join_acl([_-XY|T], A).

join_acl2(_, _, [], acl{}).
join_acl2(X, Y, [K|T], A) :-
    join_acl2(X, Y, T, A1),
    XV = X.K, YV = Y.K, list_to_ord_set(XV, XS), list_to_ord_set(YV, YS),
    ord_union(XS, YS, XYS),
    A = A1.put(K, XYS).

www_goto(_, P, _, P, _, _).

www_load(P, _, _, P, _, _).
