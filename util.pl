% Common utilities

:- module(util, [
    is_/1,
    op(200, fy, ??),
    (??)/1,
    check_/1,
    w/1,
    wnl/1,
    wkv/2,
    wkv/1
]).

:- meta_predicate is_(0), ??0, check_(0).

% is_(+P)
% Turns a predicate throwing exception check_fail(_) into fail.
is_(P) :- catch(P, check_fail(_), fail).

% An operator equivalent to is_(P)
??P :- is_(P).

% check_(+P)
% Turns a failing predicate into throwing check_fail(_).
check_(P) :- call(P) -> true; P = _:C, C =.. [F|_], throw(check_fail(F)).

% w(+T)
% Writes term T with no depth limit.
w(T):- write_term(T, [max_depth(0)]).

% wnl(+T)
% Performs w(T) and adds a newline.
wnl(T) :- w(T), nl.

% wkv(+L, P)
% Writes a list of Key:Value pairs. Each pair is written on a new line prefixed
% with P and values are lined up in the same column.
wkv(L, P) :-
    wkv_format(L, N), wkv_write(L, P, N).

% wkv(+L)
% The same as wkv(L, '').
wkv(L) :- wkv(L, '').

wkv_format([], 2).
wkv_format([K:_|T], N) :-
    wkv_format(T, N0), atom_length(K, N1),
    (N1 + 2 > N0 -> N is N1 + 2; N = N0).

wkv_write([], _, _).
wkv_write([K:V|T], P, N) :-
    format('~w~w:~*|~t~w~n', [P, K, N, V]), wkv_write(T, P, N).
