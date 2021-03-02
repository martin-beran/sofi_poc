% Common utilities

:- module(util, [
    is_/1,
    op(200, fy, ??),
    (??)/1,
    check_/1
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
