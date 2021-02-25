% Common utilities

:- module(util, [
    is_/1,
    op(200, fy, ??),
    (??)/1,
    check_/1
]).

:- meta_predicate is_(0), ??0, check_(0).

is_(P) :- catch(P, check_fail(_), fail).

??P :- is_(P).

check_(P) :- call(P) -> true; P = _:C, C =.. [F|_], throw(check_fail(F)).
