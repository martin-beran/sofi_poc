% Operations

:- module(operation, [
    check_f_type/1,
    check_f_result/1,
    f_execute/7
]).

:- use_module(entity).
:- use_module(integrity).
:- use_module(util).

f_type_r(r).
f_type_r(rw).

f_type_w(w).
f_type_w(rw).

% check_f_type(?T)
% Checks that T is a valid operation type (read/writer/read-write)
check_f_type(RW) :- check_(f_type_r(RW) -> true; f_type_w(RW)).

f_result(allow).
f_result(deny).
f_result(error).

% check_f_result(?R)
% Checks that R is a valid operation result
check_f_result(R) :- check_(f_result(R)).

% f_execute(+S1, +O1, +F, +T, -S2, -O2, -R)
% Executes operation F of type T on subject S1 and object O2, yielding subject
% S2 and object O2, with result R.
f_execute(S1, O1, F, T, S2, O2, R) :-
    check_subject(S1), check_object(O1),
    check_(current_predicate(F/4)), check_f_type(T),
    (
        test_acl(S1.i, F, O1.acl),
        (f_type_r(T) -> update_r(S1, O1, F, SI); SI = S1.i), SI #>= S1.mi,
        (f_type_w(T) -> update_w(S1, O1, F, OI); OI = O1.i), OI #>= O1.mi ->
            (
                CALL =.. [F, S1.data, O1.data, SD, OD], CALL ->
                    S2 = S1.put([i:SI, data:SD]),
                    O2 = O1.put([i:OI, data:OD]),
                    R = allow
                ;
                    S2 = S1,
                    O2 = O1,
                    R = error
            )
        ;
            S2 = S1,
            O2 = O1,
            R = deny
    ),
    check_subject(S2), check_object(O2), check_f_result(R).

update_r(S, O, F, I) :-
    TCALL =.. [S.t, F, S.i, O.i, TI1], TCALL,
    TI #:= S.i #* TI1,
    PCALL =.. [O.p, F, O.i, S.i, PI1], PCALL,
    PI #:= PI1 #* O.i,
    RCALL =.. [S.r, F, S.i, PI, RI1], RCALL,
    RI #:= RI1 #* PI,
    I #:= TI #+ RI.

update_w(S, O, F, I) :-
    TCALL =.. [O.t, F, O.i, S.i, TI1], TCALL,
    TI #:= O.i #* TI1,
    PCALL =.. [S.p, F, S.i, O.i, PI1], PCALL,
    PI #:= PI1 #* S.i,
    RCALL =.. [O.p, F, O.i, PI, RI1], RCALL,
    RI #:= RI1 #* PI,
    I #:= TI #+ RI.
