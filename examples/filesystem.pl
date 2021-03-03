% SOFI example: A file system

:- use_module(sofi).

% Available users
user(
    entity{
        data: user(nobody),
        i: integrity{ia:[], ca:[]},
        mi: MI, t: test_id, p: prov_none, r: recv_none
    }
) :-
    integrity_min(MI).

user(
    entity{
        data: user(root),
        i: I,
        mi: MI, t: test_ok, p: prov_none, r: recv_none
    }
) :-
    integrity_max(I), integrity_max(MI).

user(
    entity{
        data: user(admin),
        i: I,
        mi: MI, t: test_id, p: prov_none, r: recv_none
    }
) :-
    integrity_max(I), integrity_min(MI).

% current_user_name(?N)
% The name of the currently logged-in user
:- dynamic current_user_name/1.
current_user_name(nobody).

% current_user(?U)
% The currently logged-in user
current_user(U) :- user(U), current_user_name(N), U.data == user(N), !.

% login(+N)
% Logs in the user with name N.
login(N) :-
    user(U), U.data == user(N), !,
    retractall(current_user_name(_)), assertz(current_user_name(N)).

% file(?F)
% Existing files; F is an object with F.data = [Name, Content]
:- dynamic file/1.
file(
    entity{
        data: [empty, ""],
        i: I,
        mi: MI, t: test_id, p: prov_none, r: recv_none
    }
) :-
    integrity_max(I), integrity_min(MI).
