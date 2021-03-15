% SOFI example: A file system (implementation module)

:- module(examples_filesystem, [
    current_user_name/1,
    current_user/1,
    user_ls/0,
    user_ls/1,
    user_stat/0,
    user_stat/1,
    user_set_integrity/1,
    user_set_min_integrity/1,
    login/1,
    op_ls/0,
    op_ls/1,
    file_ls/0,
    file_ls/1,
    file_stat/1,
    file_create/1,
    file_rm/1,
    file_test/2,
    file_read/3,
    file_write/3,
    file_swap/4,
    file_get_sofi/3,
    file_set_integrity/3,
    file_set_sofi/3
]).

:- use_module(sofi).

% Available users
% User U is an subject with U.data = user(Name).
:- dynamic user/1.
user(U) :-
    U = entity{
        data: user(nobody),
        i: I, mi: MI, t: test_id, p: prov_none, r: recv_none
    },
    make_integrity([], [], I), integrity_min(MI),
    check_entity(U).

user(U) :-
    U = entity{
        data: user(root),
        i: I, mi: MI, t: test_ok, p: prov_none, r: recv_none
    },
    integrity_max(I), integrity_max(MI),
    check_entity(U).

user(U) :-
    U = entity{
        data: user(admin),
        i: I, mi: MI, t: test_id, p: prov_none, r: recv_none
    },
    integrity_max(I), integrity_min(MI),
    check_entity(U).

user(U) :-
    U = entity{
        data: user(alice),
        i: I, mi: MI, t: test_id, p: prov_none, r: recv_none
    },
    make_integrity([u_alice, g_alice, g_users], [], I),
    integrity_min(MI),
    check_entity(U).

user(U) :-
    U = entity{
        data: user(john),
        i: I, mi: MI, t: test_id, p: prov_none, r: recv_none
    },
    make_integrity([u_john, g_john, g_users, g_project], [], I),
    integrity_min(MI),
    check_entity(U).

user(U) :-
    U = entity{
        data: user(peter),
        i: I,
        mi: MI, t: test_id, p: prov_none, r: recv_none
    },
    make_integrity([peter, g_peter, g_users, g_project],
    [], I), integrity_min(MI),
    check_entity(U).

% current_user_name(?N)
% The name of the currently logged-in user
current_user_name(N) :- current_user(U), U.data = user(N), !.

% current_user(?U)
% The currently logged-in user
:- dynamic current_user/1.
current_user(U) :- user(U), U.data == user(nobody), !.

% user_ls
% Displays names of all existing users.
user_ls :-
    current_user_name(N), user_ls(L), member(U, L),
    write(U), (U = N -> write(' [current]'); true), nl, fail.
user_ls.

% user_ls(-U)
% Lists names of all existing users.
user_ls(LS) :-
    findall(N, (user(U), entity{data: user(N)} :< U), L), sort(L, LS).

% user_stat
% Displays details about the current user.
user_stat :-
    current_user(U), U.data = user(N), write_entity([name:N], U), nl, !.

% user_stat(+N)
% Displays details about the user with name N.
user_stat(N) :-
    user(U), U.data = user(N), write_entity([name:N], U), nl, !.

% user_set_integrity(+I)
% Sets integrity of the current user. It fails if the new integrity is not
% between the minimum and the current integrity.
user_set_integrity(I) :-
    current_user(U), I #>= U.mi, I #=< U.i, UI = U.put(i, I), update_user(UI).

% user_set_min_integrity(+M)
% Sets the minimum integrity of the current user. It fails if the new minimum
% integrity is greater than the current integrity.
user_set_min_integrity(M) :-
    current_user(U), M #=< U.i, UM = U.put(mi, M), update_user(UM).

% login(+N)
% Logs in the user with name N.
login(N) :-
    user(U), U.data == user(N), update_user(U), !.

update_user(U) :-
    retractall(current_user(_)), assertz(current_user(U)).

% file(?F)
% Existing files; F is an object with F.data = file(Name, Content)
:- dynamic file/1.

% op_type(?O, ?T)
% Defines type T (read/write/read-write) of a SOFI operation O.
op_type(f_read, r).
op_type(f_write, w).
op_type(f_swap, rw).
op_type(f_get_sofi, r).
op_type(f_set_integrity, w).
op_type(f_set_sofi, w).

% op_ls
% Displays names of all defined operations.
op_ls :- op_ls(L), member(O, L), writeln(O), fail.
op_ls.

% op_ls(-O)
% Lists names of all defined operations.
op_ls(LS) :- findall(O/T, op_type(O, T), L), sort(L, LS).

% file_ls
% Displays names of all existing files (not applying SOFI).
file_ls :- file_ls(F), member(N, F), writeln(N), fail.
file_ls.

% file_ls(-F)
% Lists names of all existing files (not applying SOFI).
file_ls(LS) :-
    findall(N, name_file(N, _, _), L), sort(L, LS).

name_file(N, C, F) :- file(F), F.data = file(N, C).

% file_stat(+N)
% Displays details about the file with name N (not applying SOFI).
file_stat(N) :-
    name_file(N, C, F), write_entity([name:N, content:C], F), nl, !.

% file_create(+N)
% Creates a new empty file with name N (not applying SOFI). The file is created
% with the integrity of the current user, ACL requiring the current user
% itegrity for all operations, and some default values of other attributes.
file_create(N) :-
    (name_file(N, _, _) -> fail; true),
    current_user(U), integrity_min(MI),
    make_acl(U.i, A),
    E = entity{
        data: file(N, []),
        i: U.i,
        mi: MI,
        t: test_id, p: prov_none, r: recv_none,
        acl: A
    },
    check_object(E),
    assertz(file(E)), !.

make_acl(I, A) :-
    findall(O, op_type(O, _), L),
    make_acl(L, I, A).

make_acl([], _, acl{}).
make_acl([O|T], I, A) :- make_acl(T, I, A0), A = A0.put(O, [I]).

% file_rm(+N)
% Deletes the file with name N (not applying SOFI). Fails if the file does not
% exist.
file_rm(N) :-
    name_file(N, _, F), retractall(file(F)), !.

% file_test(+N, +O)
% Tests if operation O is allowed by SOFI rules on the file with name N.
file_test(N, O) :-
    current_user(U), name_file(N, _, F), op_type(O, T), f_test(U, F, O, T).

file_sofi_op(N, I, F, O, R) :-
    current_user(U1), file(F1), name_file(N, _, F1),
    op_type(F, T), f_execute(U1, F1, I, F, T, U2, F2, O, R),
    update_user(U2), update_file(F2), !.

update_file(F) :-
    F.data = file(N, _), name_file(N, _, R), retractall(file(R)),
    assertz(file(F)).

% file_read(+N, ?D)
% Reads data D of the file with name N. This is a SOFI read operation 'f_read'
% with result R.
file_read(N, D, R) :- file_sofi_op(N, _, f_read, D, R).

f_read(U, file(N, D), _, U, file(N, D), D).

% file_write(+N, +D, ?R)
% Writes data D to the file with name N. It fails if the file does not exist.
% This is a SOFI write operation 'f_write' with result R.
file_write(N, D, R) :- file_sofi_op(N, D, f_write, _, R).

f_write(U, file(N, _), D, U, file(N, D), _).

% file_swap(+N, ?I, +O, ?R)
% Reads data I of the file with name N and stores new data O in the file. This
% is a SOFI read-write operation 'f_swap' with result R.
file_swap(N, I, O, R) :- file_sofi_op(N, I, f_swap, O, R).

f_swap(U, file(N, D2), D1, U, file(N, D1), D2).

% file_get_sofi(+N, ?A, ?R)
% Gets SOFI attributes (the entity without data) of the file with name N. This
% is a SOFI read operation 'f_get_sofi' with result R, but it does not change
% the integrity of the current user (the reader).
file_get_sofi(N, A, R) :-
    file_test(N, f_get_sofi) ->
        name_file(N, _, F),  del_dict(data, F, _, A), R = allow
    ;
        R = deny.

% file_set_integrity(+N, +I, ?R)
% Sets integrity I of the file with name N. This is a SOFI write operation
% 'set_integrity' with result R, but instead of the current user integrity UI,
% it uses UI #* I when determining the new integrity of the file.
file_set_integrity(N, I, R) :-
    current_user(U), IF #:= U.i #* I, name_file(N, _, F1),
    test_acl(U.i, f_set_integrity, F1.acl), IF #>= F1.mi ->
        F2 = F1.put(i, I), R = allow, update_file(F2)
    ;
        R = deny.

% file_set_sofi(+N, +A, ?R)
% Ssets SOFI attributes (the entity without data) of the file with name N. This
% is a SOFI write operation 'set_sofi' with result R. The integrity of the file
% is set to A.i #* UI, where UI is the integrity of the current user.
file_set_sofi(N, A, R) :-
    current_user(U), name_file(N, _, F1), IF #:= U.i #* A.i, IF #>= A.mi,
    test_acl(U.i, f_set_sofi, F1.acl) ->
        F2 = A.put([i:IF, data:F1.data]), R = allow, update_file(F2)
    ;
        R = deny.
