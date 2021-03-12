% SOFI example: A file system (implementation module)

:- module(examples_filesystem, [
    current_user_name/1,
    current_user/1,
    user_ls/0,
    user_ls/1,
    user_stat/1,
    user_set_integrity/1,
    login/1,
    op_ls/0,
    op_ls/1,
    file_ls/0,
    file_ls/1,
    file_stat/1,
    file_create/1,
    file_rm/1,
    file_test/2,
    file_read/2,
    file_write/2,
    file_swap/3,
    file_get_sofi/2,
    file_set_integrity/2,
    file_set_sofi/2
]).

:- use_module(sofi).

% Available users
% User U is an subject with U.data = user(Name).
:- dynamic user/1.
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

% user_stat(+N)
% Displays details about the user with name N.
user_stat(_N).

% user_set_integrity(+I)
% Sets integrity of the current user. The integrity may only be made smaller.
user_set_integrity(_I).

% login(+N)
% Logs in the user with name N.
login(N) :-
    user(U), U.data == user(N), !,
    retractall(current_user_name(_)), assertz(current_user_name(N)).

% file(?F)
% Existing files; F is an object with F.data = file(Name, Content)
:- dynamic file/1.

% op_type(?O, ?T)
% Defines type T (read/write/read-write) of a SOFI operation O.
op_type(read, r).
op_type(write, w).
op_type(swap, rw).
op_type(get_sofi, r).
op_type(set_integrity, w).
op_type(set_sofi, w).

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
    findall(N, (file(F), entity{data: file(N,_)} :< F), L), sort(L, LS).

% file_stat(+N)
% Displays details about the file with name N (not applying SOFI).
file_stat(_N).

% file_create(+N)
% Creates a new empty file with name N (not applying SOFI). The file is created
% with the integrity of the current user, ACL requiring the current user
% itegrity for all operations, and some default values of other attributes.
file_create(N) :-
    (file(F), F.data = file(N, _) -> fail; true),
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
    assertz(file(E)).

make_acl(I, A) :-
    findall(O, op_type(O, _), L),
    make_acl(L, I, A).

make_acl([], _, acl{}).
make_acl([O|T], I, A) :- make_acl(T, I, A0), A = A0.put(O, [I]).

% file_rm(+N)
% Deletes the file with name N (not applying SOFI). Fails if the file does not
% exist.
file_rm(_N).

% file_test(+N, +O)
% Tests if operation O is allowed by SOFI rules on the file with name N.
file_test(_N, _O).

% file_set_integrity(+N, +I)
% Sets a new integrity of 
% file_read(+N, ?D)
% Reads data D of the file with name N. This is a SOFI read operation 'read'.
file_read(_N, _D).

% file_write(+N, +D)
% Writes data D to the file with name N. It fails if the file does not exist.
% This is a SOFI write operation 'write'.
file_write(_N, _D).

% file_swap(+N, ?R, +W)
% Reads data R of the file with name N and stores new data W in the file. This
% is a SOFI read-write operation 'swap'.
file_swap(_N, _R, _W).

% file_get_sofi(+N, ?A)
% Gets SOFI attributes (the entity without data) of the file with name N. This
% is a SOFI read operation 'get_sofi'.
file_get_sofi(_N, _A).

% file_set_integrity(+N, +I)
% Sets integrity I of the file with name N. This is a SOFI write operation
% 'set_integrity', but it uses the current user integrity UI #* I instead of UI
% when determining the new integrity of the file.
file_set_integrity(_N, _I).

% file_set_sofi(+N, +A)
% Ssets SOFI attributes (the entity without data) of the file with name N. This
% is a SOFI write operation 'set_sofi'. The integrity of the file is set to
% A.i #* UI, where UI is the integrity of the current user.
file_set_sofi(_N, _A).
