% SOFI example: A file system (startup file)

:- use_module(sofi).
:- use_module('implementation/filesystem_impl').

%?- guitracer.
%?- trace.
?- file_create(empty).

% Creates a file shared by g_project members
scenario_project_file :-
    FN = document,
    ignore(file_rm(FN)),
    spf_create_file(FN),
    spf_john_write(FN),
    spf_peter_read(FN),
    spf_alice_read(FN).

% User john creates a document, allows reading and writing by g_project
spf_create_file(FN) :-
    login(john),
    file_create(FN),
    file_get_sofi(FN, A, allow),
    L = A.acl.f_read, make_integrity([g_project],[], I), L2=[I|L],
    A2 = A.put(acl/f_read, L2), A3 = A2.put(acl/f_write, L2),
    A4 = A3.put(acl/f_swap, L2), file_set_sofi(FN, A4, allow).

% User john writes data to the document
spf_john_write(FN) :-
    file_write(FN, "John's data", allow).

% Reading from file changes peter's integrity
spf_peter_read(FN) :-
    login(peter),
    file_read(FN, D, allow),
    w('File content: '), wnl(D),
    user_stat.

% User alice cannot read the document, her integrity does not change
spf_alice_read(FN) :-
    login(alice),
    file_read(FN, D, deny),
    w('File content: '), wnl(D),
    user_stat.
