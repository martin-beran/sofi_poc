% SOFI example: A file system (startup file)

:- use_module(sofi).
:- use_module('implementation/filesystem_impl').

%?- guitracer.
%?- trace.
?- file_create(empty).

%%% scenario_project_file %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% It creates a file shared by g_project members, propagates integrity among
% group members, denies access to users outside the group.

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

%%% scenario_secret_data %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% It creates a secret file. Its data cannot be copied to an unclassified file
% and cannot be read by a user without a security clearance.

scenario_secret_file :-
    FU = unclassified,
    FS = secret,
    ignore(file_rm(FU)),
    ignore(file_rm(FS)),
    ssf_create_files(FU, FS),
    ssf_alice_write_secret(FS),
    ssf_john_secret2unclassifed(FS, FU),
    ssf_peter_no_clearance(FS).

% User admin prepares the files.
ssf_create_files(FU, FS) :-
    login(admin),
    file_create(FU),
    ssf_set_unclassified(FU),
    file_create(FS),
    ssf_set_secret(FS),
    wnl('%%% Created files %%%'),
    file_stat(FU),
    file_stat(FS).

ssf_set_unclassified(FU) :-
    file_get_sofi(FU, A, allow),
    integrity_min(I),
    integrity_min_public(IP),
    A2 = A.put(acl/f_read, [I]), A3 = A2.put(acl/f_write, [I]),
    A4 = A3.put(acl/f_swap, [I]), A5 = A4.put(mi, IP),
    file_set_sofi(FU, A5, allow).

ssf_set_secret(FS) :-
    file_get_sofi(FS, A, allow),
    integrity_min(I),
    make_integrity(root, [secret], IS),
    A2 = A.put(acl/f_read, [I]), A3 = A2.put(acl/f_write, [I]),
    A4 = A3.put(acl/f_swap, [I]), A5 = A4.put(mi, I), A6 = A5.put(i, IS),
    file_set_sofi(FS, A6, allow).

% User alice writes secret data.
ssf_alice_write_secret(FS) :-
    login(alice),
    file_write(FS, "Alice's secret data", allow).

% User john reads secret data and tries to write them to the unclassified file.
ssf_john_secret2unclassifed(FS, FU) :-
    login(john),
    wnl('%%% Trying to copy secret to unclassified %%%'),
    file_read(FS, D, allow),
    w('Secret data: '), wnl(D),
    file_write(FU, D, deny),
    file_stat(FU).

% Security clearance of peter is reduced, so he cannot read secret data.
ssf_peter_no_clearance(FS) :-
    login(peter),
    current_user(U), I = U.i, make_integrity(I.ia, [], INC),
    user_set_min_integrity(INC),
    wnl('%%% Trying to read secret data with low clearance %%%'),
    file_read(FS, D, deny),
    user_stat,
    file_stat(FS),
    w('Secret data: '), wnl(D).
