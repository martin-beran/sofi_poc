% SOFI example: Identity management (implementation module)

:- module(examples_identity, [
    identity_certify_user/3,
    identity_certify_service/3,
    identity_read_identity/4
]).

:- use_module('../../sofi').

% identity_agent_provider(?A)
% A is the agent specification of an identity provider.
identity_agent_provider([provider]).

% identity_agent_service(?A)
% A is the agent specification of a service.
identity_agent_service([service]).

% identity_agent_user(?A)
% A is the agent specification of a user.
identity_agent_user([user]).

% op_type(?O, ?T)
% Defines type T (read/write/read-write) of a SOFI operation O.
op_type(id_read, r). % Read an identity

% make_acl(+I, ?A)
% Create an ACL A such that all operations require integrity I.
make_acl(I, A) :-
    findall(O, op_type(O, _), L),
    make_acl(L, I, A).

make_acl([], _, acl{}).
make_acl([O|T], I, A) :- make_acl(T, I, A0), A = A0.put(O, [I]).

% identity_certify_user(+U, +IA, -M)
% To be used by an identity provider. It certifies that user identity data
% U are correct and require an integrity containing integrity attribute IA to
% be read. The certification result is message M.
identity_certify_user(U, IA, M) :-
    E = entity{
        data: U, i:MI, mi:MI, t:test_id, p:prov_none, r:recv_none, acl:A
    },
    integrity_min(MI), make_integrity([IA], [], I), make_acl(I, A),
    identity_agent_provider(AG),
    export(AG, identity_export, E, M), !.

identity_export(A, E, K, V) :-
    identity_agent_provider(AG), member(A, AG), V = E.K.

% identity_certify_service(+S, +IA, -M)
% To be used by an identity provider. It certifies that service S has integrity
% containing integrity attribute IA. The certification result is message M.
identity_certify_service(S, IA, M) :-
    E = entity{
        data:S, i:I, mi:I, t:test_ok, p:prov_none, r:recv_none, acl:A
    },
    make_integrity([IA], [], I),
    acl_empty(A),
    identity_agent_provider(AG),
    export(AG, identity_export, E, M), !.

% identity_read_identity(+S, +U, ?I, ?R)
% It uses service certification message S and user certification message U to
% get identity information from U. This is a SOFI read operation 'id_read' with
% subject S and object U. It returns identity information in I and SOFI result
% in R.
identity_read_identity(S, U, I, R) :-
    identity_agent_service(AS), import(AS, identity_import, S, SE),
    identity_agent_user(AU), import(AU, identity_import, U, UE),
    F = id_read, op_type(F, T),
    f_execute(SE, UE, _, F, T, SE, UE, I, R), !.

identity_import(AG, _, [_-V|_], V) :-
    identity_agent_user(AG); identity_agent_service(AG).

id_read(S, U, _, S, U, U).
