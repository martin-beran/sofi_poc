% SOFI example: World Wide Web (implementation module)

:- module(examples_www, [
    server/3,
    init_browser/0,
    browser_stat/0
]).

:- use_module(sofi).

% op_type(?O, ?T)
% Defines type T (read/write/read-write) of a SOFI operation O.
op_type(www_goto, r). % Go to another page
op_type(www_load, r). % Load a resource from a server into the current page
op_type(www_post, w). % Send data to a server resource from the current page
op_type(browser_read, r). % Read from a loaded resource
op_type(browser_write, w). % Write to a loaded resource

% server(+H, +P, ?E)
% An entity (WWW resource) E available on a WWW server host H at path P.
server('www.company.example', '/', E) :-
    E = entity{
        data: "Company WWW presentation",
        i: I, mi: MI, t: test_id, p: prov_none, r: recv_none, acl: A
    },
    make_integrity([], [], I), integrity_min(MI), make_acl(I, A),
    check_entity(E).

% make_acl(+I, ?A)
% Create an ACL A such that all operations require integrity I.
make_acl(I, A) :-
    findall(O, op_type(O, _), L),
    make_acl(L, I, A).

make_acl([], _, acl{}).
make_acl([O|T], I, A) :- make_acl(T, I, A0), A = A0.put(O, [I]).

% browser(+P, +R)
% The current state of the browser. P is the current page represented as a SOFI
% subject. R is a list of resources, each being a SOFI object.
:- dynamic browser/2.

% init_browser
% Initialize the browser.
init_browser :-
    E = entity{
        data: "",
        i: I, mi: MI, t: test_id, p: prov_none, r: recv_none, acl: A
    },
    integrity_max(I), integrity_min(MI), make_acl(MI, A),
    update_browser(E, []).

update_browser(P, R) :-
    retractall(browser(_, _)), assertz(browser(P, R)).

browser_stat :-
    browser(P, R),
    wnl('%%% Page %%%'),
    write_entity(P),
    write_resources(R, 0).

write_resources([], _).
write_resources([R|T], I) :-
    w('%%% Resource '), w(I), wnl(' %%%'),
    write_entity(R),
    I1 is I + 1,
    write_resources(T, I1).
