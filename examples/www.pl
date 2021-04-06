% SOFI example: World Wide Web (startup file)

:- use_module(sofi).
:- use_module('implementation/www_impl').

?- init_browser.

%%% scenario_load_page %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% It loads a page, accesses other resources from the page, and switches to
% another page.

scenario_load_page :-
    wnl('%%% Init %%%'),
    init_browser,
    browser_stat,
    wnl('\n%%% Load page %%%'),
    browser_goto('www.company.example', '/', R1), R1 == allow,
    w('Result: '), wnl(R1),
    browser_stat,
    wnl('\n%%% Load resource %%%'),
    browser_load('www.company.example', '/public_data', R2), R2 == allow,
    w('Result: '), wnl(R2),
    browser_stat,
    wnl('\n%%% Deny foreign resource %%%'),
    browser_load('www.other.example', '/', R3), R3 == deny,
    w('Result: '), wnl(R3),
    browser_stat,
    wnl('\n%%% Go to other page %%%'),
    browser_goto('www.other.example', '/', R4), R4 == allow,
    w('Result: '), wnl(R4),
    browser_stat.

%%% scenario_deny_private %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% It allows access to a resource from the same server, but denies from other
% pages or when entered directly in the browser.

scenario_deny_private :-
    wnl('%%% Init %%%'),
    init_browser,
    browser_stat,
    wnl('\n%%% Deny direct %%%'),
    browser_goto('www.company.example', '/private_data', R1), R1 == deny,
    w('Result: '), wnl(R1),
    browser_stat,
    wnl('\n%%% Deny from other %%%'),
    browser_goto('www.other.example', '/', allow),
    browser_goto('www.company.example', '/private_data', R2), R2 == deny,
    w('Result: '), wnl(R2),
    browser_stat,
    wnl('\n%%% Allow from the same server %%%'),
    browser_goto('www.company.example', '/', allow),
    browser_goto('www.company.example', '/private_data', R3), R3 == allow,
    w('Result: '), wnl(R3),
    browser_stat.

%%% scenario_xsrf %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% XSRF protection: allow a request directly from the browser address line or
% from the main page of the same server, deny otherwise.

scenario_xsrf :-
    wnl('%%% Init %%%'),
    init_browser,
    wnl('\n%%% Allow direct %%%'),
    browser_stat,
    browser_goto('www.company.example', '/restricted', R1), R1 == allow,
    w('Result: '), wnl(R1),
    browser_stat,
    wnl('\n%%% Allow from main %%%'),
    browser_goto('www.company.example', '/', allow),
    browser_stat,
    browser_goto('www.company.example', '/restricted', R2), R2 == allow,
    w('Result: '), wnl(R2),
    browser_stat,
    wnl('\n%%% Deny from other page %%%'),
    browser_goto('www.company.example', '/public_data', allow),
    browser_stat,
    browser_goto('www.company.example', '/restricted', R3), R3 == deny,
    w('Result: '), wnl(R3),
    browser_stat,
    wnl('\n%%% Deny from other server %%%'),
    browser_goto('www.other.example', '/', allow),
    browser_stat,
    browser_goto('www.company.example', '/restricted', R4), R4 == deny,
    w('Result: '), wnl(R4),
    browser_stat.
