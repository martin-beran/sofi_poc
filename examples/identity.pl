% SOFI example: Identity management (startup file)

:- use_module('../sofi').
:- use_module('implementation/identity_impl').

%%% scenario_identity_verification %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

% A post office may check user's address, but not age.
% A bar may check user's age, but not address.
scenario_identity_verification :-
    wnl('%%% Certify services %%%'),
    identity_certify_service(post_office, address, POST_OFFICE),
    display_certificate('Service', POST_OFFICE),
    identity_certify_service(bar, age, BAR),
    display_certificate('Service', BAR),
    wnl('%%% Certify users %%%'),
    identity_certify_user(
        user{name:'Max Peck', address:'Hotel Rice, Houston'}, address,
        PECK_ADDR
    ),
    display_certificate('User address', PECK_ADDR),
    identity_certify_user( user{name:'Max Peck', age: 45}, age, PECK_AGE),
    display_certificate('User age', PECK_AGE),
    wnl('%%% Post office %%%'),
    identity_read_identity(POST_OFFICE, PECK_ADDR, I1, allow),
    w('Address: '), wnl(I1),
    identity_read_identity(POST_OFFICE, PECK_AGE, I2, deny),
    w('Age: '), wnl(I2), nl,
    wnl('%%% Bar %%%'),
    identity_read_identity(BAR, PECK_ADDR, I3, deny),
    w('Address: '), wnl(I3),
    identity_read_identity(BAR, PECK_AGE, I4, allow),
    w('Age: '), wnl(I4).

display_certificate(N, C) :-
    wnl(N), E = C.provider, write_entity(E), nl.
