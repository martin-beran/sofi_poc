% SOFI example: A file system (startup file)

:- use_module(sofi).
:- use_module('implementation/filesystem_impl').

%?- guitracer.
%?- trace.
?- file_create(empty).
