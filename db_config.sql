-- Regano database configuration default values
--
-- Uses PostgreSQL extensions.
--
--  Regano is a domain registration system for OpenNIC TLDs written in
--  Perl.  This file is part of Regano.
--
--  Regano may be distributed under the same terms as Perl itself.  Of
--  particular importance, note that while regano is distributed in the
--  hope that it will be useful, there is NO WARRANTY OF ANY KIND
--  WHATSOEVER WHETHER EXPLICIT OR IMPLIED.


-- The type definitions in db_types.sql must already be installed.
-- The table definitions in db_tables.sql are needed for this to actually work.
-- The function definitions in db_functions.sql must already be installed.

-- auth/crypt:	(text)
--	algorithm to use with crypt()
-- auth/crypt:	(number)
--	iteration count to use with crypt()
SELECT regano.config_set('auth/crypt', 'bf');
SELECT regano.config_set('auth/crypt', 10);
-- Note that the default 'bf' algorithm only accepts up to 72 characters of
-- input and ignores excess input data.  Base64 encoded SHA384 fits in
-- this, but simple hex encoded SHA512 exceeds this limit.

-- session/max_age:	(interval)
--	automatic logout regardless of activity
SELECT regano.config_set('session/max_age', interval '6 hours');
-- session/max_idle:	(interval)
--	automatic logout due to inactivity
SELECT regano.config_set('session/max_idle', interval '10 minutes');

-- verify/max_age:	(interval)
--	amount of time that verfication emails are valid
SELECT regano.config_set('verify/max_age', interval '24 hours');

-- domain/pend_term	(interval)
--	amount of time that a domain may remain pending before it is deleted
SELECT regano.config_set('domain/pend_term', interval '36 hours');
-- domain/term:		(interval)
--	amount of time that domains remain registered if not renewed
SELECT regano.config_set('domain/term', interval '1 year');
