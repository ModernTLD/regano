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

-- session/max_age:	(interval)
--	automatic logout regardless of activity
SELECT regano.config_set('session/max_age', interval '6 hours');
-- session/max_idle:	(interval)
--	automatic logout due to inactivity
SELECT regano.config_set('session/max_idle', interval '10 minutes');
