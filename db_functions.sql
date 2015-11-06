-- Regano database internal function definitions
--
-- Uses PostgreSQL extensions.
--
-- These functions are for internal use.
--
--  Regano is a domain registration system for OpenNIC TLDs written in
--  Perl.  This file is part of Regano.
--
--  Regano may be distributed under the same terms as Perl itself.  Of
--  particular importance, note that while regano is distributed in the
--  hope that it will be useful, there is NO WARRANTY OF ANY KIND
--  WHATSOEVER WHETHER EXPLICIT OR IMPLIED.


-- The type definitions in db_types.sql must already be installed.
-- The table definitions in db_tables.sql are needed for these to actually work.

CREATE OR REPLACE FUNCTION regano.config_set
	(key text, value bigint)
	RETURNS void AS $$
BEGIN
    PERFORM * FROM regano.config WHERE regano.config.key = config_set.key;
    IF FOUND THEN
	UPDATE regano.config SET number = value
	    WHERE regano.config.key = config_set.key;
    ELSE
	INSERT INTO regano.config (key, number) VALUES (key, value);
    END IF;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER;
ALTER FUNCTION regano.config_set (text, bigint)
	OWNER TO regano;

CREATE OR REPLACE FUNCTION regano.config_set
	(key text, value interval)
	RETURNS void AS $$
BEGIN
    PERFORM * FROM regano.config WHERE regano.config.key = config_set.key;
    IF FOUND THEN
	UPDATE regano.config SET interval = value
	    WHERE regano.config.key = config_set.key;
    ELSE
	INSERT INTO regano.config (key, interval) VALUES (key, value);
    END IF;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER;
ALTER FUNCTION regano.config_set (text, interval)
	OWNER TO regano;

CREATE OR REPLACE FUNCTION regano.config_set
	(key text, value text)
	RETURNS void AS $$
BEGIN
    PERFORM * FROM regano.config WHERE regano.config.key = config_set.key;
    IF FOUND THEN
	UPDATE regano.config SET text = value
	    WHERE regano.config.key = config_set.key;
    ELSE
	INSERT INTO regano.config (key, text) VALUES (key, value);
    END IF;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER;
ALTER FUNCTION regano.config_set (text, text)
	OWNER TO regano;


CREATE OR REPLACE FUNCTION regano.config_get (key text)
	RETURNS regano.config AS $$
SELECT * FROM regano.config WHERE key = $1
$$ LANGUAGE SQL STABLE STRICT SECURITY INVOKER;
ALTER FUNCTION regano.config_get (text)
	OWNER TO regano;


CREATE OR REPLACE FUNCTION regano.username (regano.sessions)
	RETURNS text AS $$
SELECT username FROM regano.users WHERE id = $1.user_id;
$$ LANGUAGE SQL STABLE STRICT SECURITY INVOKER;
ALTER FUNCTION regano.username (regano.sessions)
	OWNER TO regano;
CREATE OR REPLACE FUNCTION regano.username (session_id uuid)
	RETURNS text AS $$
SELECT username
    FROM regano.sessions JOIN regano.users
	ON (regano.sessions.user_id = regano.users.id)
    WHERE regano.sessions.id = $1;
$$ LANGUAGE SQL STABLE STRICT SECURITY INVOKER;
ALTER FUNCTION regano.username (uuid)
	OWNER TO regano;

CREATE OR REPLACE FUNCTION regano.session_user_id (uuid) RETURNS bigint AS $$
SELECT user_id FROM regano.sessions WHERE id = $1
$$ LANGUAGE SQL STABLE STRICT SECURITY INVOKER;
ALTER FUNCTION regano.session_user_id (uuid)
	OWNER TO regano;
