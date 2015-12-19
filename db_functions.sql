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

CREATE OR REPLACE FUNCTION regano.zone_verify_access
	(session_id uuid, zone_name regano.dns_fqdn, action text)
	RETURNS regano.domains AS $$
DECLARE
    user_id		CONSTANT bigint NOT NULL
			    := regano.session_user_id(session_id);

    primary_label	regano.dns_label;
    tail		regano.dns_fqdn;

    domain		regano.domains%ROWTYPE;
BEGIN
    primary_label := substring(zone_name from '^([^.]+)[.]');
    tail := substring(zone_name from '^[^.]+([.].+[.])$');

    SELECT * INTO STRICT domain
	FROM regano.domains
	WHERE (lower(primary_label) = lower(domain_name))
	    AND (lower(tail) = lower(domain_tail));

    IF user_id <> domain.owner_id THEN
	RAISE EXCEPTION
	'attempt made to modify zone (%) not belonging to current user (%): %',
	    zone_name, regano.username(session_id), action;
    END IF;

    RETURN domain;
END
$$ LANGUAGE plpgsql STABLE STRICT SECURITY INVOKER;
ALTER FUNCTION regano.zone_verify_access (uuid, regano.dns_fqdn, text)
	OWNER TO regano;

CREATE OR REPLACE FUNCTION regano.zone_next_seq_no (bigint)
	RETURNS bigint AS $$
SELECT COALESCE(MAX(seq_no), 0) + 1
    FROM regano.domain_records WHERE domain_id = $1;
$$ LANGUAGE SQL STABLE STRICT SECURITY INVOKER;
ALTER FUNCTION regano.zone_next_seq_no (bigint)
	OWNER TO regano;

CREATE OR REPLACE FUNCTION regano.canonicalize_record_name
	(input regano.dns_name, zone_name regano.dns_fqdn)
	RETURNS regano.dns_name AS $$
SELECT CASE WHEN lower($1) = lower($2) THEN regano.dns_name '@'
	    WHEN char_length($1) > (1+char_length($2))
		 AND (lower($1) LIKE lower('%.' || $2))
		 THEN CAST(substring($1 from 1
				     for (char_length($1) - char_length($2) - 1))
			   AS regano.dns_name)
	    ELSE $1
       END
$$ LANGUAGE SQL IMMUTABLE STRICT SECURITY INVOKER;
ALTER FUNCTION regano.canonicalize_record_name
	(regano.dns_name, regano.dns_fqdn)
	OWNER TO regano;
