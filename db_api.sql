-- Regano database function definitions
--
-- Uses PostgreSQL extensions.
--
-- These functions are intended to be called from the Web UI or other frontend.
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

-- Inquire about the status of a domain.
CREATE OR REPLACE FUNCTION regano_api.domain_status
	(domain_ regano.dns_fqdn)
	RETURNS regano.domain_status AS $$
DECLARE
    active_domain	regano.domains%ROWTYPE;

    primary_label	regano.dns_label;
    tail		regano.dns_fqdn;
BEGIN
    primary_label := substring(domain_ from '^([^.]+)[.]');
    tail:= substring(domain_ from '^[^.]+([.].+[.])$');

    PERFORM * FROM regano.bailiwicks WHERE domain_tail = tail;
    IF NOT FOUND THEN
	RETURN 'ELSEWHERE';
    END IF;

    PERFORM * FROM regano.reserved_domains
		WHERE domain_name = lower(primary_label);
    IF FOUND THEN
	RETURN 'RESERVED';
    END IF;

    PERFORM * FROM regano.pending_domains
		WHERE lower(domain_name) = lower(domain_);
    IF FOUND THEN
	RETURN 'PENDING';
    END IF;

    SELECT * INTO active_domain
	FROM regano.domains WHERE (lower(domain_) = lower(domain_name));

    IF FOUND THEN
	IF now() < active_domain.expiration THEN
	    RETURN 'REGISTERED';
	ELSE
	    RETURN 'EXPIRED';
	END IF;
    END IF;

    RETURN 'AVAILABLE';
END;
$$ LANGUAGE plpgsql STABLE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.domain_status (regano.dns_fqdn)
	OWNER TO regano;

-- Inquire why a domain is reserved.
CREATE OR REPLACE FUNCTION regano_api.domain_reservation_reason
	(regano.dns_fqdn)
	RETURNS text AS $$
SELECT reason FROM regano.reserved_domains
	WHERE domain_name = substring($1 from '^([^.]+)[.]')
$$ LANGUAGE SQL STABLE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.domain_reservation_reason (regano.dns_fqdn)
	OWNER TO regano;


-- Create a new user account.
CREATE OR REPLACE FUNCTION regano_api.user_register
	(text, regano.password, text, text)
	RETURNS void AS $$
DECLARE
    username_		ALIAS FOR $1;
    password_		ALIAS FOR $2;
    contact_name	ALIAS FOR $3;
    contact_email	ALIAS FOR $4;

    crypt_alg		CONSTANT text NOT NULL
			    := (regano.config_get('auth/crypt')).text;
    crypt_iter		CONSTANT integer NOT NULL
			    := (regano.config_get('auth/crypt')).number;

    new_user_id		bigint; -- row ID of new user record
    new_contact_id	bigint; -- row ID of new user's primary contact record
BEGIN
    INSERT INTO users (username, password)
	VALUES (username_, ROW(password_.xdigest, password_.xsalt,
				crypt(password_.digest,
				      gen_salt(crypt_alg, crypt_iter))))
	RETURNING id INTO STRICT new_user_id;
    INSERT INTO contacts (owner_id, name, email)
	VALUES (new_user_id, contact_name, contact_email)
	RETURNING id INTO STRICT new_contact_id;
    UPDATE users SET contact_id = new_contact_id WHERE id = new_user_id;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.user_register (text, regano.password, text, text)
	OWNER TO regano;

-- Get the external digest algorithm and salt for a user.
CREATE OR REPLACE FUNCTION regano_api.user_get_salt_info
	(username_ text)
	RETURNS regano.password AS $$
DECLARE
    password_	regano.password;
BEGIN
    SELECT (password).xdigest, (password).xsalt INTO password_
	FROM regano.users WHERE (username = username_);
    IF NOT FOUND THEN
	-- return an unspecified record to impede timing attacks
	SELECT (password).xdigest, (password).xsalt INTO password_
	    FROM regano.users FETCH FIRST 1 ROW ONLY;
    END IF;

    RETURN password_;
END;
$$ LANGUAGE plpgsql STABLE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.user_get_salt_info (text)
	OWNER TO regano;

-- Begin a session for a user.
CREATE OR REPLACE FUNCTION regano_api.user_login
	(text, regano.password)
	RETURNS uuid AS $$
<<var>>
DECLARE
    username	ALIAS FOR $1;
    password	ALIAS FOR $2;

    crypt_alg	CONSTANT text NOT NULL
		    := (regano.config_get('auth/crypt')).text;
    crypt_iter	CONSTANT integer NOT NULL
		    := (regano.config_get('auth/crypt')).number;
    max_age	CONSTANT interval NOT NULL
		    := (regano.config_get('session/max_age')).interval;

    user_id	bigint;	-- row ID of user record
    stored_pw	text;	-- password hash from database
    session_id	uuid;	-- session ID
BEGIN
    SELECT id, (regano.users.password).digest INTO user_id, stored_pw
	FROM regano.users WHERE (regano.users.username = var.username);
    IF NOT FOUND THEN
	-- fake a stored password to impede timing attacks
	stored_pw := gen_salt(crypt_alg, crypt_iter);
    END IF;
    -- clean up expired sessions
    DELETE FROM regano.sessions WHERE start < (CURRENT_TIMESTAMP - max_age);
    -- verify password; note that a bare salt cannot match any hash
    IF crypt(password.digest, stored_pw) = stored_pw THEN
	-- login successful
	INSERT INTO regano.sessions (id, user_id)
	    VALUES (gen_random_uuid(), user_id)
	    RETURNING id INTO STRICT session_id;
	RETURN session_id;
    ELSE
	-- login failed
	RETURN NULL;
    END IF;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.user_login (text, regano.password)
	OWNER TO regano;

-- Change a logged-in user's password.
CREATE OR REPLACE FUNCTION regano_api.user_change_password
	(uuid, regano.password, regano.password)
	RETURNS boolean AS $$
DECLARE
    session_id	ALIAS FOR $1;
    old_pw	ALIAS FOR $2;
    new_pw	ALIAS FOR $3;

    crypt_alg	CONSTANT text NOT NULL
		    := (regano.config_get('auth/crypt')).text;
    crypt_iter	CONSTANT integer NOT NULL
		    := (regano.config_get('auth/crypt')).number;

    user_id	bigint;	-- row ID of user record
BEGIN
    SELECT regano.sessions.user_id INTO user_id
	FROM regano.sessions WHERE id = session_id;
    IF NOT FOUND THEN
	RETURN FALSE;
    END IF;

    new_pw.digest := crypt(new_pw.digest, gen_salt(crypt_alg, crypt_iter));

    UPDATE regano.users SET password = new_pw
	WHERE ((id = user_id) AND
	    (crypt(old_pw.digest, (regano.users.password).digest) =
	     (regano.users.password).digest));
    RETURN FOUND;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.user_change_password
	(uuid, regano.password, regano.password)
	OWNER TO regano;

-- End a session.
CREATE OR REPLACE FUNCTION regano_api.session_logout
	(session uuid)
	RETURNS void AS $$
DELETE FROM regano.sessions WHERE id = $1
$$ LANGUAGE SQL VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.session_logout (uuid)
	OWNER TO regano;

-- Retrieve username for a session, update session activity timestamp, and
-- perform auto-logout if the session has expired.
CREATE OR REPLACE FUNCTION regano_api.session_check
	(id uuid)
	RETURNS text AS $$
DECLARE
    max_age	CONSTANT interval NOT NULL
		    := (regano.config_get('session/max_age')).interval;
    max_idle	CONSTANT interval NOT NULL
		    := (regano.config_get('session/max_idle')).interval;

    session	regano.sessions%ROWTYPE;
BEGIN
    SELECT * INTO session
	FROM regano.sessions WHERE regano.sessions.id = session_check.id;
    IF FOUND THEN
	IF ((CURRENT_TIMESTAMP - session.activity) > max_idle) OR
	   ((CURRENT_TIMESTAMP - session.start) > max_age) THEN
	    -- session is expired
	    PERFORM regano_api.session_logout(session.id);
	    RETURN NULL;
	ELSE
	    -- update activity timestamp
	    UPDATE regano.sessions SET activity = CURRENT_TIMESTAMP
		WHERE regano.sessions.id = session_check.id;
	END IF;
    ELSE
	-- no such session exists
	RETURN NULL;
    END IF;
    RETURN regano.username(session);
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.session_check (uuid)
	OWNER TO regano;
