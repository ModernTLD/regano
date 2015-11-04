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
    bailiwick		regano.bailiwicks%ROWTYPE;
    reserved_domain	regano.reserved_domains%ROWTYPE;
    pending_domain	regano.pending_domains%ROWTYPE;
    active_domain	regano.domains%ROWTYPE;

    primary_label	regano.dns_label;
BEGIN
    SELECT * INTO bailiwick
	FROM regano.bailiwicks
	WHERE (domain_ LIKE ('%' || domain_tail));
    IF NOT FOUND THEN
	RETURN 'ELSEWHERE';
    END IF;

    primary_label :=
	substring(domain_
		  from '([^.]+)' ||
			replace(bailiwick.domain_tail, '.', '[.]') || '$');

    SELECT * INTO reserved_domain
	FROM regano.reserved_domains WHERE (lower(primary_label) = domain_name);
    IF FOUND THEN
	RETURN 'RESERVED';
    END IF;

    SELECT * INTO pending_domain
	FROM regano.pending_domains WHERE (lower(domain_) = lower(domain_name));
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


-- Create a new user account.
CREATE OR REPLACE FUNCTION regano_api.user_register
	(text, regano.password, text, text)
	RETURNS void AS $$
DECLARE
    username_		ALIAS FOR $1;
    password_		ALIAS FOR $2;
    contact_name	ALIAS FOR $3;
    contact_email	ALIAS FOR $4;

    new_user_id		bigint; -- row ID of new user record
    new_contact_id	bigint; -- row ID of new user's primary contact record
BEGIN
	-- TODO: make algorithm and iterations for crypt() configurable
    INSERT INTO users (username, password)
	VALUES (username_, ROW(password_.xdigest, password_.xsalt,
				crypt(password_.digest, gen_salt('bf', 10))))
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

    user_id	bigint;	-- row ID of user record
    stored_pw	text;	-- password hash from database
    session_id	uuid;	-- session ID
BEGIN
    SELECT id, (regano.users.password).digest INTO user_id, stored_pw
	FROM regano.users WHERE (regano.users.username = var.username);
    IF NOT FOUND THEN
	-- fake a stored password to impede timing attacks
	-- TODO: make algorithm and iterations for fake crypt() configurable
	stored_pw := gen_salt('bf', 10);
    END IF;
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

-- End a session.
CREATE OR REPLACE FUNCTION regano_api.session_logout
	(session uuid)
	RETURNS void AS $$
DELETE FROM regano.sessions WHERE id = $1
$$ LANGUAGE SQL VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.session_logout (uuid)
	OWNER TO regano;

-- Retreive username for a session.
CREATE OR REPLACE FUNCTION regano_api.session_check
	(id uuid)
	RETURNS text AS $$
DECLARE
    username	text;
BEGIN
    -- TODO: implement session expiration
    SELECT regano.users.username INTO username
	FROM regano.sessions JOIN regano.users
	    ON (regano.sessions.user_id = regano.users.id)
	WHERE regano.sessions.id = session_check.id;
    IF FOUND THEN
	UPDATE regano.sessions SET last_seen = CURRENT_TIMESTAMP
	    WHERE regano.sessions.id = session_check.id;
    END IF;
    RETURN username;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.session_check (uuid)
	OWNER TO regano;
