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
	(regano.dns_fqdn)
	RETURNS regano.domain_status AS $$
DECLARE
    name		ALIAS FOR $1;

    max_age		CONSTANT interval NOT NULL
			    := (regano.config_get('domain/pend_term')).interval;

    active_domain	regano.domains%ROWTYPE;

    primary_label	regano.dns_label;
    tail		regano.dns_fqdn;
BEGIN
    primary_label := substring(name from '^([^.]+)[.]');
    tail:= substring(name from '^[^.]+([.].+[.])$');

    PERFORM * FROM regano.bailiwicks WHERE domain_tail = tail;
    IF NOT FOUND THEN
	RETURN 'ELSEWHERE';
    END IF;

    PERFORM * FROM regano.reserved_domains
		WHERE domain_name = lower(primary_label);
    IF FOUND THEN
	RETURN 'RESERVED';
    END IF;

    -- clean up pending domains, then check if the requested domain is pending
    DELETE FROM regano.pending_domains WHERE start < (now() - max_age);
    PERFORM * FROM regano.pending_domains
		WHERE lower(domain_name) = lower(name);
    IF FOUND THEN
	RETURN 'PENDING';
    END IF;

    SELECT * INTO active_domain
	FROM regano.domains WHERE (lower(name) = lower(domain_name));

    IF FOUND THEN
	IF now() < active_domain.expiration THEN
	    RETURN 'REGISTERED';
	ELSE
	    RETURN 'EXPIRED';
	END IF;
    END IF;

    RETURN 'AVAILABLE';
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
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
CREATE OR REPLACE FUNCTION regano_api.user_get_salt_info (text)
	RETURNS regano.password AS $$
DECLARE
    username_	ALIAS FOR $1;

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
CREATE OR REPLACE FUNCTION regano_api.session_logout (uuid) RETURNS void AS $$
DELETE FROM regano.sessions WHERE id = $1
$$ LANGUAGE SQL VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.session_logout (uuid)
	OWNER TO regano;

-- Retrieve username for a session, update session activity timestamp, and
-- perform auto-logout if the session has expired.
CREATE OR REPLACE FUNCTION regano_api.session_check (uuid)
	RETURNS text AS $$
DECLARE
    id		ALIAS FOR $1;

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


-- Begin the process of verifying a contact record.
CREATE OR REPLACE FUNCTION regano_api.contact_verify_begin
	(session_id uuid, contact_id bigint)
	RETURNS void AS $$
DECLARE
    contact	regano.contacts%ROWTYPE;
    session	regano.sessions%ROWTYPE;
BEGIN
    SELECT * INTO STRICT session FROM regano.sessions WHERE id = session_id;
    SELECT * INTO STRICT contact FROM regano.contacts WHERE id = contact_id;

    IF session.user_id <> contact.owner_id THEN
	RAISE EXCEPTION
	'attempt made to verify contact (%) not belonging to current user (%)',
	    contact.id, regano.username(session);
    END IF;

    INSERT INTO regano.contact_verifications (id, key, contact_id)
	VALUES (gen_random_uuid(), gen_random_uuid(), contact_id);
    NOTIFY regano__contact_verifications;

END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.contact_verify_begin (uuid, bigint)
	OWNER TO regano;

-- Complete verification of a contact record.
CREATE OR REPLACE FUNCTION regano_api.contact_verify_complete
	(verification_id uuid, key uuid)
	RETURNS boolean AS $$
<<var>>
DECLARE
    domain_term		CONSTANT interval NOT NULL
			    := (regano.config_get('domain/term')).interval;
    max_age		CONSTANT interval NOT NULL
			    := (regano.config_get('verify/max_age')).interval;

    pending_domain	regano.pending_domains%ROWTYPE;
    verification	regano.contact_verifications%ROWTYPE;

    user_id		bigint;	-- row ID of user record
BEGIN
    -- clean up expired verifications
    DELETE
	FROM regano.contact_verifications
	WHERE start < (CURRENT_TIMESTAMP - max_age);
    -- look up the provided verification ID
    SELECT * INTO verification
	FROM regano.contact_verifications
	WHERE (id = verification_id) AND
	      (contact_verifications.key = contact_verify_complete.key);
    IF NOT FOUND THEN
	RETURN FALSE;
    END IF;
    -- mark email address as verified
    UPDATE regano.contacts
	SET email_verified = TRUE
	WHERE id = verification.contact_id
	RETURNING owner_id INTO STRICT user_id;
    -- check for a pending domain
    SELECT * INTO pending_domain
	FROM regano.pending_domains
	WHERE pending_domains.user_id = var.user_id;
    IF FOUND THEN
	-- register the pending domain
	DELETE
	    FROM regano.pending_domains
	    WHERE domain_name = pending_domain.domain_name;
	INSERT INTO regano.domains (domain_name, owner_id, expiration)
	    VALUES (pending_domain.domain_name, user_id, now() + domain_term);
    END IF;
    -- clean up the successful verification
    DELETE
	FROM regano.contact_verifications
	WHERE id = verification_id;
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.contact_verify_complete (uuid, uuid)
	OWNER TO regano;


-- Register an available domain.
CREATE OR REPLACE FUNCTION regano_api.domain_register
	(uuid, regano.dns_fqdn)
	RETURNS regano.domain_status AS $$
<<var>>
DECLARE
    session_id		ALIAS FOR $1;
    name		ALIAS FOR $2;

    domain_term		CONSTANT interval NOT NULL
			    := (regano.config_get('domain/term')).interval;

    user_id		CONSTANT bigint NOT NULL
			    := regano.session_user_id(session_id);

    verified		boolean;	-- verified email address on file?
BEGIN
    IF regano_api.domain_status(name) <> 'AVAILABLE' THEN
	RETURN regano_api.domain_status(name);
    END IF;


    SELECT email_verified INTO STRICT verified
	FROM regano.users JOIN regano.contacts
	    ON (contact_id = contacts.id)
	WHERE regano.users.id = user_id;

    IF verified THEN
	-- user has a verified email address; register the domain now
	INSERT INTO regano.domains (domain_name, owner_id, expiration)
	    VALUES (name, user_id, now() + domain_term);
	RETURN 'REGISTERED';
    ELSE
	-- no verified email address on file; registration will be pending
	INSERT INTO regano.pending_domains (domain_name, user_id)
	    VALUES (name, user_id);
	RETURN 'PENDING';
    END IF;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.domain_register (uuid, regano.dns_fqdn)
	OWNER TO regano;
