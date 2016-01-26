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
-- The table definitions in db_tables.sql must already be installed.
-- The function definitions in db_functions.sql must already be installed.
-- The configuration in db_config.sql must be loaded for these to actually work.

-- Inquire about the status of a domain.
CREATE OR REPLACE FUNCTION regano_api.domain_status
	(regano.dns_fqdn)
	RETURNS regano.domain_status AS $$
DECLARE
    name		ALIAS FOR $1;

    max_expired_age	CONSTANT interval NOT NULL
			    := (regano.config_get('domain/grace_period')).interval;
    max_pending_age	CONSTANT interval NOT NULL
			    := (regano.config_get('domain/pend_term')).interval;

    active_domain	regano.domains%ROWTYPE;

    primary_label	regano.dns_label;
    tail		regano.dns_fqdn;
BEGIN
    PERFORM *
	FROM regano.bailiwicks
	WHERE lower(domain_tail) = lower(name)
	    OR lower(domain_tail) = '.'||lower(name);
    IF FOUND THEN
	RETURN 'BAILIWICK';
    END IF;

    primary_label := substring(name from '^([^.]+)[.]');
    tail := substring(name from '^[^.]+([.].+[.])$');

    PERFORM * FROM regano.bailiwicks WHERE lower(domain_tail) = lower(tail);
    IF NOT FOUND THEN
	RETURN 'ELSEWHERE';
    END IF;

    PERFORM * FROM regano.reserved_domains
		WHERE domain_name = lower(primary_label);
    IF FOUND THEN
	RETURN 'RESERVED';
    END IF;

    -- clean up pending domains, then check if the requested domain is pending
    DELETE FROM regano.pending_domains WHERE start < (now() - max_pending_age);
    PERFORM * FROM regano.pending_domains
		WHERE lower(domain_name) = lower(primary_label)
		    AND lower(domain_tail) = lower(tail);
    IF FOUND THEN
	RETURN 'PENDING';
    END IF;

    -- clean up expired domains, then check if the requested domain is active
    DELETE FROM regano.domains WHERE expiration < (now() - max_expired_age);
    SELECT * INTO active_domain
	FROM regano.domains
	WHERE (lower(primary_label) = lower(domain_name))
	    AND (lower(tail) = lower(domain_tail));

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
SELECT CASE WHEN regano_api.domain_status($1) <> 'RESERVED' THEN NULL
	    ELSE reason END
	FROM regano.reserved_domains
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
BEGIN
    INSERT INTO users (username, password, contact_id)
	VALUES (username_, ROW(password_.xdigest, password_.xsalt,
				crypt(password_.digest,
				      gen_salt(crypt_alg, crypt_iter))), 1)
	RETURNING id INTO STRICT new_user_id;
    INSERT INTO contacts (owner_id, id, name, email)
	VALUES (new_user_id, 1, contact_name, contact_email);
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

    UPDATE regano.users
	SET password = new_pw
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
<<var>>
DECLARE
    id		ALIAS FOR $1;

    max_age	CONSTANT interval NOT NULL
		    := (regano.config_get('session/max_age')).interval;
    max_idle	CONSTANT interval NOT NULL
		    := (regano.config_get('session/max_idle')).interval;

    session	regano.sessions%ROWTYPE;
BEGIN
    SELECT * INTO session
	FROM regano.sessions WHERE regano.sessions.id = var.id;
    IF FOUND THEN
	IF ((CURRENT_TIMESTAMP - session.activity) > max_idle) OR
	   ((CURRENT_TIMESTAMP - session.start) > max_age) THEN
	    -- session is expired
	    PERFORM regano_api.session_logout(session.id);
	    RETURN NULL;
	ELSE
	    -- update activity timestamp
	    UPDATE regano.sessions
		SET activity = CURRENT_TIMESTAMP
		WHERE regano.sessions.id = var.id;
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

-- Retrieve the current user's user record, sans password.
CREATE OR REPLACE FUNCTION regano_api.user_info
	(session_id uuid)
	RETURNS regano.users AS $$
DECLARE
    user	regano.users%ROWTYPE;
BEGIN
    SELECT * INTO STRICT user
	FROM regano.users WHERE id = regano.session_user_id(session_id);
    user.password := NULL;
    RETURN user;
END;
$$ LANGUAGE plpgsql STABLE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.user_info (uuid)
	OWNER TO regano;

-- Retrieve the ID of the current user's primary contact record.
CREATE OR REPLACE FUNCTION regano_api.contact_primary_id
	(session_id uuid)
	RETURNS integer AS $$
SELECT contact_id FROM regano.users WHERE id = regano.session_user_id($1)
$$ LANGUAGE SQL STABLE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.contact_primary_id (uuid)
	OWNER TO regano;

-- Change the primary contact for the current user.
CREATE OR REPLACE FUNCTION regano_api.user_set_primary_contact
	(session_id uuid, contact_id integer)
	RETURNS void AS $$
DECLARE
    contact	regano.contacts%ROWTYPE;
    session	regano.sessions%ROWTYPE;
BEGIN
    SELECT * INTO STRICT session FROM regano.sessions WHERE id = session_id;
    SELECT * INTO STRICT contact FROM regano.contacts
	WHERE owner_id = session.user_id AND id = contact_id;

    IF NOT contact.email_verified THEN
	RAISE EXCEPTION
	'Only a verified email address may be set as primary contact.';
    END IF;

    UPDATE regano.users
	SET contact_id = contact.id
	WHERE id = session.user_id;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.user_set_primary_contact (uuid, integer)
	OWNER TO regano;

-- Retrieve all contact records belonging to the current user.
CREATE OR REPLACE FUNCTION regano_api.contact_list
	(session_id uuid)
	RETURNS SETOF regano.contacts AS $$
SELECT * FROM regano.contacts WHERE owner_id = regano.session_user_id($1)
$$ LANGUAGE SQL STABLE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.contact_list (uuid)
	OWNER TO regano;

-- Add a contact record for the current user.
CREATE OR REPLACE FUNCTION regano_api.contact_add
	(session_id uuid, name text, email text)
	RETURNS integer AS $$
INSERT INTO regano.contacts (owner_id, id, name, email)
    VALUES (regano.session_user_id($1),
	    regano.contact_next_id(regano.session_user_id($1)), $2, $3)
    RETURNING id;
$$ LANGUAGE SQL VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.contact_add (uuid, text, text)
	OWNER TO regano;

-- Remove a contact record for the current user.
CREATE OR REPLACE FUNCTION regano_api.contact_remove
	(session_id uuid, contact_id integer)
	RETURNS void AS $$
DECLARE
    user_id	CONSTANT bigint NOT NULL
		    := regano.session_user_id(session_id);
    renumbering	CURSOR (user_id bigint)
		    FOR SELECT id
			    FROM regano.contacts
			    WHERE owner_id = user_id
			    ORDER BY id
			    FOR UPDATE;
    i		integer := 0;
BEGIN
    DELETE
	FROM regano.contacts
	WHERE owner_id = user_id AND id = contact_id;
    FOR contact IN renumbering (user_id) LOOP
	i := i + 1;
	UPDATE regano.contacts
	    SET id = i
	    WHERE CURRENT OF renumbering;
    END LOOP;
END
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.contact_remove (uuid, integer)
	OWNER TO regano;

-- Update the name field of a contact record.
CREATE OR REPLACE FUNCTION regano_api.contact_update_name
	(session_id uuid, contact_id integer, value text)
	RETURNS void AS $$
DECLARE
    contact	regano.contacts%ROWTYPE;
    session	regano.sessions%ROWTYPE;
BEGIN
    SELECT * INTO STRICT session FROM regano.sessions WHERE id = session_id;
    SELECT * INTO STRICT contact FROM regano.contacts
	WHERE owner_id = session.user_id AND id = contact_id
	FOR UPDATE;

    UPDATE regano.contacts
	SET name = value
	WHERE owner_id = session.user_id AND id = contact_id;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.contact_update_name (uuid, integer, text)
	OWNER TO regano;

-- Update the email address field of a contact record.
CREATE OR REPLACE FUNCTION regano_api.contact_update_email
	(session_id uuid, contact_id integer, value text)
	RETURNS void AS $$
DECLARE
    contact		regano.contacts%ROWTYPE;
    session		regano.sessions%ROWTYPE;

    primary_contact_id	integer;
BEGIN
    SELECT * INTO STRICT session FROM regano.sessions WHERE id = session_id;
    SELECT users.contact_id INTO STRICT primary_contact_id
	FROM regano.users WHERE id = session.user_id;
    SELECT * INTO STRICT contact FROM regano.contacts
	WHERE owner_id = session.user_id AND id = contact_id
	FOR UPDATE;

    IF contact_id = primary_contact_id AND contact.email_verified THEN
	RAISE EXCEPTION
	'Verified email address (%) for primary contact (%) may not be changed.',
	    contact.email, contact_id;
    END IF;

    -- cancel any in-progress address verification
    DELETE FROM regano.contact_verifications
	WHERE contact_verifications.contact_id = contact.id;
    -- change the stored email address
    UPDATE regano.contacts
	SET email_verified = FALSE, email = value
	WHERE owner_id = session.user_id AND id = contact_id;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.contact_update_email (uuid, integer, text)
	OWNER TO regano;


-- Begin the process of verifying a contact record.
CREATE OR REPLACE FUNCTION regano_api.contact_verify_begin
	(session_id uuid, contact_id integer)
	RETURNS void AS $$
DECLARE
    contact	regano.contacts%ROWTYPE;
    session	regano.sessions%ROWTYPE;
BEGIN
    SELECT * INTO STRICT session FROM regano.sessions WHERE id = session_id;
    SELECT * INTO STRICT contact FROM regano.contacts
	WHERE owner_id = session.user_id AND id = contact_id;

    DELETE FROM regano.contact_verifications
	WHERE contact_verifications.contact_id = contact_verify_begin.contact_id
	  AND contact_verifications.user_id = session.user_id;
    INSERT INTO regano.contact_verifications (id, key, user_id, contact_id)
	VALUES (gen_random_uuid(), gen_random_uuid(),
		session.user_id, contact_id);
    NOTIFY regano__contact_verifications;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.contact_verify_begin (uuid, integer)
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

    is_primary_contact	boolean;
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
	WHERE owner_id = verification.user_id AND id = verification.contact_id;
    -- check if a primary contact was verified
    SELECT users.contact_id = verification.contact_id
	INTO STRICT is_primary_contact
	FROM regano.users
	WHERE id = verification.user_id;
    -- check for a pending domain
    SELECT * INTO pending_domain
	FROM regano.pending_domains
	WHERE pending_domains.user_id = verification.user_id;
    IF FOUND AND is_primary_contact THEN
	-- register the pending domain
	DELETE
	    FROM regano.pending_domains
	    WHERE domain_name = pending_domain.domain_name
		AND domain_tail = pending_domain.domain_tail;
	INSERT INTO regano.domains
	    (domain_name, domain_tail, owner_id, expiration)
	    VALUES (pending_domain.domain_name, pending_domain.domain_tail,
		    verification.user_id, now() + domain_term);
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


-- Retrieve information about a pending domain belonging to the current user.
CREATE OR REPLACE FUNCTION regano_api.domain_check_pending
	(uuid)
	RETURNS regano.pending_domain AS $$
SELECT  domain_name||domain_tail AS name,
	start, start + regano.config_get('domain/pend_term') AS expire
    FROM regano.pending_domains WHERE user_id = regano.session_user_id($1)
$$ LANGUAGE SQL STABLE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.domain_check_pending (uuid)
	OWNER TO regano;

-- Retrieve all domains belonging to the current user.
-- The domain table is public; this is for the account overview page.
CREATE OR REPLACE FUNCTION regano_api.domain_list
	(uuid)
	RETURNS SETOF regano.domain AS $$
SELECT domain_name||domain_tail AS name, registered, expiration, last_update,
	CASE WHEN now() < expiration
	     THEN 'REGISTERED'::regano.domain_status
	     ELSE 'EXPIRED'::regano.domain_status
	END AS status
    FROM regano.domains WHERE owner_id = regano.session_user_id($1)
$$ LANGUAGE SQL STABLE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.domain_list (uuid)
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

    primary_label	regano.dns_label;
    tail		regano.dns_fqdn;
BEGIN
    primary_label := substring(name from '^([^.]+)[.]');
    tail := substring(name from '^[^.]+([.].+[.])$');

    IF regano_api.domain_status(name) <> 'AVAILABLE' THEN
	RETURN regano_api.domain_status(name);
    END IF;

    SELECT email_verified INTO STRICT verified
	FROM regano.users JOIN regano.contacts
	    ON owner_id = user_id AND contact_id = contacts.id
	WHERE regano.users.id = user_id;

    IF verified THEN
	-- user has a verified email address; register the domain now
	INSERT INTO regano.domains
	    (domain_name, domain_tail, owner_id, expiration)
	    VALUES (primary_label, tail, user_id, now() + domain_term);
	RETURN 'REGISTERED';
    ELSE
	-- no verified email address on file; registration will be pending
	INSERT INTO regano.pending_domains
	    (domain_name, domain_tail, user_id)
	    VALUES (primary_label, tail, user_id);
	RETURN 'PENDING';
    END IF;
END;
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.domain_register (uuid, regano.dns_fqdn)
	OWNER TO regano;

-- Renew a domain
CREATE OR REPLACE FUNCTION regano_api.domain_renew
	(uuid, regano.dns_fqdn)
	RETURNS timestamp with time zone AS $$
DECLARE
    session_id		ALIAS FOR $1;
    name		ALIAS FOR $2;

    domain_term		CONSTANT interval NOT NULL
			    := (regano.config_get('domain/term')).interval;

    user_id		CONSTANT bigint NOT NULL
			    := regano.session_user_id(session_id);

    primary_label	regano.dns_label;
    tail		regano.dns_fqdn;

    domain		regano.domains%ROWTYPE;
    result		timestamp with time zone;
BEGIN
    primary_label := substring(name from '^([^.]+)[.]');
    tail := substring(name from '^[^.]+([.].+[.])$');

    SELECT * INTO STRICT domain
	FROM regano.domains
	WHERE (lower(primary_label) = lower(domain_name))
	    AND (lower(tail) = lower(domain_tail))
	FOR UPDATE;

    IF user_id <> domain.owner_id THEN
	RAISE EXCEPTION
	'attempt made to renew domain (%) not belonging to current user (%)',
	    name, regano.username(session_id);
    END IF;

    UPDATE regano.domains
	SET expiration = now() + domain_term,
	    last_update = now()
	WHERE id = domain.id
	RETURNING expiration INTO STRICT result;
    RETURN result;
END
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.domain_renew (uuid, regano.dns_fqdn)
	OWNER TO regano;

-- Immediately expire a domain
CREATE OR REPLACE FUNCTION regano_api.domain_release
	(uuid, regano.dns_fqdn)
	RETURNS void AS $$
DECLARE
    session_id		ALIAS FOR $1;
    name		ALIAS FOR $2;

    user_id		CONSTANT bigint NOT NULL
			    := regano.session_user_id(session_id);

    primary_label	regano.dns_label;
    tail		regano.dns_fqdn;

    domain		regano.domains%ROWTYPE;
BEGIN
    primary_label := substring(name from '^([^.]+)[.]');
    tail := substring(name from '^[^.]+([.].+[.])$');

    SELECT * INTO STRICT domain
	FROM regano.domains
	WHERE (lower(primary_label) = lower(domain_name))
	    AND (lower(tail) = lower(domain_tail))
	FOR UPDATE;

    IF user_id <> domain.owner_id THEN
	RAISE EXCEPTION
	'attempt made to release domain (%) not belonging to current user (%)',
	    name, regano.username(session_id);
    END IF;

    UPDATE regano.domains
	SET expiration = now(),
	    last_update = now()
	WHERE id = domain.id;
END
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.domain_release (uuid, regano.dns_fqdn)
	OWNER TO regano;

-- Set default TTL for records in a domain
CREATE OR REPLACE FUNCTION regano_api.domain_set_default_ttl
	(uuid, regano.dns_fqdn, regano.dns_interval)
	RETURNS void AS $$
DECLARE
    session_id		ALIAS FOR $1;
    name		ALIAS FOR $2;
    new_ttl		ALIAS FOR $3;

    user_id		CONSTANT bigint NOT NULL
			    := regano.session_user_id(session_id);

    primary_label	regano.dns_label;
    tail		regano.dns_fqdn;

    domain		regano.domains%ROWTYPE;
BEGIN
    primary_label := substring(name from '^([^.]+)[.]');
    tail := substring(name from '^[^.]+([.].+[.])$');

    SELECT * INTO STRICT domain
	FROM regano.domains
	WHERE (lower(primary_label) = lower(domain_name))
	    AND (lower(tail) = lower(domain_tail))
	FOR UPDATE;

    IF user_id <> domain.owner_id THEN
	RAISE EXCEPTION
	'attempt made to set TTL for domain (%) not belonging to current user (%)',
	    name, regano.username(session_id);
    END IF;

    UPDATE regano.domains
	SET default_ttl = new_ttl,
	    last_update = now()
	WHERE id = domain.id;
END
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.domain_set_default_ttl
	(uuid, regano.dns_fqdn, regano.dns_interval)
	OWNER TO regano;

-- Updating domain records is done in multiple steps, all in a single
-- database transaction.  First, the existing records for the domain are
-- removed.  Second, new records are inserted in order.  Third, the
-- database transaction is committed.

-- Remove existing records for a domain
CREATE OR REPLACE FUNCTION regano_api.zone_clear
	(session_id	uuid,
	 zone_name	regano.dns_fqdn)
	RETURNS void AS $$
DECLARE
    domain		regano.domains%ROWTYPE;
BEGIN
    domain := regano.zone_verify_access(session_id, zone_name, 'clear zone');

    DELETE
	FROM regano.domain_records
	WHERE domain_id = domain.id;
    UPDATE regano.domains
	SET last_update = now()
	WHERE id = domain.id;
END
$$ LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER;
ALTER FUNCTION regano_api.zone_clear (uuid, regano.dns_fqdn)
	OWNER TO regano;

-- Add an SOA record for a domain
-- NOTE: A domain may only have one SOA record, at the domain root, with
-- sequence number zero.
CREATE OR REPLACE FUNCTION regano_api.zone_add_SOA
	(session_id	uuid,
	 zone_name	regano.dns_fqdn,
	 rec_ttl	regano.dns_interval,
	 SOA_mbox	regano.dns_email,
	 SOA_refresh	regano.dns_interval,
	 SOA_retry	regano.dns_interval,
	 SOA_expire	regano.dns_interval,
	 SOA_minimum	regano.dns_interval)
	RETURNS void AS $$
DECLARE
    domain		regano.domains%ROWTYPE;
BEGIN
    domain := regano.zone_verify_access(session_id, zone_name, 'add SOA');

    INSERT INTO regano.domain_records
	(domain_id, seq_no, type, name, ttl, data_RR_SOA)
	VALUES (domain.id, 0, 'SOA', '@', rec_ttl,
		ROW(zone_name, SOA_mbox, SOA_refresh, SOA_retry,
		    SOA_expire, SOA_minimum));
    UPDATE regano.domains
	SET last_update = now()
	WHERE id = domain.id;
END
$$ LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT SECURITY DEFINER;
ALTER FUNCTION regano_api.zone_add_SOA
	(uuid, regano.dns_fqdn, regano.dns_interval, regano.dns_email,
	 regano.dns_interval, regano.dns_interval, regano.dns_interval,
	 regano.dns_interval)
	OWNER TO regano;

-- Add a record that stores another DNS name
CREATE OR REPLACE FUNCTION regano_api.zone_add_name
	(session_id	uuid,
	 zone_name	regano.dns_fqdn,
	 rec_ttl	regano.dns_interval,
	 rec_name	regano.dns_name,
	 rec_type	regano.dns_record_type,
	 rec_data	regano.dns_name)
	RETURNS void AS $$
DECLARE
    domain		regano.domains%ROWTYPE;
    new_seq_no		bigint;
    rec_name_c		CONSTANT regano.dns_name NOT NULL
			    := regano.canonicalize_record_name(rec_name,
							       zone_name);
BEGIN
    domain := regano.zone_verify_access(session_id, zone_name, 'add name');
    new_seq_no := regano.zone_next_seq_no(domain.id);

    INSERT INTO regano.domain_records
	(domain_id, seq_no, type, name, ttl, data_name)
	VALUES (domain.id, new_seq_no, rec_type, rec_name_c, rec_ttl, rec_data);
    UPDATE regano.domains
	SET last_update = now()
	WHERE id = domain.id;
END
$$ LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT SECURITY DEFINER;
ALTER FUNCTION regano_api.zone_add_name
	(uuid, regano.dns_fqdn, regano.dns_interval, regano.dns_name,
	 regano.dns_record_type, regano.dns_name)
	OWNER TO regano;

-- Add a record that stores free-form text
CREATE OR REPLACE FUNCTION regano_api.zone_add_text
	(session_id	uuid,
	 zone_name	regano.dns_fqdn,
	 rec_ttl	regano.dns_interval,
	 rec_name	regano.dns_name,
	 rec_type	regano.dns_record_type,
	 rec_data	text)
	RETURNS void AS $$
DECLARE
    domain		regano.domains%ROWTYPE;
    new_seq_no		bigint;
    rec_name_c		CONSTANT regano.dns_name NOT NULL
			    := regano.canonicalize_record_name(rec_name,
							       zone_name);
BEGIN
    domain := regano.zone_verify_access(session_id, zone_name, 'add text');
    new_seq_no := regano.zone_next_seq_no(domain.id);

    INSERT INTO regano.domain_records
	(domain_id, seq_no, type, name, ttl, data_text)
	VALUES (domain.id, new_seq_no, rec_type, rec_name_c, rec_ttl, rec_data);
    UPDATE regano.domains
	SET last_update = now()
	WHERE id = domain.id;
END
$$ LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT SECURITY DEFINER;
ALTER FUNCTION regano_api.zone_add_text
	(uuid, regano.dns_fqdn, regano.dns_interval, regano.dns_name,
	 regano.dns_record_type, text)
	OWNER TO regano;

-- Add an A record
CREATE OR REPLACE FUNCTION regano_api.zone_add_A
	(session_id	uuid,
	 zone_name	regano.dns_fqdn,
	 rec_ttl	regano.dns_interval,
	 rec_name	regano.dns_name,
	 rec_data	regano.dns_RR_A)
	RETURNS void AS $$
DECLARE
    domain		regano.domains%ROWTYPE;
    new_seq_no		bigint;
    rec_name_c		CONSTANT regano.dns_name NOT NULL
			    := regano.canonicalize_record_name(rec_name,
							       zone_name);
BEGIN
    domain := regano.zone_verify_access(session_id, zone_name, 'add A');
    new_seq_no := regano.zone_next_seq_no(domain.id);

    INSERT INTO regano.domain_records
	(domain_id, seq_no, type, name, ttl, data_RR_A)
	VALUES (domain.id, new_seq_no, 'A', rec_name_c, rec_ttl, rec_data);
    UPDATE regano.domains
	SET last_update = now()
	WHERE id = domain.id;
END
$$ LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT SECURITY DEFINER;
ALTER FUNCTION regano_api.zone_add_A
	(uuid, regano.dns_fqdn, regano.dns_interval, regano.dns_name,
	 regano.dns_RR_A)
	OWNER TO regano;

-- Add an AAAA record
CREATE OR REPLACE FUNCTION regano_api.zone_add_AAAA
	(session_id	uuid,
	 zone_name	regano.dns_fqdn,
	 rec_ttl	regano.dns_interval,
	 rec_name	regano.dns_name,
	 rec_data	regano.dns_RR_AAAA)
	RETURNS void AS $$
DECLARE
    domain		regano.domains%ROWTYPE;
    new_seq_no		bigint;
    rec_name_c		CONSTANT regano.dns_name NOT NULL
			    := regano.canonicalize_record_name(rec_name,
							       zone_name);
BEGIN
    domain := regano.zone_verify_access(session_id, zone_name, 'add AAAA');
    new_seq_no := regano.zone_next_seq_no(domain.id);

    INSERT INTO regano.domain_records
	(domain_id, seq_no, type, name, ttl, data_RR_AAAA)
	VALUES (domain.id, new_seq_no, 'AAAA', rec_name_c, rec_ttl, rec_data);
    UPDATE regano.domains
	SET last_update = now()
	WHERE id = domain.id;
END
$$ LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT SECURITY DEFINER;
ALTER FUNCTION regano_api.zone_add_AAAA
	(uuid, regano.dns_fqdn, regano.dns_interval, regano.dns_name,
	 regano.dns_RR_AAAA)
	OWNER TO regano;

-- Add a DS record
CREATE OR REPLACE FUNCTION regano_api.zone_add_DS
	(session_id	uuid,
	 zone_name	regano.dns_fqdn,
	 rec_ttl	regano.dns_interval,
	 rec_name	regano.dns_name,
	 DS_key_tag	regano.uint16bit,
	 DS_algorithm	regano.uint8bit,
	 DS_digest_type	regano.uint8bit,
	 DS_digest	regano.hexstring)
	RETURNS void AS $$
DECLARE
    domain		regano.domains%ROWTYPE;
    new_seq_no		bigint;
    rec_name_c		CONSTANT regano.dns_name NOT NULL
			    := regano.canonicalize_record_name(rec_name,
							       zone_name);
BEGIN
    domain := regano.zone_verify_access(session_id, zone_name, 'add DS');
    new_seq_no := regano.zone_next_seq_no(domain.id);

    INSERT INTO regano.domain_records
	(domain_id, seq_no, type, name, ttl, data_RR_DS)
	VALUES (domain.id, new_seq_no, 'DS', rec_name_c, rec_ttl,
		ROW(DS_key_tag, DS_algorithm, DS_digest_type, DS_digest));
    UPDATE regano.domains
	SET last_update = now()
	WHERE id = domain.id;
END
$$ LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT SECURITY DEFINER;
ALTER FUNCTION regano_api.zone_add_DS
	(uuid, regano.dns_fqdn, regano.dns_interval, regano.dns_name,
	 regano.uint16bit, regano.uint8bit, regano.uint8bit,
	 regano.hexstring)
	OWNER TO regano;

-- Add an MX record
CREATE OR REPLACE FUNCTION regano_api.zone_add_MX
	(session_id	uuid,
	 zone_name	regano.dns_fqdn,
	 rec_ttl	regano.dns_interval,
	 rec_name	regano.dns_name,
	 MX_preference	regano.uint16bit,
	 MX_exchange	regano.dns_name)
	RETURNS void AS $$
DECLARE
    domain		regano.domains%ROWTYPE;
    new_seq_no		bigint;
    rec_name_c		CONSTANT regano.dns_name NOT NULL
			    := regano.canonicalize_record_name(rec_name,
							       zone_name);
BEGIN
    domain := regano.zone_verify_access(session_id, zone_name, 'add MX');
    new_seq_no := regano.zone_next_seq_no(domain.id);

    INSERT INTO regano.domain_records
	(domain_id, seq_no, type, name, ttl, data_RR_MX)
	VALUES (domain.id, new_seq_no, 'MX', rec_name_c, rec_ttl,
		ROW(MX_preference, MX_exchange));
    UPDATE regano.domains
	SET last_update = now()
	WHERE id = domain.id;
END
$$ LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT SECURITY DEFINER;
ALTER FUNCTION regano_api.zone_add_MX
	(uuid, regano.dns_fqdn, regano.dns_interval, regano.dns_name,
	 regano.uint16bit, regano.dns_name)
	OWNER TO regano;

-- Add a SRV record
CREATE OR REPLACE FUNCTION regano_api.zone_add_SRV
	(session_id	uuid,
	 zone_name	regano.dns_fqdn,
	 rec_ttl	regano.dns_interval,
	 rec_name	regano.dns_name,
	 SRV_priority	regano.uint16bit,
	 SRV_weight	regano.uint16bit,
	 SRV_port	regano.uint16bit,
	 SRV_target	regano.dns_fqdn)
	RETURNS void AS $$
DECLARE
    domain		regano.domains%ROWTYPE;
    new_seq_no		bigint;
    rec_name_c		CONSTANT regano.dns_name NOT NULL
			    := regano.canonicalize_record_name(rec_name,
							       zone_name);
BEGIN
    domain := regano.zone_verify_access(session_id, zone_name, 'add SRV');
    new_seq_no := regano.zone_next_seq_no(domain.id);

    INSERT INTO regano.domain_records
	(domain_id, seq_no, type, name, ttl, data_RR_SRV)
	VALUES (domain.id, new_seq_no, 'SRV', rec_name_c, rec_ttl,
		ROW(SRV_priority, SRV_weight, SRV_port, SRV_target));
    UPDATE regano.domains
	SET last_update = now()
	WHERE id = domain.id;
END
$$ LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT SECURITY DEFINER;
ALTER FUNCTION regano_api.zone_add_SRV
	(uuid, regano.dns_fqdn, regano.dns_interval, regano.dns_name,
	 regano.uint16bit, regano.uint16bit, regano.uint16bit,
	 regano.dns_fqdn)
	OWNER TO regano;
