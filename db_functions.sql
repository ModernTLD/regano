-- Regano database function definitions
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
-- The table definitions in db_tables.sql are needed for these to actually work.

-- Inquire about the status of a domain.
CREATE OR REPLACE FUNCTION regano.domain_status
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
ALTER FUNCTION regano.domain_status (dns_fqdn)	OWNER TO regano;


-- Create a new user account.
CREATE OR REPLACE FUNCTION regano.user_register
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
ALTER FUNCTION regano.user_register (text, regano.password, text, text)
	OWNER TO regano;
