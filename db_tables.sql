-- Regano database table definitions
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

CREATE TABLE IF NOT EXISTS regano.sessions (
	id		uuid PRIMARY KEY,
	user_id		bigint NOT NULL REFERENCES regano.users (id),
	start		timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS regano.contacts (
	id		bigserial PRIMARY KEY,
	owner_id	bigint NOT NULL REFERENCES regano.users (id),
	name		text NOT NULL,
	email		text NOT NULL,
	email_verified	boolean NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS regano.users (
	id		bigserial PRIMARY KEY,
	username	varchar(64) UNIQUE,
	password	varchar, -- TODO: determine password storage
	-- id of primary contact for this user
	contact_id	bigint NOT NULL DEFAULT 0
				REFERENCES regano.contacts (id)
				DEFERRABLE INITIALLY DEFERRED,
	-- timestamp of user registration
	registered	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP
) WITH (fillfactor = 90);

CREATE TABLE IF NOT EXISTS regano.domains (
	id		bigserial PRIMARY KEY,
	domain_name	text UNIQUE,
	owner_id	bigint NOT NULL REFERENCES regano.users (id),
	registered	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expiration	timestamp with time zone NOT NULL,
	last_update	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS regano.domain_records (
	id		bigserial PRIMARY KEY,
	domain_id	bigint NOT NULL REFERENCES regano.domains (id),
	class		regano.dns_record_class NOT NULL DEFAULT 'IN',
	type		regano.dns_record_type NOT NULL,
	label		text NOT NULL,
	-- TODO: define storage for values of each type
) WITH (fillfactor = 90);
