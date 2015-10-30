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

CREATE TABLE IF NOT EXISTS regano.users (
	id		bigserial PRIMARY KEY,
	username	varchar(64) UNIQUE,
	password	varchar, -- TODO: determine password storage
	-- id of primary contact for this user
	contact_id	bigint NOT NULL DEFAULT 0,
	-- timestamp of user registration
	registered	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP
);

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
) WITH (fillfactor = 90);

ALTER TABLE regano.users ADD CONSTRAINT users_contact_id_fkey
	FOREIGN KEY (contact_id) REFERENCES regano.contacts (id)
				 DEFERRABLE INITIALLY DEFERRED;

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
	ttl		integer,
	name		regano.dns_name NOT NULL,
	-- typed storage for DNS records
	data_name	regano.dns_name,
	data_text	text,
	data_RR_SOA	regano.dns_RR_SOA,
	data_RR_A	regano.dns_RR_A,
	data_RR_AAAA	regano.dns_RR_AAAA,
	data_RR_DS	regano.dns_RR_DS,
	-- constraints to ensure proper usage
	-- - types using "data_name"
	CHECK(type IN ('CNAME', 'DNAME', 'NS', 'PTR')
		OR data_name IS NULL),
	CHECK(type NOT IN ('CNAME', 'DNAME', 'NS', 'PTR')
		OR data_name IS NOT NULL),
	-- - types using "data_text"
	CHECK(type IN ('SPF', 'TXT') OR data_text IS NULL),
	CHECK(type != 'TXT' OR data_text IS NOT NULL),
	-- TODO: implement validation of SPF data
	CHECK(type != 'SPF' OR data_text IS NOT NULL),
	-- - types using specific fields
	CHECK(type  = 'SOA' OR data_RR_SOA IS NULL),
	CHECK(type != 'SOA' OR data_RR_SOA IS NOT NULL),
	CHECK(type  = 'A' OR data_RR_A IS NULL),
	CHECK(type != 'A' OR data_RR_A IS NOT NULL),
	CHECK(type  = 'AAAA' OR data_RR_AAAA IS NULL),
	CHECK(type != 'AAAA' OR data_RR_AAAA IS NOT NULL),
	CHECK(type  = 'DS' OR data_RR_DS IS NULL),
	CHECK(type != 'DS' OR data_RR_DS IS NOT NULL)
) WITH (fillfactor = 90);
