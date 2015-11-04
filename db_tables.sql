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

-- Internal configuration options
CREATE TABLE IF NOT EXISTS regano.config (
	key		text PRIMARY KEY,
	number		bigint,
	interval	interval,
	text		text,
	CHECK(number IS NOT NULL OR interval IS NOT NULL OR text IS NOT NULL)
) WITH (fillfactor = 95);

-- Users
CREATE TABLE IF NOT EXISTS regano.users (
	id		bigserial PRIMARY KEY,
	username	varchar(64) UNIQUE,
	password	regano.password,
	-- id of primary contact for this user
	contact_id	bigint NOT NULL DEFAULT 0,
	-- timestamp of user registration
	registered	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP
) WITH (fillfactor = 90);

-- Active sessions
CREATE TABLE IF NOT EXISTS regano.sessions (
	id		uuid PRIMARY KEY,
	user_id		bigint NOT NULL REFERENCES regano.users (id),
	start		timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Contact information for users and domains
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

-- Domains under which this instance can process registrations
CREATE TABLE IF NOT EXISTS regano.bailiwicks (
	domain_tail	text PRIMARY KEY
				CHECK(domain_tail LIKE '.%.')
);

-- Domains reserved at second-level, just inside every bailiwick
CREATE TABLE IF NOT EXISTS regano.reserved_domains (
	domain_name	regano.dns_label PRIMARY KEY,
	reason		text NOT NULL,
	CONSTRAINT "Reserved domains must be entered as lowercase"
		CHECK(lower(domain_name) = domain_name)
);

-- Domains pending (pre-registered, user not yet verified, etc.)
CREATE TABLE IF NOT EXISTS regano.pending_domains (
	domain_name	regano.dns_fqdn PRIMARY KEY
);
CREATE UNIQUE INDEX pending_domains_domain_name_lower_case_unique
	ON regano.pending_domains (lower(domain_name));

-- Domains registered in this instance
CREATE TABLE IF NOT EXISTS regano.domains (
	id		bigserial PRIMARY KEY,
	domain_name	regano.dns_fqdn UNIQUE,
	owner_id	bigint NOT NULL REFERENCES regano.users (id),
	registered	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expiration	timestamp with time zone NOT NULL,
	last_update	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX domains_domain_name_lower_case_unique
	ON regano.domains (lower(domain_name));

-- DNS records hosted by this instance
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
	CHECK((type IN ('CNAME', 'DNAME', 'NS', 'PTR'))
		= (data_name IS NOT NULL)),
	-- - types using "data_text"
	CHECK((type IN ('SPF', 'TXT')) = (data_text IS NOT NULL)),
	-- TODO: implement validation of SPF data
	CHECK(type != 'SPF' OR data_text IS NOT NULL),
	-- - types using specific fields
	CHECK((type =  'SOA') = (data_RR_SOA IS NOT NULL)),
	CHECK((type =    'A') = (data_RR_A IS NOT NULL)),
	CHECK((type = 'AAAA') = (data_RR_AAAA IS NOT NULL)),
	CHECK((type =   'DS') = (data_RR_DS IS NOT NULL))
	-- TODO: ensure that a domain can have at most one SOA record
) WITH (fillfactor = 90);


ALTER TABLE regano.config OWNER TO regano;
ALTER TABLE regano.users OWNER TO regano;
ALTER TABLE regano.sessions OWNER TO regano;
ALTER TABLE regano.contacts OWNER TO regano;
ALTER TABLE regano.bailiwicks OWNER TO regano;
ALTER TABLE regano.reserved_domains OWNER TO regano;
ALTER TABLE regano.pending_domains OWNER TO regano;
ALTER TABLE regano.domains OWNER TO regano;
ALTER TABLE regano.domain_records OWNER TO regano;
