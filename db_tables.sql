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
	contact_id	integer NOT NULL DEFAULT 0,
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
	activity	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX ON regano.sessions (start);

-- Contact information for users and domains
CREATE TABLE IF NOT EXISTS regano.contacts (
	owner_id	bigint NOT NULL REFERENCES regano.users (id),
	id		integer NOT NULL,
	name		text NOT NULL,
	email		text NOT NULL,
	email_verified	boolean NOT NULL DEFAULT FALSE,
	PRIMARY KEY(owner_id, id)
) WITH (fillfactor = 90);
CREATE INDEX ON regano.contacts (owner_id);

ALTER TABLE regano.users ADD CONSTRAINT users_contact_id_fkey
	FOREIGN KEY (id, contact_id)
		REFERENCES regano.contacts (owner_id, id)
			DEFERRABLE INITIALLY DEFERRED;

-- Email verifications not yet completed
CREATE TABLE IF NOT EXISTS regano.contact_verifications (
	id		uuid PRIMARY KEY,
	key		uuid NOT NULL,
	user_id		bigint NOT NULL,
	contact_id	integer NOT NULL,
	email_sent	boolean NOT NULL DEFAULT FALSE,
	start		timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE (user_id, contact_id),
	FOREIGN KEY (user_id, contact_id)
		REFERENCES regano.contacts (owner_id, id)
);
CREATE INDEX ON regano.contact_verifications (start);

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
	domain_name	regano.dns_label NOT NULL,
	domain_tail	regano.dns_fqdn NOT NULL
				REFERENCES regano.bailiwicks (domain_tail),
	PRIMARY KEY(domain_name, domain_tail),
	-- An unverified user can only have one domain pending.
	-- A verified user immediately registers domains.
	-- Pre-registered domains do not have an associated contact.
	user_id		bigint UNIQUE
				REFERENCES regano.users (id),
	start		timestamp with time zone
				DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX pending_domains_domain_name_domain_tail_lower_case_key
	ON regano.pending_domains (lower(domain_name), lower(domain_tail));
CREATE INDEX ON regano.pending_domains (start);

-- Domains registered in this instance
CREATE TABLE IF NOT EXISTS regano.domains (
	id		bigserial PRIMARY KEY,
	domain_name	regano.dns_label NOT NULL,
	domain_tail	regano.dns_fqdn NOT NULL
				REFERENCES regano.bailiwicks (domain_tail),
	UNIQUE(domain_name, domain_tail),
	owner_id	bigint NOT NULL REFERENCES regano.users (id),
	default_ttl	regano.dns_interval NOT NULL
				DEFAULT interval '1 day',
	registered	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expiration	timestamp with time zone NOT NULL,
	last_update	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX domains_domain_name_domain_tail_lower_case_key
	ON regano.domains (lower(domain_name), lower(domain_tail));

-- DNS records hosted by this instance
CREATE TABLE IF NOT EXISTS regano.domain_records (
	domain_id	bigint NOT NULL REFERENCES regano.domains (id)
				ON DELETE CASCADE,
	seq_no		bigint NOT NULL CHECK(seq_no >= 0),
	class		regano.dns_record_class NOT NULL DEFAULT 'IN',
	type		regano.dns_record_type NOT NULL,
	ttl		regano.dns_interval,
	name		regano.dns_name NOT NULL CHECK(name NOT LIKE '%.'),
	-- typed storage for DNS records
	data_name	regano.dns_name,
	data_text	text,
	data_RR_SOA	regano.dns_RR_SOA,
	data_RR_A	regano.dns_RR_A,
	data_RR_AAAA	regano.dns_RR_AAAA,
	data_RR_DS	regano.dns_RR_DS,
	data_RR_MX	regano.dns_RR_MX,
	data_RR_SRV	regano.dns_RR_SRV,
	-- primary key
	PRIMARY KEY(domain_id, seq_no),
	-- constraints to ensure proper usage
	-- - sequence number 0 is reserved for SOA record
	CHECK((seq_no = 0) = (type = 'SOA')),
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
	CHECK((type =   'DS') = (data_RR_DS IS NOT NULL)),
	CHECK((type =   'MX') = (data_RR_MX IS NOT NULL)),
	CHECK((type =  'SRV') = (data_RR_SRV IS NOT NULL))
) WITH (fillfactor = 90);


ALTER TABLE regano.config OWNER TO regano;
ALTER TABLE regano.users OWNER TO regano;
ALTER TABLE regano.sessions OWNER TO regano;
ALTER TABLE regano.contacts OWNER TO regano;
ALTER TABLE regano.contact_verifications OWNER TO regano;
ALTER TABLE regano.bailiwicks OWNER TO regano;
ALTER TABLE regano.reserved_domains OWNER TO regano;
ALTER TABLE regano.pending_domains OWNER TO regano;
ALTER TABLE regano.domains OWNER TO regano;
ALTER TABLE regano.domain_records OWNER TO regano;
