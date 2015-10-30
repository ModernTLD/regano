-- Regano database type definitions
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


-- The role 'regano' must already exist.

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

CREATE SCHEMA IF NOT EXISTS regano AUTHORIZATION regano;

-- This is an unsigned 8 bit integer.
CREATE DOMAIN regano.uint8bit AS smallint
	CHECK(VALUE >= 0 AND VALUE < 256);
-- This is an unsigned 16 bit integer.
CREATE DOMAIN regano.uint16bit AS integer
	CHECK(VALUE >= 0 AND VALUE < 65536);
-- This is an unsigned 32 bit integer.
CREATE DOMAIN regano.uint32bit AS bigint
	CHECK(VALUE >= 0 AND VALUE < 4294967296);
-- This is an interval, less than 2^31 seconds long.
CREATE DOMAIN regano.dns_interval AS interval
	CHECK(EXTRACT(EPOCH FROM VALUE)::bigint < 2147483648);
-- This is binary data, as hexadecimal digits.
CREATE DOMAIN regano.hexstring AS text
	CHECK(VALUE SIMILAR TO '([0123456789ABCDEF]{2})+');
-- This is a name in the DNS.
CREATE DOMAIN regano.dns_name AS text;
-- This is a Fully Qualified Domain Name.
CREATE DOMAIN regano.dns_fqdn AS regano.dns_name
	CHECK(VALUE LIKE '%.');
-- This is an email address, encoded into a DNS name.
CREATE DOMAIN regano.dns_email AS regano.dns_fqdn
	CHECK(VALUE LIKE '%.%.%.');

ALTER DOMAIN regano.uint8bit		OWNER TO regano;
ALTER DOMAIN regano.uint16bit		OWNER TO regano;
ALTER DOMAIN regano.uint32bit		OWNER TO regano;
ALTER DOMAIN regano.dns_interval	OWNER TO regano;
ALTER DOMAIN regano.hexstring		OWNER TO regano;
ALTER DOMAIN regano.dns_name		OWNER TO regano;
ALTER DOMAIN regano.dns_fqdn		OWNER TO regano;
ALTER DOMAIN regano.dns_email		OWNER TO regano;

-- These are the DNS record classes defined in RFC 1035.
CREATE TYPE regano.dns_record_class AS ENUM (
	'IN',	-- Internet
	'CS',	-- CSNET (obsolete even before RFC 1035)
	'CH',	-- CHAOSnet
	'HS'	-- Hesiod
);

-- The allowed record types are a subset of those supported in BIND.
CREATE TYPE regano.dns_record_type AS ENUM (
	'SOA',		-- RFC 1035: start of authority record
	'A',		-- RFC 1035: IPv4 address
	'AAAA',		-- RFC 1886: IPv6 address
	-- TODO: CERT? (RFC 2538)
	'CNAME',	-- RFC 1035: canonical name of alias
	'DNAME',	-- RFC 2672: delegation alias
	-- TODO: are DNSSEC records other than DS needed?
	'DS',		-- RFC 4034: delegation signer
	-- TODO: IPSECKEY? (RFC 4025)
	-- TODO: LOC? (RFC 1876)
	'MX',		-- RFC 1035: mail exchange
	-- TODO: NAPTR? (RFC 2915)
	'NS',		-- RFC 1035: authoritative name server
	'PTR',		-- RFC 1035: domain name pointer
	-- TODO: RP? (RFC 1183)
	'SPF',		-- RFC 4408: Sender Policy Framework record
	'SRV',		-- RFC 2782: service location
	-- TODO: SSHFP? (RFC 4255)
	'TXT'		-- RFC 1035: general descriptive text
);

ALTER TYPE regano.dns_record_class	OWNER TO regano;
ALTER TYPE regano.dns_record_type	OWNER TO regano;

-- SOA RDATA per RFC 1035 3.3.13
CREATE TYPE regano.dns_RR_SOA AS (
	-- MNAME:	zone name
	zone		regano.dns_name,
	-- RNAME:	email address for zone admin
	mbox		regano.dns_email,
	-- SERIAL:	zone data revision
	serial		regano.uint32bit,
	-- REFRESH:	refresh interval
	refresh		regano.dns_interval,
	-- RETRY:	retry interval if refresh fails
	retry		regano.dns_interval,
	-- EXPIRE:	lifespan of zone data if refresh continues to fail
	expire		regano.dns_interval,
	-- MINIMUM:	minimum TTL of any record in this zone
	minimum		regano.dns_interval
);

-- A RDATA per RFC 1035 3.4.1
CREATE DOMAIN regano.dns_RR_A AS inet
	CONSTRAINT "an A record must hold an IPv4 address"
		CHECK(family(VALUE) = 4 AND masklen(VALUE) = 32);
ALTER DOMAIN regano.dns_RR_A		OWNER TO regano;

-- AAAA RDATA per RFC 1886
CREATE DOMAIN regano.dns_RR_AAAA AS inet
	CONSTRAINT "an AAAA record must hold an IPv6 address"
		CHECK(family(VALUE) = 6 AND masklen(VALUE) = 128);
ALTER DOMAIN regano.dns_RR_AAAA		OWNER TO regano;

-- TODO: CERT RDATA per RFC 2538?

-- CNAME RDATA per RFC 1035 3.3.1
-- use common "data_name" field

-- DNAME RDATA per RFC 2672
-- use common "data_name" field

-- DS RDATA per RFC 4034
CREATE TYPE regano.dns_RR_DS AS (
	key_tag		regano.uint16bit,
	algorithm	regano.uint8bit,
	digest_type	regano.uint8bit,
	digest		regano.hexstring
);
ALTER TYPE regano.dns_RR_DS		OWNER TO regano;

-- TODO: IPSECKEY RDATA per RFC 4025?

-- TODO: LOC RDATA per RFC 1876?

-- MX RDATA per RFC 1035 3.3.9
CREATE TYPE regano.dns_RR_MX AS (
	preference	regano.uint16bit,
	exchange	regano.dns_name
);
ALTER TYPE regano.dns_RR_MX		OWNER TO regano;

-- TODO: NAPTR RDATA per RFC 2915?

-- NS RDATA per RFC 1035 3.3.11
-- use common "data_name" field

-- PTR RDATA per RFC 1035 3.3.12
-- use common "data_name" field

-- TODO: RP RDATA per RFC 1183?

-- SPF RDATA per RFC 4408
-- use common "data_text" field

-- SRV RDATA per RFC 2782
CREATE TYPE regano.dns_RR_SRV AS (
	priority	regano.uint16bit,
	weight		regano.uint16bit,
	port		regano.uint16bit,
	target		regano.dns_fqdn
);
ALTER TYPE regano.dns_RR_SRV		OWNER TO regano;

-- TODO: SSHFP RDATA per RFC 4255?

-- TXT RDATA per RFC 1035 3.3.14
-- use common "data_text" field
