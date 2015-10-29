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

-- These are the DNS record classes defined in RFC 1035.
CREATE TYPE regano.dns_record_class AS ENUM (
	'IN',	-- Internet
	'CS',	-- CSNET (obsolete even before RFC 1035)
	'CH',	-- CHAOSnet
	'HS',	-- Hesiod
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
