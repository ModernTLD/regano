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


-- The role 'regano' must already exist.

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

CREATE SCHEMA IF NOT EXISTS regano AUTHORIZATION regano;

CREATE TABLE IF NOT EXISTS regano.sessions (
	id		uuid PRIMARY KEY,
	user_id		integer NOT NULL REFERENCES regano.users (id),
	start		timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS regano.users (
	id		serial PRIMARY KEY,
	username	varchar(64) UNIQUE,
	password	varchar, -- TODO: determine password storage
	name		text NOT NULL,
	email		text NOT NULL,
	registered	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP,
	verified	boolean NOT NULL DEFAULT FALSE
) WITH (fillfactor = 90);

CREATE TABLE IF NOT EXISTS regano.domains (
	id		serial PRIMARY KEY,
	domain_name	text UNIQUE,
	owner_id	integer NOT NULL REFERENCES regano.users (id),
	registered	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expiration	timestamp with time zone NOT NULL,
	last_update	timestamp with time zone
				NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS regano.domain_records (
	id		serial PRIMARY KEY,
	domain_id	integer NOT NULL REFERENCES regano.domains (id),
	-- TODO: how exactly to store a DNS record?
);
