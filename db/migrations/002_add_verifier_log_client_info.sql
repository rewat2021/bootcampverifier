-- Migration 002: add client_ip/user_agent to dbverifierlog, and start using
-- dbverifierlog as the verification audit log (previously unused scaffolding
-- — table existed, was EF-mapped, but no code ever wrote to it).
--
-- Run this against an EXISTING database (it only adds columns, no data loss).
-- db/init.sql has also been updated to include these columns for fresh
-- installs, but init.sql does DROP+CREATE and must not be re-run against a
-- database that already has data.
--
-- See OID4VP-1.0-COMPLIANCE-AUDIT.md and VerifierAPI/Filters/VerifierAuditLogFilter.cs.

USE `verifier`;

ALTER TABLE `dbverifierlog`
  ADD COLUMN `client_ip` varchar(64) DEFAULT NULL AFTER `created_at`,
  ADD COLUMN `user_agent` varchar(500) DEFAULT NULL AFTER `client_ip`;
