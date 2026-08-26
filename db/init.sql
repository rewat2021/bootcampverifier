CREATE DATABASE  IF NOT EXISTS `verifier` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci */ /*!80016 DEFAULT ENCRYPTION='N' */;
USE `verifier`;
-- MySQL dump 10.13  Distrib 8.0.45, for Win64 (x86_64)
--
-- Host: 127.0.0.1    Database: verifier
-- ------------------------------------------------------
-- Server version	8.0.45

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `dbdocumenttype`
--

DROP TABLE IF EXISTS `dbdocumenttype`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dbdocumenttype` (
  `id` char(36) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT (uuid()),
  `type_id` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `DocType` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `format` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'jwt_vc_json',
  `vc_type` json NOT NULL,
  `alg_values` json NOT NULL,
  `endpoint` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `type_id` (`type_id`),
  UNIQUE KEY `uq_document_type_type_id` (`type_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dbdocumenttype`
--

LOCK TABLES `dbdocumenttype` WRITE;
/*!40000 ALTER TABLE `dbdocumenttype` DISABLE KEYS */;
-- SECURITY (C-04 remediation, 2026-08-08): dc+sd-jwt was set is_active=0 during
-- Phase 0 containment because SD-JWT VC verification was incomplete/unsafe. It is
-- re-enabled (is_active=1) now that VCService.VerifySDJWTPresentation validates
-- disclosure digests, KB-JWT signature/holder-binding, sd_hash, and KB-JWT
-- nonce/aud/iat. See OID4VP-1.0-COMPLIANCE-AUDIT.md finding C-04.
INSERT IGNORE INTO `dbdocumenttype` VALUES ('68d78f2c-3bcf-11f1-8c91-506b8dc68021','transcript','transcript_credential','dc+sd-jwt','[\"VerifiableCredential\", \"TranscriptCredential\"]','[\"EdDSA\"]','TranscriptCredential',1,'2026-04-19 16:09:02','2026-05-11 03:25:02'),('8fa3b38c-3bcf-11f1-8c91-506b8dc68021','idcard','idcard_credential','jwt_vc_json','[\"VerifiableCredential\", \"IDCardCredential\"]','[\"ES256\"]',NULL,1,'2026-04-19 16:10:07','2026-04-19 17:12:43'),('a30c9a92-3bcf-11f1-8c91-506b8dc68021','driverlicense','driverlicense_credential','jwt_vc_json','[\"VerifiableCredential\", \"DriverLicenseCredential\"]','[\"ES256\"]',NULL,1,'2026-04-19 16:10:40','2026-04-19 17:13:15'),('68d78f2c-3bcf-11f1-8c91-506b8dc68022','bootcamp','bootcamp_credential','dc+sd-jwt','[\"VerifiableCredential\", \"BootCampCredential\"]','[\"EdDSA\"]','BootCampCredential',1,'2026-04-19 16:09:02','2026-05-11 03:25:02');
/*!40000 ALTER TABLE `dbdocumenttype` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `dbverificationresult`
--

DROP TABLE IF EXISTS `dbverificationresult`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dbverificationresult` (
  `Id` varchar(36) NOT NULL,
  `SessionId` varchar(36) NOT NULL,
  `IsValid` bit(1) NOT NULL,
  `HolderDid` varchar(500) DEFAULT NULL,
  `CredentialFormat` varchar(50) DEFAULT NULL,
  `NonceBound` bit(1) DEFAULT NULL,
  `AudienceBound` bit(1) DEFAULT NULL,
  `SignatureValid` bit(1) DEFAULT NULL,
  `NotRevoked` bit(1) DEFAULT NULL,
  `NotExpired` bit(1) DEFAULT NULL,
  `ClaimsJson` text,
  `ErrorMessage` varchar(500) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci DEFAULT NULL,
  `VerifiedAt` datetime NOT NULL,
  PRIMARY KEY (`Id`),
  KEY `SessionId` (`SessionId`),
  CONSTRAINT `dbverificationresult_ibfk_1` FOREIGN KEY (`SessionId`) REFERENCES `dbverifiersession` (`Id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dbverificationresult`
--

LOCK TABLES `dbverificationresult` WRITE;
/*!40000 ALTER TABLE `dbverificationresult` DISABLE KEYS */;
/*!40000 ALTER TABLE `dbverificationresult` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `dbverifierlog`
--

DROP TABLE IF EXISTS `dbverifierlog`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
-- FEATURE (audit trail, 2026-08-15): this table already existed but nothing ever
-- wrote to it — repurposed as the verification audit log (records every
-- VerifierVP call, success AND failure, via VerifierAuditLogFilter) instead of
-- adding a new table. client_ip/user_agent are the only columns new to this
-- schema; see db/migrations/002_add_verifier_log_client_info.sql for the
-- additive ALTER TABLE to run against an existing database instead of this
-- DROP+CREATE dump.
CREATE TABLE `dbverifierlog` (
  `id` int NOT NULL AUTO_INCREMENT,
  `team_id` varchar(50) NOT NULL,
  `presentation_id` varchar(100) DEFAULT NULL,
  `holder_did` varchar(255) DEFAULT NULL,
  `issuer_did` varchar(255) DEFAULT NULL,
  `credential_type` varchar(100) DEFAULT NULL,
  `status` enum('success','failed') NOT NULL,
  `verified` tinyint(1) DEFAULT NULL,
  `error_code` varchar(100) DEFAULT NULL,
  `error_message` text,
  `vp_token` text,
  `claims` json DEFAULT NULL,
  `presentation_submission` json DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `client_ip` varchar(64) DEFAULT NULL,
  `user_agent` varchar(500) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_team` (`team_id`),
  KEY `idx_status` (`status`),
  KEY `idx_verified` (`verified`),
  KEY `idx_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dbverifierlog`
--

LOCK TABLES `dbverifierlog` WRITE;
/*!40000 ALTER TABLE `dbverifierlog` DISABLE KEYS */;
/*!40000 ALTER TABLE `dbverifierlog` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `dbverifierresponse`
--

DROP TABLE IF EXISTS `dbverifierresponse`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dbverifierresponse` (
  `Id` int NOT NULL AUTO_INCREMENT,
  `SessionId` varchar(36) NOT NULL,
  `VpToken` text NOT NULL,
  `VcPayload` text,
  `PresentationSubmission` text,
  `ResponseCode` varchar(256) DEFAULT NULL,
  `ReceivedAt` datetime NOT NULL,
  PRIMARY KEY (`Id`),
  KEY `SessionId` (`SessionId`),
  CONSTRAINT `dbverifierresponse_ibfk_1` FOREIGN KEY (`SessionId`) REFERENCES `dbverifiersession` (`Id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dbverifierresponse`
--
-- SECURITY (Phase 0 remediation, 2026-08-08): captured VP/VC response payloads
-- removed from this seed file. This table must contain no real presentation
-- or credential data in source control. See OID4VP-1.0-COMPLIANCE-AUDIT.md C-05.
--

LOCK TABLES `dbverifierresponse` WRITE;
/*!40000 ALTER TABLE `dbverifierresponse` DISABLE KEYS */;
/*!40000 ALTER TABLE `dbverifierresponse` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `dbverifiersession`
--

DROP TABLE IF EXISTS `dbverifiersession`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dbverifiersession` (
  `Id` varchar(36) NOT NULL,
  `DocTypeId` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `State` varchar(256) NOT NULL,
  `ClientId` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `Nonce` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `DcqlQuery` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `Status` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `CreatedAt` datetime NOT NULL,
  `ExpiresAt` datetime NOT NULL,
  `CompletedAt` datetime DEFAULT NULL,
  PRIMARY KEY (`Id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dbverifiersession`
--
-- SECURITY (Phase 0 remediation, 2026-08-08): populated verifier sessions
-- (including state/nonce/client_id values) removed from this seed file.
-- See OID4VP-1.0-COMPLIANCE-AUDIT.md C-05.
--

LOCK TABLES `dbverifiersession` WRITE;
/*!40000 ALTER TABLE `dbverifiersession` DISABLE KEYS */;
/*!40000 ALTER TABLE `dbverifiersession` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `usednonce`
--

DROP TABLE IF EXISTS `usednonce`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `usednonce` (
  `Nonce` varchar(256) NOT NULL,
  `UsedAt` datetime NOT NULL,
  `ExpiredAt` datetime NOT NULL,
  PRIMARY KEY (`Nonce`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `usednonce`
--

LOCK TABLES `usednonce` WRITE;
/*!40000 ALTER TABLE `usednonce` DISABLE KEYS */;
/*!40000 ALTER TABLE `usednonce` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-05-12 13:58:51
