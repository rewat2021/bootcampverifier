using System;
using System.Text;
using VerifierAPI.Databases;
using VerifierAPI.Models;
using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;

namespace VerifierAPI.Service
{
    public class DBService
    {

        public VpRequestSession SaveVerifierSession(string docTypeId)
        {
            VpRequestSession model = new VpRequestSession();
            using (VerifierDbContext dbContext = new VerifierDbContext())
            {
                // 1. ตรวจสอบว่า DocumentType มีอยู่จริง
                var docType = dbContext.Dbdocumenttypes.Where(d => d.TypeId == docTypeId.ToLower() && d.IsActive == true).FirstOrDefault();

                if (docType == null)
                    throw new ArgumentException($"DocumentType '{docTypeId}' not found");

                // 2. สร้าง session ใหม่
                Guid guid = Guid.NewGuid();
                // FIX (Phase 1 item 1, 2026-08-09): the old nonce was 6 chars from a
                // 36-symbol alphabet (~31 bits) — far below the spec's 128-bit-or-greater
                // requirement (§5) and small enough to be guessable/replayable. Now uses
                // 256 bits of CSPRNG output, base64url-encoded (43 chars, no padding).
                // See OID4VP-1.0-COMPLIANCE-AUDIT.md Phase 1 item 1.
                string nonce = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
                var session = new Dbverifiersession
                {
                    Id = guid.ToString(),
                    DocTypeId = docType.TypeId,
                    State = guid.ToString(),
                    Nonce = nonce,
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(10)  // หมดอายุใน 10 นาที
                };

                dbContext.Dbverifiersessions.Add(session);
                dbContext.SaveChanges();

                model.stateId = guid.ToString();
                model.nonce = nonce;
                return model;
            }
        }

        public Dbdocumenttype GetRequestDocType(string ID)
        {
            string docuType = null;
            Dbdocumenttype docu = null;
            using (VerifierDbContext dbContext = new VerifierDbContext())
            {
                Dbverifiersession verifier = dbContext.Dbverifiersessions.Where(i => i.Id == ID).FirstOrDefault();

                if(verifier != null)
                {
                    docu = dbContext.Dbdocumenttypes.Where(i => i.TypeId.Equals(verifier.DocTypeId) && i.IsActive == true).FirstOrDefault();
                    if (docu != null)
                    {
                        docuType = docu.TypeId;
                    }
                }

               
            }


            return docu;
        }

        public Dbdocumenttype GetRequestByDocType(string type_id)
        {
            string docuType = null;
            Dbdocumenttype docu = null;
            using (VerifierDbContext dbContext = new VerifierDbContext())
            {

                if (!string.IsNullOrEmpty(type_id))
                {
                    docu = dbContext.Dbdocumenttypes.Where(i => i.TypeId.Contains(type_id) && i.IsActive == true).FirstOrDefault();
                    if (docu != null)
                    {
                        return docu;
                    }
                }


            }


            return null;
        }
    }
}
