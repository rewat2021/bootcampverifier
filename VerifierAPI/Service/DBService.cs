using System;
using System.Text;
using VerifierAPI.Databases;
using VerifierAPI.Models;
using System.Security.Cryptography;

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
                const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                string nonce =  RandomNumberGenerator.GetString(chars, 6); // เช่น "K3X9B2"
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
    }
}
