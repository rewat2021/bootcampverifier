using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Pomelo.EntityFrameworkCore.MySql.Scaffolding.Internal;

namespace VerifierAPI.Databases;

public partial class IssuerDbContext : DbContext
{
    public IssuerDbContext()
    {
    }

    public IssuerDbContext(DbContextOptions<IssuerDbContext> options)
        : base(options)
    {
    }

    public virtual DbSet<Dbdocumenttype> Dbdocumenttypes { get; set; }

    public virtual DbSet<Dbuser> Dbusers { get; set; }

    public virtual DbSet<Dbverificationresult> Dbverificationresults { get; set; }

    public virtual DbSet<Dbverifierlog> Dbverifierlogs { get; set; }

    public virtual DbSet<Dbverifierresponse> Dbverifierresponses { get; set; }

    public virtual DbSet<Dbverifiersession> Dbverifiersessions { get; set; }

    public virtual DbSet<Usednonce> Usednonces { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. You can avoid scaffolding the connection string by using the Name= syntax to read it from configuration - see https://go.microsoft.com/fwlink/?linkid=2131148. For more guidance on storing connection strings, see https://go.microsoft.com/fwlink/?LinkId=723263.
        => optionsBuilder.UseMySql("server=192.100.10.48;port=3306;database=verifier;user=root;password=P@ssw0rd@1234;sslmode=None", Microsoft.EntityFrameworkCore.ServerVersion.Parse("8.0.45-mysql"));

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder
            .UseCollation("utf8mb4_0900_ai_ci")
            .HasCharSet("utf8mb4");

        modelBuilder.Entity<Dbdocumenttype>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity
                .ToTable("dbdocumenttype")
                .UseCollation("utf8mb4_unicode_ci");

            entity.HasIndex(e => e.TypeId, "type_id").IsUnique();

            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.AlgValues)
                .HasColumnType("json")
                .HasColumnName("alg_values");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("CURRENT_TIMESTAMP")
                .HasColumnType("datetime")
                .HasColumnName("created_at");
            entity.Property(e => e.DocType).HasMaxLength(100);
            entity.Property(e => e.Endpoint)
                .HasMaxLength(50)
                .HasColumnName("endpoint");
            entity.Property(e => e.Format)
                .HasMaxLength(50)
                .HasDefaultValueSql("'jwt_vc_json'")
                .HasColumnName("format");
            entity.Property(e => e.IsActive)
                .IsRequired()
                .HasDefaultValueSql("'1'")
                .HasColumnName("is_active");
            entity.Property(e => e.TypeId)
                .HasMaxLength(100)
                .HasColumnName("type_id");
            entity.Property(e => e.UpdatedAt)
                .ValueGeneratedOnAddOrUpdate()
                .HasDefaultValueSql("CURRENT_TIMESTAMP")
                .HasColumnType("datetime")
                .HasColumnName("updated_at");
            entity.Property(e => e.VcType)
                .HasColumnType("json")
                .HasColumnName("vc_type");
        });

        modelBuilder.Entity<Dbuser>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.ToTable("dbusers");

            entity.HasIndex(e => e.Email, "email").IsUnique();

            entity.HasIndex(e => e.Username, "username").IsUnique();

            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("CURRENT_TIMESTAMP")
                .HasColumnType("timestamp")
                .HasColumnName("created_at");
            entity.Property(e => e.Email)
                .HasMaxLength(100)
                .HasColumnName("email");
            entity.Property(e => e.FirstName)
                .HasMaxLength(100)
                .HasColumnName("first_name");
            entity.Property(e => e.LastName)
                .HasMaxLength(100)
                .HasColumnName("last_name");
            entity.Property(e => e.Password)
                .HasMaxLength(255)
                .HasColumnName("password");
            entity.Property(e => e.Username)
                .HasMaxLength(50)
                .HasColumnName("username");
        });

        modelBuilder.Entity<Dbverificationresult>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.ToTable("dbverificationresult");

            entity.HasIndex(e => e.SessionId, "SessionId");

            entity.Property(e => e.Id).HasMaxLength(36);
            entity.Property(e => e.AudienceBound).HasColumnType("bit(1)");
            entity.Property(e => e.ClaimsJson).HasColumnType("text");
            entity.Property(e => e.CredentialFormat).HasMaxLength(50);
            entity.Property(e => e.ErrorMessage)
                .HasMaxLength(500)
                .UseCollation("utf8mb3_general_ci")
                .HasCharSet("utf8mb3");
            entity.Property(e => e.HolderDid).HasMaxLength(500);
            entity.Property(e => e.IsValid).HasColumnType("bit(1)");
            entity.Property(e => e.NonceBound).HasColumnType("bit(1)");
            entity.Property(e => e.NotExpired).HasColumnType("bit(1)");
            entity.Property(e => e.NotRevoked).HasColumnType("bit(1)");
            entity.Property(e => e.SessionId).HasMaxLength(36);
            entity.Property(e => e.SignatureValid).HasColumnType("bit(1)");
            entity.Property(e => e.VerifiedAt).HasColumnType("datetime");

            entity.HasOne(d => d.Session).WithMany(p => p.Dbverificationresults)
                .HasForeignKey(d => d.SessionId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("dbverificationresult_ibfk_1");
        });

        modelBuilder.Entity<Dbverifierlog>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.ToTable("dbverifierlog");

            entity.HasIndex(e => e.CreatedAt, "idx_created");

            entity.HasIndex(e => e.Status, "idx_status");

            entity.HasIndex(e => e.TeamId, "idx_team");

            entity.HasIndex(e => e.Verified, "idx_verified");

            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.Claims)
                .HasColumnType("json")
                .HasColumnName("claims");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("CURRENT_TIMESTAMP")
                .HasColumnType("datetime")
                .HasColumnName("created_at");
            entity.Property(e => e.CredentialType)
                .HasMaxLength(100)
                .HasColumnName("credential_type");
            entity.Property(e => e.ErrorCode)
                .HasMaxLength(100)
                .HasColumnName("error_code");
            entity.Property(e => e.ErrorMessage)
                .HasColumnType("text")
                .HasColumnName("error_message");
            entity.Property(e => e.HolderDid)
                .HasMaxLength(255)
                .HasColumnName("holder_did");
            entity.Property(e => e.IssuerDid)
                .HasMaxLength(255)
                .HasColumnName("issuer_did");
            entity.Property(e => e.PresentationId)
                .HasMaxLength(100)
                .HasColumnName("presentation_id");
            entity.Property(e => e.PresentationSubmission)
                .HasColumnType("json")
                .HasColumnName("presentation_submission");
            entity.Property(e => e.Status)
                .HasColumnType("enum('success','failed')")
                .HasColumnName("status");
            entity.Property(e => e.TeamId)
                .HasMaxLength(50)
                .HasColumnName("team_id");
            entity.Property(e => e.Verified).HasColumnName("verified");
            entity.Property(e => e.VpToken)
                .HasColumnType("text")
                .HasColumnName("vp_token");
        });

        modelBuilder.Entity<Dbverifierresponse>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.ToTable("dbverifierresponse");

            entity.HasIndex(e => e.SessionId, "SessionId");

            entity.Property(e => e.PresentationSubmission).HasColumnType("text");
            entity.Property(e => e.ReceivedAt).HasColumnType("datetime");
            entity.Property(e => e.ResponseCode).HasMaxLength(256);
            entity.Property(e => e.SessionId).HasMaxLength(36);
            entity.Property(e => e.VcPayload).HasColumnType("text");
            entity.Property(e => e.VpToken).HasColumnType("text");

            entity.HasOne(d => d.Session).WithMany(p => p.Dbverifierresponses)
                .HasForeignKey(d => d.SessionId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("dbverifierresponse_ibfk_1");
        });

        modelBuilder.Entity<Dbverifiersession>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.ToTable("dbverifiersession");

            entity.Property(e => e.Id).HasMaxLength(36);
            entity.Property(e => e.ClientId).HasMaxLength(500);
            entity.Property(e => e.CompletedAt).HasColumnType("datetime");
            entity.Property(e => e.CreatedAt).HasColumnType("datetime");
            entity.Property(e => e.DocTypeId).HasMaxLength(256);
            entity.Property(e => e.ExpiresAt).HasColumnType("datetime");
            entity.Property(e => e.Nonce).HasMaxLength(500);
            entity.Property(e => e.State).HasMaxLength(256);
            entity.Property(e => e.Status).HasMaxLength(20);
        });

        modelBuilder.Entity<Usednonce>(entity =>
        {
            entity.HasKey(e => e.Nonce).HasName("PRIMARY");

            entity.ToTable("usednonce");

            entity.Property(e => e.Nonce).HasMaxLength(256);
            entity.Property(e => e.ExpiredAt).HasColumnType("datetime");
            entity.Property(e => e.UsedAt).HasColumnType("datetime");
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
