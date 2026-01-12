use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Fix Email Verification Tokens PK Structure
        // 1. Drop existing table
        manager.drop_table(Table::drop().table(EmailVerificationTokens::Table).to_owned()).await?;
        
        // 2. Re-create with correct schema (ID as BigInt PK, PublicID as UUID)
        manager.create_table(
            Table::create()
                .table(EmailVerificationTokens::Table)
                .if_not_exists()
                .col(ColumnDef::new(EmailVerificationTokens::Id).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(EmailVerificationTokens::PublicId).uuid().not_null().unique_key())
                .col(ColumnDef::new(EmailVerificationTokens::UserId).big_integer().not_null())
                .col(ColumnDef::new(EmailVerificationTokens::Token).string().not_null().unique_key())
                .col(ColumnDef::new(EmailVerificationTokens::Email).string().not_null())
                .col(ColumnDef::new(EmailVerificationTokens::ExpiresAt).timestamp_with_time_zone().not_null())
                .col(ColumnDef::new(EmailVerificationTokens::UsedAt).timestamp_with_time_zone().null())
                .col(ColumnDef::new(EmailVerificationTokens::CreatedAt).timestamp_with_time_zone().not_null().default(Expr::current_timestamp()))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_email_verification_user_id")
                        .from(EmailVerificationTokens::Table, EmailVerificationTokens::UserId)
                        .to(Users::Table, Users::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                )
                .to_owned(),
        ).await?;

        // Fix Password Reset Tokens PK Structure
        manager.drop_table(Table::drop().table(PasswordResetTokens::Table).to_owned()).await?;

        manager.create_table(
            Table::create()
            .table(PasswordResetTokens::Table)
                .if_not_exists()
                .col(ColumnDef::new(PasswordResetTokens::Id).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(PasswordResetTokens::PublicId).uuid().not_null().unique_key())
                .col(ColumnDef::new(PasswordResetTokens::UserId).big_integer().not_null())
                .col(ColumnDef::new(PasswordResetTokens::Token).string().not_null().unique_key())
                .col(ColumnDef::new(PasswordResetTokens::ExpiresAt).timestamp_with_time_zone().not_null())
                .col(ColumnDef::new(PasswordResetTokens::UsedAt).timestamp_with_time_zone().null())
                .col(ColumnDef::new(PasswordResetTokens::CreatedAt).timestamp_with_time_zone().not_null().default(Expr::current_timestamp()))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_password_reset_user_id")
                        .from(PasswordResetTokens::Table, PasswordResetTokens::UserId)
                        .to(Users::Table, Users::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                )
                .to_owned(),
        ).await?;

        // Fix Audit Logs PK Structure
        manager.drop_table(Table::drop().table(AuditLogs::Table).to_owned()).await?;

        manager.create_table(
            Table::create()
                .table(AuditLogs::Table)
                .if_not_exists()
                .col(ColumnDef::new(AuditLogs::Id).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(AuditLogs::PublicId).uuid().not_null().unique_key())
                .col(ColumnDef::new(AuditLogs::UserId).big_integer().null())
                .col(ColumnDef::new(AuditLogs::Action).string().not_null())
                .col(ColumnDef::new(AuditLogs::Resource).string().not_null())
                .col(ColumnDef::new(AuditLogs::ResourceId).string().null())
                .col(ColumnDef::new(AuditLogs::IpAddress).string().null())
                .col(ColumnDef::new(AuditLogs::UserAgent).string().null())
                .col(ColumnDef::new(AuditLogs::Method).string().null())
                .col(ColumnDef::new(AuditLogs::Path).text().null())
                .col(ColumnDef::new(AuditLogs::Status).string().not_null())
                .col(ColumnDef::new(AuditLogs::ErrorMessage).text().null())
                .col(ColumnDef::new(AuditLogs::Metadata).json_binary().null()) 
                .col(ColumnDef::new(AuditLogs::CreatedAt).timestamp_with_time_zone().not_null().default(Expr::current_timestamp()))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_audit_logs_user_id")
                        .from(AuditLogs::Table, AuditLogs::UserId)
                        .to(Users::Table, Users::Id)
                        .on_delete(ForeignKeyAction::SetNull)
                )
                .to_owned(),
        ).await?;

        // Fix Sessions PK Structure
        manager.drop_table(Table::drop().table(Sessions::Table).to_owned()).await?;
        manager.create_table(
            Table::create()
                .table(Sessions::Table)
                .if_not_exists()
                .col(ColumnDef::new(Sessions::Id).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(Sessions::PublicId).uuid().not_null().unique_key())
                .col(ColumnDef::new(Sessions::UserId).big_integer().not_null())
                .col(ColumnDef::new(Sessions::RefreshTokenJti).string().not_null().unique_key())
                .col(ColumnDef::new(Sessions::UserAgent).string().null())
                .col(ColumnDef::new(Sessions::IpAddress).string().null())
                .col(ColumnDef::new(Sessions::DeviceType).string().null())
                .col(ColumnDef::new(Sessions::DeviceName).string().null())
                .col(ColumnDef::new(Sessions::Country).string().null())
                .col(ColumnDef::new(Sessions::City).string().null())
                .col(ColumnDef::new(Sessions::LastActivity).timestamp_with_time_zone().not_null())
                .col(ColumnDef::new(Sessions::ExpiresAt).timestamp_with_time_zone().not_null())
                .col(ColumnDef::new(Sessions::CreatedAt).timestamp_with_time_zone().not_null().default(Expr::current_timestamp()))
                .col(ColumnDef::new(Sessions::RevokedAt).timestamp_with_time_zone().null())
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_sessions_user_id")
                        .from(Sessions::Table, Sessions::UserId)
                        .to(Users::Table, Users::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                )
                .to_owned(),
        ).await?;

        // Fix OAuth Accounts PK Structure
        manager.drop_table(Table::drop().table(OauthAccounts::Table).to_owned()).await?;
        manager.create_table(
            Table::create()
                .table(OauthAccounts::Table)
                .if_not_exists()
                .col(ColumnDef::new(OauthAccounts::Id).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(OauthAccounts::PublicId).uuid().not_null().unique_key())
                .col(ColumnDef::new(OauthAccounts::UserId).big_integer().not_null())
                .col(ColumnDef::new(OauthAccounts::Provider).string().not_null())
                .col(ColumnDef::new(OauthAccounts::ProviderUserId).string().not_null())
                .col(ColumnDef::new(OauthAccounts::AccessToken).text().null())
                .col(ColumnDef::new(OauthAccounts::RefreshToken).text().null())
                .col(ColumnDef::new(OauthAccounts::TokenExpiresAt).timestamp_with_time_zone().null())
                .col(ColumnDef::new(OauthAccounts::ProviderEmail).string().null())
                .col(ColumnDef::new(OauthAccounts::ProviderName).string().null())
                .col(ColumnDef::new(OauthAccounts::ProviderAvatar).text().null())
                .col(ColumnDef::new(OauthAccounts::CreatedAt).timestamp_with_time_zone().not_null().default(Expr::current_timestamp()))
                .col(ColumnDef::new(OauthAccounts::UpdatedAt).timestamp_with_time_zone().not_null().default(Expr::current_timestamp()))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_oauth_accounts_user_id")
                        .from(OauthAccounts::Table, OauthAccounts::UserId)
                        .to(Users::Table, Users::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                )
                .index(
                    Index::create()
                        .name("idx_oauth_provider_user")
                        .table(OauthAccounts::Table)
                        .col(OauthAccounts::Provider)
                        .col(OauthAccounts::ProviderUserId)
                        .unique()
                )
                .to_owned(),
        ).await?;

        // Fix Token Blacklist PK Structure
        manager.drop_table(Table::drop().table(TokenBlacklist::Table).to_owned()).await?;
        manager.create_table(
            Table::create()
                .table(TokenBlacklist::Table)
                .if_not_exists()
                .col(ColumnDef::new(TokenBlacklist::Id).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(TokenBlacklist::PublicId).uuid().not_null().unique_key())
                .col(ColumnDef::new(TokenBlacklist::Jti).string().not_null().unique_key())
                .col(ColumnDef::new(TokenBlacklist::UserId).big_integer().null())
                .col(ColumnDef::new(TokenBlacklist::ExpiresAt).timestamp_with_time_zone().not_null())
                .col(ColumnDef::new(TokenBlacklist::CreatedAt).timestamp_with_time_zone().not_null().default(Expr::current_timestamp()))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_token_blacklist_user_id")
                        .from(TokenBlacklist::Table, TokenBlacklist::UserId)
                        .to(Users::Table, Users::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                )
                .to_owned(),
        ).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Just drop the tables in down migration
        manager.drop_table(Table::drop().table(EmailVerificationTokens::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(PasswordResetTokens::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(AuditLogs::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(Sessions::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(OauthAccounts::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(TokenBlacklist::Table).to_owned()).await?;
        Ok(())
    }
}

#[derive(Iden)]
enum Users {
    Table,
    Id,
}

#[derive(Iden)]
enum EmailVerificationTokens {
    Table,
    Id,
    PublicId,
    UserId,
    Token,
    Email,
    ExpiresAt,
    UsedAt,
    CreatedAt,
}

#[derive(Iden)]
enum PasswordResetTokens {
    Table,
    Id,
    PublicId,
    UserId,
    Token,
    ExpiresAt,
    UsedAt,
    CreatedAt,
}

#[derive(Iden)]
enum AuditLogs {
    Table,
    Id,
    PublicId,
    UserId,
    Action,
    Resource,
    ResourceId,
    IpAddress,
    UserAgent,
    Method,
    Path,
    Status,
    ErrorMessage,
    Metadata,
    CreatedAt,
}

#[derive(Iden)]
enum Sessions {
    Table,
    Id,
    PublicId,
    UserId,
    RefreshTokenJti,
    UserAgent,
    IpAddress,
    DeviceType,
    DeviceName,
    Country,
    City,
    LastActivity,
    ExpiresAt,
    CreatedAt,
    RevokedAt,
}

#[derive(Iden)]
enum OauthAccounts {
    Table,
    Id,
    PublicId,
    UserId,
    Provider,
    ProviderUserId,
    AccessToken,
    RefreshToken,
    TokenExpiresAt,
    ProviderEmail,
    ProviderName,
    ProviderAvatar,
    CreatedAt,
    UpdatedAt,
}

#[derive(Iden)]
enum TokenBlacklist {
    Table,
    Id,
    PublicId,
    Jti,
    UserId,
    ExpiresAt,
    CreatedAt,
}
