use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Buat Tabel Dulu
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Users::Id).big_integer().not_null().auto_increment().primary_key())
                    .col(ColumnDef::new(Users::PublicId).uuid().not_null().unique_key()) // Tetap UUID
                    // Perhatikan: Email & Username TIDAK dikasih .unique_key() di sini
                    .col(ColumnDef::new(Users::Username).string().not_null())
                    .col(ColumnDef::new(Users::Email).string().not_null())
                    .col(ColumnDef::new(Users::PasswordHash).string().not_null())
                    .col(ColumnDef::new(Users::CreatedAt).timestamp_with_time_zone().not_null())
                    .col(ColumnDef::new(Users::UpdatedAt).timestamp_with_time_zone().not_null())
                    .col(ColumnDef::new(Users::DeletedAt).timestamp_with_time_zone().null())
                    .col(ColumnDef::new(Users::CreatedBy).uuid().null())
                    .col(ColumnDef::new(Users::UpdatedBy).uuid().null())
                    .col(ColumnDef::new(Users::DeletedBy).uuid().null())
                    .to_owned(),
            )
            .await?;

        // 2. Buat Index Unik Khusus (Partial Index)
        // Logika: Unik HANYA JIKA deleted_at IS NULL
        // Ini support Postgres & SQLite. MySQL butuh trik lain, tapi karena kamu pakai Aiven(Pg) & Local(SQLite), ini aman.
        
        // Index Email Aktif
        manager.get_connection()
            .execute_unprepared(
                "CREATE UNIQUE INDEX idx_users_email_active ON users (email) WHERE deleted_at IS NULL"
            )
            .await?;

        // Index Username Aktif
        manager.get_connection()
            .execute_unprepared(
                "CREATE UNIQUE INDEX idx_users_username_active ON users (username) WHERE deleted_at IS NULL"
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Hapus Index dulu (Opsional, karena drop table otomatis hapus index, tapi biar rapi)
        manager.get_connection().execute_unprepared("DROP INDEX IF EXISTS idx_users_email_active").await?;
        manager.get_connection().execute_unprepared("DROP INDEX IF EXISTS idx_users_username_active").await?;
        
        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum Users {
    Table,
    Id,
    PublicId,
    Username, 
    Email,
    PasswordHash,
    CreatedAt,
    UpdatedAt,
    DeletedAt,
    CreatedBy,
    UpdatedBy,
    DeletedBy,
}