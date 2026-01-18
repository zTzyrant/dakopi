use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Create Media Table
        manager.create_table(
            Table::create()
                .table(Media::Table)
                .if_not_exists()
                .col(ColumnDef::new(Media::Id).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(Media::PublicId).uuid().not_null().unique_key()) // External ID
                .col(ColumnDef::new(Media::Name).string().not_null())
                .col(ColumnDef::new(Media::Url).string().not_null())
                .col(ColumnDef::new(Media::MimeType).string().not_null())
                .col(ColumnDef::new(Media::Size).big_integer().not_null())
                .col(ColumnDef::new(Media::AltText).string().null())
                .col(ColumnDef::new(Media::UploaderId).big_integer().not_null()) // Ownership
                .col(ColumnDef::new(Media::CreatedAt).timestamp_with_time_zone().not_null().default(Expr::current_timestamp()))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_media_uploader_id")
                        .from(Media::Table, Media::UploaderId)
                        .to(Users::Table, Users::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                )
                .to_owned(),
        ).await?;

        // 2. Create Articles Table
        manager.create_table(
            Table::create()
                .table(Articles::Table)
                .if_not_exists()
                .col(ColumnDef::new(Articles::Id).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(Articles::PublicId).uuid().not_null().unique_key()) // External ID
                .col(ColumnDef::new(Articles::Title).string().not_null())
                .col(ColumnDef::new(Articles::Slug).string().not_null().unique_key())
                .col(ColumnDef::new(Articles::Content).text().not_null())
                .col(ColumnDef::new(Articles::HtmlContent).text().null())
                .col(ColumnDef::new(Articles::Status).string().not_null().default("draft"))
                .col(ColumnDef::new(Articles::Visibility).string().not_null().default("public"))
                .col(ColumnDef::new(Articles::PublishedAt).timestamp_with_time_zone().null())
                .col(ColumnDef::new(Articles::Tags).json_binary().null())
                .col(ColumnDef::new(Articles::FeaturedImage).string().null())
                .col(ColumnDef::new(Articles::AuthorId).big_integer().not_null())
                .col(ColumnDef::new(Articles::CreatedAt).timestamp_with_time_zone().not_null().default(Expr::current_timestamp()))
                .col(ColumnDef::new(Articles::UpdatedAt).timestamp_with_time_zone().not_null().default(Expr::current_timestamp()))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_articles_author_id")
                        .from(Articles::Table, Articles::AuthorId)
                        .to(Users::Table, Users::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                )
                .to_owned(),
        ).await?;

        // Index for searching/sorting
        manager.create_index(Index::create().name("idx_articles_status").table(Articles::Table).col(Articles::Status).to_owned()).await?;
        manager.create_index(Index::create().name("idx_articles_published_at").table(Articles::Table).col(Articles::PublishedAt).to_owned()).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(Articles::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(Media::Table).to_owned()).await?;
        Ok(())
    }
}

#[derive(Iden)]
enum Media {
    Table,
    Id,
    PublicId,
    Name,
    Url,
    MimeType,
    Size,
    AltText,
    UploaderId,
    CreatedAt,
}

#[derive(Iden)]
enum Articles {
    Table,
    Id,
    PublicId,
    Title,
    Slug,
    Content,
    HtmlContent,
    Status,
    Visibility,
    PublishedAt,
    Tags,
    FeaturedImage,
    AuthorId,
    CreatedAt,
    UpdatedAt,
}

#[derive(Iden)]
enum Users {
    Table,
    Id,
}