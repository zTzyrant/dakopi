use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Add excerpt column to articles
        manager.alter_table(
            Table::alter()
                .table(Articles::Table)
                .add_column(ColumnDef::new(Articles::Excerpt).text().null()) // Nullable for existing data
                .to_owned()
        ).await?;

        // 2. Drop tags column from articles (we move to relational table)
        // Note: Data migration script would be needed here if production data existed.
        // Assuming dev env, we just drop.
        manager.alter_table(
            Table::alter()
                .table(Articles::Table)
                .drop_column(Articles::Tags)
                .to_owned()
        ).await?;

        // 3. Create Tags Table
        manager.create_table(
            Table::create()
                .table(Tags::Table)
                .if_not_exists()
                .col(ColumnDef::new(Tags::Id).big_integer().not_null().auto_increment().primary_key())
                .col(ColumnDef::new(Tags::PublicId).uuid().not_null().unique_key())
                .col(ColumnDef::new(Tags::Name).string().not_null().unique_key())
                .col(ColumnDef::new(Tags::Slug).string().not_null().unique_key())
                .col(ColumnDef::new(Tags::CreatedAt).timestamp_with_time_zone().not_null().default(Expr::current_timestamp()))
                .to_owned(),
        ).await?;

        // 4. Create ArticleTags Table (Many-to-Many)
        manager.create_table(
            Table::create()
                .table(ArticleTags::Table)
                .if_not_exists()
                .col(ColumnDef::new(ArticleTags::ArticleId).big_integer().not_null())
                .col(ColumnDef::new(ArticleTags::TagId).big_integer().not_null())
                .primary_key(Index::create().col(ArticleTags::ArticleId).col(ArticleTags::TagId))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_article_tags_article_id")
                        .from(ArticleTags::Table, ArticleTags::ArticleId)
                        .to(Articles::Table, Articles::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_article_tags_tag_id")
                        .from(ArticleTags::Table, ArticleTags::TagId)
                        .to(Tags::Table, Tags::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                )
                .to_owned(),
        ).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(ArticleTags::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(Tags::Table).to_owned()).await?;
        
        manager.alter_table(
            Table::alter()
                .table(Articles::Table)
                .drop_column(Articles::Excerpt)
                .add_column(ColumnDef::new(Articles::Tags).json_binary().null())
                .to_owned()
        ).await?;
        
        Ok(())
    }
}

#[derive(Iden)]
enum Articles {
    Table,
    Id,
    Excerpt,
    Tags,
}

#[derive(Iden)]
enum Tags {
    Table,
    Id,
    PublicId,
    Name,
    Slug,
    CreatedAt,
}

#[derive(Iden)]
enum ArticleTags {
    Table,
    ArticleId,
    TagId,
}
