pub use sea_orm_migration::prelude::*;

mod m20220101_000001_create_table;
mod m20260104_000002_create_roles_and_casbin;
mod m20260105_000003_create_auth_tables;
mod m20260106_000004_add_backup_codes;
mod m20260111_000005_create_article_media_tables;
mod m20260112_000006_standardize_pk_structure;
mod m20260113_000007_refactor_article_tags;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20220101_000001_create_table::Migration),
            Box::new(m20260104_000002_create_roles_and_casbin::Migration),
            Box::new(m20260105_000003_create_auth_tables::Migration),
            Box::new(m20260106_000004_add_backup_codes::Migration),
            Box::new(m20260111_000005_create_article_media_tables::Migration),
            Box::new(m20260112_000006_standardize_pk_structure::Migration),
            Box::new(m20260113_000007_refactor_article_tags::Migration),
        ]
    }
}
