pub use sea_orm_migration::prelude::*;

mod m20220101_000001_create_table;
mod m20260104_000002_create_roles_and_casbin;
mod m20260105_000003_create_auth_tables;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20220101_000001_create_table::Migration),
            Box::new(m20260104_000002_create_roles_and_casbin::Migration),
            Box::new(m20260105_000003_create_auth_tables::Migration),
        ]
    }
}
