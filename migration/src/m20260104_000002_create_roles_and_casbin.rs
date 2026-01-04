use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Tabel Roles
        manager
            .create_table(
                Table::create()
                    .table(Roles::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Roles::Id).big_integer().not_null().auto_increment().primary_key())
                    .col(ColumnDef::new(Roles::PublicId).uuid().not_null().unique_key())
                    .col(ColumnDef::new(Roles::Name).string().not_null().unique_key())
                    .col(ColumnDef::new(Roles::Description).string().null())
                    .to_owned(),
            )
            .await?;

        // 2. Tabel UserRoles (Pivot/Join Table)
        manager
            .create_table(
                Table::create()
                    .table(UserRoles::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(UserRoles::UserId).big_integer().not_null())
                    .col(ColumnDef::new(UserRoles::RoleId).big_integer().not_null())
                    .primary_key(Index::create().col(UserRoles::UserId).col(UserRoles::RoleId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_roles_user_id")
                            .from(UserRoles::Table, UserRoles::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_roles_role_id")
                            .from(UserRoles::Table, UserRoles::RoleId)
                            .to(Roles::Table, Roles::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // 3. Tabel CasbinRule (Standard Casbin Database Adapter)
        manager
            .create_table(
                Table::create()
                    .table(CasbinRule::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(CasbinRule::Id).big_integer().not_null().auto_increment().primary_key())
                    .col(ColumnDef::new(CasbinRule::Ptype).string().not_null())
                    .col(ColumnDef::new(CasbinRule::V0).string().null())
                    .col(ColumnDef::new(CasbinRule::V1).string().null())
                    .col(ColumnDef::new(CasbinRule::V2).string().null())
                    .col(ColumnDef::new(CasbinRule::V3).string().null())
                    .col(ColumnDef::new(CasbinRule::V4).string().null())
                    .col(ColumnDef::new(CasbinRule::V5).string().null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(CasbinRule::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(UserRoles::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(Roles::Table).to_owned()).await?;
        Ok(())
    }
}

#[derive(Iden)]
enum Roles {
    Table,
    Id,
    PublicId,
    Name,
    Description,
}

#[derive(Iden)]
enum UserRoles {
    Table,
    UserId,
    RoleId,
}

#[derive(Iden)]
enum Users {
    Table,
    Id,
}

#[derive(Iden)]
enum CasbinRule {
    Table,
    Id,
    Ptype,
    V0,
    V1,
    V2,
    V3,
    V4,
    V5,
}
