use casbin::{Enforcer, CoreApi};
use sea_orm_adapter::SeaOrmAdapter;
use sea_orm::DatabaseConnection;
use std::sync::Arc;
use tokio::sync::RwLock;

pub type SharedEnforcer = Arc<RwLock<Enforcer>>;

pub async fn setup_casbin(db: DatabaseConnection) -> SharedEnforcer {
    // SeaOrmAdapter::new membutuhkan objek koneksi, bukan string URL
    let adapter = SeaOrmAdapter::new(db).await
        .expect("Gagal inisialisasi Casbin adapter");

    let enforcer = Enforcer::new("src/auth/rbac_model.conf", adapter).await
        .expect("Gagal inisialisasi Casbin enforcer");

    Arc::new(RwLock::new(enforcer))
}