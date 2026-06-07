mod models;
mod queries;

pub use models::*;
pub use queries::*;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .connect(url)
            .await?;

        tracing::info!("connected to database");
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        tracing::info!("database migrations applied");
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}
