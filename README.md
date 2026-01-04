# ☕ Dakopi Backend

Dakopi is a high-performance backend application built with **Rust**, designed with a focus on speed, strict security, and modern architecture. It utilizes the **Axum** framework and **SeaORM**, featuring a dynamic authorization system powered by **Casbin**.

## 🏗️ Layered Architecture

Dakopi follows a **Layered Architecture** (Controller-Service-Repository) to ensure a clean separation of concerns and maintainable, testable code:

1.  **Handlers (Controller Layer)**: Manages HTTP requests, validates input using `ValidatedJson`, and returns standardized `ApiResponse`.
2.  **Services (Business Logic Layer)**: Contains core business logic, third-party integrations (Email, Auth), and orchestrates data flow between repositories.
3.  **Repositories (Data Access Layer)**: Encapsulates database queries using SeaORM for secure and abstraction-friendly data interaction.
4.  **Entities (Database Models)**: Maps database tables directly to Rust structs.
5.  **Models (DTOs)**: Data Transfer Objects used to separate internal database structures from publicly exposed data.

## 🛠️ Tech Stack

-   **Framework**: [Axum](https://github.com/tokio-rs/axum) (Web Server)
-   **ORM**: [SeaORM](https://www.sea-ql.org/SeaORM/) (PostgreSQL & SQLite support)
-   **Security**: [Casbin-rs](https://casbin.org/) (RBAC & Dynamic Authorization)
-   **Cache**: [Redis](https://redis.io/) (Rate Limiting & Session Management)
-   **Email**: [Brevo API](https://www.brevo.com/) via HTTP (Hybrid mode with [Mailpit](https://github.com/axllent/mailpit) for local development)
-   **Validation**: [Validator](https://github.com/Keats/validator)
-   **Database Migration**: Built-in SeaORM Migration workspace

## 🚀 Key Features

-   **Dynamic RBAC**: Manage permissions (Policies) directly in the database without server restarts using Casbin.
-   **Email Rate Limiting**: Daily limit of 100 emails with a tiered soft-limit and hard-limit system enforced via Redis.
-   **Auto Seeding**: Automatic initialization of `super`, `admin`, and `user` roles along with a default superadmin account on first run.
-   **Timezone Aware**: Global server synchronization set to **UTC+8 (WITA)**.
-   **Zero Dollar Hosting Ready**: Optimized for low resource consumption, making it perfectly suited for free-tier cloud providers.

## 📦 Running Locally

### Prerequisites
-   Rust (Latest Stable)
-   Mailpit (For local email testing)
-   Redis
-   PostgreSQL or SQLite

### Installation
1.  Clone the repository.
2.  Copy `.env.example` to `.env` and adjust the configuration values.
3.  Run database migrations:
    ```bash
    cargo run -p migration
    ```
4.  Start the server:
    ```bash
    cargo run
    ```

## 🚢 Deployment (Railway)

This project includes a multi-stage `Dockerfile` optimized for Rust workspaces.
-   **Build Stage**: Uses `rust:latest` for compilation.
-   **Runner Stage**: Uses `debian:bookworm-slim` for a minimal final image size.
-   **Auto-Migrate**: Automatically executes `./migration up` before the application starts via a `start.sh` entrypoint.

---

## ❤️ Special Thanks

This project is made possible thanks to the following services that support the developer ecosystem with their generous free tiers:

-   **[Railway](https://railway.app/)**: For seamless application and Redis hosting.
-   **[Aiven](https://aiven.io/)**: Providing stable and reliable Managed PostgreSQL for free.
-   **[Brevo](https://www.brevo.com/)**: For their excellent SMTP/Email API (300 emails/day free).
-   **[ImageKit](https://imagekit.io/)**: For fast image management and CDN services.

**Dakopi** - *Brewing code with safety and speed.*