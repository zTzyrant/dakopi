# Dakopi Backend - Project Context

## Project Overview
Dakopi is a backend application built with **Rust** using the **Axum** web framework. It uses **SeaORM** for database interactions and **Tokio** as the asynchronous runtime. The project follows a **Layered Architecture** (Controller-Service-Repository) to separate concerns.

## Technology Stack
- **Language:** Rust (Edition 2021)
- **Web Framework:** Axum 0.8
- **Database ORM:** SeaORM 1.1 (Supports Postgres, MySQL, SQLite)
- **Database Migrations:** SeaORM Migration
- **Async Runtime:** Tokio
- **Authentication:** JWT (`jsonwebtoken`), Argon2 (`argon2`)
- **Validation:** Validator crate (`validator`)
- **Logging:** Tracing (`tracing`, `tracing-subscriber`)
- **Config:** `dotenvy`

## Directory Structure
- **`src/`**: Main application source code.
  - **`main.rs`**: Application entry point. Sets up DB connection, tracing, and starts the server.
  - **`config.rs`**: Configuration management.
  - **`routes/`**: Route definitions and nesting logic.
  - **`handlers/`**: **(Controller Layer)** HTTP request parsing using `ValidatedJson`, calling services, and returning standard `ApiResponse`.
  - **`services/`**: **(Business Logic Layer)** Reusable logic, complex validation, and orchestration (e.g., `auth_service.rs`).
  - **`repositories/`**: **(Data Access Layer)** Encapsulates all SeaORM database queries.
  - **`entities/`**: SeaORM entity definitions (Database models).
  - **`models/`**: Data Transfer Objects (DTOs) with validation rules (e.g., `auth_model.rs`).
  - **`utils/`**: Shared utilities:
    - `api_response.rs`: Standard API response format.
    - `validated_wrapper.rs`: Custom extractor for automatic JSON validation.
    - `validator_utils.rs`: Custom validators (e.g., `validate_required` for Options).
- **`migration/`**: Database migration logic.
- **`Bruno/`**: API collection for testing.
- **`.env.example`**: Template for environment variables.

## Building and Running

### Prerequisites
- Rust (Cargo)
- Database (PostgreSQL recommended)

### Environment Setup
1. Copy `.env.example` to `.env`.
2. Configure `DATABASE_URL` and `JWT_SECRET`.

### Database Migrations
```sh
cargo run -p migration
```

### Running the Server
```sh
cargo run
```

## Development Conventions

### Standard API Response
All API endpoints must return the `ApiResponse<T>` format defined in `src/utils/api_response.rs`.
```json
{
  "status": "success", // or "error"
  "code": "AUTH_LOGIN_SUCCESS", // or error code like "VALIDATION_ERROR"
  "message": "Login successful",
  "data": { ... } // Optional
}
```

### Request Validation
Use `ValidatedJson<T>` in handlers.
1.  **Model Definition**: Use `Option<T>` for fields to allow capturing missing fields during validation rather than deserialization.
2.  **Validators**:
    *   Required: `#[validate(custom(function = "crate::utils::validator_utils::validate_required"))]`
    *   Length: `#[validate(length(min = 3))]` (Apply to `Option` field, `validator` handles it).
3.  **Error Response**: Returns "VALIDATION_ERROR" with `data` containing a **LIST** of invalid fields.
    ```json
    {
      "status": "error",
      "code": "VALIDATION_ERROR",
      "message": "Validation failed",
      "data": [
         {
             "field": "email",
             "title": "invalid_email",
             "message": "Invalid email format"
         },
         {
             "field": "password",
             "title": "is_required",
             "message": "This field is required"
         }
      ]
    }
    ```

### Architecture Pattern (DTOs)
We explicitly separate Data Transfer Objects (Request/Response) from Database Entities.
- **Request DTOs**: defined in `src/models/`. Use `Option` types for fields to enable full validation reporting.
- **Response DTOs**: defined in `src/models/`. Contains only data safe for public exposure.
- **Entities**: defined in `src/entities/`. Maps directly to database tables.

### Naming Conventions
- **Services**: `src/services/{domain}_service.rs` (e.g., `auth_service.rs`).
- **Repositories**: `src/repositories/{domain}_repository.rs`.
- **Models**: `src/models/{domain}_model.rs`.

### Database Logic
- **Soft Delete**: Handlers/Repositories *must* filter by `deleted_at IS NULL` for active records.
- **UUID**: Uses `Uuid::now_v7()` for primary keys.

### Authentication
- **Mechanism**: JWT (JSON Web Tokens).
- **Hashing**: Argon2.

## Key Commands
| Action | Command |
| :--- | :--- |
| Run Server | `cargo run` |
| Run Migrations | `cargo run -p migration` |
| Check API | Use Bruno App with `Bruno/` collection |
