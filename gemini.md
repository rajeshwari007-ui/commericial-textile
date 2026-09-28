# Gemini Development Instructions — Readymade Shop Billing Software

> This document provides instructions for Gemini (or any AI assistant) when
> working on this project in future sessions. Read this file carefully before
> making any changes.

---

## Project Overview

This is a **Readymade Shop Billing Software** — a full-stack web application
designed to manage billing, inventory, and shop operations for a readymade
(garments/apparel) retail shop.

---

## Current Development Phase

**Phase 1 — Admin and Cashier Login / Authentication only.**

- The **only** work in progress right now is implementing secure login and
  authentication for two roles: **Admin** and **Cashier**.
- No other modules (billing, inventory, products, customers, GST, reports,
  etc.) should be implemented yet.

---

## Roles

| Role      | Description                                                   |
|-----------|---------------------------------------------------------------|
| `ADMIN`   | Full administrator access to all shop management features.    |
| `CASHIER` | Restricted access to cashier/POS operations only.             |

---

## Authentication Requirements

- Passwords must **never** be stored as plaintext. Always hash passwords using
  a strong algorithm (e.g., bcrypt, Argon2).
- Authentication must be **secure** — use industry-standard practices.
- Use **session tokens or JWTs** (follow the existing implementation pattern
  if already established).
- **Role-based authorization must be enforced server-side** — never trust the
  client alone.
- Protected routes must require a valid, authenticated session/token.
- A `CASHIER` must **never** be able to access Admin-only routes.
- Unauthenticated users must always be redirected to `/login`.

---

## Technology Stack

- Follow the **existing project technology stack and architecture** exactly.
- Before making any changes, **inspect the existing files** to understand the
  framework, folder structure, conventions, and patterns already in use.
- Do **not** switch frameworks, replace libraries, or introduce unnecessary
  new dependencies without explicit instruction.

---

## Coding Guidelines

1. **Inspect before you change.** Always read existing files before editing or
   adding code. Never assume the structure — verify it.
2. **Do not unnecessarily rewrite existing code.** Make targeted, minimal
   changes.
3. **Keep code modular and maintainable.** Separate concerns: routes,
   controllers, services, models, middleware, etc.
4. **Validate all input** — both on the frontend (for UX) and on the backend
   (for security). Never trust client-side validation alone.
5. **Do not expose secrets.** API keys, database credentials, JWT secrets, and
   similar values must only exist in environment variables (`.env`), never
   hardcoded in source files.
6. **Follow secure coding practices** at all times — sanitize inputs, prevent
   SQL injection, prevent XSS, use HTTPS in production.
7. **Test changes before considering them complete.** Verify that login works,
   roles are enforced, and edge cases (wrong password, inactive account, etc.)
   are handled correctly.
8. **Document non-obvious logic** with brief inline comments.

---

## Future Modules (Do NOT Implement Now)

The following features are **planned for future phases** and must **not** be
implemented during the current phase:

- Billing / Point of Sale (POS)
- Products and product categories
- Inventory management
- Barcode scanning
- Customer management
- Supplier management
- Purchases and purchase orders
- Sales and sales orders
- Returns and exchanges
- GST / tax calculation and reports
- Financial reports and analytics
- Expense tracking
- Multi-branch / multi-store support
- Online orders
- Loyalty / rewards program

Only begin these when explicitly instructed and after the authentication phase
is complete and verified.

---

## Protected Route Map (Current Phase)

| Route               | Allowed Role(s)      | Notes                          |
|---------------------|----------------------|--------------------------------|
| `/login`            | Public               | Redirect to dashboard if logged in |
| `/admin/dashboard`  | `ADMIN` only         | Placeholder — not yet built    |
| `/cashier/dashboard`| `CASHIER` only       | Placeholder — not yet built    |

---

## Summary Checklist Before Starting Any Work

- [ ] Read this file (`gemini.md`) fully.
- [ ] Read `prod.specification.md` for detailed module requirements.
- [ ] Inspect the existing project file structure and technology stack.
- [ ] Confirm that the work you are about to do is within the current phase scope.
- [ ] Never store plaintext passwords.
- [ ] Never skip server-side authorization.
- [ ] Never hardcode secrets.
- [ ] Test your changes.
