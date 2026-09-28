# Product Specification — Readymade Shop Billing Software
## Authentication / Login Module

| Field       | Value                                 |
|-------------|---------------------------------------|
| **Product** | Readymade Shop Billing Software       |
| **Module**  | Authentication / Login                |
| **Version** | 1.0                                   |
| **Phase**   | 1 — Login & Authentication only       |
| **Date**    | 2026-08-18                            |

---

## 1. Roles

| Role       | Enum Value  | Description                                      |
|------------|-------------|--------------------------------------------------|
| Admin      | `ADMIN`     | Full administrator access to all shop operations |
| Cashier    | `CASHIER`   | Restricted access to cashier/POS workflows only  |

---

## 2. Login Page — UI Requirements

### 2.1 Branding

| Element      | Requirement                                                                 |
|--------------|-----------------------------------------------------------------------------|
| **Shop Logo**| Display the shop logo prominently at the top of the login form.             |
| **Shop Name**| Display the shop name below the logo in a clear, readable heading.          |

### 2.2 Login Form Fields

| Field                         | Requirement                                                                                          |
|-------------------------------|------------------------------------------------------------------------------------------------------|
| **Username / Email / Mobile** | A single input field accepting username, email address, or mobile number for flexible login.         |
| **Password**                  | A password input field. Input must be masked by default.                                             |
| **Show / Hide Password**      | A toggle button (eye icon) to reveal or re-mask the password. Accessible via keyboard.              |
| **Login Button**              | A primary action button labelled "Login". Triggers form submission.                                  |
| **Remember Me**               | A checkbox allowing the user to persist their session across browser restarts.                       |
| **Forgot Password**           | A placeholder link labelled "Forgot Password?" — no functionality in v1.0; reserved for future.     |

### 2.3 States & Feedback

| State                        | Requirement                                                                                         |
|------------------------------|-----------------------------------------------------------------------------------------------------|
| **Loading State**            | Show a visible loading indicator (spinner or disabled button) while the authentication request is in progress. Prevent duplicate submissions. |
| **Validation Messages**      | Display inline, accessible error messages for empty fields, invalid email format, password too short, etc. Validate on blur and on submit. |
| **Invalid Credential Error** | Display a non-specific error message such as "Invalid username or password." Do not reveal which field is wrong. |
| **Account Inactive**         | If the account status is `INACTIVE`, display a clear message: "Your account has been deactivated. Contact the administrator." |

---

## 3. Authentication

### 3.1 Password Security

| Requirement               | Detail                                                                                         |
|---------------------------|-----------------------------------------------------------------------------------------------|
| **No Plaintext Passwords**| Passwords must never be stored as plaintext. They must be hashed before storage.              |
| **Hashing Algorithm**     | Use a strong, salted hashing algorithm — bcrypt (min cost 10) or Argon2id recommended.        |
| **Password Complexity**   | Minimum 8 characters. Encourage a mix of letters, numbers, and symbols (enforce as needed).   |

### 3.2 User Authentication Flow

1. User submits login credentials (username/email/mobile + password).
2. Backend looks up the user by the provided identifier.
3. Backend verifies the submitted password against the stored password hash.
4. If credentials are valid and account is `ACTIVE`, issue a session token or JWT.
5. If credentials are invalid, return a generic error without specifying which field failed.
6. If the account is `INACTIVE`, return a specific account-deactivated message.

### 3.3 Session / Token Handling

| Requirement            | Detail                                                                                            |
|------------------------|---------------------------------------------------------------------------------------------------|
| **Token Type**         | Use JWT (JSON Web Token) or server-side sessions — follow the existing stack convention.          |
| **Token Storage**      | Store tokens securely — `HttpOnly` cookies preferred to prevent XSS access.                      |
| **Token Expiry**       | Tokens must have a defined expiry. Short-lived access tokens; optional refresh tokens.            |
| **Remember Me**        | When checked, extend session/token lifetime (e.g., 7–30 days). When unchecked, session expires on browser close. |

### 3.4 Logout

| Requirement            | Detail                                                                               |
|------------------------|--------------------------------------------------------------------------------------|
| **Logout Action**      | Clear the session/token from client storage and invalidate it server-side if applicable. |
| **Redirect**           | After logout, redirect the user to `/login`.                                         |

### 3.5 Account Status

| Status     | Enum Value   | Behaviour                                                    |
|------------|--------------|--------------------------------------------------------------|
| Active     | `ACTIVE`     | User can log in normally.                                    |
| Inactive   | `INACTIVE`   | Login is blocked. User receives account-deactivated message. |

---

## 4. Protected Routes & Role-Based Access Control

### 4.1 Route Authorization

| Route                 | Access              | Behaviour for Unauthorized Access                              |
|-----------------------|---------------------|----------------------------------------------------------------|
| `/login`              | Public              | If already authenticated, redirect to the user's role dashboard. |
| `/admin/dashboard`    | `ADMIN` only        | `CASHIER` or unauthenticated users → redirect to `/login` (or 403). |
| `/cashier/dashboard`  | `CASHIER` only      | `ADMIN` or unauthenticated users → redirect to `/login` (or appropriate page). |
| Any protected route   | Authenticated only  | Unauthenticated users → redirect to `/login`.                 |

### 4.2 Rules

- Role-based authorization **must** be enforced **server-side** on every
  protected API endpoint and route. Frontend route guards are supplementary only.
- A `CASHIER` must never be able to access Admin-only routes or APIs, even
  by directly navigating to the URL or manipulating client-side state.
- Unauthenticated requests to any protected route/API must receive a `401
  Unauthorized` or redirect to `/login`.

### 4.3 Post-Login Redirect

| Role      | Redirect Destination  |
|-----------|-----------------------|
| `ADMIN`   | `/admin/dashboard`    |
| `CASHIER` | `/cashier/dashboard`  |

---

## 5. User Model

### 5.1 Fields

| Field           | Type         | Description                                          | Notes                        |
|-----------------|--------------|------------------------------------------------------|------------------------------|
| `id`            | Integer / UUID | Unique identifier for each user.                   | Primary key, auto-generated. |
| `name`          | String       | Full display name of the user.                       | Required.                    |
| `username`      | String       | Unique login username.                               | Required, unique.            |
| `email`         | String       | Email address.                                       | Required, unique, valid email format. |
| `mobile`        | String       | Mobile phone number.                                 | Optional or required; unique if provided. |
| `password_hash` | String       | Hashed password. **Never plaintext.**                | Required. Not exposed in API responses. |
| `role`          | Enum         | User role: `ADMIN` or `CASHIER`.                     | Required.                    |
| `status`        | Enum         | Account status: `ACTIVE` or `INACTIVE`.              | Default: `ACTIVE`.           |
| `created_at`    | Timestamp    | Record creation timestamp.                           | Auto-set on creation.        |
| `updated_at`    | Timestamp    | Record last-updated timestamp.                       | Auto-updated on modification.|

### 5.2 Role Enum

| Value      | Description                        |
|------------|------------------------------------|
| `ADMIN`    | Administrator — full access.       |
| `CASHIER`  | Cashier — restricted access.       |

### 5.3 Status Enum

| Value      | Description                          |
|------------|--------------------------------------|
| `ACTIVE`   | Account is active and can log in.    |
| `INACTIVE` | Account is disabled; login blocked.  |

---

## 6. UI/UX Requirements

| Requirement                  | Detail                                                                                            |
|------------------------------|---------------------------------------------------------------------------------------------------|
| **Design Style**             | Professional, modern, and clean — appropriate for a billing/retail software application.         |
| **Responsive Layout**        | Fully responsive across desktop, tablet, and mobile screen sizes.                                |
| **Keyboard Accessibility**   | All form fields, buttons, and controls must be fully usable via keyboard alone (Tab, Enter, Space). |
| **Error States**             | Error messages must be clear, visible, and accessible (ARIA roles where applicable).             |
| **Loading States**           | Loading indicators must be visible during async operations to prevent user confusion.             |
| **Form Labels**              | All form inputs must have associated, accessible `<label>` elements (not just placeholders).     |
| **Password Visibility Toggle**| Eye icon button with appropriate ARIA label ("Show password" / "Hide password").               |
| **Colour & Contrast**        | Text and UI elements must meet WCAG 2.1 AA contrast ratio requirements.                          |
| **No Unnecessary Elements**  | Keep the login UI focused and uncluttered — show only what is needed for login.                  |

---

## 7. Placeholder Dashboards

The following routes are **reserved for future implementation**. In v1.0, they
may be simple placeholder pages (e.g., "Welcome, Admin" / "Welcome, Cashier")
to confirm successful login and role-based routing.

| Route                 | Role      | Status in v1.0        |
|-----------------------|-----------|-----------------------|
| `/admin/dashboard`    | `ADMIN`   | Placeholder only      |
| `/cashier/dashboard`  | `CASHIER` | Placeholder only      |

> **Do NOT implement full dashboard functionality now.**

---

## 8. Out of Scope — Current Phase

The following are **explicitly out of scope** for Phase 1 (v1.0) and must
**not** be implemented at this stage:

| Module / Feature          | Reason           |
|---------------------------|------------------|
| Billing / Point of Sale   | Future phase     |
| Products & Categories     | Future phase     |
| Inventory Management      | Future phase     |
| Barcode Scanning          | Future phase     |
| Customer Management       | Future phase     |
| Supplier Management       | Future phase     |
| Purchases / Purchase Orders | Future phase   |
| Sales / Sales Orders      | Future phase     |
| Returns & Exchanges       | Future phase     |
| GST / Tax Calculation     | Future phase     |
| Reports & Analytics       | Future phase     |
| Expense Tracking          | Future phase     |
| Multi-Branch / Multi-Store| Future phase     |
| Online Orders             | Future phase     |
| Loyalty / Rewards         | Future phase     |

---

## 9. Acceptance Criteria — v1.0

- [ ] Login page renders correctly on desktop, tablet, and mobile.
- [ ] User can log in with valid username/email/mobile and password.
- [ ] Invalid credentials show a generic error message.
- [ ] Inactive accounts are blocked with a clear message.
- [ ] Passwords are stored as hashes — never plaintext.
- [ ] `ADMIN` user is redirected to `/admin/dashboard` after login.
- [ ] `CASHIER` user is redirected to `/cashier/dashboard` after login.
- [ ] `CASHIER` cannot access `/admin/dashboard` (server-side enforcement).
- [ ] Unauthenticated users are redirected to `/login`.
- [ ] Logout clears the session and redirects to `/login`.
- [ ] Remember Me extends session as expected.
- [ ] All form fields have accessible labels.
- [ ] Show/hide password toggle works correctly.
- [ ] Loading state is shown during login request.
- [ ] Validation messages appear for empty/invalid fields.
