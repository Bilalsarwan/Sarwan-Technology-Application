# Sarwan Technology Billing & Business Management System

A production-grade, full-stack financial billing, invoicing, and business management application built for Sarwan Technology.

---

## 1. System Overview & Architecture

The application implements a secure full-stack architecture combining a Vite-powered React 19 frontend with an Express backend service:

* **Frontend**: React 19, TypeScript, Tailwind CSS v4, Lucide Icons, Motion.
* **Backend**: Node.js / Express server (`server.ts`) hosting trusted authentication, session validation, and step-up authorization endpoints.
* **Database & Auth**: Google Cloud Firestore & Firebase Authentication via Google Identity Toolkit REST API.
* **Financial Ledger**: Atomic transactions protecting invoice balances, cash payment records, customer ledgers, and append-only audit trails.

---

## 2. Security Architecture & Invariants

* **Server-Authoritative Authentication**: Legacy password verification occurs strictly inside server memory using timing-safe comparisons (`crypto.timingSafeEqual`), eliminating side-channel timing attacks.
* **Zero Credential Leakage**: User profiles returned to browser clients are strictly sanitized (`passwordHash` and `passwordSalt` are stripped).
* **Canonical Identity Mapping**:
  * Staff accounts: `u.<official_user_id>@auth.sarwan.tech`
  * Customer portal accounts: `c.<customer_id>@customer.sarwan.tech`
* **Session Cryptographic Verification**: Restored sessions are verified against Google Identity Toolkit (`/api/auth/verify-session`). Client-side `localStorage` tampering cannot elevate privileges to Super Admin.
* **48-Hour Payment Reversal Rule**: Payment reversals are strictly restricted to the Super Admin role and must occur within 48 hours of payment creation timestamp (`createdAt`). Future timestamps, already-voided payments, and expired windows are automatically rejected.
* **Immutable Audit Trail**: Reversals atomically update invoice `totalPaid` and `remaining` balances, mark original payments as `isVoid: true`, optionally create replacement payments, and append immutable audit log records.

---

## 3. Installation & Setup

### Prerequisites
* Node.js v20+ or v22+
* npm v10+

### Step 1: Install Dependencies
```bash
npm install
```

### Step 2: Configure Environment
Copy the environment template and provide your Firebase project details:
```bash
cp .env.example .env
```

Ensure `firebase-applet-config.json` exists in the project root with your project credentials:
```json
{
  "projectId": "your_project_id",
  "apiKey": "your_api_key",
  "authDomain": "your_project_id.firebaseapp.com",
  "firestoreDatabaseId": "(default)"
}
```

---

## 4. Development & Running

### Start Development Server
Starts the Express server mounting Vite middlewares in development mode on port 3000:
```bash
npm run dev
```

### Type Checking & Linting
```bash
npm run lint
```

---

## 5. Automated Test Suites

Run any of the 19 automated test suites verifying business logic, security invariants, and layout:

```bash
# Security & Auth Migration Tests (17 tests)
npm run test:security-auth

# 48-Hour Payment Reversal Business Rules (13 tests)
npm run test:reversal-48h

# Payment Reversal Super Admin Authorization (7 tests)
npm run test:reversal-auth

# Theme & Design System Compliance (42 tests)
npm run test:theme

# Customer Module Workflows
npm run test:customer

# Invoice Expenses & Disbursements
npm run test:invoice-expenses

# Invoice Flows & PDF Parity
npm run test:flows

# KPI & Dashboard Balance Checks
npm run test:kpi
```

To run all automated test suites sequentially:
```bash
npm run test:security-auth && npm run test:reversal-48h && npm run test:reversal-auth && npm run test:theme && npm run test:customer && npm run test:invoice-expenses && npm run test:flows
```

---

## 6. Production Build & Deployment

### Production Build
Compiles TypeScript and bundles static assets to `dist/`:
```bash
npm run build
```

### Production Start
Starts the Express production server serving static frontend files from `dist/` and hosting API endpoints:
```bash
npm run start
```

### Rollback Procedure
If a deployment needs to be rolled back:
1. Revert to the prior verified release commit.
2. Run `npm run clean && npm run build`.
3. Restart the service process (`npm run start`).
4. Financial ledger records remain immutable in Firestore and require zero database migrations on rollback.
