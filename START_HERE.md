# Employee Payroll Naming Convention Improvement System
## Cloud deployment package

This package is prepared for **Render + PostgreSQL**. It can also run locally with SQLite.

### 1. What changed
- Flask application served by Gunicorn.
- PostgreSQL support through `DATABASE_URL`; SQLite is used locally when no database URL is supplied.
- Passwords are stored as secure password hashes, not plain text.
- Secret key and initial administrator credentials come from environment variables.
- Individual user accounts can be created from **Admin Panel**.
- Roles: Administrator, HR, Employee.
- CSRF protection for POST forms.
- Secure session-cookie settings for HTTPS deployment.
- Security headers and a `/health` endpoint.
- Render Blueprint included in `render.yaml`.

### 2. Deploy to Render
1. Create a GitHub account if you do not already have one.
2. Create a new GitHub repository, for example `employee-payroll-naming-system`.
3. Upload **all files and folders in this package** to the repository root.
4. Open Render and sign in with GitHub.
5. Choose **New -> Blueprint** and select your GitHub repository.
6. Render reads `render.yaml` and creates the web service and PostgreSQL database.
7. During setup, enter your own values for:
   - `ADMIN_USERNAME` — your first administrator username.
   - `ADMIN_PASSWORD` — use a strong password of at least 8 characters.
8. Deploy the Blueprint.
9. After deployment, Render gives the web service an `onrender.com` HTTPS address.
10. Open that address in Chrome and sign in with the administrator account you supplied.
11. Open **Admin Panel** and create separate accounts for HR/employees. Do not share one account between users.

### 3. Important database note
The included Blueprint uses Render's free PostgreSQL plan for a college/demo deployment. Render's current documentation states that free PostgreSQL databases expire after 30 days. For long-term or real organizational use, select an appropriate paid database plan and establish backups/retention requirements before putting real employee or salary data into the system.

### 4. Local test on Windows
Open Command Prompt in this folder:

```text
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
set ADMIN_USERNAME=admin
set ADMIN_PASSWORD=ChangeMe_123!
python app.py
```

Then open:

`http://127.0.0.1:5000`

For local HTTP, keep `SESSION_COOKIE_SECURE=0` or leave it unset.

### 5. Production security
This package is a college/demo deployment foundation, not a security certification for a public-sector production system. Before real deployment with employee or salary information, have the organization/security team review access control, privacy requirements, audit logging, backups, retention, incident response, password policy, MFA/SSO, network restrictions, and applicable laws/regulations.

### 6. Custom domain
Do not use `your-payroll-system.com` unless you own/register that domain and configure its DNS. Render provides an HTTPS `onrender.com` address first; a custom domain can be configured later.
