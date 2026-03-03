# 🛡️ ZTS – Zero Trust Security Demo

**MSc Dissertation Project** – A fully functional web application demonstrating Zero Trust Architecture principles based on **NIST SP 800-207**.

> *"Never Trust, Always Verify"*

---

## 📋 Features

### 1. Login & Identity Security
- Username + password authentication
- **OTP-based Multi-Factor Authentication** (simulated or email)
- Account lockout after 5 failed attempts (30-minute auto-unlock)
- Session timeout with auto-logout on inactivity
- **bcrypt** password hashing
- Adaptive authentication (new IP/device → forced OTP)

### 2. Role-Based Access Control (RBAC)
| Role | Access |
|------|--------|
| SuperAdmin | All dashboards + admin panel |
| HR | Employee records, leave, payroll |
| Finance | Budgets, invoices, expenses |
| IT | Servers, tickets, access requests |
| CustomerSupport | Tickets, knowledge base, feedback |

- Least privilege enforcement
- Department-based isolation

### 3. Device Trust Verification
- Browser, OS, IP capture at login
- Device fingerprinting
- Device registration & trust management
- Unknown device → high risk flag
- Device health status dashboard

### 4. Network & Location Security
- IP address logging
- Geo-IP country detection (simulated)
- **Impossible travel detection** (speed > 900 km/h)
- VPN detection simulation
- Conditional access (block critical-risk logins)

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.11+ / FastAPI |
| Frontend | HTML, CSS, JavaScript (Jinja2 templates) |
| Database | Supabase (PostgreSQL) |
| Auth | bcrypt + OTP MFA |
| Server | Uvicorn + Gunicorn |
| Deployment | Ubuntu VPS compatible |

---

## 🚀 Quick Start

### 1. Clone & install dependencies

```bash
cd zts
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Set up Supabase

1. Create a project at [supabase.com](https://supabase.com)
2. Open **SQL Editor** and run the contents of `supabase_schema.sql`
3. Copy your project URL and keys

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env with your Supabase URL, anon key, and service role key
```

### 4. Seed default users

```bash
python seed.py
```

### 5. Run the app

```bash
# Development
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Production
gunicorn main:app -c gunicorn_conf.py
```

Visit **http://localhost:8000**

---

## 👤 Default Users

| Username | Password | Role |
|----------|----------|------|
| superadmin | Password1! | SuperAdmin |
| hr_user | Password1! | HR |
| finance_user | Password1! | Finance |
| it_user | Password1! | IT |
| cs_user | Password1! | CustomerSupport |

---

## 📁 Project Structure

```
zts/
├── main.py                 # FastAPI entry point
├── seed.py                 # Database seeder
├── requirements.txt        # Python dependencies
├── gunicorn_conf.py        # Production server config
├── supabase_schema.sql     # Database schema
├── zts.service             # systemd unit file
├── .env.example            # Environment template
├── app/
│   ├── config.py           # Settings loader
│   ├── database.py         # Supabase client
│   ├── security.py         # Auth, OTP, sessions, audit
│   ├── trust_engine.py     # Risk scoring, geo-IP, device trust
│   └── routes/
│       ├── auth.py         # Login, OTP, logout endpoints
│       └── dashboard.py    # Dashboard, admin, API endpoints
├── templates/
│   ├── login.html          # Login page
│   ├── otp.html            # OTP verification
│   ├── locked.html         # Account locked notice
│   ├── dashboard.html      # Main RBAC dashboard
│   ├── admin_logs.html     # Audit log viewer
│   └── admin_users.html    # User management
└── static/
    ├── css/style.css       # Full stylesheet
    └── js/app.js           # Device fingerprinting & UI
```

---

## 🔒 Zero Trust Principles Implemented

| Principle | Implementation |
|-----------|---------------|
| Verify explicitly | MFA (password + OTP) on every login |
| Least privilege | RBAC with department isolation |
| Assume breach | Continuous risk scoring, session monitoring |
| Device trust | Fingerprinting, registration, trust levels |
| Network awareness | Geo-IP, impossible travel, VPN detection |
| Micro-segmentation | Role-based dashboard isolation |
| Audit everything | Complete security event logging |

---

## 🖥️ Ubuntu VPS Deployment

```bash
# 1. Upload project to /opt/zts
# 2. Install dependencies
sudo apt update && sudo apt install python3.11 python3.11-venv -y
cd /opt/zts
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Configure .env
cp .env.example .env
nano .env

# 4. Seed database
python seed.py

# 5. Install systemd service
sudo cp zts.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable zts
sudo systemctl start zts

# 6. Check status
sudo systemctl status zts
```

---

## 📝 License

MSc Dissertation Project — University of the West of Scotland
