This is the OS project for a User-Friendly System Call Interface for Enhanced Security.
# 🔒 Secure System Call Interface

A role-based GUI wrapper for system commands with enhanced security logging.

![Screenshot](assets/demo.png) *(Optional: Add UI screenshot)*

## 🚀 Features
- **Role-Based Access Control (RBAC)**
  - Admin: Full command access
  - User: Restricted command set
- **Cross-Platform Support**
  - Windows (`dir`, `del`) ↔ Linux (`ls`, `rm`) auto-translation
- **Secure Logging**
  - Timestamped record of all executed commands
- **Intuitive GUI**
  - ttkBootstrap-powered interface with dark/light modes

## 📦 Installation
```bash
# Clone repository
git clone https://github.com/yourusername/secure-system-call.git

# Install dependencies
pip install -r requirements.txt

# Run application
python main.py
