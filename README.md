# 🛡️ Password Manager (Tkinter + MySQL)

A simple yet functional **Password Manager desktop app** built with **Python**, **Tkinter**, and **MySQL**.  
It allows users to **generate secure passwords**, **store them locally in a database**, and **view or copy saved credentials** from a graphical interface.

---

## 🚀 Features

- **Password Generator**  
  Generates strong random passwords containing letters, numbers, and symbols.
  
- **Local Database Storage (MySQL)**  
  Stores all saved credentials (website, email, and password) securely in a local MySQL database.
  
- **Clipboard Copy**  
  Automatically copies newly generated or selected passwords to clipboard using `pyperclip`.

- **GUI with Tkinter**  
  Clean and user-friendly interface for adding, viewing, and copying passwords.

- **Dynamic Password List**  
  View all stored credentials in a table, with auto-refresh and double-click copy functionality.

---

## 🧰 Tech Stack

| Component | Technology |
|------------|-------------|
| GUI | Tkinter |
| Database | MySQL |
| Clipboard | Pyperclip |
| Language | Python 3.x |
| Encryption Library | Cryptography *(placeholder for future encryption)* |

---

## 📦 Requirements

Make sure you have the following installed:

- Python 3.8+
- MySQL Server
- The following Python packages:
  ```bash
  pip install mysql-connector-python pyperclip cryptography
