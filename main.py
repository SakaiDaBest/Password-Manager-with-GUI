import tkinter as tk
from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from random import choice, randint, shuffle
import pyperclip
import mysql.connector
from cryptography.fernet import Fernet
import base64
import hashlib


# ---------------------------- ENCRYPTION CLASS ------------------------------- #
class EncryptionManager:
    def __init__(self, master_key="default_master_key"):
        """
        Initialize encryption with a master key.
        In production, use a secure key management system.
        """
        # Derive a 32-byte key from the master key using SHA-256
        key = hashlib.sha256(master_key.encode()).digest()
        # Encode to base64 for Fernet compatibility
        self.key = base64.urlsafe_b64encode(key)
        self.cipher = Fernet(self.key)

    def encrypt(self, data):
        """Encrypt data and return as string"""
        if isinstance(data, str):
            data = data.encode()
        encrypted = self.cipher.encrypt(data)
        return encrypted.decode()

    def decrypt(self, encrypted_data):
        """Decrypt data and return as string"""
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode()
        decrypted = self.cipher.decrypt(encrypted_data)
        return decrypted.decode()


# ---------------------------- DATABASE CLASS ------------------------------- #
class DatabaseManager:
    def __init__(self, host="localhost", user="appuser", password="app_password", database="passwords"):
        self.conn = mysql.connector.connect(
            host=host,
            user=user,
            passwd=password,
            database=database
        )
        self.cursor = self.conn.cursor()
        self.current_user_id = None
        self.is_admin = False
        self.encryption = EncryptionManager()
        self._create_tables()

    def _create_tables(self):
        # Create login_users table for authentication
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE,
                password VARCHAR(50),
                is_admin BOOLEAN DEFAULT FALSE
            )
        """)

        # Create users table for passwords (with longer password field for encrypted data)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                website VARCHAR(255),
                credential VARCHAR(255),
                user_password TEXT,
                FOREIGN KEY (user_id) REFERENCES login_users(id)
            )
        """)

        # Check if user_id column exists
        try:
            self.cursor.execute("SELECT user_id FROM users LIMIT 1")
            self.cursor.fetchone()
        except mysql.connector.errors.ProgrammingError:
            print("Adding user_id column to users table...")
            self.cursor.execute("ALTER TABLE users ADD COLUMN user_id INT")
            self.cursor.execute("""
                ALTER TABLE users
                ADD FOREIGN KEY (user_id) REFERENCES login_users(id)
            """)
            self.conn.commit()

        # Check if is_admin column exists, if not add it
        try:
            self.cursor.execute("SELECT is_admin FROM login_users LIMIT 1")
            self.cursor.fetchone()
        except mysql.connector.errors.ProgrammingError:
            print("Adding is_admin column to login_users table...")
            self.cursor.execute("""
                ALTER TABLE login_users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE
            """)
            self.conn.commit()
            print("is_admin column added successfully!")

        # Modify user_password column to TEXT if it's not already
        try:
            self.cursor.execute("""
                ALTER TABLE users MODIFY COLUMN user_password TEXT
            """)
            self.conn.commit()
        except:
            pass

        # Insert default admin user if not exists
        try:
            self.cursor.execute("INSERT INTO login_users (username, password, is_admin) VALUES (%s, %s, %s)",
                                ("admin", "admin123", True))
            self.conn.commit()
        except mysql.connector.IntegrityError:
            pass

        # Insert default user if not exists
        try:
            self.cursor.execute("INSERT INTO login_users (username, password, is_admin) VALUES (%s, %s, %s)",
                                ("user", "123", False))
            self.conn.commit()
        except mysql.connector.IntegrityError:
            pass

    def create_user(self, username, password):
        try:
            query = "INSERT INTO login_users (username, password, is_admin) VALUES (%s, %s, %s)"
            self.cursor.execute(query, (username, password, False))
            self.conn.commit()
            return True, "Account created successfully!"
        except mysql.connector.IntegrityError:
            return False, "Username already exists. Please choose a different username."

    def verify_login(self, username, password):
        query = "SELECT id, is_admin FROM login_users WHERE username=%s AND password=%s"
        self.cursor.execute(query, (username, password))
        result = self.cursor.fetchone()
        if result:
            self.current_user_id = result[0]
            self.is_admin = result[1]
            return True
        return False

    def insert_user(self, website, credential, user_password):
        """Insert user credentials with encryption"""
        # Encrypt sensitive data
        encrypted_website = self.encryption.encrypt(website)
        encrypted_credential = self.encryption.encrypt(credential)
        encrypted_password = self.encryption.encrypt(user_password)

        query = "INSERT INTO users (user_id, website, credential, user_password) VALUES (%s, %s, %s, %s)"
        self.cursor.execute(query, (self.current_user_id, encrypted_website, encrypted_credential, encrypted_password))
        self.conn.commit()

    def fetch_all(self):
        """Fetch all passwords and decrypt them"""
        query = "SELECT * FROM users WHERE user_id=%s"
        self.cursor.execute(query, (self.current_user_id,))
        rows = self.cursor.fetchall()

        # Decrypt the data
        decrypted_rows = []
        for row in rows:
            try:
                decrypted_row = (
                    row[0],  # id
                    row[1],  # user_id
                    self.encryption.decrypt(row[2]),  # website
                    self.encryption.decrypt(row[3]),  # credential
                    self.encryption.decrypt(row[4])  # user_password
                )
                decrypted_rows.append(decrypted_row)
            except Exception as e:
                # If decryption fails (old unencrypted data), keep original
                print(f"Decryption error for row {row[0]}: {e}")
                decrypted_rows.append(row)

        return decrypted_rows

    def get_all_users(self):
        """Admin function to get all users"""
        query = "SELECT id, username, password FROM login_users WHERE is_admin=FALSE"
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def update_user_password(self, user_id, new_password):
        """Admin function to update a user's master password"""
        query = "UPDATE login_users SET password=%s WHERE id=%s"
        self.cursor.execute(query, (new_password, user_id))
        self.conn.commit()

    def delete_user(self, user_id):
        """Admin function to delete a user"""
        # First delete all their saved passwords
        self.cursor.execute("DELETE FROM users WHERE user_id=%s", (user_id,))
        # Then delete the user account
        self.cursor.execute("DELETE FROM login_users WHERE id=%s", (user_id,))
        self.conn.commit()


# ---------------------------- PASSWORD GENERATOR CLASS ------------------------------- #
class PasswordGenerator:
    def __init__(self):
        self.letters = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
        self.numbers = list("0123456789")
        self.symbols = list("!#$%&()*+")

    def generate(self):
        password_letters = [choice(self.letters) for _ in range(randint(8, 10))]
        password_symbols = [choice(self.symbols) for _ in range(randint(2, 4))]
        password_numbers = [choice(self.numbers) for _ in range(randint(2, 4))]

        password_list = password_letters + password_symbols + password_numbers
        shuffle(password_list)
        password = "".join(password_list)
        pyperclip.copy(password)
        return password


# ---------------------------- APP CLASS ------------------------------- #
class PasswordManagerApp:
    def __init__(self, root):
        self.db = DatabaseManager()
        self.generator = PasswordGenerator()
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("600x400")

        self.container = tk.Frame(self.root)
        self.container.pack(fill="both", expand=True)

        self.frames = {}
        for F in (LoginScreen, CreateUserScreen, MainScreen, PasswordListScreen, AdminDashboard):
            frame = F(self.container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(LoginScreen)

    def show_frame(self, page):
        frame = self.frames[page]
        frame.tkraise()
        if page == PasswordListScreen:
            frame.load_passwords()
        elif page == AdminDashboard:
            frame.load_users()


# ---------------------------- LOGIN SCREEN ------------------------------- #
class LoginScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.setup_ui()

    def setup_ui(self):
        # Title
        Label(self, text="Password Manager", font=("Arial", 20, "bold")).pack(pady=30)
        Label(self, text="🔒 Encrypted Storage", font=("Arial", 10, "italic"), fg="green").pack(pady=5)
        Label(self, text="Login", font=("Arial", 14)).pack(pady=10)

        # Username
        Label(self, text="Username:").pack(pady=5)
        self.username_entry = Entry(self, width=30)
        self.username_entry.pack(pady=5)
        self.username_entry.focus()

        # Password
        Label(self, text="Password:").pack(pady=5)
        self.password_entry = Entry(self, width=30, show="*")
        self.password_entry.pack(pady=5)

        # Login button
        Button(self, text="Login", width=20, command=self.login).pack(pady=10)

        # Create user button
        Button(self, text="Create New Account", width=20,
               command=lambda: self.controller.show_frame(CreateUserScreen)).pack(pady=5)

        # Bind Enter key to login
        self.password_entry.bind("<Return>", lambda e: self.login())

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if len(username) == 0 or len(password) == 0:
            messagebox.showerror("Error", "Please enter both username and password.")
            return

        if self.controller.db.verify_login(username, password):
            messagebox.showinfo("Success", f"Welcome back, {username}!")
            self.username_entry.delete(0, END)
            self.password_entry.delete(0, END)

            # Check if admin
            if self.controller.db.is_admin:
                self.controller.show_frame(AdminDashboard)
            else:
                self.controller.show_frame(MainScreen)
        else:
            messagebox.showerror("Error", "Invalid username or password.")
            self.password_entry.delete(0, END)


# ---------------------------- CREATE USER SCREEN ------------------------------- #
class CreateUserScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.setup_ui()

    def setup_ui(self):
        # Title
        Label(self, text="Create New Account", font=("Arial", 16, "bold")).pack(pady=30)

        # Username
        Label(self, text="Username:").pack(pady=5)
        self.username_entry = Entry(self, width=30)
        self.username_entry.pack(pady=5)
        self.username_entry.focus()

        # Password
        Label(self, text="Password:").pack(pady=5)
        self.password_entry = Entry(self, width=30, show="*")
        self.password_entry.pack(pady=5)

        # Confirm Password
        Label(self, text="Confirm Password:").pack(pady=5)
        self.confirm_password_entry = Entry(self, width=30, show="*")
        self.confirm_password_entry.pack(pady=5)

        # Create account button
        Button(self, text="Create Account", width=20, command=self.create_account).pack(pady=20)

        # Back button
        Button(self, text="Back to Login", width=20,
               command=lambda: self.controller.show_frame(LoginScreen)).pack(pady=5)

        # Bind Enter key
        self.confirm_password_entry.bind("<Return>", lambda e: self.create_account())

    def create_account(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        # Validation
        if len(username) == 0 or len(password) == 0:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if len(username) < 3:
            messagebox.showerror("Error", "Username must be at least 3 characters long.")
            return

        if len(password) < 3:
            messagebox.showerror("Error", "Password must be at least 3 characters long.")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        # Try to create user
        success, message = self.controller.db.create_user(username, password)

        if success:
            messagebox.showinfo("Success", message)
            self.username_entry.delete(0, END)
            self.password_entry.delete(0, END)
            self.confirm_password_entry.delete(0, END)
            self.controller.show_frame(LoginScreen)
        else:
            messagebox.showerror("Error", message)


# ---------------------------- ADMIN DASHBOARD ------------------------------- #
class AdminDashboard(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.setup_ui()

    def setup_ui(self):
        tk.Label(self, text="Admin Dashboard", font=("Arial", 20, "bold")).pack(pady=20)
        tk.Label(self, text="Manage User Accounts", font=("Arial", 14)).pack(pady=10)

        # Treeview for users
        self.tree = ttk.Treeview(self, columns=("ID", "Username", "Password"), show="headings", height=10)
        self.tree.heading("ID", text="ID")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Password", text="Master Password")

        self.tree.column("ID", width=50)
        self.tree.column("Username", width=200)
        self.tree.column("Password", width=200)

        self.tree.pack(fill="both", expand=True, padx=20, pady=20)

        # Buttons frame
        button_frame = tk.Frame(self)
        button_frame.pack(pady=10)

        Button(button_frame, text="Edit Password", command=self.edit_password, width=15).pack(side="left", padx=5)
        Button(button_frame, text="Delete User", command=self.delete_user, width=15).pack(side="left", padx=5)
        Button(button_frame, text="Refresh", command=self.load_users, width=15).pack(side="left", padx=5)

        Button(self, text="Logout", command=lambda: self.controller.show_frame(LoginScreen), width=20).pack(pady=10)

    def load_users(self):
        # Clear existing data
        for row in self.tree.get_children():
            self.tree.delete(row)

        # Load all users
        users = self.controller.db.get_all_users()
        for user in users:
            self.tree.insert("", "end", values=(user[0], user[1], user[2]))

    def edit_password(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a user first.")
            return

        values = self.tree.item(selected_item, "values")
        user_id = values[0]
        username = values[1]

        # Create popup window for editing
        edit_window = tk.Toplevel(self)
        edit_window.title(f"Edit Password for {username}")
        edit_window.geometry("300x150")

        Label(edit_window, text=f"User: {username}", font=("Arial", 12, "bold")).pack(pady=10)
        Label(edit_window, text="New Master Password:").pack(pady=5)

        new_password_entry = Entry(edit_window, width=30, show="*")
        new_password_entry.pack(pady=5)
        new_password_entry.focus()

        def save_new_password():
            new_password = new_password_entry.get()
            if len(new_password) == 0:
                messagebox.showerror("Error", "Password cannot be empty.")
                return

            if len(new_password) < 3:
                messagebox.showerror("Error", "Password must be at least 3 characters long.")
                return

            self.controller.db.update_user_password(user_id, new_password)
            messagebox.showinfo("Success", f"Password updated for {username}!")
            edit_window.destroy()
            self.load_users()

        Button(edit_window, text="Save", command=save_new_password, width=15).pack(pady=10)
        new_password_entry.bind("<Return>", lambda e: save_new_password())

    def delete_user(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a user first.")
            return

        values = self.tree.item(selected_item, "values")
        user_id = values[0]
        username = values[1]

        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete user '{username}' and all their saved passwords?"
        )

        if confirm:
            self.controller.db.delete_user(user_id)
            messagebox.showinfo("Success", f"User '{username}' has been deleted.")
            self.load_users()


# ---------------------------- MAIN SCREEN ------------------------------- #
class MainScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.setup_ui()

    def setup_ui(self):
        # Logo
        canvas = Canvas(self, height=200, width=200)
        try:
            self.logo_img = PhotoImage(file="logo.png")
            canvas.create_image(128, 100, image=self.logo_img)
        except Exception:
            pass
        canvas.grid(row=0, column=1, sticky="")

        # Labels
        Label(self, text="Website:").grid(row=1, column=0, sticky="e")
        Label(self, text="Email/Username:").grid(row=2, column=0, sticky="e")
        Label(self, text="Password:").grid(row=3, column=0, sticky="e")

        # Entries
        self.website_entry = Entry(self, width=43)
        self.website_entry.grid(row=1, column=1, columnspan=2, sticky="e")
        self.website_entry.focus()

        self.email_entry = Entry(self, width=43)
        self.email_entry.grid(row=2, column=1, columnspan=2, sticky="e")
        self.email_entry.insert(0, "example@gmail.com")

        self.password_entry = Entry(self, width=23)
        self.password_entry.grid(row=3, column=1, sticky="e")

        # Buttons
        Button(self, text="Generate Password", command=self.generate_password).grid(row=3, column=2, sticky="w")
        Button(self, text="Add", width=40, command=self.save_password).grid(row=4, column=1, columnspan=2, sticky="e")
        Button(self, text="Show Passwords", width=40,
               command=lambda: self.controller.show_frame(PasswordListScreen)).grid(row=5, column=1, columnspan=2,
                                                                                    sticky="e")
        Button(self, text="Logout", width=40,
               command=lambda: self.controller.show_frame(LoginScreen)).grid(row=6, column=1, columnspan=2, sticky="e")

        # Encryption indicator
        Label(self, text="🔒 All passwords encrypted", font=("Arial", 9, "italic"), fg="green").grid(row=7, column=1,
                                                                                                    columnspan=2,
                                                                                                    pady=10)

    def generate_password(self):
        password = self.controller.generator.generate()
        self.password_entry.delete(0, END)
        self.password_entry.insert(0, password)

    def save_password(self):
        website = self.website_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()

        if len(website) == 0 or len(password) == 0:
            messagebox.showinfo(title="Oops", message="Please make sure you haven't left any fields empty.")
            return

        is_ok = messagebox.askokcancel(
            title=website,
            message=f"These are the details entered: \nEmail: {email} \nPassword: {password} \nIs it ok to save?"
        )

        if is_ok:
            self.controller.db.insert_user(website, email, password)
            self.website_entry.delete(0, END)
            self.password_entry.delete(0, END)
            messagebox.showinfo("Success", "Password saved and encrypted!")


# ---------------------------- PASSWORD LIST SCREEN ------------------------------- #
class PasswordListScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        tk.Label(self, text="Saved Passwords", font=("Arial", 16)).pack(pady=10)
        tk.Label(self, text="🔒 Decrypted for viewing", font=("Arial", 9, "italic"), fg="green").pack(pady=5)

        self.tree = ttk.Treeview(self, columns=("Website", "Email", "Password"), show="headings")
        self.tree.heading("Website", text="Website")
        self.tree.heading("Email", text="Email")
        self.tree.heading("Password", text="Password")
        self.tree.pack(fill="both", expand=True, padx=20, pady=20)

        self.tree.bind("<Double-1>", self.copy_password)

        Button(self, text="Back", command=lambda: controller.show_frame(MainScreen)).pack(pady=10)
        Button(self, text="Refresh", command=self.load_passwords).pack(pady=5)

    def load_passwords(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        rows = self.controller.db.fetch_all()
        for row in rows:
            self.tree.insert("", "end", values=(row[2], row[3], row[4]))

    def copy_password(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item, "values")
            password = values[2]
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")


# ---------------------------- MAIN ------------------------------- #
if __name__ == "__main__":
    root = Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
