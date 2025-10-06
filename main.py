import tkinter as tk
from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from random import choice, randint, shuffle
import pyperclip
import mysql.connector
import cryptography
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
        self._create_table()

    def _create_table(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                website VARCHAR(50),
                credential VARCHAR(50),
                user_password VARCHAR(50)
            )
        """)

    def insert_user(self, website, credential, user_password):
        query = "INSERT INTO users (website, credential, user_password) VALUES (%s, %s, %s)"
        self.cursor.execute(query, (website, credential, user_password))
        self.conn.commit()

    def fetch_all(self):
        self.cursor.execute("SELECT * FROM users")
        return self.cursor.fetchall()


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
        for F in (MainScreen, PasswordListScreen):
            frame = F(self.container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(MainScreen)

    def show_frame(self, page):
        frame = self.frames[page]
        frame.tkraise()
        if page == PasswordListScreen:  # auto-refresh when switching to password list
            frame.load_passwords()


# ---------------------------- MAIN SCREEN ------------------------------- #
class MainScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.setup_ui()   # <-- now called here!

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
               command=lambda: self.controller.show_frame(PasswordListScreen)).grid(row=5, column=1, columnspan=2, sticky="e")

    def generate_password(self):
        password = self.controller.generator.generate()   # <-- fix here
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
            self.controller.db.insert_user(website, email, password)  # <-- fix here
            self.website_entry.delete(0, END)
            self.password_entry.delete(0, END)


# ---------------------------- PASSWORD LIST SCREEN ------------------------------- #
class PasswordListScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        tk.Label(self, text="Saved Passwords", font=("Arial", 16)).pack(pady=10)

        self.tree = ttk.Treeview(self, columns=("Website", "Email", "Password"), show="headings")
        self.tree.heading("Website", text="Website")
        self.tree.heading("Email", text="Email")
        self.tree.heading("Password", text="Password")
        self.tree.pack(fill="both", expand=True, padx=20, pady=20)

        # 👇 bind double-click to copy
        self.tree.bind("<Double-1>", self.copy_password)

        tk.Button(self, text="Back", command=lambda: controller.show_frame(MainScreen)).pack(pady=10)
        tk.Button(self, text="Refresh", command=self.load_passwords).pack(pady=5)

    def load_passwords(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        rows = self.controller.db.fetch_all()
        for row in rows:
            self.tree.insert("", "end", values=(row[1], row[2], row[3]))

    def copy_password(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item, "values")
            password = values[2]  # third column
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

# ---------------------------- MAIN ------------------------------- #
if __name__ == "__main__":
    root = Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
