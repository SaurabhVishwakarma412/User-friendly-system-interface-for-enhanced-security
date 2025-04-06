import os
import platform
import logging
import subprocess
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox, scrolledtext, Toplevel, Text, Label, Button

# Configure logging
logging.basicConfig(filename="system_call_log.txt", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# User database with roles
USER_DATABASE = {
    "admin": {"password": "adminpass", "role": "admin"},
    "user1": {"password": "userpass", "role": "user"},
}

# Detect OS
is_windows = platform.system() == "Windows"

# Command mapping
COMMAND_MAP = {
    "pwd": "cd" if is_windows else "pwd",
    "whoami": "whoami",
    "ls": "dir" if is_windows else "ls",
    "mkdir": "mkdir",
    "touch": "type nul >" if is_windows else "touch",
    "cd": "cd",
    "cat": "type" if is_windows else "cat",
    "rm": "del" if is_windows else "rm",
    "rmdir": "rmdir /s /q" if is_windows else "rm -r",
    "getpid": "echo %PROCESS_ID%" if is_windows else "echo $$",
    "get_pids": "tasklist" if is_windows else "ps -e -o pid,cmd"
}

ADMIN_COMMANDS = list(COMMAND_MAP.keys())
USER_COMMANDS = ["pwd", "whoami", "ls", "mkdir", "touch", "cd", "cat", "getpid", "rmdir", "get_pids"]

class SecureSystemGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Secure System Dashboard")
        self.root.geometry("1024x720")
        self.root.resizable(False, False)
        self.create_login_ui()

    def create_login_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        login_frame = ttk.Frame(self.root, padding=20)
        login_frame.place(relx=0.5, rely=0.5, anchor="center")

        ttk.Label(login_frame, text="Username:", font=("Arial", 12)).pack(pady=5)
        self.username_entry = ttk.Entry(login_frame, width=30)
        self.username_entry.pack(pady=5)

        ttk.Label(login_frame, text="Password:", font=("Arial", 12)).pack(pady=5)
        self.password_entry = ttk.Entry(login_frame, width=30, show="*")
        self.password_entry.pack(pady=5)

        ttk.Button(login_frame, text="Login", bootstyle="primary", command=self.authenticate).pack(pady=5, fill=X)
        ttk.Button(login_frame, text="Signup", bootstyle="success", command=self.signup).pack(pady=5, fill=X)

    def authenticate(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if username in USER_DATABASE and USER_DATABASE[username]["password"] == password:
            self.user = username
            self.role = USER_DATABASE[username]["role"]
            logging.info(f"User '{self.user}' logged in.")
            self.create_main_ui()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password!")

    def signup(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Signup Failed", "Username and password cannot be empty!")
            return

        if username in USER_DATABASE:
            messagebox.showerror("Signup Failed", "Username already exists!")
            return

        USER_DATABASE[username] = {"password": password, "role": "user"}
        messagebox.showinfo("Signup Successful", "Account created! You can now login.")

    def create_main_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        # Sidebar
        sidebar = ttk.Frame(self.root, width=200, padding=10, bootstyle="dark")
        sidebar.pack(side=LEFT, fill=Y)

        ttk.Label(sidebar, text="Commands", font=("Arial", 14, "bold"), foreground="white").pack(pady=10)

        for cmd in (ADMIN_COMMANDS if self.role == "admin" else USER_COMMANDS):
            ttk.Button(sidebar, text=cmd, bootstyle="outline-light", command=lambda c=cmd: self.command_entry.insert(END, c)).pack(fill=X, pady=2)

        ttk.Button(sidebar, text="Logout", bootstyle=DANGER, command=self.create_login_ui).pack(fill=X, pady=10)

        # Content Area
        content_frame = ttk.Frame(self.root, padding=20)
        content_frame.pack(expand=True, fill=BOTH)

        ttk.Label(content_frame, text=f"Welcome, {self.user}! Role: {self.role.upper()}", font=("Arial", 14, "bold"), bootstyle="info").pack(anchor=W)

        self.command_entry = ttk.Entry(content_frame, width=60)
        self.command_entry.pack(pady=5)

        ttk.Button(content_frame, text="Execute", bootstyle=SUCCESS, command=self.execute_command).pack(pady=5)

        self.output_box = scrolledtext.ScrolledText(
            content_frame,
            width=90,
            height=15,
            font=("Courier", 10),
            bg="#1e1e1e",
            fg="white",
            insertbackground="white"
        )
        self.output_box.pack()

        # Status Bar
        self.status_bar = ttk.Label(self.root, text="Ready", font=("Arial", 10), bootstyle=SECONDARY, anchor=W)
        self.status_bar.pack(fill=X, side=BOTTOM)

    def execute_command(self):
        command = self.command_entry.get().strip().split()
        if not command:
            self.output_box.insert(END, "❌ No command entered.\n")
            return

        cmd_name = command[0]
        allowed_commands = ADMIN_COMMANDS if self.role == "admin" else USER_COMMANDS
        if cmd_name not in allowed_commands:
            self.output_box.insert(END, "❌ Unauthorized command!\n")
            return

        try:
            if cmd_name == "cd":
                new_path = command[1] if len(command) > 1 else os.getcwd()
                try:
                    os.chdir(new_path)
                    self.output_box.insert(END, f"✅ Changed directory to {os.getcwd()}\n")
                except FileNotFoundError:
                    self.output_box.insert(END, f"❌ Directory not found: {new_path}\n")
                return

            if cmd_name == "mkdir":
                if len(command) < 2:
                    self.output_box.insert(END, "❌ Please specify a directory name.\n")
                    return
                os.mkdir(command[1])
                self.output_box.insert(END, f"✅ Directory created: {command[1]}\n")
                return

            if cmd_name == "rmdir":
                if len(command) < 2:
                    self.output_box.insert(END, "❌ Please specify a directory name.\n")
                    return
                os.rmdir(command[1])
                self.output_box.insert(END, f"✅ Directory removed: {command[1]}\n")
                return

            if cmd_name == "touch":
                if len(command) < 2:
                    self.output_box.insert(END, "❌ Please specify a file name.\n")
                    return
                with open(command[1], "w") as f:
                    pass
                self.output_box.insert(END, f"✅ File created: {command[1]}\n")
                return

            if cmd_name == "cat":
                if len(command) >= 3 and command[1] == ">>":
                    filename = command[2]

                    def save_text(event=None):  # accept optional event for key binding
                        text_to_append = text_box.get("1.0", "end-1c")
                        try:
                            with open(filename, "a") as f:
                                f.write(text_to_append + "\n")
                            self.output_box.insert(END, f"✅ Text appended to {filename}\n")
                            popup.destroy()
                        except Exception as e:
                            self.output_box.insert(END, f"❌ Error appending to file: {str(e)}\n")
                            popup.destroy()

                    popup = Toplevel(self.root)
                    popup.title(f"Append to {filename}")
                    popup.geometry("500x300")
                    popup.grab_set()  # Make the popup modal

                    Label(popup, text=f"Enter text to append to {filename}").pack(pady=5)

                    text_box = Text(popup, wrap="word", font=("Courier", 10))
                    text_box.pack(expand=True, fill=BOTH, padx=10, pady=5)
                    text_box.focus_set()

                    Button(popup, text="Save to File (Enter)", command=save_text).pack(pady=5)

                    popup.bind("<Return>", save_text)  # Bind Enter key to save_text

                    return


            full_cmd = COMMAND_MAP.get(cmd_name, cmd_name)
            if len(command) > 1:
                full_cmd += " " + " ".join(command[1:])

            result = subprocess.run(full_cmd, shell=True, text=True, capture_output=True)
            if result.stdout:
                self.output_box.insert(END, f"📤 Output:\n{result.stdout}\n")
            if result.stderr:
                self.output_box.insert(END, f"❌ Error:\n{result.stderr}\n")

            self.status_bar.config(text="Command executed successfully.")

        except Exception as e:
            self.output_box.insert(END, f"❌ Exception: {str(e)}\n")
            self.status_bar.config(text="Execution failed.")
        
        if cmd_name == "rm":
            if len(command) < 2:
                self.output_box.insert(END, "❌ Please specify a file to delete.\n")
                return

            filename = command[1]
            try:
                if os.path.isfile(filename):
                    os.remove(filename)
                    self.output_box.insert(END, f"✅ File deleted: {filename}\n")
                elif os.path.isdir(filename):
                    os.rmdir(filename)
                    self.output_box.insert(END, f"✅ Directory deleted: {filename}\n")
                else:
                    # This will only be reached if the file doesn't exist *before* deletion
                    self.output_box.insert(END, f"❌ No such file or directory: {filename}\n")
            except Exception as e:
                self.output_box.insert(END, f"❌ Error deleting: {str(e)}\n")

            self.status_bar.config(text="Command executed.")
            return

# Launch the app
if __name__ == "__main__":
    root = ttk.Window(themename="darkly")  # Dark theme
    app = SecureSystemGUI(root)
    root.mainloop()
