
import os
import platform
import logging
import subprocess
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox, scrolledtext

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
        """Creates the login UI"""
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

        # Output Box
        self.output_box = scrolledtext.ScrolledText(content_frame, width=90, height=15, font=("Courier", 10), background="#282C34", foreground="white")
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
            # Handle 'cd'
            if cmd_name == "cd":
                new_path = command[1] if len(command) > 1 else os.getcwd()
                try:
                    os.chdir(new_path)
                    self.output_box.insert(END, f"✅ Changed directory to {os.getcwd()}\n")
                except FileNotFoundError:
                    self.output_box.insert(END, f"❌ Directory not found: {new_path}\n")
                return

            # Handle 'mkdir'
            if cmd_name == "mkdir":
                if len(command) < 2:
                    self.output_box.insert(END, "❌ Please specify a directory name.\n")
                    return
                os.mkdir(command[1])
                self.output_box.insert(END, f"✅ Directory created: {command[1]}\n")
                return

            # Handle 'rmdir'
            if cmd_name == "rmdir":
                if len(command) < 2:
                    self.output_box.insert(END, "❌ Please specify a directory name.\n")
                    return
                os.rmdir(command[1])
                self.output_box.insert(END, f"✅ Directory removed: {command[1]}\n")
                return

            # Handle 'touch'
            if cmd_name == "touch":
                if len(command) < 2:
                    self.output_box.insert(END, "❌ Please specify a file name.\n")
                    return
                with open(command[1], "w") as f:
                    pass
                self.output_box.insert(END, f"✅ File created: {command[1]}\n")
                return

            # Handle 'cat'
            
            if cmd_name == "cat":
                if ">>" in command:
                    if len(command) < 3 or command[1] != ">>":
                        self.output_box.insert(END, "❌ Incorrect usage. Use: cat >> filename (then enter text, Ctrl+D to save)\n")
                        return

                    filename = command[2]

                    self.output_box.insert(END, f"📩 Enter text to append to {filename}. Press Ctrl+D (Linux/macOS) or Ctrl+Z (Windows) and Enter to finish:\n")
                    self.output_box.insert(END, ">>> ")

                    # Collect user input for appending
                    user_input = []
                    while True:
                        line = self.command_entry.get().strip()
                        if line == chr(4) or line == chr(26):  # Ctrl+D (EOF) or Ctrl+Z (EOF)
                            break
                        user_input.append(line)

                    text_to_append = "\n".join(user_input) + "\n"

                    try:
                        with open(filename, "a") as f:
                            f.write(text_to_append)
                        self.output_box.insert(END, f"✅ Text appended to {filename}\n")
                    except Exception as e:
                        self.output_box.insert(END, f"❌ Error appending to file: {str(e)}\n")
                    return
                else:
                    if len(command) < 2:
                        self.output_box.insert(END, "❌ Please specify a file name.\n")
                        return

                    filename = command[1]
                    try:
                        with open(filename, "r") as f:
                            content = f.read()
                        self.output_box.insert(END, f"📄 Content of {filename}:\n{content}\n")
                    except FileNotFoundError:
                        self.output_box.insert(END, f"❌ File not found: {filename}\n")
                    except Exception as e:
                        self.output_box.insert(END, f"❌ Error reading file: {str(e)}\n")
                    return


            
            
            
            
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
                        self.output_box.insert(END, f"❌ No such file or directory: {filename}\n")
                except Exception as e:
                    self.output_box.insert(END, f"❌ Error deleting file: {str(e)}\n")
                return

            
            

            # Execute command normally for others
            full_command = COMMAND_MAP.get(cmd_name, "") + " " + " ".join(command[1:])
            result = subprocess.run(full_command, shell=True, text=True, capture_output=True)
            output = result.stdout if result.stdout else result.stderr
            self.output_box.insert(END, output + "\n")

        except Exception as e:
            self.output_box.insert(END, f"❌ Error executing command: {str(e)}\n")



if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    app = SecureSystemGUI(root)
    root.mainloop()













