import os
import psutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import winreg
import ctypes
import sys

# Function to elevate privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

# Function to set process priority
def set_priority(pid, priority):
    try:
        process = psutil.Process(pid)
        process.nice(priority)
        messagebox.showinfo("Success", f"Priority set to {priority_names[priority]} for PID: {pid}")
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        messagebox.showerror("Error", f"Failed to set priority: {e}")

# Function to add registry entry for high priority
def add_registry_entry(exe_name, priority):
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", 0, winreg.KEY_WRITE)
        exe_key = winreg.CreateKey(reg_key, exe_name)
        winreg.SetValueEx(exe_key, "PerfOptions", 0, winreg.REG_DWORD, priority)
        winreg.CloseKey(exe_key)
        winreg.CloseKey(reg_key)
        messagebox.showinfo("Success", f"Registry entry added for {exe_name}. It will now always run with {priority_names[priority]} Priority.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to add registry entry: {e}")

# Function to remove registry entry for high priority
def remove_registry_entry(exe_name):
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", 0, winreg.KEY_WRITE)
        winreg.DeleteKey(reg_key, exe_name)
        winreg.CloseKey(reg_key)
        messagebox.showinfo("Success", f"Registry entry removed for {exe_name}. It will now revert to default priority.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to remove registry entry: {e}")

# Function to check if a process is already running
def is_process_running(exe_name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == exe_name:
            return True
    return False

# Function to load and set priority
def load_and_set_priority():
    file_path = filedialog.askopenfilename(title="Select an executable", filetypes=[("Executable files", "*.exe")])
    if file_path:
        try:
            exe_name = os.path.basename(file_path)
            if is_process_running(exe_name):
                messagebox.showwarning("Already Running", f"{exe_name} is already running.")
                return
            
            # Get selected priority from dropdown
            selected_priority = priority_var.get()
            
            # Add registry entry to enforce selected priority
            add_registry_entry(exe_name, priority_levels[priority_names.index(selected_priority)])
            
            # Launch the program
            process = psutil.Popen(file_path)
            pid = process.pid
            
            # Set priority to selected priority
            set_priority(pid, priority_levels[priority_names.index(selected_priority)])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to launch or set priority: {e}")

# Function to revert to default priority
def revert_to_default():
    file_path = filedialog.askopenfilename(title="Select an executable", filetypes=[("Executable files", "*.exe")])
    if file_path:
        try:
            exe_name = os.path.basename(file_path)
            if not is_process_running(exe_name):
                messagebox.showwarning("Not Running", f"{exe_name} is not currently running.")
                return
            
            # Remove registry entry to revert to default priority
            remove_registry_entry(exe_name)
            
            # Set process priority back to normal
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == exe_name:
                    set_priority(proc.info['pid'], psutil.NORMAL_PRIORITY_CLASS)
                    break
            messagebox.showinfo("Success", f"{exe_name} has been reverted to default priority.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to revert to default: {e}")

# Priority levels and their names
priority_levels = [psutil.BELOW_NORMAL_PRIORITY_CLASS, psutil.IDLE_PRIORITY_CLASS, psutil.NORMAL_PRIORITY_CLASS, psutil.HIGH_PRIORITY_CLASS, psutil.REALTIME_PRIORITY_CLASS]
priority_names = ["Below Normal", "Idle", "Normal", "High", "Realtime"]

# Create the GUI
def create_gui():
    root = tk.Tk()
    root.title("Priority Bypass Tool")
    root.geometry("400x350")
    root.configure(bg="black")
    root.attributes("-alpha", 0.9)  # Transparency effect
    
    style = ttk.Style()
    style.theme_use("clam")
    
    # Configure TCombobox
    style.configure("TCombobox", 
                    fieldbackground="black",      # Background color of the combobox field
                    background="black",           # Background color of the dropdown menu
                    foreground="red",             # Text color
                    arrowcolor="red",             # Color of the dropdown arrow
                    font=("Arial", 12, "bold"))   # Font styling
    
    style.map("TCombobox", 
              fieldbackground=[("readonly", "black")],  # Field background color when readonly
              background=[("readonly", "black")])       # Dropdown menu background color when readonly
    
    # Configure TMenu (dropdown menu)
    style.configure("TMenu", 
                    background="black",      # Background color of the dropdown menu
                    foreground="red",        # Text color of the dropdown menu
                    font=("Arial", 12, "bold"))  # Font styling
    
    # Configure TButton
    style.configure("TButton", 
                    foreground="red",        # Text color
                    background="black",      # Background color
                    font=("Arial", 12, "bold"),  # Font styling
                    relief="flat")           # Flat design
    
    style.map("TButton", 
              background=[("active", "black")],  # Hover effect
              foreground=[("active", "red")])    # Hover effect
    
    # Configure TLabel
    style.configure("TLabel", 
                    foreground="red",        # Text color
                    background="black",      # Background color
                    font=("Arial", 14, "bold"))  # Font styling
    
    # Title Label
    title_label = tk.Label(root, text="Priority Bypass Tool", bg="black", fg="red", font=("Arial", 16, "bold"))
    title_label.pack(pady=10)
    
    # Priority Label
    priority_label = tk.Label(root, text="Select Process Priority:", bg="black", fg="red", font=("Arial", 14, "bold"))
    priority_label.pack(pady=5)
    
    # Combobox for Priority Selection
    global priority_var
    priority_var = tk.StringVar(value="Normal")
    priority_dropdown = ttk.Combobox(root, textvariable=priority_var, values=priority_names, state="readonly")
    priority_dropdown.pack(pady=10)
    
    # Load Button
    load_button = ttk.Button(root, text="Load EXE and Set Priority", command=load_and_set_priority)
    load_button.pack(pady=20)
    
    # Revert Button
    revert_button = ttk.Button(root, text="Revert to Default", command=revert_to_default)
    revert_button.pack(pady=10)
    
    # Exit Button
    exit_button = ttk.Button(root, text="Exit", command=root.destroy)
    exit_button.pack(pady=10)
    
    root.mainloop()

# Run the GUI
if __name__ == "__main__":
    if not is_admin():
        run_as_admin()
    else:
        create_gui()