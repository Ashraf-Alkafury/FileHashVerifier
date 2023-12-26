import hashlib
import os
import tkinter as tk
from tkinter import filedialog, scrolledtext

class HashCalculatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Hash Calculator")

        self.file_path_label = tk.Label(root, text="File Path:")
        self.file_path_label.grid(row=0, column=0, padx=10, pady=10)

        self.file_path_entry = tk.Entry(root, width=50)
        self.file_path_entry.grid(row=0, column=1, padx=10, pady=10)

        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)
        self.browse_button.grid(row=0, column=2, padx=10, pady=10)

        self.hash_type_label = tk.Label(root, text="Hash Type:")
        self.hash_type_label.grid(row=1, column=0, padx=10, pady=10)

        self.hash_type_var = tk.StringVar()
        self.hash_type_var.set("md5")  # Set default hash type to md5

        hash_types = ["md5", "sha256", "sha1", "sha512"]
        self.hash_type_menu = tk.OptionMenu(root, self.hash_type_var, *hash_types)
        self.hash_type_menu.grid(row=1, column=1, padx=10, pady=10)

        self.calculate_button = tk.Button(root, text="Calculate Hash", command=self.calculate_hash)
        self.calculate_button.grid(row=2, column=0, columnspan=3, pady=10)

        self.result_text = scrolledtext.ScrolledText(root, width=50, height=10, wrap=tk.WORD, state=tk.DISABLED)
        self.result_text.grid(row=3, column=0, columnspan=3, pady=10)

        self.copy_button = tk.Button(root, text="Copy Hash", command=self.copy_hash, state=tk.DISABLED)
        self.copy_button.grid(row=4, column=0, columnspan=3, pady=10)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_path_entry.delete(0, tk.END)
        self.file_path_entry.insert(0, file_path)

    def calculate_hash(self):
        file_path = self.file_path_entry.get()
        hash_type = self.hash_type_var.get()

        if not os.path.exists(file_path):
            self.update_result_text("File not found. Please enter a valid file path.")
            return

        selected_hash = self.calculate_hash_internal(file_path, algorithm=hash_type)

        result_text = f"{hash_type.upper()} Hash: {selected_hash}"
        self.update_result_text(result_text)

        # Enable copy button when valid hash is displayed
        self.copy_button.config(state=tk.NORMAL)

    def calculate_hash_internal(self, file_path, algorithm="sha256"):
        hasher = hashlib.new(algorithm)

        with open(file_path, "rb") as file:
            chunk_size = 4096
            while chunk := file.read(chunk_size):
                hasher.update(chunk)

        return hasher.hexdigest()

    def update_result_text(self, text):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, text)
        self.result_text.config(state=tk.DISABLED)

    def copy_hash(self):
        hash_text = self.result_text.get(1.0, tk.END).strip()
        if hash_text:
            # Remove the hash type label from the text before copying
            hash_text = hash_text.split(":")[1].strip()
            self.root.clipboard_clear()
            self.root.clipboard_append(hash_text)
            self.root.update()

if __name__ == "__main__":
    root = tk.Tk()
    app = HashCalculatorApp(root)
    root.mainloop()
