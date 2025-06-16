import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading

LUA_KEYWORDS = {
    'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for',
    'function', 'if', 'in', 'local', 'nil', 'not', 'or', 'repeat',
    'return', 'then', 'true', 'until', 'while'
}

class LuaEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Lua Encryptor by kvarwaxa")
        self.root.geometry("900x600")

        self.bg_color = "#2e2e2e"          # dark gray background
        self.sidebar_bg = self.bg_color    # same for sidebars
        self.fg_editing = "#3B82F6"        # light blue text when editing
        self.fg_encrypted = "#22C55E"      # green text after encryption
        self.fg_default = "#eeeeee"        # near-white text default

        self.root.configure(bg=self.bg_color)

        self.status_var = tk.StringVar(value="Ready.")
        self.create_menu()
        self.setup_ui()

    def create_menu(self):
        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Open Lua File...", command=self.open_file)
        filemenu.add_command(label="Save Encrypted As...", command=self.save_file)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=filemenu)
        self.root.config(menu=menubar)

    def setup_ui(self):
        self.paned = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        self.paned.pack(fill=tk.BOTH, expand=True)

        self.input_frame = tk.Frame(self.paned, bg=self.bg_color)
        self.paned.add(self.input_frame, weight=1)
        self.create_text_with_line_numbers(self.input_frame, "Input Lua code...")

        self.output_frame = tk.Frame(self.paned, bg=self.bg_color)
        self.paned.add(self.output_frame, weight=1)
        self.create_text_with_line_numbers(self.output_frame, "Encrypted code will appear here...", output=True)

        bottom_frame = tk.Frame(self.root, bg=self.bg_color)
        bottom_frame.pack(fill=tk.X)

        self.encrypt_btn = tk.Button(bottom_frame, text="Encrypt", command=self.start_encrypt,
                                     bg="#444444", fg=self.fg_default, activebackground="#666666", activeforeground=self.fg_default)
        self.encrypt_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.copy_btn = tk.Button(bottom_frame, text="Copy Output", command=self.copy_output,
                                  bg="#444444", fg=self.fg_default, activebackground="#666666", activeforeground=self.fg_default)
        self.copy_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.progress = ttk.Progressbar(bottom_frame, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
        self.progress.pack_forget()

        status_bar = tk.Label(self.root, textvariable=self.status_var, anchor='w',
                              bg=self.bg_color, fg="lightgreen")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.input_text.bind('<KeyRelease>', self.on_input_change)
        self.output_text.bind('<KeyRelease>', self.on_output_change)

        self.set_input_fg(self.fg_editing)
        self.set_output_fg(self.fg_default)

        self.update_line_numbers(self.input_text, self.input_line_numbers)
        self.update_line_numbers(self.output_text, self.output_line_numbers)
        self.syntax_highlight(self.input_text)

    def create_text_with_line_numbers(self, parent, placeholder="", output=False):
        frame = parent

        line_numbers = tk.Text(frame, width=4, padx=4, takefocus=0, border=0,
                               background=self.sidebar_bg, foreground='#aaaaaa', state='disabled',
                               font=('Consolas', 11))
        line_numbers.pack(side=tk.LEFT, fill=tk.Y)

        text_widget = tk.Text(frame, wrap=tk.NONE, undo=True,
                              background=self.bg_color, foreground=self.fg_default,
                              insertbackground='white',
                              font=('Consolas', 11), border=0)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        yscroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        text_widget.config(yscrollcommand=yscroll.set)

        xscroll = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=text_widget.xview)
        xscroll.pack(side=tk.BOTTOM, fill=tk.X)
        text_widget.config(xscrollcommand=xscroll.set)

        if placeholder:
            text_widget.insert("1.0", placeholder)
            if output:
                text_widget.config(state=tk.DISABLED)

        if output:
            self.output_text = text_widget
            self.output_line_numbers = line_numbers
        else:
            self.input_text = text_widget
            self.input_line_numbers = line_numbers

    def set_input_fg(self, color):
        self.input_text.config(foreground=color)

    def set_output_fg(self, color):
        self.output_text.config(foreground=color)

    def update_line_numbers(self, text_widget, line_numbers_widget):
        line_numbers_widget.config(state=tk.NORMAL)
        line_numbers_widget.delete('1.0', tk.END)

        lines = int(text_widget.index('end-1c').split('.')[0])
        line_str = "\n".join(str(i) for i in range(1, lines + 1))
        line_numbers_widget.insert('1.0', line_str)
        line_numbers_widget.config(state=tk.DISABLED)

    def on_input_change(self, event=None):
        self.update_line_numbers(self.input_text, self.input_line_numbers)
        self.syntax_highlight(self.input_text)
        self.set_input_fg(self.fg_editing)
        self.set_output_fg(self.fg_default)
        self.status_var.set("Editing input...")

    def on_output_change(self, event=None):
        self.update_line_numbers(self.output_text, self.output_line_numbers)

    def syntax_highlight(self, text_widget):
        for tag in LUA_KEYWORDS:
            text_widget.tag_remove(tag, "1.0", tk.END)

        content = text_widget.get("1.0", tk.END)
        for kw in LUA_KEYWORDS:
            start_index = "1.0"
            while True:
                start_index = text_widget.search(r'\b' + kw + r'\b', start_index, nocase=False, stopindex=tk.END, regexp=True)
                if not start_index:
                    break
                end_index = f"{start_index}+{len(kw)}c"
                text_widget.tag_add(kw, start_index, end_index)
                start_index = end_index

        for kw in LUA_KEYWORDS:
            text_widget.tag_config(kw, foreground="#569CD6")  

    def start_encrypt(self):
        code = self.input_text.get("1.0", tk.END).strip()
        if not code:
            messagebox.showwarning("Warning", "Please enter Lua code to encrypt.")
            return

        self.encrypt_btn.config(state=tk.DISABLED)
        self.progress.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
        self.progress.start()
        self.status_var.set("Encrypting...")

        threading.Thread(target=self.encrypt_code, args=(code,), daemon=True).start()

    def encrypt_code(self, code):
        import base64
        reversed_code = code[::-1]
        encrypted_bytes = base64.b64encode(reversed_code.encode('utf-8'))
        encrypted_str = encrypted_bytes.decode('utf-8')

        wrapped = (
            f"local encoded = [[{encrypted_str}]]\n"
            "local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'\n"
            "function decode(data)\n"
            "  data = string.gsub(data, '[^'..b..'=]', '')\n"
            "  return (data:gsub('.', function(x)\n"
            "    if (x == '=') then return '' end\n"
            "    local r,f='',(b:find(x)-1)\n"
            "    for i=6,1,-1 do r=r..(f%2^i - f%2^(i-1) > 0 and '1' or '0') end\n"
            "    return r;\n"
            "  end):gsub('%d%d%d%d%d%d%d%d', function(x)\n"
            "    if (#x ~= 8) then return '' end\n"
            "    local c=0\n"
            "    for i=1,8 do c=c + (x:sub(i,i) == '1' and 2^(8-i) or 0) end\n"
            "    return string.char(c)\n"
            "  end))\n"
            "end\n"
            "local decoded = decode(encoded)\n"
            "local code = string.reverse(decoded)\n"
            "assert(load(code))()\n"
        )

        self.root.after(0, lambda: self.show_output(wrapped))

    def show_output(self, text):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, text)
        self.output_text.config(state=tk.DISABLED)
        self.progress.stop()
        self.progress.pack_forget()
        self.encrypt_btn.config(state=tk.NORMAL)
        self.set_input_fg(self.fg_encrypted)
        self.set_output_fg(self.fg_encrypted)
        self.status_var.set("Encryption complete.")

    def copy_output(self):
        self.root.clipboard_clear()
        text = self.output_text.get("1.0", tk.END)
        self.root.clipboard_append(text)
        self.status_var.set("Copied output to clipboard.")

    def open_file(self):
        path = filedialog.askopenfilename(
            filetypes=[("Lua Files", "*.lua"), ("All Files", "*.*")]
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.input_text.config(state=tk.NORMAL)
                self.input_text.delete("1.0", tk.END)
                self.input_text.insert(tk.END, content)
                self.set_input_fg(self.fg_editing)
                self.status_var.set(f"Loaded file: {path}")
                self.on_input_change()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open file:\n{e}")

    def save_file(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".lua",
            filetypes=[("Lua Files", "*.lua"), ("All Files", "*.*")]
        )
        if path:
            try:
                content = self.output_text.get("1.0", tk.END)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                self.status_var.set(f"Saved encrypted code to: {path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file:\n{e}")

def main():
    root = tk.Tk()
    app = LuaEncryptorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
