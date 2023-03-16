import subprocess
import tkinter as tk

class NmapTool(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.title("Nmap Tool")
        self.create_widgets()

    def create_widgets(self):
        self.ip_label = tk.Label(self.master, text="IP Address:")
        self.ip_label.grid(row=0, column=0)
        self.ip_entry = tk.Entry(self.master, width=20)
        self.ip_entry.grid(row=0, column=1)

        self.filename_label = tk.Label(self.master, text="Output Filename:")
        self.filename_label.grid(row=1, column=0)
        self.filename_entry = tk.Entry(self.master, width=20)
        self.filename_entry.grid(row=1, column=1)

        self.scan_type_label = tk.Label(self.master, text="Select Scan Type:")
        self.scan_type_label.grid(row=2, column=0)
        self.scan_type_var = tk.StringVar()
        self.scan_type_dropdown = tk.OptionMenu(self.master, self.scan_type_var,
                                                "nmap -sC -sV {IP} -oN {FILENAME}",
                                                "nmap -sS -sV {IP} -oN {FILENAME}",
                                                "nmap -sC -sV -T4 {IP} -oN {FILENAME}",
                                                "nmap -sS -sV -O {IP} -oN {FILENAME}",
                                                "nmap --script http-vuln-cve2017-5638.nse {IP} -oN {FILENAME}",
                                                "nmap --script smb-vuln-ms17-010.nse {IP} -oN {FILENAME}",
                                                "nmap --script vnc-brute {IP} -oN {FILENAME}")
        self.scan_type_dropdown.grid(row=2, column=1)

        self.run_button = tk.Button(self.master, text="Run Nmap", command=self.run_nmap)
        self.run_button.grid(row=3, column=0, columnspan=2)

        self.output_text = tk.Text(self.master, height=10, width=50)
        self.output_text.grid(row=4, column=0, columnspan=2)
        self.output_text.tag_configure("stdout", foreground="black")
        self.output_text.tag_configure("stderr", foreground="red")

    def run_nmap(self):
        ip_address = self.ip_entry.get()
        filename = self.filename_entry.get()
        scan_type = self.scan_type_var.get()
        command = scan_type.format(IP=ip_address, FILENAME=filename)
        self.output_text.insert(tk.END, "Starting Nmap scan...\n")
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            while True:
                output = process.stdout.readline()
                error = process.stderr.readline()
                if output:
                    self.output_text.insert(tk.END, output, "stdout")
                if error:
                    self.output_text.insert(tk.END, error, "stderr")
                if not output and not error:
                    break
            process.wait()
            self.output_text.insert(tk.END, "Nmap scan complete.\n")
        except subprocess.CalledProcessError as e:
            print(f"Command '{command}' returned non-zero exit status {e.returncode}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NmapTool(master=root)
    app.mainloop()
