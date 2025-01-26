import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import struct
import datetime
import os
import binascii

class MEN2PatcherGUI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("MEN2 LG Patcher")
        self.window.geometry("800x600")
        
        # Variables
        self.current_file = tk.StringVar()
        self.vin_number = tk.StringVar()
        self.status_text = tk.StringVar(value="Ready")
        self.features_status = {
            "Mirror Link": tk.BooleanVar(value=False),
            "Apple CarPlay": tk.BooleanVar(value=False),
            "Google Auto": tk.BooleanVar(value=False),
            "Car Data": tk.BooleanVar(value=False)
        }
        
        self.create_gui()
        
    def create_gui(self):
        # Notebook for tabs
        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(fill="both", expand=True)
        
        # Main tab
        main_frame = ttk.Frame(self.notebook)
        self.notebook.add(main_frame, text="Main")
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding=10)
        file_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(file_frame, text="EEPROM File:").pack(side="left")
        ttk.Entry(file_frame, textvariable=self.current_file, width=50).pack(side="left", padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).pack(side="left")
        
        # VIN frame
        vin_frame = ttk.LabelFrame(main_frame, text="Vehicle Information", padding=10)
        vin_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(vin_frame, text="VIN:").pack(side="left")
        ttk.Entry(vin_frame, textvariable=self.vin_number, width=20).pack(side="left", padx=5)
        
        # Features frame
        features_frame = ttk.LabelFrame(main_frame, text="Features Status", padding=10)
        features_frame.pack(fill="x", padx=10, pady=5)
        
        for feature, var in self.features_status.items():
            ttk.Checkbutton(features_frame, text=feature, variable=var, state="disabled").pack(side="left", padx=10)
        
        # Action buttons
        btn_frame = ttk.Frame(main_frame, padding=10)
        btn_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Read File", command=self.read_file).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Patch File", command=self.patch_file).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Verify Checksum", command=self.verify_and_correct_checksums).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Clear Log", command=self.clear_log).pack(side="left", padx=5)
        
        # Progress frame
        progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding=10)
        progress_frame.pack(fill="x", padx=10, pady=5)
        
        self.progress = ttk.Progressbar(progress_frame, mode="determinate")
        self.progress.pack(fill="x", pady=5)
        
        ttk.Label(progress_frame, textvariable=self.status_text).pack()
        
        # Log frame
        log_frame = ttk.LabelFrame(main_frame, text="Operation Log", padding=10)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.log_text = tk.Text(log_frame, height=10)
        self.log_text.pack(fill="both", expand=True)
        
        # Comparison viewer frame
        compare_frame = ttk.LabelFrame(main_frame, text="File Comparison", padding=10)
        compare_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Split into two columns
        left_frame = ttk.Frame(compare_frame)
        left_frame.pack(side="left", fill="both", expand=True)
        
        right_frame = ttk.Frame(compare_frame)
        right_frame.pack(side="right", fill="both", expand=True)
        
        ttk.Label(left_frame, text="Original").pack()
        self.original_text = tk.Text(left_frame, height=10, width=40)
        self.original_text.pack(fill="both", expand=True)
        
        ttk.Label(right_frame, text="Patched").pack()
        self.patched_text = tk.Text(right_frame, height=10, width=40)
        self.patched_text.pack(fill="both", expand=True)
        
        # Diff tab
        diff_frame = ttk.Frame(self.notebook)
        self.notebook.add(diff_frame, text="Diff")
        
        # Split into two columns for diff
        left_diff_frame = ttk.Frame(diff_frame)
        left_diff_frame.pack(side="left", fill="both", expand=True)
        
        right_diff_frame = ttk.Frame(diff_frame)
        right_diff_frame.pack(side="right", fill="both", expand=True)
        
        ttk.Label(left_diff_frame, text="Original").pack()
        self.original_diff_text = tk.Text(left_diff_frame, height=10, width=40)
        self.original_diff_text.pack(fill="both", expand=True)
        
        ttk.Label(right_diff_frame, text="Patched/Corrected").pack()
        self.patched_diff_text = tk.Text(right_diff_frame, height=10, width=40)
        self.patched_diff_text.pack(fill="both", expand=True)

    def log(self, message):
        self.log_text.insert("end", f"{message}\n")
        self.log_text.see("end")
        self.window.update()

    def clear_log(self):
        self.log_text.delete("1.0", "end")

    def browse_file(self):
        filename = filedialog.askopenfilename(
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )
        if filename:
            self.current_file.set(filename)
            self.read_file()

    def read_file(self):
        if not self.current_file.get():
            messagebox.showerror("Error", "Please select a file first")
            return
            
        try:
            with open(self.current_file.get(), 'rb') as f:
                data = f.read()
                
            if len(data) != 32768:
                messagebox.showerror("Error", "Invalid file size. Expected 32768 bytes")
                return
                
            self.log("Reading file structure...")
            self.progress["value"] = 0
            
            # Read FAZIT
            fazit = data[256:279].decode('ascii', errors='ignore')
            self.log(f"FAZIT: {fazit}")
            
            # Read version
            version = data[5140:5160].decode('ascii', errors='ignore')
            self.log(f"Version: {version}")
            
            # Read feature status bytes
            self.progress["value"] = 30
            self.status_text.set("Reading features status...")
            
            # Example feature detection (simplified)
            features = {
                "Mirror Link": data[0x1C40:0x1C42] == b'\x11\x02',
                "Apple CarPlay": data[0x1D00:0x1D02] == b'\x11\x02', 
                "Google Auto": data[0x22C0:0x22C2] == b'\x11\x02',
                "Car Data": data[0x2380:0x2382] == b'\x11\x02'
            }
            
            for feature, status in features.items():
                self.features_status[feature].set(status)
                self.log(f"{feature}: {'Activated' if status else 'Not activated'}")
                
            self.progress["value"] = 100
            self.status_text.set("File read successfully")
            
            # Show original hex dump
            self.show_hex_dump(data)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {str(e)}")
            self.log(f"Error: {str(e)}")

    def patch_file(self):
        if not self.current_file.get():
            messagebox.showerror("Error", "Please select a file first")
            return
            
        if not self.vin_number.get() or len(self.vin_number.get()) != 17:
            messagebox.showerror("Error", "Please enter a valid 17-character VIN")
            return
            
        try:
            with open(self.current_file.get(), 'rb') as f:
                data = bytearray(f.read())
                
            self.progress["value"] = 0
            self.status_text.set("Patching file...")
            
            # Patch magic bytes and feature codes
            patch_locations = {
                "Mirror Link": (0x1C40, b'\x11\x02\x00\x06\x09\x00'),
                "Apple CarPlay": (0x1D00, b'\x11\x02\x00\x06\x01\x00'),
                "Google Auto": (0x22C0, b'\x11\x02\x00\x06\x08\x00'),
                "Car Data": (0x2380, b'\x11\x02\x00\x06\x03\x00')
            }
            
            for feature, (offset, magic) in patch_locations.items():
                self.log(f"Patching {feature}...")
                data[offset:offset+len(magic)] = magic
                self.progress["value"] += 20
                
            # Update VIN
            vin_locations = [0x1C4C, 0x1D0C, 0x22CC, 0x238C]
            for loc in vin_locations:
                data[loc:loc+17] = self.vin_number.get().encode()
                
            # Update timestamps
            current_time = int(datetime.datetime.now().timestamp())
            time_bytes = current_time.to_bytes(4, 'big')
            
            timestamp_locations = [0x1C54, 0x1D14, 0x22D4, 0x2394]
            for loc in timestamp_locations:
                data[loc:loc+4] = time_bytes
                
            # Save patched file
            output_file = self.current_file.get().replace('.bin', '_patched.bin')
            with open(output_file, 'wb') as f:
                f.write(data)
                
            self.progress["value"] = 100
            self.status_text.set("File patched successfully")
            self.log(f"Saved patched file: {output_file}")
            
            # Show comparison
            self.show_hex_dump(data, patched=True)
            
            # Verify checksums and correct them automatically
            self.verify_and_correct_checksums(data, output_file)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to patch file: {str(e)}")
            self.log(f"Error: {str(e)}")

    def verify_and_correct_checksums(self, data, output_file):
        try:
            self.progress["value"] = 0
            self.status_text.set("Verifying and correcting checksums...")
            
            # CRC-CCITT checking logic here
            # For each 64-byte block...
            blocks = len(data) // 64
            errors = []
            
            for block in range(blocks):
                self.progress["value"] = (block / blocks) * 100
                
                block_data = data[block*64:(block+1)*64]
                crc = binascii.crc_hqx(block_data, 0)
                
                # Compare with stored checksum
                stored_crc = int.from_bytes(data[32768-1024+(block*2):32768-1024+(block*2)+2], 'big')
                
                if crc != stored_crc:
                    errors.append(block)
                    self.log(f"Checksum error in block {block}")
                    
            if errors:
                self.correct_checksums(data, errors)
                self.log("All checksums corrected.")
                corrected_output_file = output_file.replace('_patched.bin', '_corrected.bin')
                with open(corrected_output_file, 'wb') as f:
                    f.write(data)
                self.log(f"Saved corrected file: {corrected_output_file}")
                self.show_diff(data)
            else:
                self.status_text.set("All checksums verified successfully")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to verify and correct checksums: {str(e)}")
            self.log(f"Error: {str(e)}")

    def correct_checksums(self, data, error_blocks):
        try:
            for i, block in enumerate(error_blocks):
                self.progress["value"] = (i / len(error_blocks)) * 100
                
                block_data = data[block*64:(block+1)*64]
                new_crc = binascii.crc_hqx(block_data, 0)
                
                # Store new checksum
                data[32768-1024+(block*2):32768-1024+(block*2)+2] = new_crc.to_bytes(2, 'big')
                
            self.progress["value"] = 100
            self.status_text.set("Checksums corrected successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to correct checksums: {str(e)}")
            self.log(f"Error: {str(e)}")

    def show_hex_dump(self, data, patched=False):
        # Create a formatted hex dump
        hex_dump = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_line = f"{i:08x}  {' '.join([f'{b:02x}' for b in chunk]):<48}  "
            ascii_line = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in chunk])
            hex_dump.append(f"{hex_line}{ascii_line}")
            
        dump_text = '\n'.join(hex_dump)
        
        if patched:
            self.patched_text.delete("1.0", "end")
            self.patched_text.insert("1.0", dump_text)
        else:
            self.original_text.delete("1.0", "end")
            self.original_text.insert("1.0", dump_text)

    def show_diff(self, patched_data):
        try:
            with open(self.current_file.get(), 'rb') as f:
                original_data = f.read()
                
            original_hex_dump = []
            patched_hex_dump = []
            
            for i in range(0, len(original_data), 16):
                original_chunk = original_data[i:i+16]
                patched_chunk = patched_data[i:i+16]
                
                original_hex_line = f"{i:08x}  {' '.join([f'{b:02x}' for b in original_chunk]):<48}  "
                patched_hex_line = f"{i:08x}  {' '.join([f'{b:02x}' for b in patched_chunk]):<48}  "
                
                original_ascii_line = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in original_chunk])
                patched_ascii_line = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in patched_chunk])
                
                original_hex_dump.append(f"{original_hex_line}{original_ascii_line}")
                patched_hex_dump.append(f"{patched_hex_line}{patched_ascii_line}")
                
            original_dump_text = '\n'.join(original_hex_dump)
            patched_dump_text = '\n'.join(patched_hex_dump)
            
            self.original_diff_text.delete("1.0", "end")
            self.original_diff_text.insert("1.0", original_dump_text)
            
            self.patched_diff_text.delete("1.0", "end")
            self.patched_diff_text.insert("1.0", patched_dump_text)
            
            # Highlight changes in the diff tab
            self.highlight_changes(original_data, patched_data)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show diff: {str(e)}")
            self.log(f"Error: {str(e)}")

    def highlight_changes(self, original_data, patched_data):
        for i in range(0, len(original_data), 16):
            original_chunk = original_data[i:i+16]
            patched_chunk = patched_data[i:i+16]
            
            for j in range(len(original_chunk)):
                if original_chunk[j] != patched_chunk[j]:
                    start_index = f"{i//16 + 1}.{j*3}"
                    end_index = f"{i//16 + 1}.{j*3 + 2}"
                    self.patched_diff_text.tag_add("highlight", start_index, end_index)
                    self.patched_diff_text.tag_config("highlight", background="green")

if __name__ == "__main__":
    app = MEN2PatcherGUI()
    app.window.mainloop()
