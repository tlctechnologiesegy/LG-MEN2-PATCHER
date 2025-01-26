import struct
import datetime
import os
import binascii
from PyQt5 import QtWidgets, QtCore, QtGui

# Add Windows-specific imports
if os.name == 'nt':  # Windows
    import winreg
    import ctypes.wintypes
    CSIDL_APPDATA = 26

class MEN2PatcherGUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LG-UNIT-PATCHER")  # Change the window title here
        self.resize(800, 600)
        
        # Add icon support
        icon_path = os.path.normpath(os.path.join(os.path.dirname(__file__), 'app_logo.png'))
        if os.path.exists(icon_path):
            app_icon = QtGui.QIcon(icon_path)
            self.setWindowIcon(app_icon)

        self.status_text = "Ready"
        self.file_data = None  # Add this line to store file data
        self.setup_ui()

    def setup_ui(self):
        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QtWidgets.QVBoxLayout(central_widget)

        self.notebook = QtWidgets.QTabWidget()
        main_layout.addWidget(self.notebook)

        main_tab = QtWidgets.QWidget()
        self.notebook.addTab(main_tab, "Main")
        main_tab_layout = QtWidgets.QVBoxLayout(main_tab)

        file_frame = QtWidgets.QGroupBox("File Selection")
        file_layout = QtWidgets.QHBoxLayout(file_frame)
        main_tab_layout.addWidget(file_frame)

        self.current_file_edit = QtWidgets.QLineEdit()
        file_layout.addWidget(QtWidgets.QLabel("EEPROM File:"))
        file_layout.addWidget(self.current_file_edit)
        browse_button = QtWidgets.QPushButton("Browse")
        browse_button.clicked.connect(self.browse_file)
        file_layout.addWidget(browse_button)

        vin_frame = QtWidgets.QGroupBox("Vehicle Information")
        vin_layout = QtWidgets.QHBoxLayout(vin_frame)
        main_tab_layout.addWidget(vin_frame)

        vin_layout.addWidget(QtWidgets.QLabel("VIN:"))
        self.vin_edit = QtWidgets.QLineEdit()
        vin_layout.addWidget(self.vin_edit)
        dummy_vin = "TMBJJ7NE5H0171997"
        vin_layout.addWidget(QtWidgets.QLabel("Dummy VIN:"))
        dummy_label = QtWidgets.QLabel(dummy_vin)
        dummy_label.setStyleSheet("color: red;")
        vin_layout.addWidget(dummy_label)

        copy_button = QtWidgets.QPushButton("Copy")
        copy_button.clicked.connect(lambda: self.copy_dummy_vin(dummy_vin))
        vin_layout.addWidget(copy_button)

        features_frame = QtWidgets.QGroupBox("Features Status")
        features_layout = QtWidgets.QHBoxLayout(features_frame)
        main_tab_layout.addWidget(features_frame)
        self.checkboxes = {}
        for feature in ["Mirror Link","Apple CarPlay","Google Auto","Car Data"]:
            cb = QtWidgets.QCheckBox(feature)
            cb.setEnabled(False)
            features_layout.addWidget(cb)
            self.checkboxes[feature] = cb

        btn_frame = QtWidgets.QWidget()
        btn_layout = QtWidgets.QHBoxLayout(btn_frame)
        main_tab_layout.addWidget(btn_frame)

        read_button = QtWidgets.QPushButton("Read File")
        read_button.clicked.connect(self.read_file)
        btn_layout.addWidget(read_button)

        patch_button = QtWidgets.QPushButton("Patch File")
        patch_button.clicked.connect(self.patch_file)
        btn_layout.addWidget(patch_button)

        verify_button = QtWidgets.QPushButton("Verify Checksum")
        verify_button.clicked.connect(self.verify_checksum)
        btn_layout.addWidget(verify_button)

        clear_button = QtWidgets.QPushButton("Clear Log")
        clear_button.clicked.connect(self.clear_log)
        btn_layout.addWidget(clear_button)

        progress_frame = QtWidgets.QGroupBox("Progress")
        progress_layout = QtWidgets.QVBoxLayout(progress_frame)
        main_tab_layout.addWidget(progress_frame)

        self.progress = QtWidgets.QProgressBar()
        progress_layout.addWidget(self.progress)
        self.status_label = QtWidgets.QLabel(self.status_text)
        progress_layout.addWidget(self.status_label)

        log_frame = QtWidgets.QGroupBox("Operation Log")
        log_layout = QtWidgets.QVBoxLayout(log_frame)
        main_tab_layout.addWidget(log_frame)
        self.log_text = QtWidgets.QPlainTextEdit()
        log_layout.addWidget(self.log_text)

        # Remove the file comparison section from the main tab
        # compare_frame = QtWidgets.QGroupBox("File Comparison")
        # compare_layout = QtWidgets.QHBoxLayout(compare_frame)
        # main_tab_layout.addWidget(compare_frame)

        # Add table for differences
        # self.differences_table = QtWidgets.QTableWidget()
        # self.differences_table.setColumnCount(3)
        # self.differences_table.setHorizontalHeaderLabels(["Offset", "Original", "Modified"])
        # compare_layout.addWidget(self.differences_table)

        # Create a new tab for file comparison
        compare_tab = QtWidgets.QWidget()
        self.notebook.addTab(compare_tab, "File Comparison")
        compare_layout = QtWidgets.QVBoxLayout(compare_tab)

        # Add file selection frame
        file_select_frame = QtWidgets.QGroupBox("File Selection")
        file_select_layout = QtWidgets.QGridLayout(file_select_frame)
        compare_layout.addWidget(file_select_frame)

        # Original file selection
        file_select_layout.addWidget(QtWidgets.QLabel("Original File:"), 0, 0)
        self.original_file_var = QtWidgets.QLineEdit()
        file_select_layout.addWidget(self.original_file_var, 0, 1)
        orig_browse_btn = QtWidgets.QPushButton("Browse")
        orig_browse_btn.clicked.connect(lambda: self.browse_for_diff("original"))
        file_select_layout.addWidget(orig_browse_btn, 0, 2)

        # Patched file selection
        file_select_layout.addWidget(QtWidgets.QLabel("Patched File:"), 1, 0)
        self.patched_file_var = QtWidgets.QLineEdit()
        file_select_layout.addWidget(self.patched_file_var, 1, 1)
        patched_browse_btn = QtWidgets.QPushButton("Browse")
        patched_browse_btn.clicked.connect(lambda: self.browse_for_diff("patched"))
        file_select_layout.addWidget(patched_browse_btn, 1, 2)

        # Compare button
        compare_btn = QtWidgets.QPushButton("Compare Files")
        compare_btn.clicked.connect(self.compare_files)
        file_select_layout.addWidget(compare_btn, 2, 1)

        # Differences table
        self.differences_table = QtWidgets.QTableWidget()
        self.differences_table.setColumnCount(4)
        self.differences_table.setHorizontalHeaderLabels(["Offset", "Original", "Modified", "ASCII"])
        self.differences_table.horizontalHeader().setStretchLastSection(True)
        compare_layout.addWidget(self.differences_table)

    def log(self, message):
        self.log_text.appendPlainText(message)

    def clear_log(self):
        self.log_text.clear()

    def copy_dummy_vin(self, dummy_vin):
        self.vin_edit.setText(dummy_vin)
        self.vin_edit.selectAll()
        self.vin_edit.setFocus()

    def browse_file(self):
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, 
            "Open File", 
            os.path.expanduser("~"), # Use home directory as starting point
            "Binary files (*.bin);;All files (*.*)"  # Add .* for Windows
        )
        if filename:
            self.current_file_edit.setText(filename)
            self.read_file()

    def read_file(self):
        if not self.current_file_edit.text():
            QtWidgets.QMessageBox.critical(self, "Error", "Please select a file first")
            return
            
        try:
            with open(self.current_file_edit.text(), 'rb') as f:
                data = f.read()
                
            if len(data) != 32768:
                QtWidgets.QMessageBox.critical(self, "Error", "Invalid file size. Expected 32768 bytes")
                return
                
            self.log("Reading file structure...")
            self.progress.setValue(0)
            
            self.file_endianness = self.detect_endianness(data)
            self.log(f"File Endianness: {self.file_endianness}")
            
            fazit = data[256:279].decode('ascii', errors='ignore')
            self.log(f"FAZIT: {fazit}")
            
            version = data[5140:5160].decode('ascii', errors='ignore')
            self.log(f"Version: {version}")
            
            self.progress.setValue(30)
            self.status_label.setText("Reading features status...")
            
            features = {
                "Mirror Link": data[0x1C40:0x1C42] == b'\x11\x02',
                "Apple CarPlay": data[0x1D00:0x1D02] == b'\x11\x02', 
                "Google Auto": data[0x22C0:0x22C2] == b'\x11\x02',
                "Car Data": data[0x2380:0x2382] == b'\x11\x02'
            }
            
            for feature, status in features.items():
                self.checkboxes[feature].setChecked(status)
                self.log(f"{feature}: {'Activated' if status else 'Not activated'}")
                
            self.progress.setValue(100)
            self.status_label.setText("File read successfully")
            
            self.show_hex_dump(data)
            
            original_checksums = self.calculate_checksum(data)
            self.log("\nOriginal Checksums:")
            self.log(f"Number of blocks: {len(original_checksums)}")
            self.log(f"First block checksum: 0x{original_checksums[0]:04X}")
            self.log(f"Last block checksum: 0x{original_checksums[-1]:04X}")
            
            self.file_data = data  # Store the file data in an instance variable
            
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to read file: {str(e)}")
            self.log(f"Error: {str(e)}")

    def patch_file(self):
        if not self.current_file_edit.text():
            QtWidgets.QMessageBox.critical(self, "Error", "Please select a file first")
            return
            
        if not self.vin_edit.text() or len(self.vin_edit.text()) != 17:
            QtWidgets.QMessageBox.critical(self, "Error", "Please enter a valid 17-character VIN")
            return
            
        try:
            with open(self.current_file_edit.text(), 'rb') as f:
                data = bytearray(f.read())
                
            self.progress.setValue(0)
            self.status_label.setText("Patching file...")
            
            # Update patch locations to match original script
            features_data = {
                "Mirror Link": {
                    'magic': (0x1C40, b'\x11\x02\x00\x06\x09\x00'),
                    'status': (0x1FE0, b'\xFF\x01'),  # FECstatus_val1 value
                    'copies': [(0x4580, b'\x11\x02\x00\x06\x09\x00'), (0x6EC0, b'\x11\x02\x00\x06\x09\x00')]
                },
                "Apple CarPlay": {
                    'magic': (0x1D00, b'\x11\x02\x00\x06\x01\x00'),
                    'status': (0x1FF8, b'\xFF\x01'),  # FECstatus_val2 value
                    'copies': [(0x4640, b'\x11\x02\x00\x06\x01\x00'), (0x6F80, b'\x11\x02\x00\x06\x01\x00')]
                },
                "Google Auto": {
                    'magic': (0x22C0, b'\x11\x02\x00\x06\x08\x00'),
                    'status': (0x2010, b'\xFF\x01'),  # FECstatus_val3 value  
                    'copies': [(0x4C00, b'\x11\x02\x00\x06\x08\x00'), (0x7540, b'\x11\x02\x00\x06\x08\x00')]
                },
                "Car Data": {
                    'magic': (0x2380, b'\x11\x02\x00\x06\x03\x00'),
                    'status': (0x2028, b'\xFF\x01'),  # FECstatus_val4 value
                    'copies': [(0x4CC0, b'\x11\x02\x00\x06\x03\x00'), (0x7600, b'\x11\x02\x00\x06\x03\x00')]
                }
            }
            
            # Apply patches for each feature including copies and status flags
            for feature, patches in features_data.items():
                self.log(f"Patching {feature}...")
                # Main feature block
                offset, magic = patches['magic']
                data[offset:offset+len(magic)] = magic
                
                # Status flag
                status_offset, status_val = patches['status'] 
                data[status_offset:status_offset+len(status_val)] = status_val
                
                # Copy blocks
                for copy_offset, copy_magic in patches['copies']:
                    data[copy_offset:copy_offset+len(copy_magic)] = copy_magic
                
                self.progress.setValue(self.progress.value() + 20)

            # Update VIN in all locations
            vin_locations = [
                0x1C4C, 0x1D0C, 0x22CC, 0x238C,  # Primary copies
                0x4580 + 0x0C, 0x4640 + 0x0C, 0x4C00 + 0x0C, 0x4CC0 + 0x0C,  # Secondary copies
                0x6EC0 + 0x0C, 0x6F80 + 0x0C, 0x7540 + 0x0C, 0x7600 + 0x0C   # Tertiary copies
            ]
            
            vin_data = self.vin_edit.text().encode()
            for loc in vin_locations:
                data[loc:loc+17] = vin_data

            # Update timestamps
            current_time = int(datetime.datetime.now().timestamp())
            time_bytes = current_time.to_bytes(4, 'big')
            
            timestamp_locations = [
                0x1C54, 0x1D14, 0x22D4, 0x2394,  # Primary timestamps
                0x4580 + 0x14, 0x4640 + 0x14, 0x4C00 + 0x14, 0x4CC0 + 0x14,  # Secondary timestamps
                0x6EC0 + 0x14, 0x6F80 + 0x14, 0x7540 + 0x14, 0x7600 + 0x14   # Tertiary timestamps
            ]
            
            for loc in timestamp_locations:
                data[loc:loc+4] = time_bytes

            # Save patched file and verify checksums
            output_file = self.current_file_edit.text().replace('.bin', '_patched.bin')
            with open(output_file, 'wb') as f:
                f.write(data)
                
            self.progress.setValue(100)
            self.status_label.setText("File patched successfully")
            self.log(f"Saved patched file: {output_file}")
            
            # Verify and correct checksums
            self.verify_and_correct_checksums(data, output_file)
            self.file_data = data

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to patch file: {str(e)}")
            self.log(f"Error: {str(e)}")

    def verify_checksum(self):
        if self.file_data is None:
            QtWidgets.QMessageBox.critical(self, "Error", "No file data available. Please read or patch a file first.")
            return
            
        # Store original file data for comparison
        original_data = self.file_data
        # Make a copy of the data for verification
        data_copy = bytearray(self.file_data)
        self.verify_and_correct_checksums(data_copy, None)

    def verify_and_correct_checksums(self, data, output_file):
        try:
            # Convert data to bytearray if it's bytes to make it mutable
            if isinstance(data, bytes):
                data = bytearray(data)
                
            self.progress.setValue(0)
            self.status_label.setText("Verifying and correcting checksums...")
            
            blocks = len(data) // 64  # File is split into 64-byte blocks
            errors = []
            
            for block in range(blocks):
                self.progress.setValue(int((block / blocks) * 100))
                
                block_data = data[block*64:(block+1)*64]  # Get current 64-byte block
                # Calculate CRC-CCITT (0x1021) checksum for current block
                crc = binascii.crc_hqx(block_data, 0)
                
                # Get stored checksum from checksum table at end of file
                # Checksum table starts at offset 31744 (32768-1024)
                # Each block's checksum is 2 bytes
                stored_crc = int.from_bytes(data[32768-1024+(block*2):32768-1024+(block*2)+2], 'big')
                
                # Compare calculated vs stored checksum
                if crc != stored_crc:
                    errors.append(block)
                    self.log(f"Checksum error in block {block}")
                    
            if errors:
                self.correct_checksums(data, errors)
                self.log("All checksums corrected.")
                if output_file:
                    with open(output_file, 'wb') as f:
                        f.write(data)
                    self.log(f"Updated checksums in patched file: {output_file}")
                
                # Remove show_diff call since we use the comparison table now
                self.update_main_tab_differences(self.file_data, data)
                # Switch to comparison tab
                self.notebook.setCurrentIndex(1)  # Index 1 is the comparison tab
            else:
                self.status_label.setText("All checksums verified successfully")
                
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to verify and correct checksums: {str(e)}")
            self.log(f"Error: {str(e)}")

    def correct_checksums(self, data, error_blocks):
        try:
            for i, block in enumerate(error_blocks):
                self.progress.setValue(int((i / len(error_blocks)) * 100))
                
                block_data = data[block*64:(block+1)*64]
                new_crc = binascii.crc_hqx(block_data, 0)
                
                data[32768-1024+(block*2):32768-1024+(block*2)+2] = new_crc.to_bytes(2, 'big')
                
            self.progress.setValue(100)
            self.status_label.setText("Checksums corrected successfully")
            
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to correct checksums: {str(e)}")
            self.log(f"Error: {str(e)}")

    def show_hex_dump(self, data, patched=False):
        hex_dump = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_line = f"{i:08x}  {' '.join([f'{b:02x}' for b in chunk]):<48}  "
            ascii_line = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in chunk])
            hex_dump.append(f"{hex_line}{ascii_line}")
            
        dump_text = '\n'.join(hex_dump)

    def browse_for_diff(self, file_type):
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Open File", "", "Binary files (*.bin);;All files (*)")
        if filename:
            if file_type == "original":
                self.original_file_var.setText(filename)
            else:
                self.patched_file_var.setText(filename)

    def compare_files(self):
        try:
            if not self.original_file_var.text() or not self.patched_file_var.text():
                QtWidgets.QMessageBox.critical(self, "Error", "Please select both files for comparison")
                return
                
            progress_dialog = QtWidgets.QDialog(self)
            progress_dialog.setWindowTitle("Scanning Files")
            progress_dialog.resize(300, 100)
            progress_dialog.setModal(True)
            
            progress_label = QtWidgets.QLabel("Scanning files for differences...", progress_dialog)
            progress_label.move(10, 10)
            
            progress_bar = QtWidgets.QProgressBar(progress_dialog)
            progress_bar.setGeometry(10, 40, 280, 30)
            
            progress_dialog.show()
            
            with open(self.original_file_var.text(), 'rb') as f:
                original_data = f.read()
            with open(self.patched_file_var.text(), 'rb') as f:
                patched_data = f.read()
            
            self.differences_table.setRowCount(0)
            min_len = min(len(original_data), len(patched_data))
            
            diff_rows = []
            for i in range(min_len):
                progress_bar.setValue(int((i / min_len) * 100))
                if original_data[i] != patched_data[i]:
                    # Improved ASCII representation
                    orig_byte = original_data[i]
                    mod_byte = patched_data[i]
                    
                    # Only show ASCII conversion if both bytes are printable
                    if 32 <= orig_byte <= 126 and 32 <= mod_byte <= 126:
                        ascii_repr = f"'{chr(orig_byte)}' → '{chr(mod_byte)}'"
                    else:
                        # For non-printable characters, just show hex
                        ascii_repr = f"0x{orig_byte:02X} → 0x{mod_byte:02X}"
                    
                    diff_rows.append((
                        i,
                        f"{orig_byte:02X}",
                        f"{mod_byte:02X}",
                        ascii_repr
                    ))
            
            self.differences_table.setRowCount(len(diff_rows))
            for row, (offset, orig, modified, ascii_repr) in enumerate(diff_rows):
                self.differences_table.setItem(row, 0, QtWidgets.QTableWidgetItem(f"0x{offset:04X}"))
                self.differences_table.setItem(row, 1, QtWidgets.QTableWidgetItem(orig))
                self.differences_table.setItem(row, 2, QtWidgets.QTableWidgetItem(modified))
                self.differences_table.setItem(row, 3, QtWidgets.QTableWidgetItem(ascii_repr))
                
                # Color the row if significant changes detected
                if orig != modified:
                    for col in range(4):
                        item = self.differences_table.item(row, col)
                        item.setBackground(QtGui.QColor(255, 235, 235))
            
            self.differences_table.resizeColumnsToContents()
            progress_dialog.close()
            
        except Exception as e:
            progress_dialog.close()
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to compare files: {str(e)}")
            self.log(f"Error: {str(e)}")

    def highlight_all_differences(self, original_data, patched_data):
        pass

    def calculate_checksum(self, data):
        checksums = []
        for block in range(len(data) // 64):
            block_data = data[block*64:(block+1)*64]
            crc = binascii.crc_hqx(block_data, 0)
            checksums.append(crc)
        return checksums

    def correct_endianness(self, data):
        data = bytearray(data)
        locations = [0x1C40, 0x1D00, 0x22C0, 0x2380]
        for loc in locations:
            data[loc:loc+2] = data[loc:loc+2][::-1]
        return data

    def create_hex_dump(self, data):
        hex_dump = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_line = f"{i:08x}  "
            hex_values = ' '.join([f"{b:02x}" for b in chunk])
            hex_line += f"{hex_values:<48}  "
            ascii_values = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in chunk])
            hex_line += ascii_values
            hex_dump.append(hex_line)
            
        return '\n'.join(hex_dump)

    def detect_endianness(self, data):
        """
        Detect file endianness by checking known magic numbers at certain offsets.
        Returns 'little', 'big', or 'unknown'.
        """
        magic_locations = [0x1C40, 0x1D00, 0x22C0, 0x2380]
        for loc in magic_locations:
            magic = data[loc:loc+2]
            if magic == b'\x11\x02':
                return 'little'
            elif magic == b'\x02\x11':
                return 'big'
        return 'unknown'

    def update_main_tab_differences(self, original_data, patched_data):
        self.differences_table.setRowCount(0)
        length = min(len(original_data), len(patched_data))
        diff_rows = []
        for i in range(length):
            if original_data[i] != patched_data[i]:
                diff_rows.append((i, original_data[i], patched_data[i]))
        self.differences_table.setRowCount(len(diff_rows))
        for row, (offset, orig_byte, patched_byte) in enumerate(diff_rows):
            offset_item = QtWidgets.QTableWidgetItem(f"0x{offset:04X}")
            original_item = QtWidgets.QTableWidgetItem(f"{orig_byte:02X}")
            patched_item = QtWidgets.QTableWidgetItem(f"{patched_byte:02X}")
            self.differences_table.setItem(row, 0, offset_item)
            self.differences_table.setItem(row, 1, original_item)
            self.differences_table.setItem(row, 2, patched_item)

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    
    # Platform-specific icon handling
    icon_path = os.path.normpath(os.path.join(os.path.dirname(__file__), 'app_logo.png'))
    if os.path.exists(icon_path):
        app_icon = QtGui.QIcon(icon_path)
        app.setWindowIcon(app_icon)
        
        if os.name == 'nt':  # Windows
            # Windows-specific taskbar icon
            myappid = 'lg.unit.patcher.1.0'  # arbitrary string
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
            
            # Set Windows taskbar icon
            import ctypes
            ctypes.windll.user32.SetProcessDPIAware()  # Handle high DPI displays
        else:
            # Linux/Unix handling
            try:
                from PyQt5.QtX11Extras import QX11Info
                if hasattr(app, "setDesktopFileName"):
                    app.setDesktopFileName("lg-unit-patcher")
            except:
                pass
    
    app.setApplicationName("LG-UNIT-PATCHER")
    app.setApplicationDisplayName("LG-UNIT-PATCHER")
    gui = MEN2PatcherGUI()
    gui.show()
    sys.exit(app.exec_())
