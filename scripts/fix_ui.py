# Python script to fix the main_window.py interface combo width
# Run this with: python fix_ui.py

old_code = '''        self.interface_combo = QComboBox()
        interface_layout.addWidget(self.interface_combo)'''

new_code = '''        self.interface_combo = QComboBox()
        # Set wider minimum width for full interface names with icons
        self.interface_combo.setMinimumWidth(450)
        # Auto-size to fit content including emoji icons
        self.interface_combo.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        interface_layout.addWidget(self.interface_combo)'''

with open(r'c:\Users\Helly\Documents\Git\Packet-Capture\ui\main_window.py', 'r', encoding='utf-8') as f:
    content = f.read()

if old_code in content:
    content = content.replace(old_code, new_code)
    with open(r'c:\Users\Helly\Documents\Git\Packet-Capture\ui\main_window.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("SUCCESS: Updated interface combo width to 450px")
else:
    print("WARNING: Could not find exact code")
