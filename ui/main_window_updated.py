# This is a placeholder - the actual update to main_window.py needs to be:
# Find: self.interface_combo = QComboBox()
#        interface_layout.addWidget(self.interface_combo)
# Replace with:
#        self.interface_combo = QComboBox()
#        # Set wider minimum width for full interface names with icons
#        self.interface_combo.setMinimumWidth(450)
#        # Auto-size to fit content including emoji icons
#        self.interface_combo.setSizeAdjustPolicy(
#            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
#        )
#        interface_layout.addWidget(self.interface_combo)
