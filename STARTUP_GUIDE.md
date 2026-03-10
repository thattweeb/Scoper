# 🚀 CyberOctet Startup Guide

## ⚡ **5-MINUTE TEAM SETUP**

### **Step 1: Get the Code**
```bash
git clone <repository-url>
```

### **Step 2: Install Dependencies**
```bash
pip install -r requirements.txt
```

### **Step 3: Install Npcap (CRITICAL)**
```bash
python install_npcap.py
# Follow guide - CHECK "Support non-administrator users"
```

### **Step 4: Run Application**
```bash
python run.py
```

---

## 🎯 **SUCCESS INDICATORS**

✅ **Working Setup Shows:**
- User-friendly interfaces: "Wi-Fi", "Ethernet"
- No admin privilege warnings
- Real-time packet capture
- Dashboard updating with PPS/bandwidth

❌ **Issues & Solutions:**

**"Npcap Required"** → Run `python install_npcap.py`
**No interfaces** → Check Npcap service
**Capture fails** → Try `python run_admin.py`

---

## 🧪 **TESTING**

```bash
# Test traffic generation
python test_traffic.py

# Test Npcap status
python install_npcap.py

# Test interface detection
python debug_interfaces.py
```

---

## 📋 **QUICK REFERENCE**

**Filters:** `tcp port 80`, `host 192.168.1.1`
**Interface names:** Wi-Fi, Ethernet, Bluetooth
**Dashboard:** PPS, Bytes/s, Total Packets, Protocol charts

---

**🎯 When properly configured, CyberOctet works like Wireshark without admin prompts!**
