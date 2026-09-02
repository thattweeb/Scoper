# 🔧 Npcap Setup Guide for CyberOctet

## ⚠️ **CURRENT ISSUE: Npcap Required**

The application is showing "Npcap Required" because Npcap is not installed or not configured for non-admin users.

---

## 🎯 **QUICK SOLUTION**

### **Step 1: Download Npcap**
1. **Visit**: https://npcap.com/
2. **Download**: Latest Npcap installer
3. **Save to**: Your Downloads folder

### **Step 2: Install Npcap (CRITICAL)**
1. **Right-click** the installer
2. **Select "Run as Administrator"**
3. **IMPORTANT**: Check the box: **"Support non-administrator users to capture packets"**
4. **Click "Install"**
5. **Wait for installation to complete**

### **Step 3: Restart CyberOctet**
1. **Close** CyberOctet if running
2. **Run**: `python run.py`
3. **Should now work without admin privileges**

---

## 📋 **DETAILED INSTRUCTIONS**

### **Why Npcap is Required:**
- **Packet Capture**: Provides low-level network access
- **Non-Admin Support**: Allows capture without Administrator privileges
- **Industry Standard**: Used by Wireshark, Nmap, and other tools
- **Security**: Proper Windows driver implementation

### **Installation Screenshots:**
```
[ ] Install Npcap in WinPcap API-compatible Mode
[✓] Support non-administrator users to capture packets  ← CHECK THIS!
[ ] Install Npcap Loopback Adapter
```

### **What Each Option Means:**
- **WinPcap Compatible**: Ensures compatibility with older tools
- **Non-Admin Support**: ⭐ **MOST IMPORTANT** - Allows capture without admin
- **Loopback Adapter**: Enables capturing local traffic (optional)

---

## 🔍 **TROUBLESHOOTING**

### **If Still Shows "Npcap Required":**

1. **Check Installation**:
   ```bash
   # Check if Npcap is installed
   dir "C:\Windows\System32\Npcap"
   ```

2. **Check Service**:
   ```bash
   # Check if Npcap service is running
   sc query npcap
   ```

3. **Restart Service**:
   ```bash
   # Restart Npcap service (as Administrator)
   net stop npcap
   net start npcap
   ```

### **If Shows "Npcap Reinstall Required":**
- Npcap is installed but without non-admin support
- **Solution**: Reinstall with "Support non-administrator users" checked

### **If Shows "Npcap Service Issue":**
- Npcap service is not running
- **Solution**: Restart service or reinstall Npcap

---

## 🚀 **VERIFICATION**

### **After Installation, You Should See:**
- ✅ **No warning banner** in CyberOctet
- ✅ **Interface dropdown** populated with network interfaces
- ✅ **Start Capture button** enabled
- ✅ **Status**: "Ready for capture"

### **Test Capture:**
1. **Start CyberOctet**
2. **Select network interface**
3. **Click "Start Capture"**
4. **Generate test traffic**: `python test_traffic.py`
5. **Should see packets** in the table

---

## 📊 **EXPECTED BEHAVIOR**

### **Before Npcap:**
```
⚠️ Npcap Required: CyberOctet requires Npcap for packet capture. Please install Npcap with non-admin support.
[Start Capture] - DISABLED
[Interface] - DISABLED
```

### **After Npcap:**
```
✅ Ready for capture
[Start Capture] - ENABLED
[Interface] - ENABLED with network options
```

---

## 🎯 **FINAL GOAL**

Once Npcap is properly installed with non-admin support:

1. **Run CyberOctet normally** (no admin required)
2. **Select network interface** from dropdown
3. **Start capturing packets** immediately
4. **Professional behavior** like Wireshark

---

## 📞 **SUPPORT**

### **If Issues Persist:**
1. **Check Windows Event Viewer** for Npcap errors
2. **Verify installation** with correct options
3. **Restart computer** after installation
4. **Contact support** with error details

### **Common Mistakes:**
- ❌ Not running installer as Administrator
- ❌ Not checking "Support non-administrator users"
- ❌ Installing without WinPcap compatibility
- ❌ Not restarting after installation

---

## 🏆 **SUCCESS INDICATORS**

**When Npcap is properly configured:**
- ✅ Application starts without warnings
- ✅ Network interfaces appear in dropdown
- ✅ Packet capture works immediately
- ✅ No Administrator privileges required
- ✅ Professional-grade functionality

**CyberOctet will then behave like a commercial packet analyzer!** 🚀
