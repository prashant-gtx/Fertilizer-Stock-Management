# 🌾 Fertilizer Stock Management System

A complete **Fertilizer Inventory and Stock Management System** built using **Flask (Python)** and **SQLite3**.  
It helps small to medium agricultural businesses track fertilizers, manage stock levels, get automatic alerts for low stock or expiry, and log all product activities securely.

---

## 🚀 Features

✅ **User Authentication**  
- Secure login and registration using password hashing  
- Session-based access with role-based segregation  

✅ **Product Management**  
- Add, update, search, and delete fertilizers  
- Manage product categories, suppliers, and pricing  
- Auto-updates timestamps on product changes  

✅ **Smart Alerts System (SQLite Triggers)**  
- **Low Stock Alerts** (below 50 units)  
- **Expiry Warnings** (products expiring within 30 days)  
- **Prevention of Expired or Negative Stock Entries**  
- **Activity & Deletion Logs** maintained automatically  

✅ **Logs and Reports**  
- Tracks all actions performed by the user  
- Maintains a record of deleted products  
- Allows easy audit and reporting  

✅ **Responsive UI**  
- Built with clean and simple HTML/CSS templates  
- User-friendly dashboard and alert display  

---

## 🗄️ Database Schema

SQLite3 database with the following tables:

- `users`
- `products`
- `stock_alerts`
- `deleted_products_log`
- `activity_log`

Each table is linked through foreign keys with **ON DELETE CASCADE** rules for data integrity.


