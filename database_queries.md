# Device Unlock Hub - Database Query Guide

## MongoDB Connection
```bash
mongosh mongodb://localhost:27017/device_unlock_hub
```

## Useful Database Queries

### 1. View All Users
```javascript
db.users.find({}).pretty()
```

### 2. Count Total Users
```javascript
db.users.countDocuments()
```

### 3. Find User by Email
```javascript
db.users.findOne({"email": "rohitarora07773@gmail.com"})
```

### 4. View Users with Low Credits (less than 50)
```javascript
db.users.find({"credits": {$lt: 50}})
```

### 5. View All IMEI Processing Requests
```javascript
db.processing_requests.find({}).pretty()
```

### 6. Count Requests by Status
```javascript
db.processing_requests.aggregate([
  { $group: { _id: "$status", count: { $sum: 1 } } }
])
```

### 7. Find All "new" Requests (Ready for Selenium Processing)
```javascript
db.processing_requests.find({"status": "new"})
```

### 8. Find Requests by User ID
```javascript
db.processing_requests.find({"user_id": "your-user-id-here"})
```

### 9. Find Requests by Batch ID
```javascript
db.processing_requests.find({"batch_id": "your-batch-id-here"})
```

### 10. Update Request Status (Simulate Selenium Processing)
```javascript
// Update a request from "new" to "processing"
db.processing_requests.updateOne(
  {"id": "request-id-here"}, 
  {
    $set: {
      "status": "processing",
      "updated_at": new Date()
    }
  }
)

// Update request to completed with response
db.processing_requests.updateOne(
  {"id": "request-id-here"}, 
  {
    $set: {
      "status": "completed",
      "request_number": "REQ123456",
      "response": "Device unlocked successfully",
      "updated_at": new Date()
    }
  }
)
```

### 11. View Recent Requests (Last 24 hours)
```javascript
db.processing_requests.find({
  "created_at": {
    $gte: new Date(Date.now() - 24*60*60*1000)
  }
}).sort({"created_at": -1})
```

### 12. Database Statistics
```javascript
// Collection statistics
db.users.stats()
db.processing_requests.stats()

// Database overview
db.stats()
```

## For Your Selenium Automation Script

### Query for New Requests to Process
```javascript
// This is what your selenium script should query
db.processing_requests.find({"status": "new"}).limit(10)
```

### Update Request After Processing
```javascript
// After selenium processes an IMEI, update it like this:
db.processing_requests.updateOne(
  {"id": "REQUEST_ID_FROM_YOUR_SCRIPT"},
  {
    $set: {
      "status": "completed",  // or "failed"
      "request_number": "ATT_REQUEST_NUMBER_FROM_WEBSITE",
      "response": "Success message or error details",
      "updated_at": new Date()
    }
  }
)
```

## Backup Commands
```bash
# Backup database
mongodump --db device_unlock_hub --out /app/backup/

# Restore database  
mongorestore --db device_unlock_hub /app/backup/device_unlock_hub/
```