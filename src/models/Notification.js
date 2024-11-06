const mongoose = require("mongoose");

const NotificationSchema = new mongoose.Schema({
  context: { type: String, required: true },// "Đơn hàng mới"
  title: { type: String, required: true },
  body: { type: String, required: true }, 
  referenceId: { type: String }, // ID tham chiếu 
  recipientIds: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    isRead: { type: Boolean, default: false }
  }],
}, {
    timestamps: true
});

const Notification = mongoose.model("Notification", NotificationSchema);

module.exports = Notification;
