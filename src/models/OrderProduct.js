const mongoose = require("mongoose");

const orderSchema = new mongoose.Schema(
  {
    orderItems: [
      {
        name: { type: String, required: true },
        amount: { type: Number, required: true },
        image: { type: String, required: true },
        price: { type: Number, required: true },
        discount: { type: Number },
        product: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Product",
          required: true,
        },
      },
    ],
    shippingAddress: {
      fullName: { type: String, required: true },
      address: { type: String, required: true },
      city: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "City",
        required: true,
      },
      phone: { type: Number, required: true },
    },
    paymentMethod: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "PaymentType",
      required: true,
    },
    deliveryMethod: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "DeliveryType",
      required: true,
    },
    itemsPrice: { type: Number, required: true },
    shippingPrice: { type: Number, required: true },
    totalPrice: { type: Number, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    isPaid: {
      type: Number,
      default: 0,
      enum: [0, 1],
    },
    paidAt: { type: Date },
    deliveryAt: { type: Date },
    isDelivered: {
      type: Number,
      default: 0,
      enum: [0, 1],
    },
    status: {
      type: Number,
      enum: [0, 1, 2, 3], // 0: wait payment, 1: wait delivery, 2: done, 3, cancel
      default: 1
    },
  },
  {
    timestamps: true,
  }
);
const Order = mongoose.model("Order", orderSchema);
module.exports = Order;
