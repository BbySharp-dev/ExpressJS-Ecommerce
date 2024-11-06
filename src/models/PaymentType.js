const mongoose = require("mongoose");
const { PAYMENT_TYPES } = require("../configs/index");

const paymentTypeSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, unique: true },
    type: {
      type: String,
      required: true,
      enum: Object.values(PAYMENT_TYPES),
    },
  },
  {
    timestamps: true,
  }
);
const PaymentType = mongoose.model("PaymentType", paymentTypeSchema);

module.exports = PaymentType;
