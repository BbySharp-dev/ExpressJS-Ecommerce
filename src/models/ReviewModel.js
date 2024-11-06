const mongoose = require("mongoose");

const ReviewSchema = new mongoose.Schema(
  {
    content: { type: String, required: true },
    star: { type: Number, required: true, min: 1, max: 5 },
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Product",
      required: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  {
    timestamps: true,
  }
);
const Review = mongoose.model("Review", ReviewSchema);

module.exports = Review;
