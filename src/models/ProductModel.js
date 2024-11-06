const mongoose = require("mongoose");

const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    slug: { type: String, required: true, unique: true },
    image: { type: String },
    price: { type: Number, required: true },
    countInStock: { type: Number, required: true },
    description: { type: String },
    discount: { type: Number },
    discountStartDate: { type: Date },
    discountEndDate: { type: Date },
    sold: { type: Number },
    type: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "ProductType",
      required: true,
    },
    location: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "City",
    },
    likedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    totalLikes: { type: Number, default: 0 },
    status: {
      type: Number,
      default: 0,
      enum: [0, 1],
    },
    views: { type: Number, default: 0 },
    uniqueViews: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  },
  {
    timestamps: true,
  }
);
const Product = mongoose.model("Product", productSchema);

module.exports = Product;
