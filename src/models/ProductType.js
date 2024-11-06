const mongoose = require("mongoose");

const productTypeSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    slug: { type: String, required: true, unique: true },
  },
  {
    timestamps: true,
  }
);
const ProductType = mongoose.model(
  "ProductType",
  productTypeSchema
);

module.exports = ProductType;
