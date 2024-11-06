const mongoose = require("mongoose");

const citySchema = new mongoose.Schema(
  {
    name: { type: String, required: true, unique: true }
  },
  {
    timestamps: true,
  }
);
const City = mongoose.model("City", citySchema);

module.exports = City;
