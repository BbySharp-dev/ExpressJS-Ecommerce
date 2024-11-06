const mongoose = require("mongoose");

const roleSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  permissions: { type: [String], default: [] },
},{
  timestamps: true,
});

const Role = mongoose.model("Role", roleSchema);

module.exports = Role;
