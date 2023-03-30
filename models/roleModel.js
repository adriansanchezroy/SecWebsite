const mongoose = require("mongoose");

const roleSchema = new mongoose.Schema({
  name: {
    type: String,
    enum: ['admin', 'residential', 'business']
  }
});

const Role = mongoose.model("Role", roleSchema);

module.exports = Role;
