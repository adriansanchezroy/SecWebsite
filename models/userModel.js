const { ref } = require("@hapi/joi/lib/compile");
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    min: 6,
    max: 255,
  },
  password: {
    type: String,
    required: true,
    max: 2048,
    min: 6,
  },
  roles: [
    {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Role"
    }
  ]
});

module.exports = mongoose.model("User", userSchema);