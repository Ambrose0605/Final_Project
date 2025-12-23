const mongoose = require("mongoose");

const ReviewSchema = new mongoose.Schema(
  {
    storeKey: { type: String, required: true, index: true },     // e.g. "中正區-店名"
    storeName: { type: String, default: "" },
    district: { type: String, default: "" },

    rating: { type: Number, required: true, min: 1, max: 5 },
    comment: { type: String, required: true },

    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    userName: { type: String, required: true }, // 固定用 token 的 username（前端不可改）
  },
  { timestamps: true }
);

module.exports = mongoose.model("Review", ReviewSchema);