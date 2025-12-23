// ===== 1. 載入套件（Node.js 後端常用工具） =====
const express = require("express");        // 建立後端伺服器、路由
const mongoose = require("mongoose");      // 連接 MongoDB、操作資料庫
const path = require("path");              // 處理檔案路徑（跨平台安全）
const dotenv = require("dotenv");          // 讀取 .env 環境變數
const cors = require("cors");              // 允許跨網域請求（前端/後端不同來源時要用）
const bcrypt = require("bcryptjs");        // 密碼加密 / 比對
const jwt = require("jsonwebtoken");       // 產生與驗證 JWT token（登入用）

// 讀取 .env 檔案內容（例如 MONGO_URI、JWT_SECRET、PORT）
dotenv.config();

// ===== 2. 載入你自己寫的 Mongoose Model（資料表結構） =====
// User：存帳號密碼（密碼會存 hash）
// Review：存評論資料
const User = require("./models/User");
const Review = require("./models/Review");

// 建立 express app
const app = express();


// =======================
// 3) Middleware（中介層）
// =======================

// 允許跨來源（例如你未來前端不是同一個網址時）
app.use(cors());

// 允許接收 JSON body，limit 設 2mb（避免被超大 payload 攻擊）
app.use(express.json({ limit: "2mb" }));

// 允許接收 form 表單資料（例如 application/x-www-form-urlencoded）
app.use(express.urlencoded({ extended: true }));


// =======================
// 4) 靜態檔案（public/）
// =======================
// 這行會讓你可以直接用網址開到 public 裡面的檔案，例如：
// http://localhost:3000/foodmap.html
app.use(express.static(path.join(__dirname, "public")));


// =======================
// 5) 連接 MongoDB 資料庫
// =======================
async function connectDB() {
  // 從 .env 讀取 MongoDB 的連線字串
  const uri = process.env.MONGO_URI;

  // 如果沒設 MONGO_URI 就直接終止程式（避免程式卡住或亂跑）
  if (!uri) {
    console.error("缺少 MONGO_URI，請在 .env 設定");
    process.exit(1);
  }

  // 連線 MongoDB
  await mongoose.connect(uri);

  console.log("MongoDB connected");
}

// 真的執行連線
connectDB().catch((e) => {
  console.error("MongoDB connect failed:", e);
  process.exit(1);
});


// =======================
// 6) Helper Functions（共用工具）
// =======================

// 6-1) 產生 JWT token：登入成功後發給前端保存
function signToken(user) {
  const secret = process.env.JWT_SECRET;

  // JWT_SECRET 是簽名用的密鑰，一定要在 .env 設定
  if (!secret) {
    throw new Error("Missing JWT_SECRET in .env");
  }

  // jwt.sign(payload, secret, options)
  // payload 放你要存進 token 的資料（這裡放 userId 與 username）
  // expiresIn: token 7 天後過期
  return jwt.sign(
    { userId: user._id.toString(), username: user.username },
    secret,
    { expiresIn: "7d" }
  );
}

// 6-2) 驗證 token 的中介層（保護需要登入的 API）
function authMiddleware(req, res, next) {
  // 讀取 headers 裡的 Authorization: Bearer xxxxx
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  // 沒 token：直接回 401（未登入）
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    // 驗證 token（成功會拿到 payload）
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    // 把 payload 放到 req.user，後面路由就能用 req.user.userId / req.user.username
    req.user = payload;

    // 放行到下一個 middleware / route
    next();
  } catch (e) {
    // token 不合法 / 過期
    return res.status(401).json({ message: "Invalid token" });
  }
}


// =======================
// 7) Favorite Model（收藏）
// 你把 Schema 寫在 server.js 內，避免多一個檔案
// =======================

const FavoriteSchema = new mongoose.Schema(
  {
    // userId：收藏是誰的（用 ObjectId 連到 User）
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },

    // storeKey：店家唯一識別（你前端用 district-name 組成）
    storeKey: { type: String, required: true, index: true },

    // storeName / district：存顯示用資訊（方便 profile 顯示）
    storeName: { type: String, default: "" },
    district: { type: String, default: "" },
  },
  { timestamps: true } // 自動加 createdAt / updatedAt
);

// 同一個人同一間店只能收藏一次（避免重複收藏）
FavoriteSchema.index({ userId: 1, storeKey: 1 }, { unique: true });

// 建立 Favorite model（對應 MongoDB 的 favorites collection）
const Favorite = mongoose.model("Favorite", FavoriteSchema);



// =====================================================
// 8) Auth APIs（註冊 / 登入 / 檢查登入 / 改密碼）
// =====================================================

// 8-1) 註冊
app.post("/api/auth/register", async (req, res) => {
  try {
    // 取出帳密，做基本清理
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    // 基本限制：帳號至少 3
    if (username.length < 3) {
      return res.status(400).json({ message: "帳號至少 3 個字" });
    }

    // 密碼至少 6
    if (password.length < 6) {
      return res.status(400).json({ message: "密碼至少 6 個字" });
    }

    // 查是否已註冊
    const exists = await User.findOne({ username });
    if (exists) {
      return res.status(400).json({ message: "此帳號已被註冊" });
    }

    // 把明碼密碼加密成 hash（bcrypt）
    const passwordHash = await bcrypt.hash(password, 10);

    // 建立使用者
    const user = await User.create({ username, passwordHash });

    // 產生 token
    const token = signToken(user);

    // 回傳 token + user 基本資料
    return res.json({
      token,
      user: { username: user.username, id: user._id },
    });
  } catch (e) {
    return res.status(500).json({ message: "Register failed" });
  }
});

// 8-2) 登入
app.post("/api/auth/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    // 找使用者
    const user = await User.findOne({ username });

    // 找不到或密碼不對都回同一句（避免洩漏帳號存在與否）
    if (!user) return res.status(400).json({ message: "帳號或密碼錯誤" });

    // bcrypt 比對輸入密碼 vs 資料庫 hash
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ message: "帳號或密碼錯誤" });

    // 登入成功發 token
    const token = signToken(user);

    return res.json({
      token,
      user: { username: user.username, id: user._id },
    });
  } catch (e) {
    return res.status(500).json({ message: "Login failed" });
  }
});

// 8-3) 檢查登入狀態（前端用來顯示目前登入者）
app.get("/api/auth/me", authMiddleware, async (req, res) => {
  // 只要 token 有效就能拿到 req.user.username
  return res.json({ user: { username: req.user.username } });
});

// 8-4) 修改密碼（必須提供原密碼）
app.post("/api/auth/change-password", authMiddleware, async (req, res) => {
  try {
    const oldPassword = String(req.body.oldPassword || "");
    const newPassword = String(req.body.newPassword || "");

    // 新密碼基本限制
    if (newPassword.length < 6) {
      return res.status(400).json({ message: "新密碼至少 6 個字" });
    }

    // 透過 token 的 userId 找使用者
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(401).json({ message: "User not found" });

    // 比對原密碼
    const ok = await bcrypt.compare(oldPassword, user.passwordHash);
    if (!ok) return res.status(400).json({ message: "原密碼錯誤" });

    // 更新 hash
    user.passwordHash = await bcrypt.hash(newPassword, 10);
    await user.save();

    return res.json({ message: "Password updated" });
  } catch (e) {
    return res.status(500).json({ message: "Change password failed" });
  }
});



// ======================================
// 9) Favorites APIs（收藏功能）
// ======================================

// 9-1) 取得我的收藏（需要登入）
app.get("/api/favorites", authMiddleware, async (req, res) => {
  try {
    // 找出此 userId 所有收藏，按照最新的在最前面
    const favorites = await Favorite.find({ userId: req.user.userId })
      .sort({ createdAt: -1 })
      .lean();

    return res.json({ favorites });
  } catch (e) {
    return res.status(500).json({ message: "Favorites read failed" });
  }
});

// 9-2) 新增收藏（需要登入）
app.post("/api/favorites", authMiddleware, async (req, res) => {
  try {
    const storeKey = String(req.body.storeKey || "").trim();
    const storeName = String(req.body.storeName || "").trim();
    const district = String(req.body.district || "").trim();

    if (!storeKey) return res.status(400).json({ message: "storeKey required" });

    // 建立收藏（若同一 user + storeKey 已存在，會觸發 unique index 錯誤）
    const fav = await Favorite.create({
      userId: req.user.userId,
      storeKey,
      storeName,
      district,
    });

    return res.json({ favorite: fav });
  } catch (e) {
    // E11000 = MongoDB duplicate key error（重複收藏）
    if (String(e.message).includes("E11000")) {
      return res.status(400).json({ message: "已經收藏過囉～" });
    }
    return res.status(500).json({ message: "Favorite failed" });
  }
});

// 9-3) 移除收藏（用 query 參數 storeKey）
app.delete("/api/favorites", authMiddleware, async (req, res) => {
  try {
    const storeKey = String(req.query.storeKey || "").trim();
    if (!storeKey) return res.status(400).json({ message: "storeKey required" });

    // 刪除指定收藏
    await Favorite.deleteOne({ userId: req.user.userId, storeKey });

    return res.json({ message: "Favorite removed" });
  } catch (e) {
    return res.status(500).json({ message: "Remove favorite failed" });
  }
});



// ======================================
// 10) Reviews APIs（評論功能）
// ======================================

// 10-1) 列出某店評論（不需要登入，任何人都能看）
app.get("/api/reviews", async (req, res) => {
  try {
    const storeKey = String(req.query.storeKey || "").trim();
    if (!storeKey) return res.status(400).json({ message: "storeKey required" });

    // 找該店評論，最新的在前面，只挑必要欄位回傳
    const reviews = await Review.find({ storeKey })
      .sort({ createdAt: -1 })
      .select("storeKey storeName district rating comment userName createdAt")
      .lean();

    return res.json({ reviews });
  } catch (e) {
    return res.status(500).json({ message: "Reviews read failed" });
  }
});

// 10-2) 新增評論（需要登入）
app.post("/api/reviews", authMiddleware, async (req, res) => {
  try {
    const storeKey = String(req.body.storeKey || "").trim();
    const storeName = String(req.body.storeName || "").trim();
    const district = String(req.body.district || "").trim();
    const rating = Number(req.body.rating || 0);
    const comment = String(req.body.comment || "").trim();

    // 基本驗證
    if (!storeKey) return res.status(400).json({ message: "storeKey required" });
    if (!comment) return res.status(400).json({ message: "comment required" });
    if (!(rating >= 1 && rating <= 5)) return res.status(400).json({ message: "rating 1~5" });

    // 建立評論
    const review = await Review.create({
      storeKey,
      storeName,
      district,
      rating,
      comment,

      // userId：用 token 內的 userId（防止前端偽造）
      userId: req.user.userId,

      // userName：用 token 的 username（前端不可改）
      userName: req.user.username,
    });

    return res.json({ review });
  } catch (e) {
    return res.status(500).json({ message: "Review post failed" });
  }
});

// 10-3) 某店評論摘要（平均分 & 評論數）
app.get("/api/reviews/summary", async (req, res) => {
  try {
    const storeKey = String(req.query.storeKey || "").trim();
    if (!storeKey) return res.status(400).json({ message: "storeKey required" });

    // aggregate：MongoDB 內建聚合管線
    const agg = await Review.aggregate([
      { $match: { storeKey } }, // 只挑該店
      {
        $group: {
          _id: "$storeKey",
          avgRating: { $avg: "$rating" }, // 平均
          count: { $sum: 1 },             // 數量
        },
      },
    ]);

    // 沒有評論就回 0
    if (agg.length === 0) return res.json({ avgRating: 0, count: 0 });

    return res.json({
      avgRating: agg[0].avgRating || 0,
      count: agg[0].count || 0,
    });
  } catch (e) {
    return res.status(500).json({ message: "Summary failed" });
  }
});

// 10-4) 我的評論（個人檔案頁用，需要登入）
app.get("/api/reviews/mine", authMiddleware, async (req, res) => {
  try {
    // 找出此使用者的所有評論
    const reviews = await Review.find({ userId: req.user.userId })
      .sort({ createdAt: -1 })
      .select("storeKey storeName district rating comment createdAt")
      .lean();

    return res.json({ reviews });
  } catch (e) {
    return res.status(500).json({ message: "Mine failed" });
  }
});



// ======================================
// 11) Rankings APIs（近 30 天 Top10）
// ======================================
app.get("/api/rankings/top", async (req, res) => {
  try {
    // 現在時間
    const now = new Date();

    // 30 天前
    const from = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    const rankings = await Review.aggregate([
      // 只看 30 天內的評論
      { $match: { createdAt: { $gte: from } } },

      // 以 storeKey 分組，算平均分 + 數量
      {
        $group: {
          _id: "$storeKey",
          storeKey: { $first: "$storeKey" },
          storeName: { $first: "$storeName" },
          district: { $first: "$district" },
          avgRating: { $avg: "$rating" },
          count: { $sum: 1 },
        },
      },

      // 先比平均分，再比評論數（平均高、且評論多的優先）
      { $sort: { avgRating: -1, count: -1 } },

      // 只取前 10 名
      { $limit: 10 },

      // 回傳欄位整理（_id 不要，avgRating 四捨五入）
      {
        $project: {
          _id: 0,
          storeKey: 1,
          storeName: 1,
          district: 1,
          avgRating: { $round: ["$avgRating", 2] },
          count: 1,
        },
      },
    ]);

    return res.json({ rankings });
  } catch (e) {
    return res.status(500).json({ message: "Rankings failed" });
  }
});



// ======================================
// 12) 首頁路由（可選）
// ======================================
// 你直接打 http://localhost:3000/ 的時候，就回傳 foodmap.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "foodmap.html"));
});



// ======================================
// 13) 啟動伺服器
// ======================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running: http://localhost:${PORT}`);
<<<<<<< HEAD
});
=======
});
>>>>>>> 4e4ad381b7f12cdce04f5970d1cfafee202d73d6
