var express = require("express");
var router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const { User } = require("../models/user");


router.post("/register", async function (req, res) {
  try {
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(req.body.password, salt);
    req.body.password = hash;
    const user = new User({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
    });
    await user.save();
    return res.json({ message: "User registered successfully" });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

router.post("/login", async function (req, res) {
  try {
    console.log("🔍 Checking MongoDB Query...");
    console.log(
      "📧 Email from request:",
      req.body.email,
      "| Type:",
      typeof req.body.email,
      "| Length:",
      req.body.email.length
    );
    const user = await User.findOne({ email: req.body.email }).maxTimeMS(30000);
    console.log("✅ Query Success:", user);
    if (!user) {
      return res.status(400).json({ message: "Invalid Credentials" });
    }
    const isValid = bcrypt.compareSync(req.body.password, user.password);
    if (!isValid) {
      return res.status(400).json({ message: "Invalid Credentials" });
    }
    const token = jwt.sign(
      {
        id: user._id.toString(),
        email: String(user.email),
        name: String(user.name),
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    return res.json({
      message: "User Logged in Successfully",
      token: token,
      email: user.email,
      name: user.name,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

// Configure Nodemailer
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER, // Use proper environment variable names
    pass: process.env.EMAIL_PASS, // Use App Password if using Gmail
  },
});

// Request Password Reset
router.post("/reset-password", async (req, res) => {
  try {
    const { email } = req.body;
    console.log("User Email:", email);

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Generate a secure reset token (hashed)
    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedResetToken = crypto.createHash("sha256").update(resetToken).digest("hex");
    const resetTokenExpiry = Date.now() + 15 * 60 * 1000; // 15 minutes expiry

    // Save hashed token in the database
    user.resetToken = hashedResetToken;
    user.resetTokenExpiry = resetTokenExpiry;
    await user.save();

    // Create reset link (pointing to frontend)
    const resetLink = `http://localhost:5173/reset-password/${resetToken}`;
    console.log("Reset Link - ",resetLink)
    // Send email with reset link
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset Request",
      html: `<p>You requested a password reset. Click <a href="${resetLink}">here</a> to reset your password. This link is valid for 15 minutes.</p>`,
    });
    console.log("Generated Reset Token:", resetToken);
    console.log("Hashed Reset Token:", hashedResetToken);
    
    res.json({ message: "Password reset link sent to your email." });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

router.post("/update-password", async (req, res) => {
  try {
    const { token, password } = req.body;

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    console.log("Received Token (before hashing):", token);
    console.log("Hashed Received Token:", hashedToken);
    
    
    // Find user with matching token
    const user = await User.findOne({
      resetToken: hashedToken,
      resetTokenExpiry: { $gt: Date.now() }, // Ensure token is not expired
    });
    console.log("Stored Hashed Token:", user?.resetToken);
    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token." });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);
    
    // Clear reset token fields
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;

    await user.save();

    res.json({ message: "Password reset successful!" });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

module.exports = router;
