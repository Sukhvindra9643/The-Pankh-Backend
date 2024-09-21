const bcrypt = require("bcryptjs");
const pool = require("../db"); // Assuming this is configured for MySQL
const jwt = require("jsonwebtoken");
const config = require("../config/config");
const uuid = require("uuid");
const cloudinary = require("cloudinary").v2;

const registerUser = async (req, res) => {
//  console.log("req.body", req.body);
  try {
    const { username, password, phonenumber, role, file } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    let myCloud = null;
    if (file) {
      myCloud = await cloudinary.uploader.upload(file, {
        folder: "thepankh/users",
        transformation: [{ width: 500, height: 500, crop: "fill" }],
      });
    }

    const id = uuid.v4();
    const fileid = myCloud ? myCloud.public_id : "user_s2xxsm";
    const fileurl = myCloud
      ? myCloud.secure_url
      : "https://res.cloudinary.com/dhk1toauk/image/upload/v1724605962/user_s2xxsm.png";

    const newUserQuery = `
      INSERT INTO users (id, username, password, phonenumber, role, fileid, fileurl, createdat)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const [result] = await pool.query(newUserQuery, [
      id,
      username,
      hashedPassword,
      phonenumber,
      role,
      fileid,
      fileurl,
      new Date(),
    ]);

    res.status(201).json({ success: true, user: { id, username, role } });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ success: false, message: "Server Error" });
  }
};

const loginUser = async (req, res) => {
  try {
    const { username, password } = req.body;
    const userQuery = "SELECT * FROM users WHERE username = ?";
    const [users] = await pool.query(userQuery, [username]);

    if (users.length === 0) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
  //  console.log(user)
    const payload = {
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    };
    //console.log("config",config.jwtSecret)
    jwt.sign(
      payload,
      config.jwtSecret,
      { expiresIn: "1h" },
      (err, token) => {
        if (err) throw err;
        res.cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          maxAge: 3600000,
        });

        res.json({ success: true, message: "Logged in successfully", token });
      }
    );
  } catch (error) {
    res.status(500).send({
      success: false,
      userError: "Server Error",
      error: error.message,
    });
  }
};

const updateUserPassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const userQuery = "SELECT * FROM users WHERE id = ?";
    const [users] = await pool.query(userQuery, [req.user.id]);

    if (users.length === 0) {
      return res.status(404).json({ success: false, msg: "User not found" });
    }

    const user = users[0];
    const isPasswordMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isPasswordMatch) {
      return res.status(401).json({ success: false, msg: "Incorrect current password" });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    const updatePasswordQuery = "UPDATE users SET password = ? WHERE id = ?";
    await pool.query(updatePasswordQuery, [hashedNewPassword, req.user.id]);

    res.json({ success: true, msg: "Password updated successfully" });
  } catch (error) {
    res.status(500).json({
      success: false,
      userError: "Server Error",
      error: error.message,
    });
  }
};

const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const resetToken = crypto.randomBytes(20).toString("hex");

    const updateTokenQuery = `
      UPDATE users SET reset_token = ?, reset_token_expires = DATE_ADD(NOW(), INTERVAL 1 HOUR)
      WHERE email = ?
    `;
    await pool.query(updateTokenQuery, [resetToken, email]);

    res.json({ success: true, msg: "Password reset token sent successfully" });
  } catch (error) {
    console.error(error.message);
    res.status(500).json({ success: false, msg: "Server Error" });
  }
};

module.exports = {
  registerUser,
  loginUser,
  updateUserPassword,
  forgotPassword,
};
