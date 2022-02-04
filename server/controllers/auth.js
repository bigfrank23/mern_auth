const User = require('../models/User')
const errorHandler = require('../middleware/error');
const ErrorResponse = require('../utils/errorResponse');
const sendEmail = require('../utils/sendEmail')
const crypto = require('crypto')

exports.register = async(req, res, next) => {
    const { username, email, password } = req.body;
    try {
        const user = await User.create({username, email, password})
        sendToken(user, 201, res)
        // res.status(201).json({success: true, user, token: "rrytretere"})
    } catch (error) {
      next(error);
        // res.status(500).json({success: false, error: error.message})
    }
    // res.send("Register route...")
}

exports.login = async(req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return next(new ErrorResponse("Please provide email and password", 400));
    // res.status(400).json({success: false, error: "Please provide email and password"})
  }

  try {
    const user = await User.findOne({email}).select("+password")
    if (!user) {
      return next(new ErrorResponse("Invalid Credentials", 401));
      // res.status(404).json({success: false, error: "Invalid Credentials"})
    }

    const isMatch = await user.matchPasswords(password)
    if (!isMatch) {
      return next(new ErrorResponse("Invalid Credentials", 401));
      // res.status(404).json({ success: false, error: "Invalid Credentials" });
    }

    sendToken(user, 201, res);
    // res.status(200).json({
    //   success: true,
    //   token: "ueui45j5j53s"
    // })

  } catch (error) {
    res.status(500).json({success: false, error: error.message})
  }
  // res.send("Login route...");
};

exports.forgotpassword = async(req, res, next) => {
  const {email} = req.body
  try {
    const user = await User.findOne({email});

    if (!user) {
      return next(new ErrorResponse("Email could not be sent.", 404))
    }

    const resetToken = user.getResetPasswordToken()

    await user.save()

    const resetUrl = `http://localhost:3000/passwordreset/${resetToken}`;

    const message = 
    `
    <h1> You have requested a password reset </h1>
    <p> Please go to this link to reset your password </p>
    <a href=${resetUrl}> ${resetUrl} </a>
    `

    try {
      await sendEmail({
        to: user.email,
        subject: "Password Reset Request",
        text: message
      })

      res.status(200).json({success: true, data: "Email Sent!"})
    } catch (error) {
      user.resetPasswordToken = undefined;
      user.resetPasswordExpired = undefined;

      await user.save()

      return next(new ErrorResponse("Email could ot be sent", 500))
    }

  } catch (error) {
    next(error)
  }
  // res.send("Forgot Password route...");
};

exports.resetpassword = async(req, res, next) => {
  const resetPasswordToken = crypto.createHash("sha256").update(req.params.resetToken).digest("hex")

  try {
    const user = await User.findOne({
      resetPasswordToken, resetPasswordExpired: {$gt: Date.now()}
    })

    if (!user) {
      return next(new ErrorResponse("Invalid Reset Token", 400))
    }

    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpired = undefined;

    await user.save();

    res.status(201).json({success: true, data: "Password Reset Success"})

  } catch (error) {
    next(error)
  }
  // res.send("Reset password route...");
};

const sendToken = (user, statusCode, res) => {
  const token = user.getSignedToken()
  res.status(statusCode).json({success: true, token})
}