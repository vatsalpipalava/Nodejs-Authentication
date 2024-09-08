import path from "path";
import fs from "fs";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { ApiError } from "../utils/ApiError.js";
import { generateOTP } from "../utils/generateOTP.js";
import { sendEmail } from "../utils/mailer.js";
import { fileURLToPath } from "url";
import { cookieOptions, clearCookieOptions } from "../config/options.js";
import { UserLoginType } from "../constants.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const generateEmailVerificationTokenAndOTP = async (userId) => {
  try {
    const user = await User.findById(userId);

    const emailVerificationToken = await user.generateEmailVerificationToken();

    const { emailVerifyOTP } = generateOTP();

    user.emailVerificationToken = emailVerificationToken;
    user.emailVerifyOTP = emailVerifyOTP;
    user.emailOTPExpire = new Date(Date.now() + 5 * 60 * 1000);

    await user.save({ validateBeforeSave: false });

    return { emailVerifyOTP };
  } catch (error) {
    throw new ApiError(
      500,
      "Something wnt wrong while generating email verification token and emailVerifyOTP."
    );
  }
};

const generateForgotPasswordToken = async (userId) => {
  try {
    const user = await User.findById(userId);

    const forgotPasswordToken = await user.generateForgotPasswordToken();

    user.forgotPasswordToken = forgotPasswordToken;

    await user.save({ validateBeforeSave: false });

    return { forgotPasswordToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something wnt wrong while generating email verification token and emailVerifyOTP."
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  const existedUser = await User.findOne({ email });

  if (existedUser) {
    if (existedUser.isEmailVerified) {
      throw new ApiError(409, "Email already exists.");
    }

    // const user = await User.create({
    //   firstName: firstName,
    //   lastName: lastName,
    //   email: email,
    //   password: password,
    // });

    existedUser.firstName = firstName;
    existedUser.lastName = lastName;
    existedUser.password = password;

    await existedUser.save();

    const templatePath = path.join(
      __dirname,
      "..",
      "mails",
      "emailVerification.html"
    );
    const template = fs.readFileSync(templatePath, "utf-8");

    const { emailVerifyOTP } = await generateEmailVerificationTokenAndOTP(
      existedUser._id
    );

    await sendEmail(
      {
        emailVerifyOTP: emailVerifyOTP,
        email: email.toLowerCase(),
        firstName: firstName,
        lastName: lastName,
      },
      [email],
      template,
      "Welcome to our service"
    );

    const already_user = await User.findById(existedUser._id).select(
      "-password -refreshToken -emailVerifyOTP -forgotPasswordToken"
    );

    return res
      .status(200)
      .json(
        new ApiResponse(
          200,
          already_user,
          `Email verification instruction sent to ${email}. Please verify your email first by entering OTP.`
        )
      );
  }

  const user = await User.create({
    firstName: firstName,
    lastName: lastName,
    email: email,
    password: password,
  });

  const templatePath = path.join(
    __dirname,
    "..",
    "mails",
    "emailVerification.html"
  );

  const template = fs.readFileSync(templatePath, "utf-8");

  // const registeredUser = await User.findById(user._id);

  const { emailVerifyOTP } = await generateEmailVerificationTokenAndOTP(
    user._id
  );

  await sendEmail(
    {
      emailVerifyOTP: emailVerifyOTP,
      email: email.toLowerCase(),
      firstName: firstName,
      lastName: lastName,
    },
    [email],
    template,
    "Welcome to our service"
  );

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerifyOTP -emailOTPExpire -forgotPasswordToken"
  );

  return res
    .status(201)
    .json(
      new ApiResponse(
        201,
        createdUser,
        `Email verification instruction send to ${email}. Please, verify your email first by entering OTP.`
      )
    );
});

const verifyTokenAndGetUser = asyncHandler(async (req, res) => {
  const { emailVerificationToken, userId } = req.params;

  let decoded;
  try {
    decoded = jwt.verify(
      emailVerificationToken,
      process.env.EMAIL_VERIFICATION_TOKEN_SECRET
    );
  } catch (error) {
    throw new ApiError(401, "Invalid or expired email verification token.");
  }

  if (decoded._id !== userId) {
    throw new ApiError(400, "Token does not match the user.");
  }

  const user = await User.findById(userId).select(
    "-password -refreshToken -emailVerifyOTP -forgotPasswordToken"
  );

  if (!user) {
    throw new ApiError(400, "User not found.");
  }

  if (user.isEmailVerified) {
    throw new ApiError(400, "Email is already verified.");
  }

  if (decoded.email !== user.email) {
    throw new ApiError(400, "Token does not match the user email.");
  }

  if (user.emailVerificationToken !== emailVerificationToken) {
    throw new ApiError(400, "Invalid email verification token.");
  }

  const userEmail = user.email;

  return res
    .status(200)
    .json(
      new ApiResponse(200, { userEmail }, "Email verification token is valid.")
    );
});

const emailVerification = asyncHandler(async (req, res) => {
  const { emailVerifyOTP } = req.body;
  const { emailVerificationToken, userId } = req.params;

  let decoded;
  try {
    decoded = jwt.verify(
      emailVerificationToken,
      process.env.EMAIL_VERIFICATION_TOKEN_SECRET
    );
  } catch (error) {
    throw new ApiError(400, "Invalid or expired email verification token.");
  }

  if (decoded._id !== userId) {
    throw new ApiError(400, "Token does not match the user.");
  }

  const user = await User.findById(userId);

  if (!user) {
    throw new ApiError(404, "User not found.");
  }

  if (user.isEmailVerified) {
    throw new ApiError(400, "Email is already verified.");
  }

  if (decoded.email !== user.email) {
    throw new ApiError(400, "Token does not match the user email.");
  }

  if (user.emailVerificationToken !== emailVerificationToken) {
    throw new ApiError(400, "Invalid email verification token.");
  }

  // const verifyOTP = emailVerifyOTP === user.emailVerifyOTP;

  // if (!verifyOTP) {
  //   throw new ApiError(400, "Invalid OTP.");
  // }

  if (new Date() > user.emailOTPExpire) {
    throw new ApiError(410, "OTP has expired.");
  }

  if (emailVerifyOTP !== user.emailVerifyOTP) {
    throw new ApiError(401, "Invalid OTP.");
  }

  user.isEmailVerified = true;
  user.emailVerificationToken = undefined;
  user.emailVerifyOTP = undefined;
  user.emailOTPExpire = undefined;
  await user.save({ validateBeforeSave: false });

  const verifiedUser = await User.findById(userId).select(
    "-password -refreshToken -emailVerifyOTP -emailVerificationToken -forgotPasswordToken"
  );

  return res
    .status(200)
    .json(new ApiResponse(200, verifiedUser, "Email verified successfully"));
});

const resendEmailVerificationOTP = asyncHandler(async (req, res) => {
  const { emailVerificationToken, userId } = req.params;

  let decoded;
  try {
    decoded = jwt.verify(
      emailVerificationToken,
      process.env.EMAIL_VERIFICATION_TOKEN_SECRET
    );
  } catch (error) {
    throw new ApiError(400, "Invalid or expired email verification token.");
  }

  if (decoded._id !== userId) {
    throw new ApiError(400, "Token does not match the user.");
  }

  const user = await User.findById(userId);

  if (!user) {
    throw new ApiError(404, "User not found.");
  }

  if (user.isEmailVerified) {
    throw new ApiError(400, "Email is already verified.");
  }

  if (decoded.email !== user.email) {
    throw new ApiError(400, "Token does not match the user email.");
  }

  if (user.emailVerificationToken !== emailVerificationToken) {
    throw new ApiError(400, "Invalid email verification token.");
  }

  const templatePath = path.join(
    __dirname,
    "..",
    "mails",
    "emailVerification.html"
  );

  const template = fs.readFileSync(templatePath, "utf-8");

  const { emailVerifyOTP } = await generateEmailVerificationTokenAndOTP(
    user._id
  );

  await sendEmail(
    {
      emailVerifyOTP: emailVerifyOTP,
      email: user.email.toLowerCase(),
      firstName: user.firstName,
      lastName: user.lastName,
    },
    [user.email],
    template
  );

  const resendUser = await User.findById(user._id).select(
    "-firstName -lastName -password -refreshToken -emailVerifyOTP -emailOTPExpire -forgotPasswordToken"
  );

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        resendUser,
        `Email verification instruction sent to ${user.email}. Please verify your email first by entering OTP.`
      )
    );
});

const loginUser = asyncHandler(async (req, res) => {
  const cookies = req.cookies;

  const { email, password } = req.body;
  const foundUser = await User.findOne({
    email: email,
    isEmailVerified: true,
  }).exec();

  if (!foundUser) {
    throw new ApiError(404, "User does not exist.");
  }

  if (foundUser.loginType !== UserLoginType.EMAIL_PASSWORD) {
    // If user is registered with some other method, we will ask him/her to use the same method as registered.
    // This shows that if user is registered with methods other than email password, he/she will not be able to login with password. Which makes password field redundant for the SSO
    throw new ApiError(
      400,
      "You have previously registered using " +
        foundUser.loginType?.toLowerCase() +
        ". Please use the " +
        foundUser.loginType?.toLowerCase() +
        " login option to access your account."
    );
  }

  const match = await foundUser.isPasswordCorrect(password);
  if (match) {
    const accessToken = foundUser.generateAccessToken();
    const newRefreshToken = foundUser.generateRefreshToken();

    let newRefreshTokenArray = !cookies?.jwt // TODO: Change jwt to user_token
      ? foundUser.refreshToken
      : foundUser.refreshToken.filter((rt) => rt !== cookies.jwt); // TODO: Change jwt to user_token

    if (cookies?.jwt) {
      // TODO: Change jwt to user_token
      /* 
        Scenario added here: 
          1) User logs in but never uses RT and does not logout 
          2) RT is stolen
          3) If 1 & 2, reuse detection is needed to clear all RTs when user logs in
      */
      const refreshToken = cookies.jwt; // TODO: Change jwt to user_token
      const foundToken = await User.findOne({ refreshToken }).exec();

      // Detected refresh token reuse!
      if (!foundToken) {
        // clear out ALL previous refresh tokens
        newRefreshTokenArray = [];
      }

      res.clearCookie("jwt", clearCookieOptions); // TODO: Change jwt to user_token
    }

    // Saving refreshToken with current user
    foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
    const result = await foundUser.save({ validateBeforeSave: false });

    // Creates Secure Cookie with refresh token
    res.cookie("jwt", newRefreshToken, cookieOptions); // TODO: Change jwt to user_token

    // Send access token to user
    res.json({ accessToken });
    // res
    //   .status(200)
    //   .json(new ApiResponse(200, accessToken, "Login Successfully."));
  } else {
    // res.sendStatus(401);
    throw new ApiError(401, "Unauthorized");
  }
});

const handleSocialLogin = asyncHandler(async (req, res) => {
  const cookies = req.cookies;
  const foundUser = await User.findById(req.user?._id);

  if (!foundUser) {
    throw new ApiError(404, "User does not exist");
  }

  const accessToken = foundUser.generateAccessToken();
  const newRefreshToken = foundUser.generateRefreshToken();

  let newRefreshTokenArray = !cookies?.jwt // TODO: Change jwt to user_token
    ? foundUser.refreshToken
    : foundUser.refreshToken.filter((rt) => rt !== cookies.jwt); // TODO: Change jwt to user_token

  if (cookies?.jwt) {
    // TODO: Change jwt to user_token
    /* 
          Scenario added here: 
            1) User logs in but never uses RT and does not logout 
            2) RT is stolen
            3) If 1 & 2, reuse detection is needed to clear all RTs when user logs in
        */
    const refreshToken = cookies.jwt; // TODO: Change jwt to user_token
    const foundToken = await User.findOne({ refreshToken }).exec();

    // Detected refresh token reuse!
    if (!foundToken) {
      // clear out ALL previous refresh tokens
      newRefreshTokenArray = [];
    }

    res.clearCookie("jwt", clearCookieOptions); // TODO: Change jwt to user_token
  }

  // Saving refreshToken with current user
  foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
  const result = await foundUser.save({ validateBeforeSave: false });

  // Creates Secure Cookie with refresh token
  res.cookie("jwt", newRefreshToken, cookieOptions); // TODO: Change jwt to user_token

  res.status(301).redirect(
    // redirect user to the frontend with access and refresh token in case user is not using cookies
    `${process.env.SEC_FRONTEND_URL}/dashboard`
  );
  // res.json({ accessToken });
});

const logoutUser = asyncHandler(async (req, res) => {
  // On client, also delete the accessToken

  const cookies = req.cookies;
  if (!cookies?.jwt) {
    //No content // TODO: Change jwt to user_token
    return res.status(200).json(new ApiResponse(200, {}, "Already Logout."));
  }
  const refreshToken = cookies.jwt; // TODO: Change jwt to user_token

  // Is refreshToken in db?
  const foundUser = await User.findOne({ refreshToken }).exec();
  if (!foundUser) {
    res.clearCookie("jwt", clearCookieOptions); // TODO: Change jwt to user_token
    return res
      .status(200)
      .json(new ApiResponse(200, {}, "User not found. Already Logout."));
    // res.status(204).json(new ApiResponse(204, {}, ""));
  }

  // Delete refreshToken in db
  foundUser.refreshToken = foundUser.refreshToken.filter(
    (rt) => rt !== refreshToken
  );

  const result = await foundUser.save({ validateBeforeSave: false });

  res.clearCookie("jwt", clearCookieOptions); // TODO: Change jwt to user_token
  res.status(200).json(new ApiResponse(200, {}, "Logout Successfully."));
});

const handleRefreshToken = asyncHandler(async (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(401);
  //   {
  //   // TODO: Change jwt to user_token
  //   throw new ApiError(401, "Unauthorized. Token not found.");
  // }
  const refreshToken = cookies.jwt;
  res.clearCookie("jwt", clearCookieOptions); // TODO: Change jwt to user_token

  const foundUser = await User.findOne({ refreshToken }).exec();

  // Detected refresh token reuse!
  if (!foundUser) {
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      async (err, decoded) => {
        if (err) {
          return res.sendStatus(403);
          // throw new ApiError(403, "Forbidden");
        }

        // Delete refresh tokens of hacked user
        const hackedUser = await User.findOne({
          _id: decoded._id,
          email: decoded.email,
        });
        // hackedUser.refreshToken = [];
        // const result = await hackedUser.save();

        if (hackedUser) {
          hackedUser.refreshToken = [];
          await hackedUser.save({ validateBeforeSave: false });
        }
      }
    );
    return res.sendStatus(403);
    // throw new ApiError(403, "Forbidden t");
  }

  const newRefreshTokenArray = foundUser.refreshToken.filter(
    (rt) => rt !== refreshToken
  );

  // evaluate jwt
  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    async (err, decoded) => {
      if (err) {
        // expired refresh token
        foundUser.refreshToken = [...newRefreshTokenArray];
        const result = await foundUser.save({ validateBeforeSave: false });
      }

      const userIdString = foundUser._id.toString();

      if (err || userIdString !== decoded._id) {
        return res.sendStatus(403);
        // return res.status(403).json(new ApiResponse(403, {}, "Forbidden"))
      }

      // Refresh token was still valid
      const accessToken = foundUser.generateAccessToken();
      const newRefreshToken = foundUser.generateRefreshToken();

      // Saving refreshToken with current user
      foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
      const result = await foundUser.save({ validateBeforeSave: false });

      // Creates Secure Cookie with refresh token
      res.cookie("jwt", newRefreshToken, cookieOptions); // TODO: Change jwt to user_token

      res.json({ email: result.email, accessToken });
    }
  );
});

const getUser = asyncHandler(async (req, res) => {
  const _id = req._id;
  // const email = req.email;
  // const firstName = req.firstName;
  // const lastName = req.lastName;

  const user = await User.findById(_id).select(
    "email firstName lastName loginType"
  );

  return res
    .status(200)
    .json(new ApiResponse(200, user, "User retrieved successfully."));
});

const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    throw new ApiError(404, "User not found.");
  }

  if (user.loginType !== UserLoginType.EMAIL_PASSWORD) {
    // If user is registered with some other method, we will ask him/her to use the same method as registered.
    // This shows that if user is registered with methods other than email password, he/she will not be able to login with password. Which makes password field redundant for the SSO
    throw new ApiError(
      400,
      "You have previously registered using " +
        user.loginType?.toLowerCase() +
        ". Please use the " +
        user.loginType?.toLowerCase() +
        " login option to access your account."
    );
  }

  const templatePath = path.join(
    __dirname,
    "..",
    "mails",
    "forgotPassword.html"
  );

  const template = fs.readFileSync(templatePath, "utf-8");

  const { forgotPasswordToken } = await generateForgotPasswordToken(user._id);

  await sendEmail(
    {
      resetPasswordLink: `${process.env.SEC_FRONTEND_URL}/reset-password/${forgotPasswordToken}`,
      firstName: user.firstName,
      lastName: user.lastName,
    },
    [email],
    template,
    "Reset Password"
  );

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        {},
        `Password reset instruction send to ${email}. Please, Reset your password by clicking this link.`
      )
    );
});

const verifyForgotPasswordToken = asyncHandler(async (req, res) => {
  const { forgotPasswordToken } = req.params;

  let decoded;
  try {
    decoded = jwt.verify(
      forgotPasswordToken,
      process.env.FORGOT_PASSWORD_TOKEN_SECRET
    );
  } catch (error) {
    throw new ApiError(401, "Invalid or expire forgot password token.");
  }

  const user = await User.findById(decoded._id);

  if (!user || user.forgotPasswordToken !== forgotPasswordToken) {
    throw new ApiError(400, "Invalid token.");
  }

  return res
    .status(200)
    .json(
      new ApiResponse(200, { isValid: true }, "Forgot password token is valid.")
    );
});

const resetPassword = asyncHandler(async (req, res) => {
  const { forgotPasswordToken } = req.params;
  const { password } = req.body;

  let decoded;
  try {
    decoded = jwt.verify(
      forgotPasswordToken,
      process.env.FORGOT_PASSWORD_TOKEN_SECRET
    );
  } catch (error) {
    throw new ApiError(401, "Invalid or expire forgot password token.");
  }

  const user = await User.findById(decoded._id);

  if (!user || user.forgotPasswordToken !== forgotPasswordToken) {
    throw new ApiError(400, "Invalid token.");
  }

  user.password = password;
  user.forgotPasswordToken = undefined;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password reset successfully."));
});

const changePassword = asyncHandler(async (req, res) => {
  const userId = req._id;
  const { currentPassword, newPassword } = req.body;

  const user = await User.findById(userId);

  const match = await user.isPasswordCorrect(currentPassword);

  if (!match) {
    throw new ApiError(401, "Unauthorized");
  }

  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully."));
});

export {
  registerUser,
  verifyTokenAndGetUser,
  emailVerification,
  resendEmailVerificationOTP,
  loginUser,
  logoutUser,
  handleRefreshToken,
  getUser,
  forgotPassword,
  verifyForgotPasswordToken,
  resetPassword,
  changePassword,
  handleSocialLogin,
};