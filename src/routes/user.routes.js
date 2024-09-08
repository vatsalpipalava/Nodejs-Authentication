import { Router } from "express";
import passport from "passport";
import {
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
} from "../controllers/user.controller.js";
import { validateInput } from "../middlewares/expressValidator.middleware.js";
import "../passport/index.js";
import {
  registerValidation,
  otpValidation,
  loginValidation,
  forgotPasswordValidation,
  resetPasswordValidation,
  changePasswordValidation,
} from "../validations/user.validation.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

router
  .route("/register")
  .post(validateInput(registerValidation()), registerUser);

router
  .route("/tokenAndUserVerify/:emailVerificationToken/:userId")
  .get(verifyTokenAndGetUser);

router
  .route("/emailVerify/:emailVerificationToken/:userId")
  .post(validateInput(otpValidation()), emailVerification);

router
  .route("/resendOTP/:emailVerificationToken/:userId")
  .get(resendEmailVerificationOTP);

router.route("/login").post(validateInput(loginValidation()), loginUser);

router.route("/logout").get(verifyJWT, logoutUser);

router.route("/refresh").get(handleRefreshToken);

router.route("/profile").get(verifyJWT, getUser);

router
  .route("/forgot-password")
  .post(validateInput(forgotPasswordValidation()), forgotPassword);

router
  .route("/verifyForgotPasswordToken/:forgotPasswordToken")
  .get(verifyForgotPasswordToken);

router
  .route("/resetPassword/:forgotPasswordToken")
  .post(validateInput(resetPasswordValidation()), resetPassword);

router
  .route("/change-password")
  .post(verifyJWT, validateInput(changePasswordValidation()), changePassword);

// SSO routes
router.route("/google").get(
  passport.authenticate("google", {
    scope: ["profile", "email"],
  }),
  (req, res) => {
    res.send("redirecting to google...");
  }
);

router.route("/google/callback").get(
  passport.authenticate("google", {
    failureRedirect: `${process.env.SEC_FRONTEND_URL}/login`,
  }),
  handleSocialLogin
);

export default router;
