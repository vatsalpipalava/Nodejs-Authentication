import { body } from "express-validator";

const PWD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%]).{8,24}$/;

const registerValidation = () => {
  return [
    body("email")
      .isEmail()
      .withMessage("Invalid email format.")
      .notEmpty()
      .withMessage("Email is required."),
    body("firstName")
      .isLength({ min: 2, max: 20 })
      .withMessage("Enter valid first name.")
      .notEmpty()
      .withMessage("Email is required."),
    body("password")
      .matches(PWD_REGEX)
      .withMessage(
        "Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character."
      )
      .notEmpty()
      .withMessage("Password is required."),
  ];
};

const otpValidation = () => {
  return [
    body("emailVerifyOTP")
      .isLength({ min: 4, max: 4 })
      .withMessage("OTP must be at least 4 characters long.")
      .notEmpty()
      .withMessage("OTP is required."),
  ];
};

const loginValidation = () => {
  return [
    body("email")
      .isEmail()
      .withMessage("Invalid email format.")
      .notEmpty()
      .withMessage("Email is required."),
    body("password").notEmpty().withMessage("Password is required."),
  ];
};

const forgotPasswordValidation = () => {
  return [
    body("email")
      .isEmail()
      .withMessage("Invalid email format.")
      .notEmpty()
      .withMessage("Email is required."),
  ];
};

const resetPasswordValidation = () => {
  return [
    body("password")
      .matches(PWD_REGEX)
      .withMessage(
        "Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character."
      )
      .notEmpty()
      .withMessage("Password is required."),
  ];
};

const changePasswordValidation = () => {
  return [
    body("currentPassword").notEmpty().withMessage("Password is required."),
    body("newPassword")
      .matches(PWD_REGEX)
      .withMessage(
        "Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character."
      )
      .notEmpty()
      .withMessage("Password is required."),
  ];
};

export {
  registerValidation,
  otpValidation,
  loginValidation,
  forgotPasswordValidation,
  resetPasswordValidation,
  changePasswordValidation,
};
