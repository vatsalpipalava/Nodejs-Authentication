import { validationResult } from "express-validator";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";

const validateInput = (validationRules) =>
  asyncHandler(async (req, res, next) => {
    await Promise.all(validationRules.map((validation) => validation.run(req)));
    const errors = validationResult(req);
    if (errors.isEmpty()) {
      next();
    } else {
      // Use a Set to store unique messages
      const uniqueMessages = new Set(errors.array().map((error) => error.msg));

      // Join the unique messages into a single string
      const joinedMsg = Array.from(uniqueMessages).join(", ");
      throw new ApiError(400, joinedMsg);
    }
  });

export { validateInput };
