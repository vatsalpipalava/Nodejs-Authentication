import jwt from "jsonwebtoken";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";

const verifyJWT = asyncHandler((req, res, next) => {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    throw new ApiError(401, "Unauthorized. Token not found.");
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      throw new ApiError(403, "Invalid Access Token.");
    }

    req._id = decoded._id;
    req.email = decoded.email;
    req.firstName = decoded.firstName;
    req.lastName = decoded.lastName;
    next();
  });
});

export { verifyJWT };
