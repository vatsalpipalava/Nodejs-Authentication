import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiResponse } from "../utils/ApiResponse.js";

const healthCheck = asyncHandler(async (_, res) => {
  return res
    .status(200)
    .json(
      new ApiResponse("200", {}, "❤️ Health check route work successfully.")
    );
});

export { healthCheck };
