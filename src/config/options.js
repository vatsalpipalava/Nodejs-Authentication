import { allowedOrigins } from "./allowedOrigins.js";

const corsOptions = {
  origin: (origin, callback) => {
    if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  // credentials: true,
  optionsSuccessStatus: 200,
};

const cookieOptions = {
  httpOnly: true,
  maxAge: 24 * 60 * 60 * 1000,
  secure: true,
  sameSite: "none",
};

const clearCookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "none",
};

export { corsOptions, cookieOptions, clearCookieOptions };
