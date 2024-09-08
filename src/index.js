import { app } from "./app.js";
import dotenv from "dotenv";
import os from "os";
import connectDB from "./db/index.js";

dotenv.config({ path: "./.env" });

const getLocalIPAddress = () => {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === "IPv4" && !iface.internal) {
        return iface.address;
      }
    }
  }
  return "localhost"; // Fallback to localhost if no IP found
};

connectDB()
  .then(() => {
    app.listen(process.env.PORT || 8080, () => {
      const localIP = getLocalIPAddress();
      console.log(`⚙️ Server is running at port : ${process.env.PORT}`);
      console.log(`🌐 Local URL: http://localhost:${process.env.PORT}`);
      console.log(`🌐 Network URL: http://${localIP}:${process.env.PORT}`);
    });
  })
  .catch((err) => {
    console.log("MongoDB connection failed !!! ", err);
  });
